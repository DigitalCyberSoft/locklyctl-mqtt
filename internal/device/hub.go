package device

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// ErrOffline is returned by SendCommand when the lock is not connected.
var ErrOffline = errors.New("lock is offline")

// lockLookup is the slice of the store the hub needs (kept small for testing).
type lockLookup interface {
	GetLockByMQTTUsername(username string) (*store.Lock, error)
	GetLockByDeviceID(deviceID string) (*store.Lock, error)
	AddEvent(*store.Event) error
}

// Hub is the MQTT broker plus the Lockly device-channel protocol handler.
type Hub struct {
	store lockLookup
	log   *slog.Logger
	mq    *mqtt.Server

	// publish lets tests capture outbound messages; in production it is the
	// broker's Publish.
	publish func(topic string, payload []byte, qos byte) error

	mu      sync.Mutex
	pending map[string]chan *CommandPayload
	online  map[string]bool              // clientId -> connected
	state   map[string]map[string]string // deviceId -> statusKey -> value
}

// New builds a hub over the store. Call Listen then Start to serve.
func New(st lockLookup, log *slog.Logger) *Hub {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	h := &Hub{
		store:   st,
		log:     log,
		pending: map[string]chan *CommandPayload{},
		online:  map[string]bool{},
		state:   map[string]map[string]string{},
	}
	h.mq = mqtt.New(&mqtt.Options{Logger: log})
	_ = h.mq.AddHook(&hook{h: h}, nil)
	h.publish = func(topic string, payload []byte, qos byte) error {
		return h.mq.Publish(topic, payload, false, qos)
	}
	return h
}

// ListenConfig configures one broker listener.
type ListenConfig struct {
	ID   string
	Addr string      // host:port
	TLS  *tls.Config // nil for plaintext
}

// Listen adds a TCP (or TLS) listener. Add listeners before Start.
func (h *Hub) Listen(cfg ListenConfig) error {
	id := cfg.ID
	if id == "" {
		id = "tcp"
	}
	return h.mq.AddListener(listeners.NewTCP(listeners.Config{ID: id, Address: cfg.Addr, TLSConfig: cfg.TLS}))
}

// Start serves the broker (non-blocking).
func (h *Hub) Start() error { return h.mq.Serve() }

// Stop closes the broker.
func (h *Hub) Stop() error { return h.mq.Close() }

// Online reports whether a lock with this MQTT client id is connected.
func (h *Hub) Online(clientID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.online[clientID]
}

// LastState returns the last deviceStateCallback values for a device.
func (h *Hub) LastState(deviceID string) (map[string]string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.state[deviceID]
	if !ok {
		return nil, false
	}
	out := make(map[string]string, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out, true
}

// SendCommand relays a BLE frame (hex) to a lock and returns the lock's ACK
// hex. It waits until ctx is done. ErrOffline if the lock is not connected.
func (h *Hub) SendCommand(ctx context.Context, clientID, deviceID, frameHex string) (string, error) {
	if !h.Online(clientID) {
		return "", ErrOffline
	}
	content, err := frameToContent(frameHex)
	if err != nil {
		return "", fmt.Errorf("bad frame hex: %w", err)
	}
	rid, err := newRequestID()
	if err != nil {
		return "", err
	}
	ch := make(chan *CommandPayload, 1)
	h.mu.Lock()
	h.pending[rid] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, rid)
		h.mu.Unlock()
	}()

	env, err := marshalEnvelope(NameCommandRequest, rid, nowMs(), CommandPayload{
		DeviceID: deviceID, CommandName: CommandForward, CommandContent: content})
	if err != nil {
		return "", err
	}
	if err := h.publish(TopicClientPrefix+clientID, env, 1); err != nil {
		return "", err
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case resp := <-ch:
		if !codeIsSuccess(resp.Code) {
			return "", fmt.Errorf("lock returned code %v: %s", resp.Code, resp.ErrorMessage)
		}
		if resp.CommandContent == "" {
			return "", nil
		}
		return contentToFrame(resp.CommandContent)
	}
}

// ingest handles a message a client published to the server topic.
func (h *Hub) ingest(clientID string, payload []byte) {
	var env Envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		h.log.Debug("ingest: bad envelope", "client", clientID, "err", err)
		return
	}
	// Correlate any reply that carries our requestId (command responses,
	// exceptions to a command), as locklyctl does.
	if rid := env.Header.RequestID; rid != "" {
		h.mu.Lock()
		ch := h.pending[rid]
		h.mu.Unlock()
		if ch != nil {
			var cp CommandPayload
			_ = json.Unmarshal(env.Payload, &cp)
			select {
			case ch <- &cp:
			default:
			}
			return
		}
	}
	switch env.Header.Name {
	case NameStateCallback:
		h.handleState(env.Payload)
	case NameEventLogResponse:
		h.handleEvents(env.Payload)
	}
}

func (h *Hub) handleState(payload json.RawMessage) {
	var sp StatePayload
	if err := json.Unmarshal(payload, &sp); err != nil || sp.DeviceID == "" {
		return
	}
	h.mu.Lock()
	m := h.state[sp.DeviceID]
	if m == nil {
		m = map[string]string{}
		h.state[sp.DeviceID] = m
	}
	for _, s := range sp.States {
		m[s.StatusKey] = s.StatusValue
	}
	h.mu.Unlock()
}

func (h *Hub) handleEvents(payload json.RawMessage) {
	var body struct {
		DeviceID string `json:"deviceId"`
		Items    []struct {
			Timestamp int64  `json:"timestamp"`
			Time      string `json:"time"`
			Code      any    `json:"co"`
			PwdID     *int   `json:"pid"`
		} `json:"items"`
	}
	if err := json.Unmarshal(payload, &body); err != nil || body.DeviceID == "" {
		return
	}
	lk, err := h.store.GetLockByDeviceID(body.DeviceID)
	if err != nil {
		return
	}
	for _, it := range body.Items {
		raw, _ := json.Marshal(it)
		_ = h.store.AddEvent(&store.Event{
			LockID: lk.ID, TM: it.Timestamp, Code: fmt.Sprintf("%v", it.Code),
			PwdID: it.PwdID, Raw: string(raw)})
	}
}

// authenticate validates a lock's MQTT username/password against the store.
func (h *Hub) authenticate(username, password string) bool {
	if username == "" {
		return false
	}
	lk, err := h.store.GetLockByMQTTUsername(username)
	if err != nil || lk.MQTTPassword == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(password), []byte(lk.MQTTPassword)) == 1
}

func (h *Hub) setOnline(clientID string, up bool) {
	h.mu.Lock()
	if up {
		h.online[clientID] = true
	} else {
		delete(h.online, clientID)
	}
	h.mu.Unlock()
}

func newRequestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func nowMs() int64 { return time.Now().UnixMilli() }

// hook bridges broker events into the hub.
type hook struct {
	mqtt.HookBase
	h *Hub
}

func (hk *hook) ID() string { return "lockly-device" }

func (hk *hook) Provides(b byte) bool {
	switch b {
	case mqtt.OnConnectAuthenticate, mqtt.OnConnect, mqtt.OnDisconnect, mqtt.OnPublish:
		return true
	}
	return false
}

func (hk *hook) OnConnectAuthenticate(cl *mqtt.Client, pk packets.Packet) bool {
	return hk.h.authenticate(string(pk.Connect.Username), string(pk.Connect.Password))
}

func (hk *hook) OnConnect(cl *mqtt.Client, pk packets.Packet) error {
	hk.h.setOnline(cl.ID, true)
	return nil
}

func (hk *hook) OnDisconnect(cl *mqtt.Client, err error, expire bool) {
	hk.h.setOnline(cl.ID, false)
}

func (hk *hook) OnPublish(cl *mqtt.Client, pk packets.Packet) (packets.Packet, error) {
	if pk.TopicName == TopicServer {
		hk.h.ingest(cl.ID, pk.Payload)
	}
	return pk, nil
}
