package device

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	mqtt "github.com/mochi-mqtt/server/v2"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

type fakeStore struct {
	locks  []*store.Lock // what LocksByMQTTIdentity searches
	byDev  map[string]*store.Lock
	events []*store.Event
}

func (f *fakeStore) LocksByMQTTIdentity(u, cid string) ([]store.Lock, error) {
	var out []store.Lock
	for _, l := range f.locks {
		if (u != "" && l.MQTTUsername == u) || (cid != "" && l.MQTTClientID == cid) {
			out = append(out, *l)
		}
	}
	return out, nil
}
func (f *fakeStore) GetLockByDeviceID(d string) (*store.Lock, error) {
	if l, ok := f.byDev[d]; ok {
		return l, nil
	}
	return nil, store.ErrNotFound
}
func (f *fakeStore) AddEvent(e *store.Event) error { f.events = append(f.events, e); return nil }

func newTestHub() (*Hub, *fakeStore) {
	fs := &fakeStore{byDev: map[string]*store.Lock{}}
	return New(fs, nil), fs
}

func TestAuthenticate(t *testing.T) {
	h, fs := newTestHub()
	fs.locks = append(fs.locks, &store.Lock{DeviceID: "d1", MQTTUsername: "lock-u", MQTTPassword: "secret", MQTTClientID: "cid"})
	cases := []struct {
		u, p, cid string
		want      bool
	}{
		{"lock-u", "secret", "cid", true},
		{"lock-u", "wrong", "cid", false},
		{"lock-u", "secret", "other-cid", false}, // the client id must be the lock's own
		{"lock-u", "secret", "", false},
		{"", "", "", false},
		{"nobody", "secret", "cid", false},
	}
	for _, c := range cases {
		if got := h.authenticate(c.u, c.p, c.cid); got != c.want {
			t.Fatalf("authenticate(%q, %q, %q) = %v, want %v", c.u, c.p, c.cid, got, c.want)
		}
	}
	// a lock with no provisioned password cannot authenticate
	fs.locks = append(fs.locks, &store.Lock{DeviceID: "d2", MQTTUsername: "bare", MQTTClientID: "bare-cid"})
	if h.authenticate("bare", "", "bare-cid") {
		t.Fatal("authenticated a lock with no password")
	}
}

// Neither the MQTT username nor the client id is unique in the store, and an
// account can set both through a backup import. A second lock claiming either
// one must not let it pass as the first, so neither gets in.
func TestAuthenticateRefusesSharedOrWildcardIdentity(t *testing.T) {
	h, fs := newTestHub()
	victim := &store.Lock{DeviceID: "d1", MQTTUsername: "victim", MQTTPassword: "pw1", MQTTClientID: "cid-v"}
	fs.locks = []*store.Lock{victim,
		{DeviceID: "d2", MQTTUsername: "intruder", MQTTPassword: "pw2", MQTTClientID: "cid-v"}}
	if h.authenticate("intruder", "pw2", "cid-v") || h.authenticate("victim", "pw1", "cid-v") {
		t.Fatal("a client id two locks claim was accepted")
	}
	fs.locks = []*store.Lock{victim,
		{DeviceID: "d2", MQTTUsername: "victim", MQTTPassword: "pw2", MQTTClientID: "cid-2"}}
	if h.authenticate("victim", "pw2", "cid-2") || h.authenticate("victim", "pw1", "cid-v") {
		t.Fatal("a username two locks claim was accepted")
	}
	for _, cid := range []string{"#", "cid/#", "+"} {
		fs.locks = []*store.Lock{{DeviceID: "d3", MQTTUsername: "w", MQTTPassword: "pw", MQTTClientID: cid}}
		if h.authenticate("w", "pw", cid) {
			t.Fatalf("client id %q (an MQTT wildcard) was accepted", cid)
		}
	}
}

func TestACL(t *testing.T) {
	h, _ := newTestHub()
	hk := &hook{h: h}
	cl := &mqtt.Client{ID: "cid"}
	cases := []struct {
		topic string
		write bool
		want  bool
	}{
		{"client/cid", false, true}, // its own commands
		{"server", true, true},      // everything it sends
		{"client/cid", true, false},
		{"server", false, false}, // other locks' messages
		{"client/other", false, false},
		{"client/#", false, false},
		{"client/+", false, false},
		{"#", false, false},
		{"client/other", true, false},
	}
	for _, c := range cases {
		if got := hk.OnACLCheck(cl, c.topic, c.write); got != c.want {
			t.Errorf("OnACLCheck(%q, write=%v) = %v, want %v", c.topic, c.write, got, c.want)
		}
	}
}

// When a lock reconnects and takes its session over, the old connection's
// disconnect arrives after the new connection is up.
func TestPresenceSurvivesSessionTakeover(t *testing.T) {
	h, _ := newTestHub()
	old, cur := &mqtt.Client{ID: "cid"}, &mqtt.Client{ID: "cid"}
	h.connected("cid", "2d00", old)
	h.connected("cid", "2d00", cur)
	h.disconnected("cid", old)
	if !h.Online("cid") {
		t.Fatal("the old connection's disconnect took the lock offline")
	}
	h.disconnected("cid", cur)
	if h.Online("cid") {
		t.Fatal("still online after the current connection left")
	}
}

func TestSendCommandOffline(t *testing.T) {
	h, _ := newTestHub()
	_, err := h.SendCommand(context.Background(), "cid", "dev", "A1B2C3D4")
	if err != ErrOffline {
		t.Fatalf("want ErrOffline, got %v", err)
	}
}

func TestSendCommandRoundTrip(t *testing.T) {
	h, _ := newTestHub()
	h.connected("cid", "2d00", &mqtt.Client{ID: "cid"})

	published := make(chan []byte, 1)
	h.publish = func(topic string, payload []byte, qos byte) error {
		if topic != TopicClientPrefix+"cid" {
			t.Errorf("published to %q", topic)
		}
		published <- payload
		return nil
	}

	type result struct {
		ack string
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		ack, err := h.SendCommand(ctx, "cid", "2d00", "A1B2C3D40A0000110525")
		done <- result{ack, err}
	}()

	// read the command, echo a response correlated by requestId
	var cmd Envelope
	if err := json.Unmarshal(<-published, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Header.Name != NameCommandRequest || cmd.Header.RequestID == "" {
		t.Fatalf("unexpected command envelope: %+v", cmd.Header)
	}
	ackBytes, _ := hex.DecodeString("0A1E0011")
	resp, _ := marshalEnvelope(NameCommandResponse, cmd.Header.RequestID, nowMs(),
		CommandPayload{DeviceID: "2d00", CommandContent: base64.StdEncoding.EncodeToString(ackBytes)})
	h.ingest("cid", resp)

	r := <-done
	if r.err != nil {
		t.Fatalf("SendCommand err: %v", r.err)
	}
	if r.ack != "0A1E0011" {
		t.Fatalf("ack = %s", r.ack)
	}
}

func TestSendCommandCodeError(t *testing.T) {
	h, _ := newTestHub()
	h.connected("cid", "dev", &mqtt.Client{ID: "cid"})
	published := make(chan []byte, 1)
	h.publish = func(_ string, payload []byte, _ byte) error { published <- payload; return nil }

	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		_, err := h.SendCommand(ctx, "cid", "dev", "A1B2C3D4")
		done <- err
	}()
	var cmd Envelope
	_ = json.Unmarshal(<-published, &cmd)
	resp, _ := marshalEnvelope(NameException, cmd.Header.RequestID, nowMs(),
		CommandPayload{DeviceID: "dev", Code: "3005", ErrorMessage: "device is offline"})
	h.ingest("cid", resp)
	if err := <-done; err == nil {
		t.Fatal("expected an error for code 3005")
	}
}

func TestIngestStateCallback(t *testing.T) {
	h, _ := newTestHub()
	h.connected("cid", "2d00", &mqtt.Client{ID: "cid"})
	payload := `{"deviceId":"2d00","states":[{"statusKey":"LOCKED_STATUS","statusValue":"1"},{"statusKey":"MAGNET","statusValue":"0"}]}`
	env, _ := json.Marshal(Envelope{Header: Header{Name: NameStateCallback}, Payload: json.RawMessage(payload)})
	h.ingest("cid", env)
	st, ok := h.LastState("2d00")
	if !ok || st["LOCKED_STATUS"] != "1" || st["MAGNET"] != "0" {
		t.Fatalf("state not recorded: %v %v", ok, st)
	}
	if _, ok := h.LastState("other"); ok {
		t.Fatal("unknown device should have no state")
	}
}

func TestIngestEventsStored(t *testing.T) {
	h, fs := newTestHub()
	h.connected("cid", "2d00", &mqtt.Client{ID: "cid"})
	fs.byDev["2d00"] = &store.Lock{ID: 7, DeviceID: "2d00"}
	payload := `{"deviceId":"2d00","items":[{"timestamp":1700000000000,"co":1,"pid":4}]}`
	env, _ := json.Marshal(Envelope{Header: Header{Name: NameEventLogResponse}, Payload: json.RawMessage(payload)})
	h.ingest("cid", env)
	if len(fs.events) != 1 || fs.events[0].LockID != 7 || fs.events[0].TM != 1700000000000 {
		t.Fatalf("event not stored: %+v", fs.events)
	}
}

// Any lock may publish to the server topic, so one lock's message about
// another lock, or a message from a client that isn't a connected lock, is
// ignored.
func TestIngestOnlyTheSendersOwnLock(t *testing.T) {
	h, fs := newTestHub()
	h.connected("cid", "2d00", &mqtt.Client{ID: "cid"})
	fs.byDev["2d00"] = &store.Lock{ID: 7, DeviceID: "2d00"}
	fs.byDev["9f00"] = &store.Lock{ID: 8, DeviceID: "9f00"}
	state := func(dev string) []byte {
		env, _ := json.Marshal(Envelope{Header: Header{Name: NameStateCallback}, Payload: json.RawMessage(
			`{"deviceId":"` + dev + `","states":[{"statusKey":"LOCKED_STATUS","statusValue":"0"}]}`)})
		return env
	}
	events := func(dev string) []byte {
		env, _ := json.Marshal(Envelope{Header: Header{Name: NameEventLogResponse}, Payload: json.RawMessage(
			`{"deviceId":"` + dev + `","items":[{"timestamp":1700000000000,"co":1}]}`)})
		return env
	}
	h.ingest("cid", state("9f00"))
	h.ingest("cid", events("9f00"))
	h.ingest("ghost", state("2d00"))
	h.ingest("ghost", events("2d00"))
	if _, ok := h.LastState("9f00"); ok {
		t.Fatal("a lock set another lock's state")
	}
	if _, ok := h.LastState("2d00"); ok {
		t.Fatal("a client that isn't a connected lock set a lock's state")
	}
	if len(fs.events) != 0 {
		t.Fatalf("events stored from the wrong sender: %+v", fs.events)
	}
	// the lock's own report, in either letter case, is kept under its record's id
	h.ingest("cid", state("2D00"))
	if st, ok := h.LastState("2d00"); !ok || st["LOCKED_STATUS"] != "0" {
		t.Fatalf("the lock's own state was not recorded: %v %v", ok, st)
	}
}

func TestContentRoundTrip(t *testing.T) {
	c, err := frameToContent("A1B2C3D4")
	if err != nil {
		t.Fatal(err)
	}
	f, err := contentToFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	if f != "A1B2C3D4" {
		t.Fatalf("round trip = %s", f)
	}
}

func TestCodeIsSuccess(t *testing.T) {
	for _, c := range []any{nil, "0", "", float64(0)} {
		if !codeIsSuccess(c) {
			t.Fatalf("codeIsSuccess(%v) = false", c)
		}
	}
	for _, c := range []any{"3005", float64(3005), "1"} {
		if codeIsSuccess(c) {
			t.Fatalf("codeIsSuccess(%v) = true", c)
		}
	}
}
