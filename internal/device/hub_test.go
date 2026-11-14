package device

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

type fakeStore struct {
	byUser map[string]*store.Lock
	byDev  map[string]*store.Lock
	events []*store.Event
}

func (f *fakeStore) GetLockByMQTTUsername(u string) (*store.Lock, error) {
	if l, ok := f.byUser[u]; ok {
		return l, nil
	}
	return nil, store.ErrNotFound
}
func (f *fakeStore) GetLockByDeviceID(d string) (*store.Lock, error) {
	if l, ok := f.byDev[d]; ok {
		return l, nil
	}
	return nil, store.ErrNotFound
}
func (f *fakeStore) AddEvent(e *store.Event) error { f.events = append(f.events, e); return nil }

func newTestHub() (*Hub, *fakeStore) {
	fs := &fakeStore{byUser: map[string]*store.Lock{}, byDev: map[string]*store.Lock{}}
	return New(fs, nil), fs
}

func TestAuthenticate(t *testing.T) {
	h, fs := newTestHub()
	fs.byUser["lock-u"] = &store.Lock{MQTTUsername: "lock-u", MQTTPassword: "secret"}
	cases := []struct {
		u, p string
		want bool
	}{
		{"lock-u", "secret", true},
		{"lock-u", "wrong", false},
		{"", "", false},
		{"nobody", "secret", false},
	}
	for _, c := range cases {
		if got := h.authenticate(c.u, c.p); got != c.want {
			t.Fatalf("authenticate(%q,...) = %v, want %v", c.u, got, c.want)
		}
	}
	// a lock with no provisioned password cannot authenticate
	fs.byUser["bare"] = &store.Lock{MQTTUsername: "bare"}
	if h.authenticate("bare", "") {
		t.Fatal("authenticated a lock with no password")
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
	h.setOnline("cid", true)

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
	h.setOnline("cid", true)
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
	fs.byDev["2d00"] = &store.Lock{ID: 7, DeviceID: "2d00"}
	payload := `{"deviceId":"2d00","items":[{"timestamp":1700000000000,"co":1,"pid":4}]}`
	env, _ := json.Marshal(Envelope{Header: Header{Name: NameEventLogResponse}, Payload: json.RawMessage(payload)})
	h.ingest("cid", env)
	if len(fs.events) != 1 || fs.events[0].LockID != 7 || fs.events[0].TM != 1700000000000 {
		t.Fatalf("event not stored: %+v", fs.events)
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
