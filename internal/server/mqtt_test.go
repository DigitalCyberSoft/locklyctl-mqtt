package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/config"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// These tests speak MQTT 3.1.1 to the broker over a real socket, as a lock
// does, so they cover what the in-process device tests can't: the broker's
// authentication, its topic permissions and delivery. The fake lock is built
// from the broker's own packet codec.

const testDeviceID = "aa00112233445566778899aa"

// startServer boots a server with plaintext MQTT and HTTP on free local ports;
// each tweak adjusts the config first.
func startServer(t *testing.T, tweak ...func(*config.Config)) (*Server, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.HTTPAddr = freePort(t)
	cfg.MQTTAddr = freePort(t)
	cfg.DBPath = filepath.Join(t.TempDir(), "s.db")
	cfg.PublicMQTTHost = "mqtt.example.test"
	for _, f := range tweak {
		f(&cfg)
	}
	srv, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
		srv.Close()
	})
	waitUp(t, "http://"+cfg.HTTPAddr+"/")
	return srv, cfg
}

// addOwnerAndLock creates an account (signing in with password "pw") and one
// lock with MQTT client id "cid-1", username "lock-1", password "secret-1".
func addOwnerAndLock(t *testing.T, st *store.Store) *store.Lock {
	t.Helper()
	h, err := store.HashPassword(store.SHA256Hex("pw"))
	if err != nil {
		t.Fatal(err)
	}
	acc, err := st.CreateAccount("owner@example.test", h)
	if err != nil {
		t.Fatal(err)
	}
	lk, err := st.CreateLock(&store.Lock{DeviceID: testDeviceID, MC: "12345678", OwnerAccountID: acc.ID,
		MQTTClientID: "cid-1", MQTTUsername: "lock-1", MQTTPassword: "secret-1"})
	if err != nil {
		t.Fatal(err)
	}
	return lk
}

type fakeLock struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
}

// dialLock connects as a lock over plain TCP and returns it with the CONNACK
// return code (0 = accepted).
func dialLock(t *testing.T, addr, clientID, user, pass string) (*fakeLock, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return connectLock(t, c, clientID, user, pass)
}

// connectLock sends CONNECT over c, as dialLock does.
func connectLock(t *testing.T, c net.Conn, clientID, user, pass string) (*fakeLock, byte) {
	t.Helper()
	t.Cleanup(func() { c.Close() })
	l := &fakeLock{t: t, conn: c, r: bufio.NewReader(c)}
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Connect},
		ProtocolVersion: 4,
		Connect: packets.ConnectParams{
			ProtocolName: []byte("MQTT"), Clean: true, Keepalive: 60,
			ClientIdentifier: clientID,
			UsernameFlag:     true, Username: []byte(user),
			PasswordFlag: true, Password: []byte(pass),
		},
	}
	l.send(pk.ConnectEncode)
	ack := l.next()
	if ack.FixedHeader.Type != packets.Connack {
		t.Fatalf("want CONNACK, got packet type %d", ack.FixedHeader.Type)
	}
	return l, ack.ReasonCode
}

func (l *fakeLock) send(encode func(*bytes.Buffer) error) {
	l.t.Helper()
	var buf bytes.Buffer
	if err := encode(&buf); err != nil {
		l.t.Fatal(err)
	}
	if _, err := l.conn.Write(buf.Bytes()); err != nil {
		l.t.Fatal(err)
	}
}

// next reads one packet, failing the test if none arrives within 5 s.
func (l *fakeLock) next() packets.Packet {
	l.t.Helper()
	pk, err := l.read(5 * time.Second)
	if err != nil {
		l.t.Fatalf("reading from the broker: %v", err)
	}
	return pk
}

func (l *fakeLock) read(wait time.Duration) (packets.Packet, error) {
	_ = l.conn.SetReadDeadline(time.Now().Add(wait))
	hb, err := l.r.ReadByte()
	if err != nil {
		return packets.Packet{}, err
	}
	pk := packets.Packet{ProtocolVersion: 4}
	if err := pk.FixedHeader.Decode(hb); err != nil {
		return pk, err
	}
	n, _, err := packets.DecodeLength(l.r)
	if err != nil {
		return pk, err
	}
	pk.FixedHeader.Remaining = n
	body := make([]byte, n)
	if _, err := io.ReadFull(l.r, body); err != nil {
		return pk, err
	}
	switch pk.FixedHeader.Type {
	case packets.Connack:
		err = pk.ConnackDecode(body)
	case packets.Suback:
		err = pk.SubackDecode(body)
	case packets.Publish:
		err = pk.PublishDecode(body)
	}
	return pk, err
}

// subscribe returns the SUBACK code: 0x00-0x02 granted, 0x80 and up refused.
func (l *fakeLock) subscribe(topic string) byte {
	l.t.Helper()
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Subscribe, Qos: 1},
		ProtocolVersion: 4,
		PacketID:        1,
		Filters:         packets.Subscriptions{{Filter: topic, Qos: 1}},
	}
	l.send(pk.SubscribeEncode)
	ack := l.next()
	if ack.FixedHeader.Type != packets.Suback || len(ack.ReasonCodes) != 1 {
		l.t.Fatalf("want a SUBACK with one code, got %+v", ack)
	}
	return ack.ReasonCodes[0]
}

// publish sends at QoS 0, as a lock's replies need no acknowledgement here.
func (l *fakeLock) publish(topic, payload string) {
	l.t.Helper()
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Publish},
		ProtocolVersion: 4,
		TopicName:       topic,
		Payload:         []byte(payload),
	}
	l.send(pk.PublishEncode)
}

func (l *fakeLock) puback(id uint16) {
	l.t.Helper()
	pk := packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Puback}, ProtocolVersion: 4, PacketID: id}
	l.send(pk.PubackEncode)
}

// answerCommand reads the next command on the lock's topic, checks it carries
// wantFrame, and replies with replyFrame (both hex).
func (l *fakeLock) answerCommand(clientID, wantFrame, replyFrame string) {
	l.t.Helper()
	pk := l.next()
	if pk.FixedHeader.Type != packets.Publish || pk.TopicName != "client/"+clientID {
		l.t.Fatalf("want a command on client/%s, got type %d topic %q", clientID, pk.FixedHeader.Type, pk.TopicName)
	}
	if pk.FixedHeader.Qos > 0 {
		l.puback(pk.PacketID)
	}
	var cmd struct {
		Header struct {
			Name      string `json:"name"`
			RequestID string `json:"requestId"`
		} `json:"header"`
		Payload struct {
			DeviceID       string `json:"deviceId"`
			CommandName    string `json:"commandName"`
			CommandContent string `json:"commandContent"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(pk.Payload, &cmd); err != nil {
		l.t.Fatal(err)
	}
	want := base64.StdEncoding.EncodeToString(mustHex(l.t, wantFrame))
	if cmd.Header.Name != "lockCommandRequest" || cmd.Header.RequestID == "" ||
		cmd.Payload.CommandName != "forward" || cmd.Payload.CommandContent != want {
		l.t.Fatalf("unexpected command: %s", pk.Payload)
	}
	l.publish("server", fmt.Sprintf(`{"header":{"namespace":"com.lockly","name":"lockCommandResponse","requestId":%q},`+
		`"payload":{"deviceId":%q,"commandName":"forward","commandContent":%q,"code":0}}`,
		cmd.Header.RequestID, cmd.Payload.DeviceID, base64.StdEncoding.EncodeToString(mustHex(l.t, replyFrame))))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func postJSON(url, token string, body any) (map[string]any, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var out map[string]any
	return out, json.NewDecoder(res.Body).Decode(&out)
}

func login(t *testing.T, cfg config.Config) string {
	t.Helper()
	r, err := postJSON("http://"+cfg.HTTPAddr+"/api/login", "",
		map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("pw")})
	if err != nil || r["cod"] != "200" {
		t.Fatalf("login: %v %v", r, err)
	}
	return r["token"].(string)
}

// sendData runs /api/senddata in the background, as locklyctl would.
func sendData(cfg config.Config, token, frame string) <-chan map[string]any {
	out := make(chan map[string]any, 1)
	go func() {
		r, err := postJSON("http://"+cfg.HTTPAddr+"/api/senddata", token,
			map[string]any{"deviceId": testDeviceID, "cmd": frame})
		if err != nil {
			r = map[string]any{"error": err.Error()}
		}
		out <- r
	}()
	return out
}

func wantAck(t *testing.T, got <-chan map[string]any, ack string) {
	t.Helper()
	select {
	case r := <-got:
		if r["cod"] != "200" || r["ack"] != ack {
			t.Fatalf("senddata = %v, want cod 200 ack %s", r, ack)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("senddata never returned")
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 250; i++ {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting until %s", what)
}

func TestMQTTLockRoundTrip(t *testing.T) {
	srv, cfg := startServer(t)
	addOwnerAndLock(t, srv.Store())

	lock, code := dialLock(t, cfg.MQTTAddr, "cid-1", "lock-1", "secret-1")
	if code != 0 {
		t.Fatalf("lock refused: CONNACK %#x", code)
	}
	if c := lock.subscribe("client/cid-1"); c >= 0x80 {
		t.Fatalf("the lock's own command topic was refused: SUBACK %#x", c)
	}
	waitFor(t, "the lock is online", func() bool { return srv.hub.Online("cid-1") })

	// locklyctl relays a frame; the lock gets it on its topic and answers on
	// the server topic; locklyctl gets the answer.
	got := sendData(cfg, login(t, cfg), "A1B2C3D4")
	lock.answerCommand("cid-1", "A1B2C3D4", "0A1E0011")
	wantAck(t, got, "0A1E0011")

	// a state report reaches the server too
	lock.publish("server", `{"header":{"namespace":"com.lockly","name":"deviceStateCallback"},`+
		`"payload":{"deviceId":"`+testDeviceID+`","states":[{"statusKey":"LOCKED_STATUS","statusValue":"1"}]}}`)
	waitFor(t, "the state report is recorded", func() bool {
		s, ok := srv.hub.LastState(testDeviceID)
		return ok && s["LOCKED_STATUS"] == "1"
	})
}

func TestMQTTRefusesWrongIdentityAndOtherTopics(t *testing.T) {
	srv, cfg := startServer(t)
	addOwnerAndLock(t, srv.Store())

	if _, code := dialLock(t, cfg.MQTTAddr, "cid-1", "lock-1", "wrong"); code == 0 {
		t.Fatal("a wrong password was accepted")
	}
	// mochi runs OnConnect before authentication: a refused client must not
	// leave the lock looking online.
	time.Sleep(200 * time.Millisecond)
	if srv.hub.Online("cid-1") {
		t.Fatal("a refused connection marked the lock online")
	}
	if _, code := dialLock(t, cfg.MQTTAddr, "cid-other", "lock-1", "secret-1"); code == 0 {
		t.Fatal("the lock's credentials were accepted with another client id")
	}

	lock, code := dialLock(t, cfg.MQTTAddr, "cid-1", "lock-1", "secret-1")
	if code != 0 {
		t.Fatalf("lock refused: CONNACK %#x", code)
	}
	for _, topic := range []string{"client/cid-2", "client/#", "client/+", "#", "server"} {
		if c := lock.subscribe(topic); c < 0x80 {
			t.Errorf("subscribing to %q was granted (SUBACK %#x)", topic, c)
		}
	}
}

func TestMQTTReconnectKeepsLockOnline(t *testing.T) {
	srv, cfg := startServer(t)
	addOwnerAndLock(t, srv.Store())

	first, code := dialLock(t, cfg.MQTTAddr, "cid-1", "lock-1", "secret-1")
	if code != 0 {
		t.Fatalf("lock refused: CONNACK %#x", code)
	}
	waitFor(t, "the lock is online", func() bool { return srv.hub.Online("cid-1") })

	// The lock reconnects before the broker has noticed the old connection
	// die (a Wi-Fi drop): the new connection takes the session over.
	second, code := dialLock(t, cfg.MQTTAddr, "cid-1", "lock-1", "secret-1")
	if code != 0 {
		t.Fatalf("reconnect refused: CONNACK %#x", code)
	}
	for {
		if _, err := first.read(5 * time.Second); err != nil {
			break // the broker closed the old connection
		}
	}
	time.Sleep(300 * time.Millisecond) // let the old connection's disconnect run
	if !srv.hub.Online("cid-1") {
		t.Fatal("the old connection's disconnect marked the reconnected lock offline")
	}
	if c := second.subscribe("client/cid-1"); c >= 0x80 {
		t.Fatalf("SUBACK %#x", c)
	}
	got := sendData(cfg, login(t, cfg), "A1B2C3D4")
	second.answerCommand("cid-1", "A1B2C3D4", "0A1E0011")
	wantAck(t, got, "0A1E0011")

	second.conn.Close()
	waitFor(t, "the lock is offline after it disconnects", func() bool { return !srv.hub.Online("cid-1") })
}

// selfSignedCert writes a throwaway certificate for 127.0.0.1 and returns the
// cert and key files and a pool that trusts the certificate.
func selfSignedCert(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "locklyctl-mqtt test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

// The same round trip over the TLS listener (the server's own certificate;
// whether a real lock accepts a non-Lockly certificate is a separate,
// hardware question).
func TestMQTTOverTLS(t *testing.T) {
	certFile, keyFile, pool := selfSignedCert(t)
	srv, cfg := startServer(t, func(c *config.Config) {
		c.MQTTAddr = ""
		c.MQTTTLSAddr = freePort(t)
		c.MQTTCert, c.MQTTKey = certFile, keyFile
	})
	addOwnerAndLock(t, srv.Store())

	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", cfg.MQTTTLSAddr,
		&tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	lock, code := connectLock(t, c, "cid-1", "lock-1", "secret-1")
	if code != 0 {
		t.Fatalf("lock refused: CONNACK %#x", code)
	}
	if c := lock.subscribe("client/cid-1"); c >= 0x80 {
		t.Fatalf("SUBACK %#x", c)
	}
	waitFor(t, "the lock is online", func() bool { return srv.hub.Online("cid-1") })
	got := sendData(cfg, login(t, cfg), "A1B2C3D4")
	lock.answerCommand("cid-1", "A1B2C3D4", "0A1E0011")
	wantAck(t, got, "0A1E0011")
}
