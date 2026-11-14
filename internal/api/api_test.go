package api

import (
	"context"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/backup"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/lockly"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

const (
	tMC   = "24860092"
	tUUID = "2d0023003030471333363838"
	tCID  = "cid-1"
)

// responseFrame builds a lock reply frame (magic|len|cmdType|AES(payload)|crc).
func responseFrame(t *testing.T, cmdType, plaintextHex string) string {
	t.Helper()
	key, err := lockly.DeriveAESKey(tMC, tUUID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(plaintextHex)
	if pad := (16 - len(raw)%16) % 16; pad != 0 {
		raw = append(raw, make([]byte, pad)...)
	}
	blk, _ := aes.NewCipher(key)
	ct := make([]byte, len(raw))
	for i := 0; i < len(raw); i += 16 {
		blk.Encrypt(ct[i:i+16], raw[i:i+16])
	}
	ctHdr, _ := hex.DecodeString(cmdType)
	body := append(ctHdr, ct...)
	total := len(body) + 7 // magic(4)+len(2)+crc(1)
	frame := []byte{0xA1, 0xB2, 0xC3, 0xD4, byte(total % 256), byte(total / 256)}
	frame = append(frame, body...)
	frame = append(frame, lockly.CRC8(frame))
	return strings.ToUpper(hex.EncodeToString(frame))
}

// tryCommandByte decrypts a command frame and returns its first plaintext
// byte; ok is false for anything that is not a well-formed AES command frame.
func tryCommandByte(frameHex string) (string, bool) {
	if len(frameHex) < 16 {
		return "", false
	}
	key, err := lockly.DeriveAESKey(tMC, tUUID)
	if err != nil {
		return "", false
	}
	ct, err := hex.DecodeString(frameHex[12 : len(frameHex)-4])
	if err != nil || len(ct) == 0 || len(ct)%16 != 0 {
		return "", false
	}
	blk, _ := aes.NewCipher(key)
	pt := make([]byte, 16)
	blk.Decrypt(pt, ct[:16])
	return strings.ToUpper(hex.EncodeToString(pt[:1])), true
}

// fakeGateway answers a status query with a nonce and accepts everything else.
type fakeGateway struct {
	t      *testing.T
	online bool
	mu     sync.Mutex
	sent   []string // command frames seen
}

func (g *fakeGateway) Online(string) bool { return g.online }
func (g *fakeGateway) SendCommand(_ context.Context, _, _, frameHex string) (string, error) {
	g.mu.Lock()
	g.sent = append(g.sent, frameHex)
	g.mu.Unlock()
	cmd, ok := tryCommandByte(frameHex)
	switch {
	case ok && cmd == "1E": // status query -> reply carrying a nonce at d[38:54]
		return responseFrame(g.t, "0A1E", strings.Repeat("00", 19)+"1122334455667788"+strings.Repeat("00", 5)), nil
	case ok && cmd == "73": // 0x73 user record -> status byte 00 = accepted
		return responseFrame(g.t, "0A73", "00"+strings.Repeat("00", 15)), nil
	default: // a plain relay (e.g. a raw frame from senddata): echo an ack
		return responseFrame(g.t, "0A22", "00"+strings.Repeat("00", 15)), nil
	}
}
func (g *fakeGateway) lastCommandOfType(t *testing.T, cmd string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i := len(g.sent) - 1; i >= 0; i-- {
		if b, ok := tryCommandByte(g.sent[i]); ok && b == cmd {
			return g.sent[i]
		}
	}
	return ""
}

func setup(t *testing.T) (*httptest.Server, *store.Store, *fakeGateway) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	gw := &fakeGateway{t: t, online: true}
	a := New(st, gw, Config{MQTTHost: "mqtt.example.test", MQTTPort: 8883, HeartbeatSeconds: 300}, nil)
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(func() { srv.Close(); st.Close() })
	return srv, st, gw
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, srv.URL+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}

func opToken(t *testing.T, srv *httptest.Server, st *store.Store) string {
	h, _ := store.HashPassword("oppw")
	if _, err := st.CreateOperator("admin", h); err != nil {
		t.Fatal(err)
	}
	_, m := do(t, srv, "POST", "/admin/api/login", "", map[string]any{"username": "admin", "password": "oppw"})
	tok, _ := m["token"].(string)
	if tok == "" {
		t.Fatal("no operator token")
	}
	return tok
}

func TestLocklyFacingFlow(t *testing.T) {
	srv, st, _ := setup(t)
	op := opToken(t, srv, st)

	// operator creates an account and a lock
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "owner@example.test", "password": "secret"})
	accID := int64(acc["id"].(float64))
	do(t, srv, "POST", "/admin/api/locks", op, map[string]any{
		"DeviceID": tUUID, "MC": tMC, "Model": "PGK728WRHK", "TZ": "+8:00",
		"OwnerAccountID": accID, "MQTTClientID": tCID, "MQTTUsername": "u", "MQTTPassword": "p"})

	// locklyctl signs in with SHA-256(password), as the real client does
	_, lg := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("secret")})
	if lg["cod"] != "200" {
		t.Fatalf("login cod=%v", lg["cod"])
	}
	acctTok := lg["token"].(string)

	// a wrong password is rejected
	_, bad := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("nope")})
	if bad["cod"] == "200" {
		t.Fatal("wrong password accepted")
	}

	// qrylknew returns the lock with its mc
	_, q := do(t, srv, "POST", "/api/qrylknew", acctTok, map[string]any{})
	arr := q["arr"].([]any)
	if len(arr) != 1 || arr[0].(map[string]any)["mc"] != tMC {
		t.Fatalf("qrylknew = %v", q)
	}

	// getHeartbeatTime hands back the broker to connect to
	_, hb := do(t, srv, "POST", "/api/getHeartbeatTime", acctTok, map[string]any{"deviceId": tUUID, "model": "PGK728WRHK"})
	mq := hb["mqttConfigs"].(map[string]any)
	if mq["host"] != "mqtt.example.test" || hb["heartbeat"].(float64) != 300 {
		t.Fatalf("heartbeat = %v", hb)
	}

	// senddata relays a frame and returns the ack
	_, sd := do(t, srv, "POST", "/api/senddata", acctTok, map[string]any{"deviceId": tUUID, "cmd": "A1B2C3D40A0000110525"})
	if sd["cod"] != "200" || sd["ack"] == nil {
		t.Fatalf("senddata = %v", sd)
	}
}

func TestAdminHideAndReorderLocks(t *testing.T) {
	srv, st, _ := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "owner@example.test", "password": "secret"})
	accID := int64(acc["id"].(float64))
	mk := func(dev string) int64 {
		_, lk := do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": dev, "MC": tMC, "OwnerAccountID": accID})
		return int64(lk["id"].(float64))
	}
	id1 := mk("aa00000000000000000000b1")
	id2 := mk("aa00000000000000000000b2")

	code, lk := do(t, srv, "POST", "/admin/api/locks/"+strconv.FormatInt(id1, 10)+"/hidden", op, map[string]any{"hidden": true})
	if code != 200 || lk["hidden"] != true {
		t.Fatalf("hidden set = %d %v", code, lk)
	}

	_, ls := do(t, srv, "GET", "/admin/api/locks", op, nil)
	locks := ls["locks"].([]any)
	if len(locks) != 2 {
		t.Fatalf("locks = %v", ls)
	}
	if first := locks[0].(map[string]any); int64(first["id"].(float64)) != id1 || first["hidden"] != true {
		t.Fatalf("first lock = %v", first)
	}

	code, _ = do(t, srv, "POST", "/admin/api/locks/order", op, map[string]any{"accountId": accID, "order": []int64{id2, id1}})
	if code != 204 {
		t.Fatalf("reorder = %d", code)
	}
	_, ls = do(t, srv, "GET", "/admin/api/locks", op, nil)
	locks = ls["locks"].([]any)
	if int64(locks[0].(map[string]any)["id"].(float64)) != id2 {
		t.Fatalf("after reorder first = %v", locks[0])
	}
}

func TestAccountViewHiddenAndOrder(t *testing.T) {
	srv, st, _ := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "owner@example.test", "password": "secret"})
	accID := int64(acc["id"].(float64))
	dev1, dev2 := "aa00000000000000000000b1", "aa00000000000000000000b2"
	for _, d := range []string{dev1, dev2} {
		do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": d, "MC": tMC, "OwnerAccountID": accID})
	}
	_, lg := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("secret")})
	tok := lg["token"].(string)

	if _, hv := do(t, srv, "POST", "/api/view/hidden", tok, map[string]any{"deviceId": dev1, "hidden": true}); hv["cod"] != "200" {
		t.Fatalf("view hidden = %v", hv)
	}
	if _, ov := do(t, srv, "POST", "/api/view/order", tok, map[string]any{"order": []string{dev2, dev1}}); ov["cod"] != "200" {
		t.Fatalf("view order = %v", ov)
	}

	_, ui := do(t, srv, "POST", "/api/getUserInfoAndDvList", tok, map[string]any{})
	arr := ui["arr"].([]any)
	if len(arr) != 2 {
		t.Fatalf("arr = %v", ui)
	}
	if first := arr[0].(map[string]any); first["ID"] != dev2 {
		t.Fatalf("order not applied, first = %v", first["ID"])
	}
	for _, e := range arr {
		if m := e.(map[string]any); m["ID"] == dev1 && m["hidden"] != true {
			t.Fatalf("dev1 not hidden: %v", m)
		}
	}

	if _, bad := do(t, srv, "POST", "/api/view/order", tok, map[string]any{"order": []string{"zz00000000000000000000zz"}}); bad["cod"] == "200" {
		t.Fatal("unknown deviceId accepted")
	}
}

func TestSenddataOffline(t *testing.T) {
	srv, st, gw := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "o@example.test", "password": "s"})
	do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": tUUID, "MC": tMC,
		"OwnerAccountID": int64(acc["id"].(float64)), "MQTTClientID": tCID})
	_, lg := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "o@example.test", "password": store.SHA256Hex("s")})
	gw.online = false
	_, sd := do(t, srv, "POST", "/api/senddata", lg["token"].(string), map[string]any{"deviceId": tUUID, "cmd": "A1B2"})
	if sd["cod"] != "3005" {
		t.Fatalf("offline senddata cod=%v, want 3005", sd["cod"])
	}
}

func TestAuthRequired(t *testing.T) {
	srv, _, _ := setup(t)
	if code, _ := do(t, srv, "GET", "/admin/api/locks", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("admin without token = %d", code)
	}
	if _, m := do(t, srv, "POST", "/api/qrylknew", "", map[string]any{}); m["cod"] != "401" {
		t.Fatalf("api without token cod=%v", m["cod"])
	}
}

func TestPersonEnableDisablePush(t *testing.T) {
	srv, st, gw := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "o@example.test", "password": "s"})
	_, lk := do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": tUUID, "MC": tMC,
		"OwnerAccountID": int64(acc["id"].(float64)), "MQTTClientID": tCID})
	lockID := int64(lk["id"].(float64))

	// create a person: pushes a 0x73 with a real (permanent) window
	_, p := do(t, srv, "POST", "/admin/api/locks/"+itoa(lockID)+"/people", op, map[string]any{
		"name": "Tester", "pwdId": 8, "userId": 31, "pin": "135790", "userType": 0x22, "dateMode": "permanent"})
	if p["synced"] != true {
		t.Fatalf("create not synced: %v", p["syncDetail"])
	}
	personID := int64(p["id"].(float64))

	// suspend: pushes a 0x73 with the far-future suspend window and type 0x12
	_, tg := do(t, srv, "POST", "/admin/api/people/"+itoa(personID)+"/enabled", op, map[string]any{"enabled": false})
	if tg["enabled"] != false || tg["synced"] != true {
		t.Fatalf("suspend result: %v", tg)
	}
	dis := decryptedPush(t, gw)
	// the plaintext of a disabled push is 73 <mclen> <encmc> 01 12 ... with the
	// suspend date; assert the user_type nibble 12 and the suspend date bytes.
	if !strings.Contains(dis, "01"+"12") {
		t.Fatalf("disabled push missing type 0x12: %s", dis)
	}
	if !strings.Contains(dis, strings.ToUpper(lockly.DateSuspendedHex())) {
		t.Fatalf("disabled push missing the suspend window: %s", dis)
	}
}

func TestBackupOverTheAccountAPI(t *testing.T) {
	srv, st, _ := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "owner@example.test", "password": "secret"})
	accID := int64(acc["id"].(float64))
	_, lk := do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": tUUID, "MC": tMC, "Name": "Front",
		"OwnerAccountID": accID, "MQTTClientID": tCID, "MQTTUsername": "u", "MQTTPassword": "p"})
	lockID := int64(lk["id"].(float64))
	if _, err := st.CreatePerson(&store.Person{LockID: lockID, Name: "Guest", PwdID: 3, UserID: 9, PIN: "246800",
		UserType: 0x42, DateMode: store.DateWeekly, WeekMask: 0x1F, DateHex: "1F090011000000000000",
		MultiVerify: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	_, lg := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("secret")})
	tok := lg["token"].(string)

	_, ex := do(t, srv, "POST", "/api/backup/export", tok, map[string]any{})
	if ex["cod"] != "200" {
		t.Fatalf("export = %v", ex)
	}
	doc := ex["backup"].(map[string]any)
	first := doc["locks"].([]any)[0].(map[string]any)
	if doc["format"] != "locklyctl-backup" || first["mc"] != tMC || first["name"] != "Front" ||
		first["mqtt"].(map[string]any)["password"] != "p" {
		t.Fatalf("export doc = %v", doc)
	}
	if p := first["people"].([]any)[0].(map[string]any); p["pin"] != "246800" || p["date"] != "1F090011000000000000" {
		t.Fatalf("exported person = %v", p)
	}

	// Back into the same account: everything matches, so it's all updates.
	_, im := do(t, srv, "POST", "/api/backup/import", tok, map[string]any{"backup": doc})
	if im["cod"] != "200" || im["locksUpdated"].(float64) != 1 || im["peopleUpdated"].(float64) != 1 ||
		im["locksAdded"].(float64) != 0 {
		t.Fatalf("re-import = %v", im)
	}

	// Another account on this server can't take the lock by importing it.
	do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "other@example.test", "password": "pw2"})
	_, lg2 := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "other@example.test", "password": store.SHA256Hex("pw2")})
	_, im2 := do(t, srv, "POST", "/api/backup/import", lg2["token"].(string), map[string]any{"backup": doc, "replace": true})
	if im2["cod"] != "200" || len(im2["conflicts"].([]any)) != 1 || im2["locksAdded"].(float64) != 0 {
		t.Fatalf("other account's import = %v", im2)
	}
	if got, _ := st.GetLock(lockID); got.OwnerAccountID != accID || got.MC != tMC {
		t.Fatalf("the owner's lock changed: %+v", got)
	}

	// A fresh server takes the whole backup.
	srv2, st2, _ := setup(t)
	op2 := opToken(t, srv2, st2)
	do(t, srv2, "POST", "/admin/api/accounts", op2, map[string]any{"email": "owner@example.test", "password": "secret"})
	_, lg3 := do(t, srv2, "POST", "/api/login", "", map[string]any{"email": "owner@example.test", "password": store.SHA256Hex("secret")})
	_, im3 := do(t, srv2, "POST", "/api/backup/import", lg3["token"].(string), map[string]any{"backup": doc})
	if im3["cod"] != "200" || im3["locksAdded"].(float64) != 1 || im3["peopleAdded"].(float64) != 1 {
		t.Fatalf("fresh import = %v", im3)
	}
	if nl, _ := st2.GetLockByDeviceID(tUUID); nl.MC != tMC || nl.Name != "Front" || nl.MQTTPassword != "p" {
		t.Fatalf("lock on the new server = %+v", nl)
	}
	_, q := do(t, srv2, "POST", "/api/qrylknew", lg3["token"].(string), map[string]any{})
	if q["arr"].([]any)[0].(map[string]any)["na"] != "Front" {
		t.Fatalf("lock name not given to locklyctl: %v", q)
	}
}

func TestBackupImportRefusals(t *testing.T) {
	srv, st, _ := setup(t)
	op := opToken(t, srv, st)
	do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "o@example.test", "password": "s"})
	_, lg := do(t, srv, "POST", "/api/login", "", map[string]any{"email": "o@example.test", "password": store.SHA256Hex("s")})
	tok := lg["token"].(string)

	sealedDoc, err := backup.Seal(&backup.Doc{Format: backup.Format, Version: backup.Version}, "a passphrase")
	if err != nil {
		t.Fatal(err)
	}
	var sealedJSON map[string]any
	_ = json.Unmarshal(sealedDoc, &sealedJSON)
	if _, r := do(t, srv, "POST", "/api/backup/import", tok, map[string]any{"backup": sealedJSON}); r["cod"] != "909" ||
		!strings.Contains(r["msg"].(string), "encrypted") {
		t.Fatalf("sealed backup: %v (the server must never take a passphrase)", r)
	}
	bad := map[string]any{"format": "locklyctl-backup", "version": 1,
		"locks": []any{map[string]any{"deviceId": "nope", "mc": "1"}}}
	if _, r := do(t, srv, "POST", "/api/backup/import", tok, map[string]any{"backup": bad}); r["cod"] != "909" {
		t.Fatalf("invalid backup: %v", r)
	}
	if _, r := do(t, srv, "POST", "/api/backup/import", tok, map[string]any{}); r["cod"] != "909" {
		t.Fatalf("no backup: %v", r)
	}
}

func TestExactDateIsPushedAsIsUntilTheScheduleChanges(t *testing.T) {
	srv, st, gw := setup(t)
	op := opToken(t, srv, st)
	_, acc := do(t, srv, "POST", "/admin/api/accounts", op, map[string]any{"email": "o@example.test", "password": "s"})
	_, lk := do(t, srv, "POST", "/admin/api/locks", op, map[string]any{"DeviceID": tUUID, "MC": tMC,
		"OwnerAccountID": int64(acc["id"].(float64)), "MQTTClientID": tCID})
	p, err := st.CreatePerson(&store.Person{LockID: int64(lk["id"].(float64)), Name: "Weekdays 9-17", PwdID: 3,
		UserID: 9, PIN: "246800", UserType: 0x42, DateMode: store.DateWeekly, WeekMask: 0x1F,
		DateHex: "1F090011000000000000", MultiVerify: 1, Enabled: false})
	if err != nil {
		t.Fatal(err)
	}

	// Enabling pushes the exact 09:00-17:00 window, not an all-day weekly one.
	_, r := do(t, srv, "POST", "/admin/api/people/"+itoa(p.ID)+"/enabled", op, map[string]any{"enabled": true})
	if r["synced"] != true || r["date"] != "1F090011000000000000" {
		t.Fatalf("enable = %v", r)
	}
	if push := decryptedPush(t, gw); !strings.Contains(push, "1F090011000000000000") {
		t.Fatalf("exact date not pushed: %s", push)
	}

	// A schedule sent through the API replaces the exact one.
	_, u := do(t, srv, "PATCH", "/admin/api/people/"+itoa(p.ID), op, map[string]any{"name": "Weekdays", "pwdId": 3,
		"userId": 9, "pin": "246800", "userType": 0x42, "dateMode": "weekly", "weekMask": 0x1F})
	if _, has := u["date"]; has || u["synced"] != true {
		t.Fatalf("update = %v", u)
	}
	if push := decryptedPush(t, gw); !strings.Contains(push, strings.ToUpper(lockly.DateWeeklyHex(0x1F))) {
		t.Fatalf("new schedule not pushed: %s", push)
	}
}

// decryptedPush returns the decrypted plaintext hex of the most recent 0x73 push.
func decryptedPush(t *testing.T, gw *fakeGateway) string {
	t.Helper()
	frame := gw.lastCommandOfType(t, "73")
	if frame == "" {
		t.Fatal("no 0x73 push seen")
	}
	key, _ := lockly.DeriveAESKey(tMC, tUUID)
	ct, _ := hex.DecodeString(frame[12 : len(frame)-4])
	blk, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	for i := 0; i < len(ct); i += 16 {
		blk.Decrypt(pt[i:i+16], ct[i:i+16])
	}
	return strings.ToUpper(hex.EncodeToString(pt))
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
