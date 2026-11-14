package backup

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

var testNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

func sampleLocks() []store.AccountLock {
	start := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	end := time.Date(2027, 1, 2, 18, 5, 0, 0, time.UTC)
	return []store.AccountLock{
		{Lock: store.Lock{DeviceID: "aa00000000000000000000b1", MC: "12345678", Name: "Front",
			BLEName: "PGK728WRHK0001", Model: "PGK728WRHK", TZ: "+8:00", Hidden: true, SortIndex: 2,
			MQTTClientID: "cid-1", MQTTUsername: "u1", MQTTPassword: "p1"},
			People: []store.Person{
				{Name: "Weekday guest", PwdID: 3, UserID: 9, PIN: "246800", UserType: 0x42,
					DateMode: store.DateWeekly, WeekMask: 0x1F, DateHex: "1F090011000000000000",
					MultiVerify: 1, Enabled: true},
				{Name: "Away", PwdID: 4, UserID: 10, PIN: "135790", UserType: 0x12, DateMode: store.DatePeriod,
					StartAt: &start, EndAt: &end, MultiVerify: 1, Enabled: false},
			}},
		{Lock: store.Lock{DeviceID: "aa00000000000000000000b2", MC: "87654321", Model: "PGK728WRHK", SortIndex: 1}},
	}
}

func sampleDoc() *Doc {
	return FromStore(sampleLocks(), Source{Kind: "locklyctl-mqtt", Account: "owner@example.test"}, testNow)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fixedRandom stands in for crypto/rand: salt 00..0f, then iv 10..1f.
func fixedRandom() *bytes.Reader {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return bytes.NewReader(b)
}

func TestPlainRoundTrip(t *testing.T) {
	doc := sampleDoc()
	data, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if Encrypted(data) {
		t.Fatal("a plain backup was reported as encrypted")
	}
	back, err := Open(data, "")
	if err != nil {
		t.Fatal(err)
	}
	again := FromStore(back.ToStore(), *doc.Source, testNow)
	if mustJSON(t, again) != mustJSON(t, doc) {
		t.Fatalf("doc -> store -> doc changed it:\n%s\n%s", mustJSON(t, doc), mustJSON(t, again))
	}
	got := back.ToStore()
	if got[0].People[1].Enabled || !got[0].People[0].Enabled {
		t.Fatal("enabled flags not kept")
	}
	if got[0].People[0].DateHex != "1F090011000000000000" || got[0].Lock.MQTTPassword != "p1" || !got[0].Lock.Hidden {
		t.Fatalf("exact date / MQTT / hidden not kept: %+v", got[0])
	}
}

func TestSealOpen(t *testing.T) {
	doc := sampleDoc()
	data, err := seal(doc, "correct horse", fixedRandom(), 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !Encrypted(data) {
		t.Fatal("a sealed backup was not reported as encrypted")
	}
	for _, secret := range []string{"246800", "135790", "12345678", "87654321", "Weekday guest"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("sealed backup contains %q in the clear", secret)
		}
	}
	got, err := Open(data, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, got) != mustJSON(t, doc) {
		t.Fatal("sealed round trip changed the doc")
	}
	if _, err := Open(data, ""); !errors.Is(err, ErrPassphraseNeeded) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := Open(data, "wrong horse"); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := seal(doc, "", fixedRandom(), 1<<10); err == nil {
		t.Fatal("empty passphrase accepted")
	}
	// The real Seal uses fresh randomness and the full work factor.
	real, err := Seal(doc, "correct horse")
	if err != nil {
		t.Fatal(err)
	}
	var s sealed
	_ = json.Unmarshal(real, &s)
	if s.Encrypted.N != sealN || bytes.Equal(real, data) {
		t.Fatalf("Seal: n=%d", s.Encrypted.N)
	}
	if got, err := Open(real, "correct horse"); err != nil || mustJSON(t, got) != mustJSON(t, doc) {
		t.Fatalf("Seal/Open: %v", err)
	}
}

func reseal(t *testing.T, data []byte, edit func(*envelope)) []byte {
	t.Helper()
	var s sealed
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	edit(s.Encrypted)
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTamperingIsDetected(t *testing.T) {
	data, err := seal(sampleDoc(), "correct horse", fixedRandom(), 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b64 string) string {
		b, _ := base64.StdEncoding.DecodeString(b64)
		b[len(b)/2] ^= 1
		return base64.StdEncoding.EncodeToString(b)
	}
	cases := map[string]func(*envelope){
		"ciphertext": func(e *envelope) { e.Data = flip(e.Data) },
		"salt":       func(e *envelope) { e.Salt = flip(e.Salt) },
		"iv":         func(e *envelope) { e.IV = flip(e.IV) },
		"work n":     func(e *envelope) { e.N = 1 << 11 },
		"mac":        func(e *envelope) { e.MAC = flip(e.MAC) },
	}
	for name, edit := range cases {
		if _, err := Open(reseal(t, data, edit), "correct horse"); !errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s changed: got %v, want ErrWrongPassphrase", name, err)
		}
	}
}

func TestParameterBounds(t *testing.T) {
	data, _ := seal(sampleDoc(), "correct horse", fixedRandom(), 1<<10)
	for name, edit := range map[string]func(*envelope){
		"n too big":     func(e *envelope) { e.N = 1 << 21 },
		"too much mem":  func(e *envelope) { e.N, e.R = 1<<20, 8 },
		"n not 2^k":     func(e *envelope) { e.N = 1000 },
		"r too big":     func(e *envelope) { e.R = 64 },
		"other cipher":  func(e *envelope) { e.Cipher = "aes-256-gcm" },
		"short salt":    func(e *envelope) { e.Salt = base64.StdEncoding.EncodeToString([]byte("short")) },
		"not base64 iv": func(e *envelope) { e.IV = "%%%" },
	} {
		_, err := Open(reseal(t, data, edit), "correct horse")
		if err == nil || errors.Is(err, ErrWrongPassphrase) {
			t.Errorf("%s: got %v, want a refusal before any key work", name, err)
		}
	}
}

func TestHeaderChecks(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      "not json",
		"other format":  `{"format":"something-else","version":1,"locks":[]}`,
		"newer version": `{"format":"locklyctl-backup","version":2,"locks":[]}`,
	} {
		if _, err := Open([]byte(in), ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Open([]byte(`{"format":"locklyctl-backup","version":2,"locks":[]}`), ""); err == nil ||
		!strings.Contains(err.Error(), "version 2") {
		t.Errorf("newer version: %v", err)
	}
}

func TestMissingFieldsAndNormalising(t *testing.T) {
	in := `{"format":"locklyctl-backup","version":1,"locks":[{"deviceId":"AA00000000000000000000B1","mc":"1",
	  "people":[{"name":"a","pwdId":1,"userId":1,"userType":34,"dateMode":"permanent"},
	            {"name":"b","pwdId":2,"userId":2,"userType":34,"dateMode":"","enabled":false,"date":"ffffffffffffffffffff",
	             "multiVerify":0}]}]}`
	d, err := Open([]byte(in), "")
	if err != nil {
		t.Fatal(err)
	}
	got := d.ToStore()
	if !got[0].People[0].Enabled || got[0].People[1].Enabled {
		t.Fatalf("enabled: %+v", got[0].People)
	}
	if got[0].People[0].MultiVerify != 1 || got[0].People[1].MultiVerify != 0 {
		t.Fatalf("multiVerify: missing should be 1, an explicit 0 kept: %+v", got[0].People)
	}
	if got[0].Lock.DeviceID != "aa00000000000000000000b1" || got[0].People[1].DateMode != store.DatePermanent ||
		got[0].People[1].DateHex != "FFFFFFFFFFFFFFFFFFFF" {
		t.Fatalf("normalising: %+v", got[0])
	}
}

// golden is sampleDoc sealed with "correct horse battery staple", salt 00..0f,
// iv 10..1f and n = 2^10. locklyctl pins the same bytes (tests/test_backup.py):
// its Python seals the same document to exactly this, and each side opens the
// other's. A change here is a change to the shared format (CONTRACT.md 4).
const golden = `{
  "format": "locklyctl-backup",
  "version": 1,
  "encrypted": {
    "kdf": "scrypt",
    "n": 1024,
    "r": 8,
    "p": 1,
    "salt": "AAECAwQFBgcICQoLDA0ODw==",
    "cipher": "aes-256-ctr+hmac-sha256",
    "iv": "EBESExQVFhcYGRobHB0eHw==",
    "mac": "fgQrDSimTlWEaTIk3A2trr6TDKQCe8E9d/ddoppo/es=",
    "data": "Uny4v/6rNa3nGKHm6mlgOXyqxdSg0hLExBHGbOqsg0l+7350PH2077m6AQGIZXyLHiOrm8dWLGnga7Anm1eMmOmiKO1qSTnaKRJtTFptb7ixLDVsdBIgH9oTSt+RpFlbNKLCf6NvrVn0JTHSvo3e/SWr4nC9kQP3X7ACpzdb3GPvBmEMdN+OpNXPSds1Mr4CpXAupHxiVrk56vE6yr5wNMsihSlyWq6UhOrNquRul7Uqq5G998Xw2oURi6TpsWwgZCkcCa5WUofqWDZZOcomnhuclTfQUAf5wdfOow/uTqbOlqZxHTwQvIiauKjhyaX93n2su/XU/aquOZXcFOLn9u4JMQV2T/eyILk5VPM2O2tHu5U9m2tBZFf/rQxjq84GvX8S3ssdAyFhUoRLTUqnOT06CinZb6R15fleSvWSk42WoTlWI6gML/iHxbV/ccRsjkjKC1+jMJPdAV3zhBgMEAw0QrXAK+PHPrfwJIKgU5ULwogtviqBWAVrYBzzQSp0dUjv21+yPLH7yczOGOD1eKntydX+a8Y5bIxDyJYbM7AKzfRGJH1igHSHw7kbcseBqC76/JwiwcW0nXW1n3d9Svva+Hn1yvvVEPRYJDhuoioU9zumGE171c1A4whcpOVMnOnb722XN2hDZMhx/M3T0kV97uP+ZVM6pLQhToKpLt9iDgPeDfUlihqyYlYR6poghnO76fnmjIIMX1oX8Fvb9CHRXBce/oPhzzFhNYIRqsOJRz3yaWhMZt7/svhg3RNi3l4vu4n8jeCFbaGkC4MdQRjx2kqrvzC7acbAQB5NjESo+a1O1vnQdvhWbXKkB43Pk97VWV6xMl15i69PC3JiMfWAi3sXejY6gtdNaIJDbNhoaOeGXcaaumQNvqY5ZAZfNKntLDS58VqkMvck71WrFoYoh3hv5KHwryKtu0LTAL81pyYFpN0zAbbrqYingtnrB4xzQx1F4Z5hz4DHA08dv7kmctGig1FfOkbBzIcykACjtUxjV6Up2w1gGSBO77kSiGZ0/LfQyrVpoezZs8ddkKjbZcv/4j4bIyffSXrc0VBmodY="
  }
}`

func TestGoldenVectorSharedWithLocklyctl(t *testing.T) {
	got, err := seal(sampleDoc(), "correct horse battery staple", fixedRandom(), 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != golden {
		t.Fatalf("sealing changed; locklyctl pins this vector too:\n%s", got)
	}
	d, err := Open([]byte(golden), "correct horse battery staple")
	if err != nil || mustJSON(t, d) != mustJSON(t, sampleDoc()) {
		t.Fatalf("opening the shared vector: %v", err)
	}
}
