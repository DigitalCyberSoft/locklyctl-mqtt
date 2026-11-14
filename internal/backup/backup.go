// Package backup reads and writes locklyctl backups: one JSON document with an
// account's locks (master codes included) and the people on them (PINs
// included), optionally sealed with a passphrase. locklyctl reads and writes
// the same format (locklyctl/backup.py), so a backup moves between Lockly,
// locklyctl and any locklyctl-mqtt server. CONTRACT.md section 4 is the spec.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// Format and Version identify a backup document.
const (
	Format  = "locklyctl-backup"
	Version = 1
)

// The sealed envelope: scrypt turns the passphrase into an AES-256-CTR key and
// an HMAC-SHA256 key (encrypt-then-MAC). AES-CTR + HMAC rather than AES-GCM
// because locklyctl's pure-Python crypto (used where pycryptodome isn't) has
// the AES block cipher but no GCM; this needs only that plus the standard
// library on both sides.
const (
	kdfName    = "scrypt"
	cipherName = "aes-256-ctr+hmac-sha256"
	macLabel   = "locklyctl-backup/1"
	sealN      = 1 << 15
	sealR      = 8
	sealP      = 1
)

var (
	// ErrPassphraseNeeded is returned by Open for a sealed backup and no passphrase.
	ErrPassphraseNeeded = errors.New("this backup is encrypted: a passphrase is needed")
	// ErrWrongPassphrase is returned when the MAC doesn't check out.
	ErrWrongPassphrase = errors.New("wrong passphrase, or the backup file was changed")
)

// Doc is a backup.
type Doc struct {
	Format    string  `json:"format"`
	Version   int     `json:"version"`
	CreatedAt string  `json:"createdAt,omitempty"`
	Source    *Source `json:"source,omitempty"`
	Locks     []Lock  `json:"locks"`
}

// Source says where a backup was taken from.
type Source struct {
	Kind    string `json:"kind"` // "lockly" or "locklyctl-mqtt"
	Account string `json:"account,omitempty"`
}

// Lock is one lock in a backup.
type Lock struct {
	DeviceID  string   `json:"deviceId"`
	MC        string   `json:"mc"`
	Name      string   `json:"name,omitempty"`
	BLEName   string   `json:"bleName,omitempty"`
	Model     string   `json:"model,omitempty"`
	TZ        string   `json:"tz,omitempty"`
	FWV       string   `json:"fwv,omitempty"`
	Hidden    bool     `json:"hidden,omitempty"`
	SortIndex int      `json:"sortIndex,omitempty"`
	MQTT      *MQTT    `json:"mqtt,omitempty"`
	People    []Person `json:"people,omitempty"`
}

// MQTT is the credentials a lock uses on a locklyctl-mqtt broker. Lockly
// doesn't hand these out, so a backup taken from Lockly has none.
type MQTT struct {
	ClientID string `json:"clientId,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// Person is one person on a lock: what a 0x73 record pushes.
type Person struct {
	Name     string `json:"name"`
	PwdID    int    `json:"pwdId"`
	UserID   int    `json:"userId"`
	AdminID  int    `json:"adminId,omitempty"`
	PIN      string `json:"pin,omitempty"`
	UserType int    `json:"userType"`
	// Date is the exact 10-byte 0x73 date (20 hex digits) when known, e.g. read
	// from the lock. It wins over DateMode and the fields after it.
	Date        string `json:"date,omitempty"`
	DateMode    string `json:"dateMode"`
	StartAt     int64  `json:"startAt,omitempty"` // epoch seconds (period)
	EndAt       int64  `json:"endAt,omitempty"`
	WeekMask    int    `json:"weekMask,omitempty"`    // bit0 = Monday ... bit6 = Sunday (weekly)
	MultiVerify *int   `json:"multiVerify,omitempty"` // as the lock reports it; missing = 1 (the app's default)
	Enabled     *bool  `json:"enabled,omitempty"`     // missing = enabled
}

type sealed struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	Encrypted *envelope `json:"encrypted"`
}

type envelope struct {
	KDF    string `json:"kdf"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	Salt   string `json:"salt"`
	Cipher string `json:"cipher"`
	IV     string `json:"iv"`
	MAC    string `json:"mac"`
	Data   string `json:"data"`
}

// FromStore builds a backup from an account's locks.
func FromStore(locks []store.AccountLock, src Source, now time.Time) *Doc {
	d := &Doc{Format: Format, Version: Version, CreatedAt: now.UTC().Format(time.RFC3339), Source: &src,
		Locks: make([]Lock, 0, len(locks))}
	for _, al := range locks {
		l := al.Lock
		bl := Lock{DeviceID: l.DeviceID, MC: l.MC, Name: l.Name, BLEName: l.BLEName, Model: l.Model,
			TZ: l.TZ, FWV: l.FWV, Hidden: l.Hidden, SortIndex: l.SortIndex}
		if l.MQTTClientID != "" || l.MQTTUsername != "" || l.MQTTPassword != "" {
			bl.MQTT = &MQTT{ClientID: l.MQTTClientID, Username: l.MQTTUsername, Password: l.MQTTPassword}
		}
		for _, p := range al.People {
			enabled, mv := p.Enabled, p.MultiVerify
			bp := Person{Name: p.Name, PwdID: p.PwdID, UserID: p.UserID, AdminID: p.AdminID, PIN: p.PIN,
				UserType: p.UserType, Date: p.DateHex, DateMode: p.DateMode, WeekMask: p.WeekMask,
				MultiVerify: &mv, Enabled: &enabled}
			if p.StartAt != nil {
				bp.StartAt = p.StartAt.Unix()
			}
			if p.EndAt != nil {
				bp.EndAt = p.EndAt.Unix()
			}
			bl.People = append(bl.People, bp)
		}
		d.Locks = append(d.Locks, bl)
	}
	return d
}

// ToStore turns a backup into locks for store.ImportAccount, which checks them.
func (d *Doc) ToStore() []store.AccountLock {
	out := make([]store.AccountLock, 0, len(d.Locks))
	for _, l := range d.Locks {
		sl := store.Lock{DeviceID: strings.ToLower(l.DeviceID), MC: l.MC, Name: l.Name, BLEName: l.BLEName,
			Model: l.Model, TZ: l.TZ, FWV: l.FWV, Hidden: l.Hidden, SortIndex: l.SortIndex}
		if l.MQTT != nil {
			sl.MQTTClientID, sl.MQTTUsername, sl.MQTTPassword = l.MQTT.ClientID, l.MQTT.Username, l.MQTT.Password
		}
		al := store.AccountLock{Lock: sl}
		for _, p := range l.People {
			mode := p.DateMode
			if mode == "" {
				mode = store.DatePermanent
			}
			mv := 1
			if p.MultiVerify != nil {
				mv = *p.MultiVerify
			}
			sp := store.Person{Name: p.Name, PwdID: p.PwdID, UserID: p.UserID, AdminID: p.AdminID, PIN: p.PIN,
				UserType: p.UserType, DateMode: mode, DateHex: strings.ToUpper(p.Date), WeekMask: p.WeekMask,
				MultiVerify: mv, Enabled: p.Enabled == nil || *p.Enabled,
				StartAt: epoch(p.StartAt), EndAt: epoch(p.EndAt)}
			al.People = append(al.People, sp)
		}
		out = append(out, al)
	}
	return out
}

func epoch(sec int64) *time.Time {
	if sec == 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

// Marshal writes a backup as plain JSON. It holds master codes and PINs.
func Marshal(d *Doc) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// Encrypted reports whether data is a sealed backup.
func Encrypted(data []byte) bool {
	var probe struct {
		Encrypted json.RawMessage `json:"encrypted"`
	}
	return json.Unmarshal(data, &probe) == nil && len(probe.Encrypted) > 0 && string(probe.Encrypted) != "null"
}

// Seal encrypts a backup with a passphrase.
func Seal(d *Doc, passphrase string) ([]byte, error) {
	return seal(d, passphrase, rand.Reader, sealN)
}

func seal(d *Doc, passphrase string, rnd io.Reader, n int) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("the passphrase is empty")
	}
	plain, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	salt, iv := make([]byte, 16), make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rnd, iv); err != nil {
		return nil, err
	}
	encKey, macKey, err := keys(passphrase, salt, n, sealR, sealP)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(plain))
	cipher.NewCTR(block, iv).XORKeyStream(ct, plain)
	b64 := base64.StdEncoding.EncodeToString
	env := envelope{KDF: kdfName, N: n, R: sealR, P: sealP, Salt: b64(salt), Cipher: cipherName,
		IV: b64(iv), MAC: b64(mac(macKey, n, sealR, sealP, salt, iv, ct)), Data: b64(ct)}
	return json.MarshalIndent(sealed{Format: Format, Version: Version, Encrypted: &env}, "", "  ")
}

// Open reads a backup, plain or sealed. A sealed one needs its passphrase.
func Open(data []byte, passphrase string) (*Doc, error) {
	var s sealed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("not a locklyctl backup (not JSON: %w)", err)
	}
	if err := checkHeader(s.Format, s.Version); err != nil {
		return nil, err
	}
	plain := data
	if s.Encrypted != nil {
		if passphrase == "" {
			return nil, ErrPassphraseNeeded
		}
		var err error
		if plain, err = unseal(s.Encrypted, passphrase); err != nil {
			return nil, err
		}
	}
	var d Doc
	if err := json.Unmarshal(plain, &d); err != nil {
		return nil, fmt.Errorf("not a locklyctl backup: %w", err)
	}
	if err := checkHeader(d.Format, d.Version); err != nil {
		return nil, err
	}
	return &d, nil
}

func checkHeader(format string, version int) error {
	if format != Format {
		return fmt.Errorf("not a locklyctl backup (format %q)", format)
	}
	if version != Version {
		return fmt.Errorf("backup version %d isn't supported (this reads version %d)", version, Version)
	}
	return nil
}

func unseal(e *envelope, passphrase string) ([]byte, error) {
	if e.KDF != kdfName || e.Cipher != cipherName {
		return nil, fmt.Errorf("unsupported backup encryption %q / %q", e.KDF, e.Cipher)
	}
	// Bounds keep a hostile file from asking for unbounded scrypt memory/time:
	// scrypt needs 128*n*r bytes, capped here at 256 MiB (Seal uses 32 MiB).
	if e.N < 1<<10 || e.N > 1<<20 || e.N&(e.N-1) != 0 || e.R < 1 || e.R > 32 || e.P < 1 || e.P > 16 ||
		128*e.N*e.R > 256<<20 {
		return nil, fmt.Errorf("backup encryption parameters out of range (n=%d r=%d p=%d)", e.N, e.R, e.P)
	}
	dec := base64.StdEncoding.DecodeString
	salt, err1 := dec(e.Salt)
	iv, err2 := dec(e.IV)
	tag, err3 := dec(e.MAC)
	ct, err4 := dec(e.Data)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, fmt.Errorf("damaged backup: %w", err)
	}
	if len(salt) < 16 || len(iv) != aes.BlockSize || len(tag) != sha256.Size {
		return nil, errors.New("damaged backup: wrong salt, iv or mac length")
	}
	encKey, macKey, err := keys(passphrase, salt, e.N, e.R, e.P)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(tag, mac(macKey, e.N, e.R, e.P, salt, iv, ct)) {
		return nil, ErrWrongPassphrase
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ct)
	return plain, nil
}

func keys(passphrase string, salt []byte, n, r, p int) (encKey, macKey []byte, err error) {
	dk, err := scrypt.Key([]byte(passphrase), salt, n, r, p, 64)
	if err != nil {
		return nil, nil, err
	}
	return dk[:32], dk[32:], nil
}

// mac covers the parameters, salt and iv as well as the ciphertext, so none of
// them can be swapped without the passphrase.
func mac(key []byte, n, r, p int, salt, iv, ct []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(macLabel)
	buf.WriteByte(0)
	for _, v := range []int{n, r, p} {
		_ = binary.Write(&buf, binary.BigEndian, uint32(v))
	}
	buf.Write(salt)
	buf.Write(iv)
	buf.Write(ct)
	h := hmac.New(sha256.New, key)
	h.Write(buf.Bytes())
	return h.Sum(nil)
}
