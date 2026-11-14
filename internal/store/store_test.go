package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") {
		t.Fatal("valid password rejected")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestOperatorBootstrap(t *testing.T) {
	s := open(t)
	if n, _ := s.OperatorCount(); n != 0 {
		t.Fatalf("fresh db has %d operators", n)
	}
	h, _ := HashPassword("pw")
	if _, err := s.CreateOperator("admin", h); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.OperatorCount(); n != 1 {
		t.Fatalf("after create, count=%d", n)
	}
	o, err := s.GetOperatorByUsername("admin")
	if err != nil || !CheckPassword(o.PwHash, "pw") {
		t.Fatalf("operator lookup failed: %v", err)
	}
	if _, err := s.GetOperatorByUsername("nobody"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAccountLifecycle(t *testing.T) {
	s := open(t)
	h, _ := HashPassword("pw")
	a, err := s.CreateAccount("owner@example.test", h)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAccountByEmail("owner@example.test")
	if err != nil || got.ID != a.ID {
		t.Fatalf("GetAccountByEmail: %v", err)
	}
	nh, _ := HashPassword("new")
	if err := s.SetAccountPassword(a.ID, nh); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetAccount(a.ID)
	if !CheckPassword(got.PwHash, "new") {
		t.Fatal("password not updated")
	}
	list, _ := s.ListAccounts()
	if len(list) != 1 {
		t.Fatalf("ListAccounts = %d", len(list))
	}
	if err := s.DeleteAccount(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetAccount(a.ID); err != ErrNotFound {
		t.Fatalf("account not deleted: %v", err)
	}
}

func TestSessions(t *testing.T) {
	s := open(t)
	if err := s.CreateSession("tok", "operator", 1, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	sess, err := s.GetSession("tok")
	if err != nil || sess.SubjectType != "operator" || sess.SubjectID != 1 {
		t.Fatalf("GetSession: %v %+v", err, sess)
	}
	// expired session is not returned and is purged
	if err := s.CreateSession("old", "account", 2, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession("old"); err != ErrNotFound {
		t.Fatalf("expired session returned: %v", err)
	}
	if err := s.DeleteSession("tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetSession("tok"); err != ErrNotFound {
		t.Fatal("session not revoked")
	}
}

func TestLockAndCascade(t *testing.T) {
	s := open(t)
	h, _ := HashPassword("pw")
	a, _ := s.CreateAccount("owner@example.test", h)
	l, err := s.CreateLock(&Lock{DeviceID: "aa00112233445566778899bb", MC: "12345678",
		BLEName: "PGK728WRHKX", Model: "PGK728WRHK", TZ: "+8:00", OwnerAccountID: a.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetLockByDeviceID("aa00112233445566778899bb"); err != nil || got.MC != "12345678" {
		t.Fatalf("GetLockByDeviceID: %v", err)
	}
	if err := s.SetLockMQTT(l.ID, "cid", "user", "secret"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetLock(l.ID)
	if got.MQTTClientID != "cid" || got.MQTTPassword != "secret" {
		t.Fatalf("mqtt creds not set: %+v", got)
	}
	// a person on the lock, then delete the account: cascade removes lock + person
	p, _ := s.CreatePerson(&Person{LockID: l.ID, Name: "Tester", PwdID: 1, UserID: 7,
		PIN: "135790", UserType: 0x22, DateMode: DatePermanent, Enabled: true})
	if err := s.DeleteAccount(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLock(l.ID); err != ErrNotFound {
		t.Fatal("lock not cascade-deleted")
	}
	if _, err := s.GetPerson(p.ID); err != ErrNotFound {
		t.Fatal("person not cascade-deleted")
	}
}

func TestPersonSuspendKeepsRecord(t *testing.T) {
	s := open(t)
	h, _ := HashPassword("pw")
	a, _ := s.CreateAccount("owner@example.test", h)
	l, _ := s.CreateLock(&Lock{DeviceID: "aa00112233445566778899bb", MC: "12345678", OwnerAccountID: a.ID})
	p, err := s.CreatePerson(&Person{LockID: l.ID, Name: "Guest", PwdID: 3, UserID: 9,
		PIN: "246800", UserType: 0x12, DateMode: DatePeriod, Enabled: true, MultiVerify: 1})
	if err != nil {
		t.Fatal(err)
	}
	// suspend: the person stays, PIN intact, only enabled flips
	if err := s.SetPersonEnabled(p.ID, false); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetPerson(p.ID)
	if got.Enabled {
		t.Fatal("person still enabled after suspend")
	}
	if got.PIN != "246800" {
		t.Fatal("suspend lost the PIN")
	}
	// change type without losing the PIN (fixed window -> weekly)
	got.UserType = 0x42
	got.DateMode = DateWeekly
	got.WeekMask = 0x7F
	if err := s.UpdatePerson(got); err != nil {
		t.Fatal(err)
	}
	again, _ := s.GetPerson(p.ID)
	if again.UserType != 0x42 || again.DateMode != DateWeekly || again.PIN != "246800" {
		t.Fatalf("type change lost data: %+v", again)
	}
	people, _ := s.ListPeopleByLock(l.ID)
	if len(people) != 1 {
		t.Fatalf("ListPeopleByLock = %d", len(people))
	}
}

func TestEvents(t *testing.T) {
	s := open(t)
	h, _ := HashPassword("pw")
	a, _ := s.CreateAccount("owner@example.test", h)
	l, _ := s.CreateLock(&Lock{DeviceID: "aa00112233445566778899bb", MC: "12345678", OwnerAccountID: a.ID})
	pid := 4
	for i := 0; i < 3; i++ {
		if err := s.AddEvent(&Event{LockID: l.ID, TM: int64(1000 + i), Code: "1", PwdID: &pid, Raw: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.ListEventsByLock(l.ID, 10)
	if err != nil || len(evs) != 3 {
		t.Fatalf("events: %v %d", err, len(evs))
	}
	if evs[0].TM != 1002 { // newest first
		t.Fatalf("order wrong: %d", evs[0].TM)
	}
}

func lockIDs(ls []Lock) []int64 {
	out := make([]int64, len(ls))
	for i := range ls {
		out[i] = ls[i].ID
	}
	return out
}

func TestLockHideAndReorder(t *testing.T) {
	s := open(t)
	h, _ := HashAccountPassword("pw")
	a, _ := s.CreateAccount("owner@example.test", h)
	mk := func(dev string, acct int64) *Lock {
		l, err := s.CreateLock(&Lock{DeviceID: dev, MC: "12345678", OwnerAccountID: acct})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l1 := mk("aa00000000000000000000b1", a.ID)
	l2 := mk("aa00000000000000000000b2", a.ID)
	l3 := mk("aa00000000000000000000b3", a.ID)

	// New locks append in creation order, none hidden.
	locks, err := s.ListLocksByAccount(a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := lockIDs(locks); len(got) != 3 || got[0] != l1.ID || got[2] != l3.ID {
		t.Fatalf("initial order = %v", got)
	}
	if locks[0].Hidden {
		t.Error("new lock should not be hidden")
	}

	// Hiding a lock keeps it listed, only flags it.
	if err := s.SetLockHidden(l2.ID, true); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetLock(l2.ID); !got.Hidden {
		t.Fatal("hidden not persisted")
	}

	// Reorder to l3, l1, l2.
	if err := s.ReorderLocks(a.ID, []int64{l3.ID, l1.ID, l2.ID}); err != nil {
		t.Fatal(err)
	}
	locks, _ = s.ListLocksByAccount(a.ID)
	for i, id := range []int64{l3.ID, l1.ID, l2.ID} {
		if locks[i].ID != id {
			t.Fatalf("reordered = %v", lockIDs(locks))
		}
	}

	// A lock from another account cannot be reordered into this one.
	b, _ := s.CreateAccount("other@example.test", h)
	bl := mk("aa00000000000000000000c1", b.ID)
	if err := s.ReorderLocks(a.ID, []int64{bl.ID}); err == nil {
		t.Fatal("reorder across accounts should fail")
	}
}

func TestMigrateAddsLockColumnsToOldDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// A database created before hidden/sort_index existed.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`CREATE TABLE accounts(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, pw_hash BLOB NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE locks(id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT UNIQUE NOT NULL, mc TEXT NOT NULL, blename TEXT, model TEXT, tz TEXT, fwv TEXT, owner_account_id INTEGER NOT NULL, mqtt_client_id TEXT, mqtt_username TEXT, mqtt_password TEXT, created_at INTEGER NOT NULL);
INSERT INTO accounts(id, email, pw_hash, created_at) VALUES(1, 'o@example.test', x'00', 0);
INSERT INTO locks(id, device_id, mc, blename, model, tz, fwv, owner_account_id, mqtt_client_id, mqtt_username, mqtt_password, created_at)
  VALUES(1, 'aa00112233445566778899bb', '12345678', '', '', '', '', 1, '', '', '', 0);`)
	if err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Opening through the store runs migrate, which must add the new columns.
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open/migrate old db: %v", err)
	}
	defer s.Close()
	lk, err := s.GetLockByDeviceID("aa00112233445566778899bb")
	if err != nil {
		t.Fatalf("read migrated lock: %v", err)
	}
	if lk.Hidden {
		t.Error("migrated lock should default to not hidden")
	}
	if err := s.SetLockHidden(lk.ID, true); err != nil {
		t.Fatal(err)
	}
	if lk, _ = s.GetLockByDeviceID("aa00112233445566778899bb"); !lk.Hidden {
		t.Error("hidden not persisted after migration")
	}
}

func TestLocksByMQTTIdentity(t *testing.T) {
	s := open(t)
	h, _ := HashPassword("x")
	a, _ := s.CreateAccount("o@example.test", h)
	mk := func(dev, cid, user string) {
		if _, err := s.CreateLock(&Lock{DeviceID: dev, MC: "12345678", OwnerAccountID: a.ID,
			MQTTClientID: cid, MQTTUsername: user, MQTTPassword: "pw"}); err != nil {
			t.Fatal(err)
		}
	}
	mk("aa00000000000000000000a1", "cid-1", "user-1")
	mk("aa00000000000000000000a2", "cid-2", "user-2")
	mk("aa00000000000000000000a3", "", "") // no MQTT identity
	got := func(user, cid string) []string {
		locks, err := s.LocksByMQTTIdentity(user, cid)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, l := range locks {
			ids = append(ids, l.DeviceID[len(l.DeviceID)-2:])
		}
		return ids
	}
	if ids := got("user-1", "cid-1"); len(ids) != 1 || ids[0] != "a1" {
		t.Fatalf("own identity: %v", ids)
	}
	if ids := got("user-1", "cid-2"); len(ids) != 2 {
		t.Fatalf("username of one lock and client id of another should return both: %v", ids)
	}
	if ids := got("", ""); len(ids) != 0 {
		t.Fatalf("empty values must match nothing, got %v", ids)
	}
}
