package store

import (
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
