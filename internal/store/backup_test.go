package store

import (
	"errors"
	"testing"
)

func account(t *testing.T, s *Store, email string) *Account {
	t.Helper()
	h, _ := HashAccountPassword("pw")
	a, err := s.CreateAccount(email, h)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func lockOf(t *testing.T, s *Store, dev string) *Lock {
	t.Helper()
	l, err := s.GetLockByDeviceID(dev)
	if err != nil {
		t.Fatalf("lock %s: %v", dev, err)
	}
	return l
}

func peopleOf(t *testing.T, s *Store, dev string) map[int]Person {
	t.Helper()
	ps, err := s.ListPeopleByLock(lockOf(t, s, dev).ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[int]Person{}
	for _, p := range ps {
		out[p.UserID] = p
	}
	return out
}

const (
	devA = "aa00000000000000000000a1"
	devB = "aa00000000000000000000b2"
	devC = "aa00000000000000000000c3"
)

func TestImportMergeAddsAndUpdatesButKeeps(t *testing.T) {
	s := open(t)
	acc := account(t, s, "owner@example.test")
	l, _ := s.CreateLock(&Lock{DeviceID: devA, MC: "111", OwnerAccountID: acc.ID, Name: "Old name"})
	s.CreatePerson(&Person{LockID: l.ID, Name: "Kept", PwdID: 1, UserID: 1, PIN: "111111", UserType: 0x22,
		DateMode: DatePermanent, Enabled: true})
	s.CreatePerson(&Person{LockID: l.ID, Name: "Changed", PwdID: 2, UserID: 2, PIN: "222222", UserType: 0x22,
		DateMode: DatePermanent, Enabled: true})

	res, err := s.ImportAccount(acc.ID, []AccountLock{
		{Lock: Lock{DeviceID: devA, MC: "999", Name: "New name"}, People: []Person{
			{Name: "Changed", PwdID: 2, UserID: 2, PIN: "999999", UserType: 0x42, DateMode: DateWeekly,
				DateHex: "1F090011000000000000", Enabled: false},
			{Name: "Added", PwdID: 3, UserID: 3, PIN: "333333", UserType: 0x22, DateMode: DatePermanent, Enabled: true},
		}},
		{Lock: Lock{DeviceID: devB, MC: "222", Name: "Second"}, People: []Person{
			{Name: "On B", PwdID: 1, UserID: 7, PIN: "777777", UserType: 0x22, DateMode: DatePermanent, Enabled: true},
		}},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.LocksAdded != 1 || res.LocksUpdated != 1 || res.LocksRemoved != 0 ||
		res.PeopleAdded != 2 || res.PeopleUpdated != 1 || res.PeopleRemoved != 0 || len(res.Conflicts) != 0 {
		t.Fatalf("result = %+v", res)
	}
	if a := lockOf(t, s, devA); a.MC != "999" || a.Name != "New name" {
		t.Fatalf("lock A not updated: %+v", a)
	}
	pa := peopleOf(t, s, devA)
	if len(pa) != 3 || pa[1].Name != "Kept" || pa[1].PIN != "111111" {
		t.Fatalf("merge dropped or changed an unmentioned person: %+v", pa)
	}
	if c := pa[2]; c.PIN != "999999" || c.UserType != 0x42 || c.DateHex != "1F090011000000000000" || c.Enabled {
		t.Fatalf("person 2 not updated: %+v", c)
	}
	if len(peopleOf(t, s, devB)) != 1 || lockOf(t, s, devB).OwnerAccountID != acc.ID {
		t.Fatal("lock B not added to the account with its person")
	}
}

func TestImportReplaceMakesItExactlyTheBackups(t *testing.T) {
	s := open(t)
	acc := account(t, s, "owner@example.test")
	a, _ := s.CreateLock(&Lock{DeviceID: devA, MC: "111", OwnerAccountID: acc.ID})
	s.CreatePerson(&Person{LockID: a.ID, Name: "Stays", PwdID: 1, UserID: 1, UserType: 0x22, DateMode: DatePermanent, Enabled: true})
	s.CreatePerson(&Person{LockID: a.ID, Name: "Goes", PwdID: 2, UserID: 2, UserType: 0x22, DateMode: DatePermanent, Enabled: true})
	c, _ := s.CreateLock(&Lock{DeviceID: devC, MC: "333", OwnerAccountID: acc.ID})
	s.CreatePerson(&Person{LockID: c.ID, Name: "On C", PwdID: 1, UserID: 5, UserType: 0x22, DateMode: DatePermanent, Enabled: true})

	res, err := s.ImportAccount(acc.ID, []AccountLock{
		{Lock: Lock{DeviceID: devA, MC: "111"}, People: []Person{
			{Name: "Stays", PwdID: 1, UserID: 1, UserType: 0x22, DateMode: DatePermanent, Enabled: true}}},
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.LocksRemoved != 1 || res.PeopleRemoved != 2 || res.PeopleUpdated != 1 || res.LocksUpdated != 1 {
		t.Fatalf("result = %+v", res)
	}
	if _, err := s.GetLockByDeviceID(devC); !errors.Is(err, ErrNotFound) {
		t.Fatal("lock C not removed by replace")
	}
	if pa := peopleOf(t, s, devA); len(pa) != 1 || pa[1].Name != "Stays" {
		t.Fatalf("replace left %+v", pa)
	}
}

func TestImportNeverTouchesAnotherAccountsLock(t *testing.T) {
	s := open(t)
	mine := account(t, s, "owner@example.test")
	theirs := account(t, s, "neighbour@example.test")
	l, _ := s.CreateLock(&Lock{DeviceID: devB, MC: "theirs", OwnerAccountID: theirs.ID, Name: "Their door"})
	s.CreatePerson(&Person{LockID: l.ID, Name: "Theirs", PwdID: 1, UserID: 1, PIN: "424242", UserType: 0x22,
		DateMode: DatePermanent, Enabled: true})

	for _, replace := range []bool{false, true} {
		res, err := s.ImportAccount(mine.ID, []AccountLock{
			{Lock: Lock{DeviceID: devB, MC: "stolen", Name: "Mine now"}, People: nil},
			{Lock: Lock{DeviceID: devA, MC: "111"}},
		}, replace)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Conflicts) != 1 || res.Conflicts[0] != devB {
			t.Fatalf("replace=%v: conflicts = %v", replace, res.Conflicts)
		}
		got := lockOf(t, s, devB)
		if got.OwnerAccountID != theirs.ID || got.MC != "theirs" || got.Name != "Their door" {
			t.Fatalf("replace=%v: the other account's lock changed: %+v", replace, got)
		}
		if p := peopleOf(t, s, devB); len(p) != 1 || p[1].PIN != "424242" {
			t.Fatalf("replace=%v: the other account's people changed: %+v", replace, p)
		}
	}
}

func TestImportKeepsMQTTCredentialsUnlessGiven(t *testing.T) {
	s := open(t)
	acc := account(t, s, "owner@example.test")
	s.CreateLock(&Lock{DeviceID: devA, MC: "111", OwnerAccountID: acc.ID,
		MQTTClientID: "cid", MQTTUsername: "user", MQTTPassword: "secret"})
	if _, err := s.ImportAccount(acc.ID, []AccountLock{{Lock: Lock{DeviceID: devA, MC: "111"}}}, true); err != nil {
		t.Fatal(err)
	}
	if l := lockOf(t, s, devA); l.MQTTClientID != "cid" || l.MQTTPassword != "secret" {
		t.Fatalf("credentials lost: %+v", l)
	}
	if _, err := s.ImportAccount(acc.ID, []AccountLock{{Lock: Lock{DeviceID: devA, MC: "111",
		MQTTClientID: "cid2", MQTTUsername: "user2", MQTTPassword: "secret2"}}}, false); err != nil {
		t.Fatal(err)
	}
	if l := lockOf(t, s, devA); l.MQTTClientID != "cid2" || l.MQTTPassword != "secret2" {
		t.Fatalf("credentials not replaced: %+v", l)
	}
}

func TestInvalidImportWritesNothing(t *testing.T) {
	s := open(t)
	acc := account(t, s, "owner@example.test")
	good := AccountLock{Lock: Lock{DeviceID: devA, MC: "111"}}
	for name, bad := range map[string][]AccountLock{
		"bad device id":  {good, {Lock: Lock{DeviceID: "not-hex", MC: "1"}}},
		"no mc":          {good, {Lock: Lock{DeviceID: devB}}},
		"twice":          {good, good},
		"bad date mode":  {good, {Lock: Lock{DeviceID: devB, MC: "1"}, People: []Person{{Name: "x", DateMode: "sometimes"}}}},
		"bad exact date": {good, {Lock: Lock{DeviceID: devB, MC: "1"}, People: []Person{{Name: "x", DateMode: DatePermanent, DateHex: "XYZ"}}}},
		"same user id": {good, {Lock: Lock{DeviceID: devB, MC: "1"}, People: []Person{
			{Name: "x", UserID: 4, DateMode: DatePermanent}, {Name: "y", UserID: 4, DateMode: DatePermanent}}}},
	} {
		if _, err := s.ImportAccount(acc.ID, bad, false); !errors.Is(err, ErrInvalidImport) {
			t.Errorf("%s: got %v, want ErrInvalidImport", name, err)
		}
		if locks, _ := s.ListLocksByAccount(acc.ID); len(locks) != 0 {
			t.Fatalf("%s: wrote %d lock(s) before refusing", name, len(locks))
		}
	}
	if _, err := s.ImportAccount(9999, []AccountLock{good}, false); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown account: %v", err)
	}
}

func TestExportAccountKeepsOrderAndSecrets(t *testing.T) {
	s := open(t)
	acc := account(t, s, "owner@example.test")
	a, _ := s.CreateLock(&Lock{DeviceID: devA, MC: "111", OwnerAccountID: acc.ID})
	b, _ := s.CreateLock(&Lock{DeviceID: devB, MC: "222", OwnerAccountID: acc.ID})
	s.CreatePerson(&Person{LockID: b.ID, Name: "P", PwdID: 1, UserID: 1, PIN: "135790", UserType: 0x22,
		DateMode: DatePermanent, DateHex: "FFFFFFFFFFFFFFFFFFFF", Enabled: true})
	if err := s.ReorderLocks(acc.ID, []int64{b.ID, a.ID}); err != nil {
		t.Fatal(err)
	}
	out, err := s.ExportAccount(acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Lock.DeviceID != devB || out[0].People[0].PIN != "135790" ||
		out[0].People[0].DateHex != "FFFFFFFFFFFFFFFFFFFF" || out[1].Lock.MC != "111" {
		t.Fatalf("export = %+v", out)
	}
}
