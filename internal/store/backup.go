package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// AccountLock is a lock with its people: the unit of an export or an import.
type AccountLock struct {
	Lock   Lock
	People []Person
}

// ExportAccount returns an account's locks in display order, each with its
// people. Secrets (master codes, PINs, MQTT passwords) are included; the caller
// decides how to protect them.
func (s *Store) ExportAccount(accountID int64) ([]AccountLock, error) {
	if _, err := s.GetAccount(accountID); err != nil {
		return nil, err
	}
	locks, err := s.ListLocksByAccount(accountID)
	if err != nil {
		return nil, err
	}
	out := make([]AccountLock, 0, len(locks))
	for _, l := range locks {
		people, err := s.ListPeopleByLock(l.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, AccountLock{Lock: l, People: people})
	}
	return out, nil
}

// ImportResult says what an import changed. Conflicts lists device ids that
// another account on this server owns; those locks were left alone.
type ImportResult struct {
	LocksAdded, LocksUpdated, LocksRemoved    int
	PeopleAdded, PeopleUpdated, PeopleRemoved int
	Conflicts                                 []string
}

// ErrInvalidImport wraps every reason an import is refused before anything is
// written (as opposed to a database failure).
var ErrInvalidImport = errors.New("invalid import")

var (
	deviceIDRe = regexp.MustCompile(`^[0-9a-f]{24}$`)
	dateHexRe  = regexp.MustCompile(`^[0-9A-F]{20}$`)
)

// ImportAccount brings locks and their people into an account in one
// transaction: either all of it lands or none of it does.
//
// Merge (replace=false): a lock is matched by device id. A new one is added;
// one the account already has is updated, and so are its people, matched by
// user id (user id 0: by slot and name). Locks and people the import doesn't
// mention are kept. Replace: the account ends up with exactly the imported
// locks and people; its other locks are deleted, with their people.
//
// Either way a device id that another account owns is never touched (it is
// reported in Conflicts), and a lock that arrives without MQTT credentials
// keeps the ones it has. Nothing is sent to any lock: the locks already hold
// these records, and the server pushes a person when they are next changed.
func (s *Store) ImportAccount(accountID int64, in []AccountLock, replace bool) (*ImportResult, error) {
	if _, err := s.GetAccount(accountID); err != nil {
		return nil, err
	}
	if err := validateImport(in); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	res := &ImportResult{}
	kept := map[int64]bool{}
	now := time.Now().UTC().Unix()
	for _, al := range in {
		l := al.Lock
		var id, owner int64
		err := tx.QueryRow(`SELECT id, owner_account_id FROM locks WHERE device_id=?`, l.DeviceID).Scan(&id, &owner)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			r, err := tx.Exec(`INSERT INTO locks(device_id, mc, blename, model, tz, fwv, owner_account_id,
			    mqtt_client_id, mqtt_username, mqtt_password, hidden, sort_index, name, created_at)
			    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
				l.DeviceID, l.MC, l.BLEName, l.Model, l.TZ, l.FWV, accountID,
				l.MQTTClientID, l.MQTTUsername, l.MQTTPassword, boolInt(l.Hidden), l.SortIndex, l.Name, now)
			if err != nil {
				return nil, err
			}
			id, _ = r.LastInsertId()
			res.LocksAdded++
		case err != nil:
			return nil, err
		case owner != accountID:
			res.Conflicts = append(res.Conflicts, l.DeviceID)
			continue
		default:
			if _, err := tx.Exec(`UPDATE locks SET mc=?, blename=?, model=?, tz=?, fwv=?, hidden=?, sort_index=?, name=?
			    WHERE id=?`, l.MC, l.BLEName, l.Model, l.TZ, l.FWV, boolInt(l.Hidden), l.SortIndex, l.Name, id); err != nil {
				return nil, err
			}
			if l.MQTTClientID != "" || l.MQTTUsername != "" || l.MQTTPassword != "" {
				if _, err := tx.Exec(`UPDATE locks SET mqtt_client_id=?, mqtt_username=?, mqtt_password=? WHERE id=?`,
					l.MQTTClientID, l.MQTTUsername, l.MQTTPassword, id); err != nil {
					return nil, err
				}
			}
			res.LocksUpdated++
		}
		kept[id] = true
		if err := importPeople(tx, id, al.People, replace, now, res); err != nil {
			return nil, err
		}
	}

	if replace {
		rows, err := tx.Query(`SELECT id FROM locks WHERE owner_account_id=?`, accountID)
		if err != nil {
			return nil, err
		}
		var drop []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			if !kept[id] {
				drop = append(drop, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		for _, id := range drop {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM people WHERE lock_id=?`, id).Scan(&n); err != nil {
				return nil, err
			}
			if _, err := tx.Exec(`DELETE FROM locks WHERE id=?`, id); err != nil {
				return nil, err
			}
			res.LocksRemoved++
			res.PeopleRemoved += n
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return res, nil
}

// validateImport rejects an import that would store something the server
// can't use, before anything is written.
func validateImport(in []AccountLock) error {
	seen := map[string]bool{}
	for i, al := range in {
		l := al.Lock
		if !deviceIDRe.MatchString(l.DeviceID) {
			return fmt.Errorf("%w: lock %d: device id %q is not 24 lowercase hex digits", ErrInvalidImport, i+1, l.DeviceID)
		}
		if seen[l.DeviceID] {
			return fmt.Errorf("%w: lock %s appears twice", ErrInvalidImport, l.DeviceID)
		}
		seen[l.DeviceID] = true
		if l.MC == "" {
			return fmt.Errorf("%w: lock %s has no master code", ErrInvalidImport, l.DeviceID)
		}
		users := map[int]bool{}
		for j, p := range al.People {
			switch p.DateMode {
			case DatePermanent, DatePeriod, DateWeekly:
			default:
				return fmt.Errorf("%w: lock %s, person %d: date mode %q is not permanent, period or weekly", ErrInvalidImport,
					l.DeviceID, j+1, p.DateMode)
			}
			if p.DateHex != "" && !dateHexRe.MatchString(p.DateHex) {
				return fmt.Errorf("%w: lock %s, person %d: date %q is not 20 hex digits", ErrInvalidImport, l.DeviceID, j+1, p.DateHex)
			}
			if p.UserID > 0 {
				if users[p.UserID] {
					return fmt.Errorf("%w: lock %s: user id %d appears twice", ErrInvalidImport, l.DeviceID, p.UserID)
				}
				users[p.UserID] = true
			}
		}
	}
	return nil
}

// importPeople merges (or, with replace, sets) one lock's people.
func importPeople(tx *sql.Tx, lockID int64, people []Person, replace bool, now int64, res *ImportResult) error {
	type row struct {
		id, userID, pwdID int64
		name              string
	}
	rows, err := tx.Query(`SELECT id, user_id, pwd_id, name FROM people WHERE lock_id=?`, lockID)
	if err != nil {
		return err
	}
	var have []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.userID, &r.pwdID, &r.name); err != nil {
			rows.Close()
			return err
		}
		have = append(have, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	kept := map[int64]bool{}
	for _, p := range people {
		mv := p.MultiVerify // kept exactly: a lock can report 0 (the format's reader defaults a missing one to 1)
		var match int64
		for _, h := range have {
			if kept[h.id] {
				continue
			}
			if (p.UserID > 0 && h.userID == int64(p.UserID)) ||
				(p.UserID == 0 && h.userID == 0 && h.pwdID == int64(p.PwdID) && h.name == p.Name) {
				match = h.id
				break
			}
		}
		if match != 0 {
			if _, err := tx.Exec(`UPDATE people SET name=?, pwd_id=?, user_id=?, admin_id=?, pin=?, user_type=?,
			    date_mode=?, start_at=?, end_at=?, week_mask=?, multi_verify=?, enabled=?, date_hex=?, updated_at=?
			    WHERE id=?`,
				p.Name, p.PwdID, p.UserID, p.AdminID, p.PIN, p.UserType, p.DateMode,
				unixPtr(p.StartAt), unixPtr(p.EndAt), p.WeekMask, mv, boolInt(p.Enabled), p.DateHex, now, match); err != nil {
				return err
			}
			kept[match] = true
			res.PeopleUpdated++
			continue
		}
		r, err := tx.Exec(`INSERT INTO people(lock_id, name, pwd_id, user_id, admin_id, pin, user_type,
		    date_mode, start_at, end_at, week_mask, multi_verify, enabled, date_hex, created_at, updated_at)
		    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			lockID, p.Name, p.PwdID, p.UserID, p.AdminID, p.PIN, p.UserType, p.DateMode,
			unixPtr(p.StartAt), unixPtr(p.EndAt), p.WeekMask, mv, boolInt(p.Enabled), p.DateHex, now, now)
		if err != nil {
			return err
		}
		id, _ := r.LastInsertId()
		kept[id] = true
		res.PeopleAdded++
	}
	if replace {
		for _, h := range have {
			if kept[h.id] {
				continue
			}
			if _, err := tx.Exec(`DELETE FROM people WHERE id=?`, h.id); err != nil {
				return err
			}
			res.PeopleRemoved++
		}
	}
	return nil
}
