// Package store is the server's SQLite persistence: operator and account
// logins, registered locks, the people/PINs/schedules pushed to locks, and the
// access-log events ingested from them. Secrets (master codes, PINs, MQTT
// passwords) are stored but never logged.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup matches no row.
var ErrNotFound = errors.New("not found")

// Store wraps the database.
type Store struct{ db *sql.DB }

// Open opens (and migrates) the SQLite database at path. Use ":memory:" only
// for throwaway cases; prefer a file. Foreign keys and WAL are enabled.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite tolerates one writer; a single connection avoids lock churn.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS operators(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pw_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS accounts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  pw_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  subject_type TEXT NOT NULL,
  subject_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS locks(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT UNIQUE NOT NULL,
  mc TEXT NOT NULL,
  blename TEXT, model TEXT, tz TEXT, fwv TEXT,
  owner_account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  mqtt_client_id TEXT, mqtt_username TEXT, mqtt_password TEXT,
  hidden INTEGER NOT NULL DEFAULT 0, sort_index INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS people(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lock_id INTEGER NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  pwd_id INTEGER NOT NULL, user_id INTEGER NOT NULL, admin_id INTEGER NOT NULL DEFAULT 0,
  pin TEXT, user_type INTEGER NOT NULL,
  date_mode TEXT NOT NULL, start_at INTEGER, end_at INTEGER,
  week_mask INTEGER NOT NULL DEFAULT 0, multi_verify INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1,
  date_hex TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lock_id INTEGER NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
  tm INTEGER NOT NULL, code TEXT, pwd_id INTEGER, raw TEXT,
  created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_people_lock ON people(lock_id);
CREATE INDEX IF NOT EXISTS idx_events_lock ON events(lock_id, tm);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	// Columns added after the first release: bring older databases forward.
	for _, c := range []struct{ table, col, decl string }{
		{"locks", "hidden", "INTEGER NOT NULL DEFAULT 0"},
		{"locks", "sort_index", "INTEGER NOT NULL DEFAULT 0"},
		{"locks", "name", "TEXT NOT NULL DEFAULT ''"},
		{"people", "date_hex", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := s.addColumnIfMissing(c.table, c.col, c.decl); err != nil {
			return err
		}
	}
	return nil
}

// addColumnIfMissing adds a column when it is not already present, so migrate is
// idempotent on databases created by an earlier version. table, col and decl are
// internal constants, never user input.
func (s *Store) addColumnIfMissing(table, col, decl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == col {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + decl)
	return err
}

func unixPtr(t *time.Time) sql.NullInt64 {
	if t == nil || t.IsZero() {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func timePtr(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.Unix(n.Int64, 0).UTC()
	return &t
}

// ---- operators ----

// CreateOperator inserts an operator with an already-hashed password.
func (s *Store) CreateOperator(username string, pwHash []byte) (*Operator, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`INSERT INTO operators(username, pw_hash, created_at) VALUES(?,?,?)`,
		username, pwHash, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Operator{ID: id, Username: username, PwHash: pwHash, CreatedAt: now}, nil
}

// GetOperatorByUsername looks an operator up by name.
func (s *Store) GetOperatorByUsername(username string) (*Operator, error) {
	var o Operator
	var ca int64
	err := s.db.QueryRow(`SELECT id, username, pw_hash, created_at FROM operators WHERE username=?`, username).
		Scan(&o.ID, &o.Username, &o.PwHash, &ca)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o.CreatedAt = time.Unix(ca, 0).UTC()
	return &o, nil
}

// OperatorCount reports how many operators exist (for first-run bootstrap).
func (s *Store) OperatorCount() (int, error) {
	var n int
	return n, s.db.QueryRow(`SELECT COUNT(*) FROM operators`).Scan(&n)
}

// ---- accounts ----

// CreateAccount inserts an account (a login locklyctl uses) with a hashed password.
func (s *Store) CreateAccount(email string, pwHash []byte) (*Account, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`INSERT INTO accounts(email, pw_hash, created_at) VALUES(?,?,?)`,
		email, pwHash, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &Account{ID: id, Email: email, PwHash: pwHash, CreatedAt: now}, nil
}

func scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	var a Account
	var ca int64
	err := row.Scan(&a.ID, &a.Email, &a.PwHash, &ca)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = time.Unix(ca, 0).UTC()
	return &a, nil
}

// GetAccountByEmail looks an account up by email.
func (s *Store) GetAccountByEmail(email string) (*Account, error) {
	return scanAccount(s.db.QueryRow(`SELECT id, email, pw_hash, created_at FROM accounts WHERE email=?`, email))
}

// GetAccount looks an account up by id.
func (s *Store) GetAccount(id int64) (*Account, error) {
	return scanAccount(s.db.QueryRow(`SELECT id, email, pw_hash, created_at FROM accounts WHERE id=?`, id))
}

// ListAccounts returns all accounts, oldest first.
func (s *Store) ListAccounts() ([]Account, error) {
	rows, err := s.db.Query(`SELECT id, email, pw_hash, created_at FROM accounts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SetAccountPassword updates an account's password hash.
func (s *Store) SetAccountPassword(id int64, pwHash []byte) error {
	return s.affectOne(s.db.Exec(`UPDATE accounts SET pw_hash=? WHERE id=?`, pwHash, id))
}

// DeleteAccount removes an account and (by cascade) its locks and their people.
func (s *Store) DeleteAccount(id int64) error {
	return s.affectOne(s.db.Exec(`DELETE FROM accounts WHERE id=?`, id))
}

// ---- sessions ----

// CreateSession stores a bearer token for a subject.
func (s *Store) CreateSession(token, subjectType string, subjectID int64, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(token, subject_type, subject_id, expires_at) VALUES(?,?,?,?)`,
		token, subjectType, subjectID, expires.Unix())
	return err
}

// GetSession returns a live (unexpired) session, or ErrNotFound.
func (s *Store) GetSession(token string) (*Session, error) {
	var sess Session
	var exp int64
	err := s.db.QueryRow(`SELECT token, subject_type, subject_id, expires_at FROM sessions WHERE token=?`, token).
		Scan(&sess.Token, &sess.SubjectType, &sess.SubjectID, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = time.Unix(exp, 0).UTC()
	if time.Now().After(sess.ExpiresAt) {
		_ = s.DeleteSession(token)
		return nil, ErrNotFound
	}
	return &sess, nil
}

// DeleteSession revokes a token.
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

// ---- locks ----

// CreateLock registers a lock under an account.
func (s *Store) CreateLock(l *Lock) (*Lock, error) {
	now := time.Now().UTC()
	if l.SortIndex == 0 {
		// Append new locks after the account's existing ones.
		var m sql.NullInt64
		_ = s.db.QueryRow(`SELECT MAX(sort_index) FROM locks WHERE owner_account_id=?`, l.OwnerAccountID).Scan(&m)
		l.SortIndex = int(m.Int64) + 1
	}
	res, err := s.db.Exec(`INSERT INTO locks(device_id, mc, blename, model, tz, fwv, owner_account_id,
	    mqtt_client_id, mqtt_username, mqtt_password, hidden, sort_index, name, created_at)
	    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		l.DeviceID, l.MC, l.BLEName, l.Model, l.TZ, l.FWV, l.OwnerAccountID,
		l.MQTTClientID, l.MQTTUsername, l.MQTTPassword, boolInt(l.Hidden), l.SortIndex, l.Name, now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	l.ID, l.CreatedAt = id, now
	return l, nil
}

func scanLock(row interface{ Scan(...any) error }) (*Lock, error) {
	var l Lock
	var ca int64
	var hidden int
	err := row.Scan(&l.ID, &l.DeviceID, &l.MC, &l.BLEName, &l.Model, &l.TZ, &l.FWV,
		&l.OwnerAccountID, &l.MQTTClientID, &l.MQTTUsername, &l.MQTTPassword, &hidden, &l.SortIndex, &l.Name, &ca)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	l.Hidden = hidden != 0
	l.CreatedAt = time.Unix(ca, 0).UTC()
	return &l, nil
}

const lockCols = `id, device_id, mc, blename, model, tz, fwv, owner_account_id, mqtt_client_id, mqtt_username, mqtt_password, hidden, sort_index, name, created_at`

// GetLockByDeviceID looks a lock up by its device id.
func (s *Store) GetLockByDeviceID(deviceID string) (*Lock, error) {
	return scanLock(s.db.QueryRow(`SELECT `+lockCols+` FROM locks WHERE device_id=?`, deviceID))
}

// GetLock looks a lock up by row id.
func (s *Store) GetLock(id int64) (*Lock, error) {
	return scanLock(s.db.QueryRow(`SELECT `+lockCols+` FROM locks WHERE id=?`, id))
}

// LocksByMQTTIdentity returns every lock whose provisioned MQTT username is
// username or whose MQTT client id is clientID (an empty value matches
// nothing), for broker authentication: the broker accepts a lock only when one
// lock alone claims both, since neither is unique in the table and an account
// can set them through a backup import.
func (s *Store) LocksByMQTTIdentity(username, clientID string) ([]Lock, error) {
	return s.queryLocks(`SELECT `+lockCols+` FROM locks
		WHERE (mqtt_username <> '' AND mqtt_username = ?) OR (mqtt_client_id <> '' AND mqtt_client_id = ?)
		ORDER BY id`, username, clientID)
}

// ListLocksByAccount returns an account's locks.
func (s *Store) ListLocksByAccount(accountID int64) ([]Lock, error) {
	return s.queryLocks(`SELECT `+lockCols+` FROM locks WHERE owner_account_id=? ORDER BY sort_index, id`, accountID)
}

// ListLocks returns every lock.
func (s *Store) ListLocks() ([]Lock, error) {
	return s.queryLocks(`SELECT ` + lockCols + ` FROM locks ORDER BY owner_account_id, sort_index, id`)
}

func (s *Store) queryLocks(q string, args ...any) ([]Lock, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Lock
	for rows.Next() {
		l, err := scanLock(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}

// SetLockMQTT updates a lock's provisioned MQTT credentials.
func (s *Store) SetLockMQTT(id int64, clientID, username, password string) error {
	return s.affectOne(s.db.Exec(`UPDATE locks SET mqtt_client_id=?, mqtt_username=?, mqtt_password=? WHERE id=?`,
		clientID, username, password, id))
}

// SetLockHidden toggles whether a lock is hidden in listing views.
func (s *Store) SetLockHidden(id int64, hidden bool) error {
	return s.affectOne(s.db.Exec(`UPDATE locks SET hidden=? WHERE id=?`, boolInt(hidden), id))
}

// ReorderLocks sets each listed lock's sort_index to its position in orderedIDs.
// Every id must belong to accountID; a missing or foreign id is an error and the
// whole reorder rolls back. Locks not listed keep their current sort_index.
func (s *Store) ReorderLocks(accountID int64, orderedIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for pos, id := range orderedIDs {
		res, err := tx.Exec(`UPDATE locks SET sort_index=? WHERE id=? AND owner_account_id=?`, pos, id, accountID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
	}
	return tx.Commit()
}

// DeleteLock removes a lock and its people (cascade).
func (s *Store) DeleteLock(id int64) error {
	return s.affectOne(s.db.Exec(`DELETE FROM locks WHERE id=?`, id))
}

// ---- people ----

// CreatePerson inserts a person for a lock.
func (s *Store) CreatePerson(p *Person) (*Person, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(`INSERT INTO people(lock_id, name, pwd_id, user_id, admin_id, pin, user_type,
	    date_mode, start_at, end_at, week_mask, multi_verify, enabled, date_hex, created_at, updated_at)
	    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.LockID, p.Name, p.PwdID, p.UserID, p.AdminID, p.PIN, p.UserType,
		p.DateMode, unixPtr(p.StartAt), unixPtr(p.EndAt), p.WeekMask, p.MultiVerify,
		boolInt(p.Enabled), p.DateHex, now.Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	p.ID, p.CreatedAt, p.UpdatedAt = id, now, now
	return p, nil
}

func scanPerson(row interface{ Scan(...any) error }) (*Person, error) {
	var p Person
	var start, end sql.NullInt64
	var enabled, ca, ua int64
	err := row.Scan(&p.ID, &p.LockID, &p.Name, &p.PwdID, &p.UserID, &p.AdminID, &p.PIN, &p.UserType,
		&p.DateMode, &start, &end, &p.WeekMask, &p.MultiVerify, &enabled, &p.DateHex, &ca, &ua)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.StartAt, p.EndAt, p.Enabled = timePtr(start), timePtr(end), enabled != 0
	p.CreatedAt, p.UpdatedAt = time.Unix(ca, 0).UTC(), time.Unix(ua, 0).UTC()
	return &p, nil
}

const personCols = `id, lock_id, name, pwd_id, user_id, admin_id, pin, user_type, date_mode, start_at, end_at, week_mask, multi_verify, enabled, date_hex, created_at, updated_at`

// GetPerson looks a person up by id.
func (s *Store) GetPerson(id int64) (*Person, error) {
	return scanPerson(s.db.QueryRow(`SELECT `+personCols+` FROM people WHERE id=?`, id))
}

// ListPeopleByLock returns a lock's people.
func (s *Store) ListPeopleByLock(lockID int64) ([]Person, error) {
	rows, err := s.db.Query(`SELECT `+personCols+` FROM people WHERE lock_id=? ORDER BY id`, lockID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Person
	for rows.Next() {
		p, err := scanPerson(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// UpdatePerson writes a person's mutable fields and bumps updated_at.
func (s *Store) UpdatePerson(p *Person) error {
	p.UpdatedAt = time.Now().UTC()
	return s.affectOne(s.db.Exec(`UPDATE people SET name=?, pwd_id=?, user_id=?, admin_id=?, pin=?,
	    user_type=?, date_mode=?, start_at=?, end_at=?, week_mask=?, multi_verify=?, enabled=?, date_hex=?,
	    updated_at=? WHERE id=?`,
		p.Name, p.PwdID, p.UserID, p.AdminID, p.PIN, p.UserType, p.DateMode,
		unixPtr(p.StartAt), unixPtr(p.EndAt), p.WeekMask, p.MultiVerify, boolInt(p.Enabled), p.DateHex,
		p.UpdatedAt.Unix(), p.ID))
}

// SetPersonEnabled flips the suspend toggle.
func (s *Store) SetPersonEnabled(id int64, enabled bool) error {
	return s.affectOne(s.db.Exec(`UPDATE people SET enabled=?, updated_at=? WHERE id=?`,
		boolInt(enabled), time.Now().UTC().Unix(), id))
}

// DeletePerson removes a person.
func (s *Store) DeletePerson(id int64) error {
	return s.affectOne(s.db.Exec(`DELETE FROM people WHERE id=?`, id))
}

// ---- events ----

// AddEvent stores one access-log entry.
func (s *Store) AddEvent(e *Event) error {
	var pwd sql.NullInt64
	if e.PwdID != nil {
		pwd = sql.NullInt64{Int64: int64(*e.PwdID), Valid: true}
	}
	_, err := s.db.Exec(`INSERT INTO events(lock_id, tm, code, pwd_id, raw, created_at) VALUES(?,?,?,?,?,?)`,
		e.LockID, e.TM, e.Code, pwd, e.Raw, time.Now().UTC().Unix())
	return err
}

// ListEventsByLock returns up to limit of a lock's events, newest first.
func (s *Store) ListEventsByLock(lockID int64, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id, lock_id, tm, code, pwd_id, raw, created_at FROM events
	    WHERE lock_id=? ORDER BY tm DESC LIMIT ?`, lockID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var pwd sql.NullInt64
		var ca int64
		if err := rows.Scan(&e.ID, &e.LockID, &e.TM, &e.Code, &pwd, &e.Raw, &ca); err != nil {
			return nil, err
		}
		if pwd.Valid {
			v := int(pwd.Int64)
			e.PwdID = &v
		}
		e.CreatedAt = time.Unix(ca, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) affectOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
