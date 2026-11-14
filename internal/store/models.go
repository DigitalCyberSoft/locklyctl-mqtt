package store

import "time"

// Operator is a login for the management console / admin API.
type Operator struct {
	ID        int64
	Username  string
	PwHash    []byte
	CreatedAt time.Time
}

// Account is a login that locklyctl signs in as (the equivalent of a Lockly
// account). It owns locks.
type Account struct {
	ID        int64
	Email     string
	PwHash    []byte
	CreatedAt time.Time
}

// Session is a bearer token for an operator or an account.
type Session struct {
	Token       string
	SubjectType string // "operator" or "account"
	SubjectID   int64
	ExpiresAt   time.Time
}

// Lock is a registered lock. MC is the master code and is a secret (never
// logged); together with DeviceID it is the lock's AES key.
type Lock struct {
	ID             int64
	DeviceID       string // lowercase hex, as the account lists it
	Name           string // the door's name, as the owner calls it ("" = use BLEName)
	MC             string // master code (secret)
	BLEName        string
	Model          string
	TZ             string // e.g. "+8:00"
	FWV            string
	OwnerAccountID int64
	MQTTClientID   string
	MQTTUsername   string
	MQTTPassword   string // secret
	Hidden         bool   // hidden in listing views (still reachable by commands)
	SortIndex      int    // display order within the owner account
	CreatedAt      time.Time
}

// Date modes for a Person's access window.
const (
	DatePermanent = "permanent" // never expires (owner/family)
	DatePeriod    = "period"    // a fixed start..end window
	DateWeekly    = "weekly"    // a recurring weekly schedule
)

// Person is someone with access to a lock: a PIN and a schedule, pushed to the
// lock as a 0x73 record. Enabled is a first-class suspend toggle: a disabled
// person is pushed with a far-future window that excludes now (the lock rejects
// a past one with E3), not deleted, so their PIN and any enrolled
// fingerprint/face survive.
type Person struct {
	ID       int64
	LockID   int64
	Name     string
	PwdID    int // credential slot on the lock
	UserID   int // the account's user id for this person
	AdminID  int
	PIN      string // secret; "" means no PIN credential
	UserType int    // lockly.UserFamily / UserGuest* byte
	DateMode string // DatePermanent / DatePeriod / DateWeekly
	StartAt  *time.Time
	EndAt    *time.Time
	WeekMask int // bit0=Mon..bit6=Sun, for DateWeekly
	// DateHex is the exact 10-byte 0x73 date (20 hex digits) as read from the
	// lock, e.g. by an import. When set it is pushed verbatim instead of one
	// derived from DateMode, so a weekly window's hours survive (DateMode alone
	// can only say all-day). Changing the schedule through the API clears it.
	DateHex     string
	MultiVerify int
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Event is one access-log entry stored for a lock.
type Event struct {
	ID        int64
	LockID    int64
	TM        int64 // epoch ms
	Code      string
	PwdID     *int
	Raw       string
	CreatedAt time.Time
}
