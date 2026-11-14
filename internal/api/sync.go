package api

import (
	"context"
	"fmt"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/lockly"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// nonce fetches a fresh nonce from the lock with a status query (0x1E).
func (a *API) nonce(ctx context.Context, lk *store.Lock) (string, error) {
	frame, err := lockly.BuildStatusQuery(lk.MC, lk.DeviceID, a.now())
	if err != nil {
		return "", err
	}
	ack, err := a.gw.SendCommand(ctx, lk.MQTTClientID, lk.DeviceID, frame)
	if err != nil {
		return "", err
	}
	dec, ok := lockly.DecryptAck(ack, lk.MC, lk.DeviceID)
	if !ok {
		return "", fmt.Errorf("lock rejected the status query")
	}
	r, err := lockly.ParseStatusReply(dec)
	if err != nil {
		return "", err
	}
	return r.Nonce, nil
}

// personDate is the on-lock validity window for a person when enabled.
func (a *API) personDate(p *store.Person) string {
	switch p.DateMode {
	case store.DatePeriod:
		if p.StartAt != nil && p.EndAt != nil {
			return lockly.DatePeriodHex(*p.StartAt, *p.EndAt)
		}
	case store.DateWeekly:
		return lockly.DateWeeklyHex(p.WeekMask)
	}
	return lockly.DatePermanentHex
}

// pushPerson writes a person's record to the lock (0x73). A disabled person is
// pushed with a far-future window that excludes now (DateSuspendedHex; the lock
// rejects a past window with E3), so their PIN and enrolled face/fingerprint
// survive (verified on hardware); enabling re-pushes the real window.
func (a *API) pushPerson(ctx context.Context, lk *store.Lock, p *store.Person) error {
	nonce, err := a.nonce(ctx, lk)
	if err != nil {
		return err
	}
	u := lockly.AccessUser{
		UserType: p.UserType, PwdID: p.PwdID, UserID: p.UserID, AdminID: p.AdminID,
		PIN: p.PIN, MultiVerify: p.MultiVerify, Date: a.personDate(p),
	}
	if !p.Enabled {
		u.UserType = 0x12
		u.Date = lockly.DateSuspendedHex()
	}
	frame, err := u.BuildAccessUserSet(lk.MC, lk.DeviceID, nonce)
	if err != nil {
		return err
	}
	ack, err := a.gw.SendCommand(ctx, lk.MQTTClientID, lk.DeviceID, frame)
	if err != nil {
		return err
	}
	if !ackAccepted(ack, lk.MC, lk.DeviceID) {
		return fmt.Errorf("lock did not accept the user record")
	}
	return nil
}

// ackAccepted reports whether a reply decrypts and its status byte is 00.
func ackAccepted(ackHex, mc, uuid string) bool {
	dec, ok := lockly.DecryptAck(ackHex, mc, uuid)
	return ok && len(dec) >= 2 && dec[0:2] == "00"
}

// syncPerson pushes a person to the lock if it is online, and reports whether
// the push reached the lock. A person is always persisted first by the caller;
// an offline lock just leaves the change unsynced until next time.
func (a *API) syncPerson(ctx context.Context, lk *store.Lock, p *store.Person) (synced bool, detail string) {
	if lk.MQTTClientID == "" || !a.gw.Online(lk.MQTTClientID) {
		return false, "lock offline; change saved and will push when it reconnects"
	}
	if err := a.pushPerson(ctx, lk, p); err != nil {
		return false, "saved, but pushing to the lock failed: " + err.Error()
	}
	return true, "pushed to the lock"
}
