package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

type ctxKey int

const subjectKey ctxKey = 0

// sessionTTL is how long a bearer token stays valid.
const sessionTTL = 30 * 24 * time.Hour

type subject struct {
	kind string // "account" or "operator"
	id   int64
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// issue mints and stores a token for a subject.
func (a *API) issue(kind string, id int64) (string, error) {
	tok, err := mintToken()
	if err != nil {
		return "", err
	}
	if err := a.store.CreateSession(tok, kind, id, a.now().Add(sessionTTL)); err != nil {
		return "", err
	}
	return tok, nil
}

func (a *API) lookup(r *http.Request) (subject, bool) {
	sess, err := a.store.GetSession(bearer(r))
	if err != nil {
		return subject{}, false
	}
	return subject{kind: sess.SubjectType, id: sess.SubjectID}, true
}

// authAccount requires a valid account token (locklyctl-facing API).
func (a *API) authAccount(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.lookup(r)
		if !ok || s.kind != "account" {
			cod(w, "401", map[string]any{"msg": "not signed in"})
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), subjectKey, s)))
	}
}

// authOp requires a valid operator token (management API).
func (a *API) authOp(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.lookup(r)
		if !ok || s.kind != "operator" {
			adminErr(w, http.StatusUnauthorized, "not signed in")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), subjectKey, s)))
	}
}

func subjectOf(r *http.Request) subject {
	s, _ := r.Context().Value(subjectKey).(subject)
	return s
}

// accountLock fetches a lock and verifies it belongs to the signed-in account.
func (a *API) accountLock(r *http.Request, deviceID string) (*store.Lock, error) {
	lk, err := a.store.GetLockByDeviceID(deviceID)
	if err != nil {
		return nil, err
	}
	if s := subjectOf(r); s.kind == "account" && lk.OwnerAccountID != s.id {
		return nil, errors.New("lock not on this account")
	}
	return lk, nil
}
