// Package api is the server's HTTP surface: the locklyctl-facing REST API
// (the /api/* endpoints locklyctl calls in --server mode, per CONTRACT.md) and
// the operator management API (/admin/api/*). It drives locks through a
// Gateway (the device hub) and persists through the store.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// Gateway is how the API reaches a lock over the device channel.
type Gateway interface {
	Online(clientID string) bool
	SendCommand(ctx context.Context, clientID, deviceID, frameHex string) (string, error)
}

// Config carries the public MQTT details the API hands locks via
// getHeartbeatTime (the broker a lock should connect to).
type Config struct {
	MQTTHost         string
	MQTTPort         int
	HeartbeatSeconds int
}

// API holds the HTTP handlers.
type API struct {
	store *store.Store
	gw    Gateway
	cfg   Config
	log   *slog.Logger
	now   func() time.Time
}

// New builds the API over a store and a lock gateway.
func New(st *store.Store, gw Gateway, cfg Config, log *slog.Logger) *API {
	if log == nil {
		log = slog.Default()
	}
	if cfg.HeartbeatSeconds == 0 {
		cfg.HeartbeatSeconds = 300
	}
	return &API{store: st, gw: gw, cfg: cfg, log: log, now: time.Now}
}

// commandTimeout bounds a single relayed BLE exchange.
const commandTimeout = 30 * time.Second

// Handler returns a router with only the API routes (no web console).
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.Routes(mux)
	return mux
}

// Routes registers the API routes on mux, so a caller can also mount a web
// console at "/".
func (a *API) Routes(mux *http.ServeMux) {
	// locklyctl-facing API (CONTRACT.md section 2). Paths are the Lockly names
	// verbatim under /api/, so locklyctl's --server base-URL swap just works.
	mux.HandleFunc("POST /api/login", a.hLogin)
	mux.HandleFunc("POST /api/refresh", a.authAccount(a.hRefresh))
	mux.HandleFunc("POST /api/qrylknew", a.authAccount(a.hQrylknew))
	mux.HandleFunc("POST /api/getUserInfoAndDvList", a.authAccount(a.hUserInfoAndDvList))
	mux.HandleFunc("POST /api/getHeartbeatTime", a.authAccount(a.hHeartbeat))
	mux.HandleFunc("POST /api/senddata", a.authAccount(a.hSenddata))
	mux.HandleFunc("POST /api/v1/proto/handler", a.authAccount(a.hEventLog))
	// Dashboard view preferences (a locklyctl-mqtt extension, not a Lockly name):
	// hide/show and reorder the account's own locks.
	mux.HandleFunc("POST /api/view/hidden", a.authAccount(a.hViewHidden))
	mux.HandleFunc("POST /api/view/order", a.authAccount(a.hViewOrder))
	// Backup and migration (an extension): the account's locks and people.
	mux.HandleFunc("POST /api/backup/export", a.authAccount(a.hBackupExport))
	mux.HandleFunc("POST /api/backup/import", a.authAccount(a.hBackupImport))

	// management API.
	mux.HandleFunc("POST /admin/api/login", a.hAdminLogin)
	mux.HandleFunc("GET /admin/api/accounts", a.authOp(a.hListAccounts))
	mux.HandleFunc("POST /admin/api/accounts", a.authOp(a.hCreateAccount))
	mux.HandleFunc("DELETE /admin/api/accounts/{id}", a.authOp(a.hDeleteAccount))
	mux.HandleFunc("GET /admin/api/locks", a.authOp(a.hListLocks))
	mux.HandleFunc("POST /admin/api/locks", a.authOp(a.hCreateLock))
	mux.HandleFunc("GET /admin/api/locks/{id}", a.authOp(a.hGetLock))
	mux.HandleFunc("DELETE /admin/api/locks/{id}", a.authOp(a.hDeleteLock))
	mux.HandleFunc("GET /admin/api/locks/{id}/people", a.authOp(a.hListPeople))
	mux.HandleFunc("POST /admin/api/locks/{id}/people", a.authOp(a.hCreatePerson))
	mux.HandleFunc("PATCH /admin/api/people/{id}", a.authOp(a.hUpdatePerson))
	mux.HandleFunc("POST /admin/api/people/{id}/enabled", a.authOp(a.hSetPersonEnabled))
	mux.HandleFunc("DELETE /admin/api/people/{id}", a.authOp(a.hDeletePerson))
	mux.HandleFunc("GET /admin/api/locks/{id}/events", a.authOp(a.hListEvents))
	mux.HandleFunc("POST /admin/api/locks/order", a.authOp(a.hReorderLocks))
	mux.HandleFunc("POST /admin/api/locks/{id}/hidden", a.authOp(a.hSetLockHidden))
}

// ---- JSON helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// cod writes a Lockly-style {cod: "..."} body plus any extra fields.
func cod(w http.ResponseWriter, code string, extra map[string]any) {
	body := map[string]any{"cod": code}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, http.StatusOK, body)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func adminErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func idParam(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}

func mintToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
