package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// lockJSON is the <lock> object locklyctl expects from qrylknew. mc is returned
// only to the lock's owner over TLS; locklyctl needs it to build BLE frames.
func lockJSON(lk *store.Lock) map[string]any {
	return map[string]any{
		"ID": lk.DeviceID, "mc": lk.MC, "blename": lk.BLEName,
		"mod": lk.Model, "tz": lk.TZ, "fwv": lk.FWV, "clientId": lk.MQTTClientID,
		"hidden": lk.Hidden, "sortIndex": lk.SortIndex,
	}
}

func (a *API) hLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Password string }
	if err := readJSON(r, &req); err != nil || req.Email == "" {
		cod(w, "909", map[string]any{"msg": "bad request"})
		return
	}
	acc, err := a.store.GetAccountByEmail(req.Email)
	// req.Password is the SHA-256 hex locklyctl sends (it mirrors Lockly); the
	// stored hash is bcrypt(sha256hex(plaintext)), set via the management API.
	if err != nil || !store.CheckPassword(acc.PwHash, req.Password) {
		cod(w, "401", map[string]any{"msg": "wrong email or password"})
		return
	}
	tok, err := a.issue("account", acc.ID)
	if err != nil {
		cod(w, "990", map[string]any{"msg": "could not create a session"})
		return
	}
	cod(w, "200", map[string]any{"token": tok, "email": acc.Email, "uid": acc.ID})
}

func (a *API) hRefresh(w http.ResponseWriter, r *http.Request) {
	s := subjectOf(r)
	tok, err := a.issue("account", s.id)
	if err != nil {
		cod(w, "990", map[string]any{"msg": "could not refresh"})
		return
	}
	cod(w, "200", map[string]any{"token": tok})
}

func (a *API) hQrylknew(w http.ResponseWriter, r *http.Request) {
	locks, err := a.store.ListLocksByAccount(subjectOf(r).id)
	if err != nil {
		cod(w, "990", map[string]any{"msg": err.Error()})
		return
	}
	arr := make([]map[string]any, 0, len(locks))
	for i := range locks {
		arr = append(arr, lockJSON(&locks[i]))
	}
	cod(w, "200", map[string]any{"arr": arr})
}

func (a *API) hUserInfoAndDvList(w http.ResponseWriter, r *http.Request) {
	s := subjectOf(r)
	acc, err := a.store.GetAccount(s.id)
	if err != nil {
		cod(w, "990", map[string]any{"msg": err.Error()})
		return
	}
	locks, _ := a.store.ListLocksByAccount(s.id)
	arr := make([]map[string]any, 0, len(locks))
	for i := range locks {
		arr = append(arr, lockJSON(&locks[i]))
	}
	cod(w, "200", map[string]any{"account": map[string]any{"email": acc.Email, "uid": acc.ID}, "arr": arr})
}

func (a *API) hHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"deviceId"`
		Model    string `json:"model"`
	}
	if err := readJSON(r, &req); err != nil {
		cod(w, "909", map[string]any{"msg": "bad request"})
		return
	}
	lk, err := a.accountLock(r, req.DeviceID)
	if err != nil {
		cod(w, "901", map[string]any{"msg": "no such lock"})
		return
	}
	cod(w, "200", map[string]any{
		"mqttConfigs": map[string]any{"host": a.cfg.MQTTHost, "port": a.cfg.MQTTPort},
		"heartbeat":   a.cfg.HeartbeatSeconds,
		"clientId":    lk.MQTTClientID,
	})
}

func (a *API) hSenddata(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"deviceId"`
		Cmd      string `json:"cmd"`
	}
	if err := readJSON(r, &req); err != nil || req.Cmd == "" {
		cod(w, "909", map[string]any{"msg": "bad request"})
		return
	}
	lk, err := a.accountLock(r, req.DeviceID)
	if err != nil {
		cod(w, "901", map[string]any{"msg": "no such lock"})
		return
	}
	if lk.MQTTClientID == "" || !a.gw.Online(lk.MQTTClientID) {
		cod(w, "3005", map[string]any{"msg": "device is offline"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), commandTimeout)
	defer cancel()
	ack, err := a.gw.SendCommand(ctx, lk.MQTTClientID, lk.DeviceID, req.Cmd)
	if err != nil {
		// Mirror Lockly: a lock that does not answer is "offline".
		cod(w, "3005", map[string]any{"msg": err.Error()})
		return
	}
	cod(w, "200", map[string]any{"ack": ack})
}

func (a *API) hEventLog(w http.ResponseWriter, r *http.Request) {
	var env struct {
		Header  map[string]any `json:"header"`
		Payload struct {
			DeviceID string `json:"deviceId"`
			Limit    int    `json:"limit"`
		} `json:"payload"`
	}
	if err := readJSON(r, &env); err != nil {
		cod(w, "909", map[string]any{"msg": "bad request"})
		return
	}
	lk, err := a.accountLock(r, env.Payload.DeviceID)
	if err != nil {
		writeJSON(w, http.StatusOK, errorEnvelope("no such lock"))
		return
	}
	evs, err := a.store.ListEventsByLock(lk.ID, env.Payload.Limit)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, errorEnvelope(err.Error()))
		return
	}
	items := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		items = append(items, map[string]any{"timestamp": e.TM, "co": e.Code, "pid": e.PwdID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"header":  map[string]any{"namespace": "com.lockly", "name": "lockEventLogQueryResponse"},
		"payload": map[string]any{"deviceId": env.Payload.DeviceID, "items": items},
	})
}

// hViewHidden hides or shows one of the account's own locks (a dashboard view
// preference; the lock stays reachable by commands either way).
func (a *API) hViewHidden(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID string `json:"deviceId"`
		Hidden   bool   `json:"hidden"`
	}
	if err := readJSON(r, &req); err != nil || req.DeviceID == "" {
		cod(w, "909", map[string]any{"msg": "deviceId is required"})
		return
	}
	lk, err := a.accountLock(r, req.DeviceID)
	if err != nil {
		cod(w, "901", map[string]any{"msg": "no such lock"})
		return
	}
	if err := a.store.SetLockHidden(lk.ID, req.Hidden); err != nil {
		cod(w, "990", map[string]any{"msg": err.Error()})
		return
	}
	cod(w, "200", map[string]any{"deviceId": req.DeviceID, "hidden": req.Hidden})
}

// hViewOrder reorders the account's locks by a list of device ids.
func (a *API) hViewOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Order []string `json:"order"`
	}
	if err := readJSON(r, &req); err != nil || len(req.Order) == 0 {
		cod(w, "909", map[string]any{"msg": "order (a list of deviceIds) is required"})
		return
	}
	locks, err := a.store.ListLocksByAccount(subjectOf(r).id)
	if err != nil {
		cod(w, "990", map[string]any{"msg": err.Error()})
		return
	}
	byDev := make(map[string]int64, len(locks))
	for i := range locks {
		byDev[locks[i].DeviceID] = locks[i].ID
	}
	ids := make([]int64, 0, len(req.Order))
	for _, dev := range req.Order {
		id, ok := byDev[dev]
		if !ok {
			cod(w, "901", map[string]any{"msg": "unknown deviceId: " + dev})
			return
		}
		ids = append(ids, id)
	}
	if err := a.store.ReorderLocks(subjectOf(r).id, ids); err != nil {
		cod(w, "990", map[string]any{"msg": err.Error()})
		return
	}
	cod(w, "200", map[string]any{"ok": true})
}

func errorEnvelope(msg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"header":  map[string]any{"namespace": "com.lockly", "name": "exception"},
		"payload": map[string]any{"code": "990", "errorMessage": msg},
	})
	return b
}
