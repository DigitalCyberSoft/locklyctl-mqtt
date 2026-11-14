package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

// ---- operator auth ----

func (a *API) hAdminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if err := readJSON(r, &req); err != nil {
		adminErr(w, http.StatusBadRequest, "bad request")
		return
	}
	op, err := a.store.GetOperatorByUsername(req.Username)
	if err != nil || !store.CheckPassword(op.PwHash, req.Password) {
		adminErr(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	tok, err := a.issue("operator", op.ID)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, "could not create a session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "username": op.Username})
}

// ---- accounts ----

func accountJSON(a *store.Account) map[string]any {
	return map[string]any{"id": a.ID, "email": a.Email, "createdAt": a.CreatedAt.Unix()}
}

func (a *API) hListAccounts(w http.ResponseWriter, r *http.Request) {
	accs, err := a.store.ListAccounts()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(accs))
	for i := range accs {
		out = append(out, accountJSON(&accs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out})
}

func (a *API) hCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req struct{ Email, Password string }
	if err := readJSON(r, &req); err != nil || req.Email == "" || req.Password == "" {
		adminErr(w, http.StatusBadRequest, "email and password are required")
		return
	}
	// locklyctl signs in by sending SHA-256(password); store bcrypt of that.
	hash, err := store.HashAccountPassword(req.Password)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	acc, err := a.store.CreateAccount(req.Email, hash)
	if err != nil {
		adminErr(w, http.StatusConflict, "could not create account (duplicate email?)")
		return
	}
	writeJSON(w, http.StatusCreated, accountJSON(acc))
}

func (a *API) hDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := a.store.DeleteAccount(id); err != nil {
		adminErr(w, http.StatusNotFound, "no such account")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- locks ----

func (a *API) lockJSONAdmin(lk *store.Lock) map[string]any {
	online := lk.MQTTClientID != "" && a.gw.Online(lk.MQTTClientID)
	return map[string]any{
		"id": lk.ID, "deviceId": lk.DeviceID, "name": lk.Name, "blename": lk.BLEName, "model": lk.Model,
		"tz": lk.TZ, "fwv": lk.FWV, "ownerAccountId": lk.OwnerAccountID,
		"mqttClientId": lk.MQTTClientID, "mqttUsername": lk.MQTTUsername, "online": online,
		"hidden": lk.Hidden, "sortIndex": lk.SortIndex,
	}
}

func (a *API) hListLocks(w http.ResponseWriter, r *http.Request) {
	locks, err := a.store.ListLocks()
	if err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(locks))
	for i := range locks {
		out = append(out, a.lockJSONAdmin(&locks[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"locks": out})
}

func (a *API) hCreateLock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID, MC, Name, BLEName, Model, TZ, FWV string
		OwnerAccountID                              int64
		MQTTClientID, MQTTUsername, MQTTPassword    string
	}
	if err := readJSON(r, &req); err != nil || req.DeviceID == "" || req.MC == "" || req.OwnerAccountID == 0 {
		adminErr(w, http.StatusBadRequest, "deviceId, mc and ownerAccountId are required")
		return
	}
	if _, err := a.store.GetAccount(req.OwnerAccountID); err != nil {
		adminErr(w, http.StatusBadRequest, "owner account does not exist")
		return
	}
	lk, err := a.store.CreateLock(&store.Lock{
		DeviceID: req.DeviceID, MC: req.MC, Name: req.Name, BLEName: req.BLEName, Model: req.Model,
		TZ: req.TZ, FWV: req.FWV, OwnerAccountID: req.OwnerAccountID,
		MQTTClientID: req.MQTTClientID, MQTTUsername: req.MQTTUsername, MQTTPassword: req.MQTTPassword,
	})
	if err != nil {
		adminErr(w, http.StatusConflict, "could not create lock (duplicate deviceId?)")
		return
	}
	writeJSON(w, http.StatusCreated, a.lockJSONAdmin(lk))
}

func (a *API) hGetLock(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	lk, err := a.store.GetLock(id)
	if err != nil {
		adminErr(w, http.StatusNotFound, "no such lock")
		return
	}
	resp := a.lockJSONAdmin(lk)
	if st, ok := a.gw.(interface {
		LastState(string) (map[string]string, bool)
	}); ok {
		if state, has := st.LastState(lk.DeviceID); has {
			resp["state"] = state
		}
	}
	evs, _ := a.store.ListEventsByLock(lk.ID, 20)
	resp["recentEvents"] = eventsJSON(evs)
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) hDeleteLock(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := a.store.DeleteLock(id); err != nil {
		adminErr(w, http.StatusNotFound, "no such lock")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) hSetLockHidden(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		Hidden bool `json:"hidden"`
	}
	if err := readJSON(r, &req); err != nil {
		adminErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := a.store.SetLockHidden(id, req.Hidden); err != nil {
		adminErr(w, http.StatusNotFound, "no such lock")
		return
	}
	lk, err := a.store.GetLock(id)
	if err != nil {
		adminErr(w, http.StatusNotFound, "no such lock")
		return
	}
	writeJSON(w, http.StatusOK, a.lockJSONAdmin(lk))
}

func (a *API) hReorderLocks(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AccountID int64   `json:"accountId"`
		Order     []int64 `json:"order"`
	}
	if err := readJSON(r, &req); err != nil || req.AccountID == 0 || len(req.Order) == 0 {
		adminErr(w, http.StatusBadRequest, "accountId and order (lock ids) are required")
		return
	}
	if err := a.store.ReorderLocks(req.AccountID, req.Order); err != nil {
		adminErr(w, http.StatusBadRequest, "could not reorder (every id must belong to the account)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- people ----

type personInput struct {
	Name        string `json:"name"`
	PwdID       int    `json:"pwdId"`
	UserID      int    `json:"userId"`
	AdminID     int    `json:"adminId"`
	PIN         string `json:"pin"`
	UserType    int    `json:"userType"`
	DateMode    string `json:"dateMode"`
	StartAt     int64  `json:"startAt"` // epoch seconds, 0 = unset
	EndAt       int64  `json:"endAt"`
	WeekMask    int    `json:"weekMask"`
	MultiVerify int    `json:"multiVerify"`
	Enabled     *bool  `json:"enabled"`
}

// personJSON omits the PIN (never echoed back); has_pin signals its presence.
func personJSON(p *store.Person) map[string]any {
	out := map[string]any{
		"id": p.ID, "lockId": p.LockID, "name": p.Name, "pwdId": p.PwdID,
		"userId": p.UserID, "adminId": p.AdminID, "hasPin": p.PIN != "",
		"userType": p.UserType, "dateMode": p.DateMode, "weekMask": p.WeekMask,
		"multiVerify": p.MultiVerify, "enabled": p.Enabled,
	}
	if p.StartAt != nil {
		out["startAt"] = p.StartAt.Unix()
	}
	if p.EndAt != nil {
		out["endAt"] = p.EndAt.Unix()
	}
	if p.DateHex != "" {
		out["date"] = p.DateHex // the exact on-lock date, pushed as is
	}
	return out
}

func epochPtr(sec int64) *time.Time {
	if sec == 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func (a *API) hListPeople(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	people, err := a.store.ListPeopleByLock(id)
	if err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(people))
	for i := range people {
		out = append(out, personJSON(&people[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"people": out})
}

func (a *API) hCreatePerson(w http.ResponseWriter, r *http.Request) {
	lockID, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	lk, err := a.store.GetLock(lockID)
	if err != nil {
		adminErr(w, http.StatusNotFound, "no such lock")
		return
	}
	var in personInput
	if err := readJSON(r, &in); err != nil || in.Name == "" {
		adminErr(w, http.StatusBadRequest, "name is required")
		return
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if in.DateMode == "" {
		in.DateMode = store.DatePermanent
	}
	if in.MultiVerify == 0 {
		in.MultiVerify = 1
	}
	p, err := a.store.CreatePerson(&store.Person{
		LockID: lk.ID, Name: in.Name, PwdID: in.PwdID, UserID: in.UserID, AdminID: in.AdminID,
		PIN: in.PIN, UserType: in.UserType, DateMode: in.DateMode,
		StartAt: epochPtr(in.StartAt), EndAt: epochPtr(in.EndAt), WeekMask: in.WeekMask,
		MultiVerify: in.MultiVerify, Enabled: enabled,
	})
	if err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.respondPerson(w, r, lk, p, http.StatusCreated)
}

func (a *API) hUpdatePerson(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	p, err := a.store.GetPerson(id)
	if err != nil {
		adminErr(w, http.StatusNotFound, "no such person")
		return
	}
	var in personInput
	if err := readJSON(r, &in); err != nil {
		adminErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if in.Name != "" {
		p.Name = in.Name
	}
	p.PwdID, p.UserID, p.AdminID = in.PwdID, in.UserID, in.AdminID
	p.PIN, p.UserType = in.PIN, in.UserType
	if in.DateMode != "" {
		p.DateMode = in.DateMode
		p.DateHex = "" // a schedule sent here replaces the exact one read from the lock
	}
	p.StartAt, p.EndAt, p.WeekMask = epochPtr(in.StartAt), epochPtr(in.EndAt), in.WeekMask
	if in.MultiVerify != 0 {
		p.MultiVerify = in.MultiVerify
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if err := a.store.UpdatePerson(p); err != nil {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	lk, _ := a.store.GetLock(p.LockID)
	a.respondPerson(w, r, lk, p, http.StatusOK)
}

func (a *API) hSetPersonEnabled(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		adminErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := a.store.SetPersonEnabled(id, req.Enabled); err != nil {
		adminErr(w, http.StatusNotFound, "no such person")
		return
	}
	p, err := a.store.GetPerson(id)
	if err != nil {
		adminErr(w, http.StatusNotFound, "no such person")
		return
	}
	lk, _ := a.store.GetLock(p.LockID)
	a.respondPerson(w, r, lk, p, http.StatusOK)
}

func (a *API) hDeletePerson(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	if err := a.store.DeletePerson(id); err != nil {
		adminErr(w, http.StatusNotFound, "no such person")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// respondPerson pushes the person to the lock (best effort) and returns the
// record plus whether the push reached the lock.
func (a *API) respondPerson(w http.ResponseWriter, r *http.Request, lk *store.Lock, p *store.Person, status int) {
	ctx, cancel := context.WithTimeout(r.Context(), commandTimeout)
	defer cancel()
	synced, detail := a.syncPerson(ctx, lk, p)
	resp := personJSON(p)
	resp["synced"] = synced
	resp["syncDetail"] = detail
	writeJSON(w, status, resp)
}

// ---- events ----

func eventsJSON(evs []store.Event) []map[string]any {
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, map[string]any{"tm": e.TM, "code": e.Code, "pwdId": e.PwdID})
	}
	return out
}

func (a *API) hListEvents(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r)
	if err != nil {
		adminErr(w, http.StatusBadRequest, "bad id")
		return
	}
	evs, err := a.store.ListEventsByLock(id, 200)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		adminErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": eventsJSON(evs)})
}
