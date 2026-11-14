# locklyctl-mqtt wire contract

The single source of truth for how **locklyctl** (Python) and **locklyctl-mqtt**
(this Go server) talk, and how a **lock** talks to the server. Both repos
implement to this file; change it here first.

There are three interfaces:

1. lock <-> server: the Lockly MQTT device channel (fixed by the lock firmware).
2. locklyctl <-> server: a clean REST API (defined here; NOT Lockly's `para`
   crypto, because Lockly login is RSA-sealed to Lockly's own key).
3. operator <-> server: the management REST API + web UI.

---

## 1. Lock <-> server (MQTT device channel)

The lock connects to the broker it was given during Wi-Fi setup (0x99), at the
host/port from `getHeartbeatTime` (or locklyctl's `--mqtt-host/--mqtt-port`
override). The server is an MQTT broker (mochi-mqtt) plus a protocol handler.

- Topics (as the Lockly broker uses): the lock subscribes to `client/<clientId>`
  and publishes to `server`. The server publishes commands to
  `client/<clientId>` and receives on `server`.
- Message envelope (JSON):
  `{"header":{"namespace":"com.lockly","name":<type>,"requestId":<uuid>,"timestamp":<ms>},"payload":{...}}`
- Lock -> server: `deviceStateCallback`, `lockCommandResponse`,
  `lockEventLogQueryResponse`, `firmwareUpgradeProgress`, `firmwareUpgradeFailure`,
  `exception` (with a `code`, e.g. 3005).
- Server -> lock: `lockCommandRequest` (relay a BLE frame, `commandName:"forward"`),
  `firmwareUpgradeRequest`, `lockEventLogQueryRequest`.
- The BLE frames inside `lockCommandRequest` / `lockCommandResponse` are the AES
  frames from `internal/lockly` (same bytes locklyctl builds).
- TLS: configurable. Plaintext, or TLS with the server's own CA. Whether a given
  lock accepts a non-Lockly server certificate is UNVERIFIED hardware behaviour;
  do not claim it works until tried on a lock.

Lock MQTT credentials (username/password/clientId) are provisioned per lock and
stored server-side; the broker's auth hook validates them.

## 2. locklyctl <-> server REST (the `--server` mode)

Base URL = locklyctl's `--server <url>`. All requests are plain JSON over HTTPS.
Responses always carry `cod` as the string `"200"` on success, else an error
code string. Auth is a bearer token from `/login`, sent as
`Authorization: Bearer <token>` on every other call.

| Method & path | Request | Response |
| --- | --- | --- |
| `POST /api/login` | `{"email","password"}` | `{"cod":"200","token","email","uid"}` |
| `POST /api/refresh` | `{}` (bearer) | `{"cod":"200","token"}` |
| `POST /api/qrylknew` | `{}` | `{"cod":"200","arr":[<lock>]}` |
| `POST /api/getUserInfoAndDvList` | `{}` | `{"cod":"200","account":{...},"arr":[<lock>]}` |
| `POST /api/getHeartbeatTime` | `{"deviceId","model"}` | `{"cod":"200","mqttConfigs":{"host","port"},"heartbeat","clientId"}` |
| `POST /api/senddata` | `{"deviceId","cmd":"<ble-hex>"}` | `{"cod":"200","ack":"<ble-hex>"}` (relays over MQTT, waits for the lock's reply) |
| `POST /api/v1/proto/handler` | Lockly event-log envelope | the `lockEventLogQueryResponse` envelope |
| `POST /api/view/hidden` | `{"deviceId","hidden":bool}` | `{"cod":"200","deviceId","hidden"}` (extension: hide/show one of the account's locks in listings) |
| `POST /api/view/order` | `{"order":["<deviceId>",...]}` | `{"cod":"200","ok":true}` (extension: the listed locks take that order; unlisted ones keep theirs; an unknown deviceId is `901`) |

`<lock>` object keys (subset of Lockly `qrylknew`, enough for locklyctl):
`ID` (device id, lowercase hex), `mc` (master code), `blename`, `mod` (model),
`tz` (e.g. `+8:00`), `fwv`, `clientId`. `mc` is a secret; the server only
returns it to the lock's owner account over TLS. Two extensions that Lockly's
reply does not have: `hidden` (bool: leave the lock out of listings; commands,
including bulk ones, still reach it) and `sortIndex` (int: display order; `arr`
comes back sorted by it).

locklyctl behaviour in `--server` mode:
- Skip Lockly's `para` RSA/3DES encryption; send/receive plain JSON.
- Keep every existing feature working by swapping only the base URL + auth and
  routing remote BLE through `/api/senddata` instead of Lockly `senddata`/MQTT.

## 3. Operator <-> server (management API + web UI)

Base path `/admin/api`, bearer auth with an operator token (`POST
/admin/api/login` `{username,password}`). CRUD over:

- `accounts` (the logins locklyctl signs in as): create/list/delete, set password.
- `locks`: register `{ID, mc, blename, mod, tz, ownerAccountId}`, set MQTT creds,
  list (ordered by account, then `sortIndex`), show live state + recent events,
  delete; hide/unhide (`POST /admin/api/locks/{id}/hidden` `{hidden}`) and
  reorder within an account (`POST /admin/api/locks/order`
  `{accountId, order:[lockIds]}`, `204`; a lock from another account is `400`).
- `people`: a named person on a lock with a PIN and a schedule; create/list/update/delete.
  **`enabled` is a first-class field.** Disabling a person pushes a far-future
  validity window that excludes now (the lock rejects a past window with `E3`),
  not a 1-minute-a-day workaround; enabling re-pushes the real window. PIN
  changes re-push the 0x73 record.
- `events`: read the stored access-log per lock.

The web UI (`/`) is a small console over this API: accounts, locks (hide and
unhide, with a "Show hidden" toggle so a hidden lock can always be brought back,
and move up/down), people (with the enable/disable toggle), and a live state /
event view.

## Wi-Fi MQTT override (locklyctl `wifi`)

`locklyctl wifi LOCK --ssid ... --mqtt-host HOST --mqtt-port PORT` writes HOST/PORT
into the lock's 0x99 Wi-Fi-setup frame instead of the host/port from
`getHeartbeatTime`. This is how a lock is pointed at a private server. It works
against Lockly or `--server` alike; the heartbeat still comes from the server
(or a default) unless also overridden.
