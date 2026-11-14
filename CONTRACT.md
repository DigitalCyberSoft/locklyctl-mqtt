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
stored server-side. The broker accepts a connection only when all three match one
lock's record and no other lock claims that username or client id; a client id
holding an MQTT wildcard (`+`, `#`) is refused. A connected lock may subscribe
only to `client/<its clientId>` and publish only to `server`; its
`deviceStateCallback` and access-log events count only for its own device id
(command replies are matched by `requestId`). A lock is online from when its
session is established until that connection, not an older one it took over,
disconnects.

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
| `POST /api/backup/export` | `{}` | `{"cod":"200","backup":<plain backup, section 4>}` (extension) |
| `POST /api/backup/import` | `{"backup":<plain backup>,"replace":bool}` | `{"cod":"200","locksAdded","locksUpdated","locksRemoved","peopleAdded","peopleUpdated","peopleRemoved","conflicts":["<deviceId>",...]}`; `909` for an invalid or sealed backup (extension, section 4) |

`<lock>` object keys (subset of Lockly `qrylknew`, enough for locklyctl):
`ID` (device id, lowercase hex), `na` (the door's name; `""` when unset, then
locklyctl shows `blename`), `mc` (master code), `blename`, `mod` (model),
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
- `locks`: register `{ID, mc, name, blename, mod, tz, ownerAccountId}`, set MQTT creds,
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

## 4. Backups: moving between Lockly, servers and locklyctl

One JSON document, read and written the same way by locklyctl (`backup` /
`restore`) and this server (`export` / `import`, `/api/backup/*`). The Go
reference is `internal/backup`; locklyctl's is `locklyctl/backup.py`.

```json
{
  "format": "locklyctl-backup", "version": 1,
  "createdAt": "2026-11-14T12:00:00Z",
  "source": {"kind": "lockly", "account": "owner@example.test"},
  "locks": [{
    "deviceId": "<24 lowercase hex>", "mc": "<master code>", "name": "Front",
    "bleName": "PGK728WRHK...", "model": "PGK728WRHK", "tz": "+8:00", "fwv": "...",
    "hidden": false, "sortIndex": 1,
    "mqtt": {"clientId": "...", "username": "...", "password": "..."},
    "people": [{
      "name": "Weekday guest", "pwdId": 3, "userId": 9, "adminId": 0, "pin": "246800",
      "userType": 66, "date": "1F090011000000000000",
      "dateMode": "weekly", "weekMask": 31, "multiVerify": 1, "enabled": true
    }]
  }]
}
```

- `source.kind` is `"lockly"` or `"locklyctl-mqtt"`. It holds master codes,
  PINs and MQTT passwords. `mqtt` only comes from a server (Lockly doesn't hand
  those out).
- A person is what a 0x73 record pushes. `date` is the exact 10-byte 0x73 date
  (20 hex digits) when known, e.g. read from the lock; it wins over `dateMode`
  (`permanent` / `period` / `weekly`), `startAt` / `endAt` (epoch seconds) and
  `weekMask` (bit 0 = Monday), which then only describe it. Without `date` a
  weekly window can only be all-day. A missing `enabled` means enabled.
- Fingerprints and faces stay on the lock: a backup carries the record, and
  re-pushing a 0x73 record keeps them (proven on a Visage).

**Sealed** (the default; plain only on request):

```json
{"format": "locklyctl-backup", "version": 1, "encrypted": {
  "kdf": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<base64, 16 bytes>",
  "cipher": "aes-256-ctr+hmac-sha256", "iv": "<base64, 16 bytes>",
  "mac": "<base64, 32 bytes>", "data": "<base64>"}}
```

- `dk = scrypt(passphrase as UTF-8, salt, n, r, p, 64 bytes)`; the AES key is
  `dk[0:32]`, the HMAC key `dk[32:64]`.
- `data` = AES-256-CTR over the plain document's JSON, the counter block
  starting at `iv` and counting up as a 128-bit big-endian number.
- `mac` = HMAC-SHA256 over `"locklyctl-backup/1"`, a 0x00 byte, `n`, `r`, `p`
  as 4-byte big-endian, then `salt`, `iv`, `data`. It is checked (in constant
  time) before anything is decrypted, so a wrong passphrase and a changed file
  look the same. Readers refuse `n` that isn't a power of two from 2^10 to
  2^20, `r` outside 1..32 and `p` outside 1..16, before any key work.
- AES-CTR + HMAC rather than AES-GCM: locklyctl's pure-Python crypto (used
  where pycryptodome isn't) has the AES block cipher but no GCM.
- The passphrase never reaches a server: locklyctl seals and opens, and
  `/api/backup/import` refuses a sealed document.

**Import** (one transaction: all of it or nothing):

- Merge (default): a lock is matched by device id; new ones are added, ones
  the account has are updated, and so are their people, matched by user id
  (user id 0: by slot and name). Anything the backup doesn't mention is kept.
- Replace (`replace` / `-replace`): the account ends up with exactly the
  backup's locks and people; its other locks are deleted, with their people.
- A device id another account on the server owns is never touched, in either
  mode: it is reported in `conflicts`. A lock that arrives without `mqtt`
  keeps its credentials.
- Nothing is sent to any lock: the locks already hold these records; the
  server pushes a person when they are next changed.

Server CLI: `locklyctl-mqtt export -account EMAIL -out FILE [-no-encrypt]
[-passphrase-file F]` (never overwrites a file; owner-only) and
`locklyctl-mqtt import -account EMAIL -in FILE [-replace [-yes]]
[-passphrase-file F]` (exits non-zero if a lock was skipped as another
account's).

## Wi-Fi MQTT override (locklyctl `wifi`)

`locklyctl wifi LOCK --ssid ... --mqtt-host HOST --mqtt-port PORT` writes HOST/PORT
into the lock's 0x99 Wi-Fi-setup frame instead of the host/port from
`getHeartbeatTime`. This is how a lock is pointed at a private server. It works
against Lockly or `--server` alike; the heartbeat still comes from the server
(or a default) unless also overridden.
