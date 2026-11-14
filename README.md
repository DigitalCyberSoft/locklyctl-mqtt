# locklyctl-mqtt

A self-hosted MQTT server and management backend for Lockly Wi-Fi locks, built
to pair with [locklyctl](https://github.com/DigitalCyberSoft/locklyctl). It is
the broker a lock connects to instead of Lockly's cloud, it stores the people,
PINs and schedules for each lock, and it re-pushes them over the Lockly device
channel. locklyctl points at it with `--server`.

> **Status: early.** The protocol primitives are ported from locklyctl and
> pinned by test vectors, and the HTTP/MQTT wiring is tested. **Whether a given
> lock will accept a non-Lockly broker over TLS is unverified hardware
> behaviour** (the Wi-Fi module stores its CA separately and may require a
> Lockly-signed server cert). Prove it on a spare lock before relying on it. See
> `CONTRACT.md`.

## What it does

- **MQTT broker** the locks connect to (plaintext and/or TLS), speaking the
  Lockly device channel (`lockCommandRequest`/`Response`, `deviceStateCallback`,
  event log).
- **locklyctl-facing REST API** that mirrors the Lockly endpoints locklyctl
  calls, so `locklyctl --server https://you login` is a base-URL swap.
- **Management API + web console** to create logins (the accounts locklyctl
  signs in as), register locks, and manage people: PINs, schedules, and a
  first-class **enable/disable** that suspends a person by pushing an expired
  window (credential-preserving), not by deleting them.

## Layout

| Path | What |
| --- | --- |
| `internal/lockly` | Lockly BLE frame crypto and builders, vector-tested against locklyctl |
| `internal/store` | SQLite persistence: accounts, locks, people, events |
| `internal/device` | MQTT broker and the device-channel protocol |
| `internal/api` | the locklyctl-facing and management REST APIs |
| `internal/web` | the management web console (embedded) |
| `internal/server` | wiring |
| `cmd/locklyctl-mqtt` | the `serve` and admin CLI |

## Build, test, run

```console
$ go build ./...
$ go test ./...
$ ./locklyctl-mqtt serve -public-mqtt-host your.host.example -public-mqtt-port 1883
```

Bootstrap (before the console is useful):

```console
$ ./locklyctl-mqtt create-operator -username admin -password '...'    # web console login
$ ./locklyctl-mqtt create-account  -email you@example.com -password '...'   # locklyctl signs in as this
$ ./locklyctl-mqtt add-lock -device-id <hex> -mc <code> -owner <accountId> \
      -model PGK728WRHK -mqtt-client-id <id> -mqtt-username <u> -mqtt-password <p>
```

Then open `http://host:8080/` for the console, and point locklyctl at it:

```console
$ locklyctl --server http://host:8080 login
$ locklyctl wifi <LOCK> --ssid <net> --mqtt-host your.host.example --mqtt-port 1883
```

The last command writes your broker into the lock during Wi-Fi setup.

### Docker

```console
$ docker build -t locklyctl-mqtt .
$ docker run -p 8080:8080 -p 1883:1883 -v $PWD/data:/data locklyctl-mqtt \
      serve -db /data/locklyctl-mqtt.db -public-mqtt-host your.host.example
```

## serve flags

`-http` (`:8080`), `-https-cert`/`-https-key`, `-mqtt` (`:1883`), `-mqtt-tls`
(`:8883`) with `-mqtt-cert`/`-mqtt-key`, `-public-mqtt-host`,
`-public-mqtt-port`, `-heartbeat` (seconds), `-db`. For automatic TLS:
`-acme-domains`, `-acme-email`, `-acme-accept-tos`, `-acme-http`, `-acme-cache`,
`-acme-directory` (see below).

`-public-mqtt-host`/`-public-mqtt-port` are what the server hands a lock through
`getHeartbeatTime`: the broker address the lock should connect to.

### Let's Encrypt (automatic TLS)

Instead of supplying cert files, let the server obtain and renew a certificate
from Let's Encrypt (any ACME CA):

```
locklyctl-mqtt serve \
  -mqtt-tls :8883 \
  -acme-domains lock.example.com \
  -acme-email you@example.com \
  -acme-accept-tos
```

The ACME HTTP-01 challenge is answered on `-acme-http` (`:80` by default), which
must be reachable from the internet at each `-acme-domains` name. The issued
certificate serves the MQTT TLS listener and the HTTP API (so `-https-cert` and
`-acme-domains` are mutually exclusive). Certs are cached in `-acme-cache`
(`acme-cache/`). Point `-acme-directory` at a staging URL while testing to avoid
the production rate limit. Whether a given lock trusts a Let's Encrypt chain over
TLS is still unverified on hardware (see the note at the top).

## Security notes

- A lock's master code plus its device id are its AES key. The store holds them;
  nothing logs them. Serve the APIs over TLS in production (`-https-cert`).
- Account passwords are verified as bcrypt over the SHA-256 that locklyctl sends
  (it mirrors Lockly), so set an account password through the management API and
  sign in with the same password from locklyctl.

See `CONTRACT.md` for the wire protocol between locklyctl, this server and locks,
and `NOTICE` for attribution (the crypto is ported from locklyctl / LocklyHA).
