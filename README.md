# locklyctl-mqtt

A self-hosted MQTT server and management backend for Lockly Wi-Fi locks, built
to pair with [locklyctl](https://github.com/DigitalCyberSoft/locklyctl). It lets
a lock connect to **your** broker instead of Lockly's cloud, stores the people,
PINs and schedules for each lock, and re-pushes them over the Lockly device
channel.

Status: early. The protocol primitives are ported from locklyctl and pinned by
test vectors. Whether a given lock will accept a non-Lockly server certificate
over TLS is unverified hardware behaviour (see `CONTRACT.md`); prove it on a
spare lock before relying on it.

## Layout

- `internal/lockly` - Lockly BLE frame crypto and builders (vector-tested against locklyctl).
- `internal/store` - SQLite persistence: accounts, locks, people, events.
- `internal/device` - MQTT broker and the Lockly device-channel protocol.
- `internal/api` - REST: the locklyctl-facing API and the management API.
- `internal/web` - the management web console.
- `cmd/locklyctl-mqtt` - the `serve` and admin CLI.

See `CONTRACT.md` for the wire protocol between locklyctl, this server, and locks.

## Build and test

    go build ./...
    go test ./...
