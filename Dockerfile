# Build a static binary (modernc SQLite is pure Go, so CGO is off).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/locklyctl-mqtt ./cmd/locklyctl-mqtt

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /data
COPY --from=build /out/locklyctl-mqtt /usr/local/bin/locklyctl-mqtt
# HTTP API + console, and the plaintext MQTT broker.
EXPOSE 8080 1883
ENTRYPOINT ["locklyctl-mqtt"]
CMD ["serve", "-db", "/data/locklyctl-mqtt.db"]
