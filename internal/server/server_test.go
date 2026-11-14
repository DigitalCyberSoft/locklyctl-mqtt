package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/config"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
)

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestServerBootAndServe(t *testing.T) {
	cfg := config.Default()
	cfg.HTTPAddr = freePort(t)
	cfg.MQTTAddr = freePort(t)
	cfg.DBPath = filepath.Join(t.TempDir(), "s.db")
	cfg.PublicMQTTHost = "mqtt.example.test"

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	// bootstrap an operator
	h, _ := store.HashPassword("pw")
	if _, err := srv.Store().CreateOperator("admin", h); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	base := "http://" + cfg.HTTPAddr
	waitUp(t, base+"/")

	// the console is served at /
	res, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "locklyctl-mqtt") {
		t.Fatalf("console: status=%d", res.StatusCode)
	}

	// the admin API is reachable
	loginRes, err := http.Post(base+"/admin/api/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"pw"}`))
	if err != nil {
		t.Fatal(err)
	}
	loginRes.Body.Close()
	if loginRes.StatusCode != 200 {
		t.Fatalf("admin login status=%d", loginRes.StatusCode)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func waitUp(t *testing.T, url string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		if res, err := http.Get(url); err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server never came up")
}
