// Package server wires the store, the MQTT device hub and the HTTP API +
// console into one runnable server.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/api"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/config"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/device"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/store"
	"github.com/DigitalCyberSoft/locklyctl-mqtt/internal/web"
	"golang.org/x/crypto/acme/autocert"
)

// Server is the assembled service.
type Server struct {
	cfg  config.Config
	log  *slog.Logger
	st   *store.Store
	hub  *device.Hub
	http *http.Server
	acme *autocert.Manager
}

// New opens the store and assembles the server. Call Close when done.
func New(cfg config.Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	hub := device.New(st, log)
	a := api.New(st, hub, api.Config{
		MQTTHost: cfg.PublicMQTTHost, MQTTPort: cfg.PublicMQTTPort, HeartbeatSeconds: cfg.HeartbeatSeconds,
	}, log)

	mux := http.NewServeMux()
	a.Routes(mux)
	mux.Handle("/", web.Handler())

	return &Server{
		cfg: cfg, log: log, st: st, hub: hub,
		http: &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		acme: cfg.ACMEManager(),
	}, nil
}

// Store exposes the store for admin bootstrap.
func (s *Server) Store() *store.Store { return s.st }

// Close closes the store.
func (s *Server) Close() error { return s.st.Close() }

// Run starts the broker and HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.cfg.MQTTAddr != "" {
		if err := s.hub.Listen(device.ListenConfig{ID: "tcp", Addr: s.cfg.MQTTAddr}); err != nil {
			return err
		}
		s.log.Info("mqtt broker listening", "addr", s.cfg.MQTTAddr, "tls", false)
	}
	if s.cfg.MQTTTLSAddr != "" {
		var tlsCfg *tls.Config
		if s.acme != nil {
			tlsCfg = &tls.Config{GetCertificate: s.acme.GetCertificate, MinVersion: tls.VersionTLS12}
		} else {
			var err error
			tlsCfg, err = s.cfg.MQTTTLSConfig()
			if err != nil {
				return err
			}
		}
		if err := s.hub.Listen(device.ListenConfig{ID: "tls", Addr: s.cfg.MQTTTLSAddr, TLS: tlsCfg}); err != nil {
			return err
		}
		s.log.Info("mqtt broker listening", "addr", s.cfg.MQTTTLSAddr, "tls", true, "acme", s.acme != nil)
	}
	if err := s.hub.Start(); err != nil {
		return err
	}
	defer s.hub.Stop()

	errCh := make(chan error, 1)

	// ACME HTTP-01 challenge responder (and plain-HTTP to HTTPS redirect).
	var challenge *http.Server
	if s.acme != nil {
		challenge = &http.Server{
			Addr:              s.cfg.ACME.HTTPAddr,
			Handler:           s.acme.HTTPHandler(nil),
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			s.log.Info("acme http-01 challenge listening", "addr", s.cfg.ACME.HTTPAddr)
			if err := challenge.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		s.http.TLSConfig = s.acme.TLSConfig()
	}

	go func() {
		tlsOn := s.acme != nil || s.cfg.HTTPSCert != ""
		s.log.Info("http listening", "addr", s.cfg.HTTPAddr, "tls", tlsOn, "acme", s.acme != nil)
		var err error
		switch {
		case s.acme != nil:
			err = s.http.ListenAndServeTLS("", "")
		case s.cfg.HTTPSCert != "":
			err = s.http.ListenAndServeTLS(s.cfg.HTTPSCert, s.cfg.HTTPSKey)
		default:
			err = s.http.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if challenge != nil {
			_ = challenge.Shutdown(shutCtx)
		}
		return s.http.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
