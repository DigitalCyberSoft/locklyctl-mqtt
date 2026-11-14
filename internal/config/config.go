// Package config holds the server's runtime configuration and its defaults.
package config

import (
	"crypto/tls"
	"fmt"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config is the server configuration.
type Config struct {
	// HTTP management + locklyctl-facing API.
	HTTPAddr  string // e.g. ":8080"
	HTTPSCert string // optional: serve the HTTP API over TLS
	HTTPSKey  string

	// MQTT broker the locks connect to.
	MQTTAddr    string // plaintext listener, e.g. ":1883" ("" to disable)
	MQTTTLSAddr string // TLS listener, e.g. ":8883" ("" to disable)
	MQTTCert    string // cert/key for the TLS listener
	MQTTKey     string

	// What getHeartbeatTime hands a lock: the broker it should connect to.
	PublicMQTTHost   string
	PublicMQTTPort   int
	HeartbeatSeconds int

	DBPath string

	// ACME (Let's Encrypt) automatic TLS. Enabled when ACME.Domains is set.
	ACME ACME
}

// ACME configures automatic TLS certificates from an ACME CA (Let's Encrypt by
// default). It is enabled when Domains is non-empty. When enabled, the MQTT TLS
// listener (and the HTTP API) serve the issued certificate, and an HTTP-01
// challenge responder runs on ACME.HTTPAddr.
type ACME struct {
	Domains      []string // cert domains; also the HostPolicy whitelist
	Email        string   // ACME account contact (optional)
	CacheDir     string   // directory the issued certs are cached in
	DirectoryURL string   // ACME directory URL; empty means Let's Encrypt production
	HTTPAddr     string   // listener for the HTTP-01 challenge, e.g. ":80"
	AcceptTOS    bool     // must be true to agree to the CA's terms of service
}

// Enabled reports whether ACME is configured.
func (a ACME) Enabled() bool { return len(a.Domains) > 0 }

// Default returns a config with sensible defaults.
func Default() Config {
	return Config{
		HTTPAddr:         ":8080",
		MQTTAddr:         ":1883",
		PublicMQTTPort:   1883,
		HeartbeatSeconds: 300,
		DBPath:           "locklyctl-mqtt.db",
		ACME:             ACME{HTTPAddr: ":80", CacheDir: "acme-cache"},
	}
}

// Validate checks the config and fills dependent defaults.
func (c *Config) Validate() error {
	if c.HTTPAddr == "" {
		return fmt.Errorf("HTTPAddr is required")
	}
	if c.MQTTAddr == "" && c.MQTTTLSAddr == "" {
		return fmt.Errorf("at least one of MQTTAddr or MQTTTLSAddr is required")
	}
	if c.MQTTTLSAddr != "" && !c.ACME.Enabled() && (c.MQTTCert == "" || c.MQTTKey == "") {
		return fmt.Errorf("MQTTTLSAddr needs MQTTCert and MQTTKey (or ACME)")
	}
	if c.ACME.Enabled() {
		if !c.ACME.AcceptTOS {
			return fmt.Errorf("ACME needs AcceptTOS to agree to the CA terms of service")
		}
		if c.MQTTTLSAddr == "" {
			return fmt.Errorf("ACME needs MQTTTLSAddr: the TLS listener the locks connect to")
		}
		if c.HTTPSCert != "" {
			return fmt.Errorf("ACME and HTTPSCert are mutually exclusive")
		}
		if c.ACME.HTTPAddr == "" {
			c.ACME.HTTPAddr = ":80"
		}
		if c.ACME.CacheDir == "" {
			c.ACME.CacheDir = "acme-cache"
		}
	}
	if (c.HTTPSCert == "") != (c.HTTPSKey == "") {
		return fmt.Errorf("HTTPSCert and HTTPSKey must be set together")
	}
	if c.PublicMQTTPort == 0 {
		c.PublicMQTTPort = 1883
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 300
	}
	return nil
}

// MQTTTLSConfig loads the TLS config for the MQTT TLS listener, or nil if none.
func (c *Config) MQTTTLSConfig() (*tls.Config, error) {
	if c.MQTTTLSAddr == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.MQTTCert, c.MQTTKey)
	if err != nil {
		return nil, fmt.Errorf("mqtt tls: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// ACMEManager builds the autocert manager, or nil when ACME is disabled.
// Validate requires AcceptTOS before enabling ACME, so the manager's prompt
// always agrees to the CA's terms.
func (c *Config) ACMEManager() *autocert.Manager {
	if !c.ACME.Enabled() {
		return nil
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(c.ACME.CacheDir),
		HostPolicy: autocert.HostWhitelist(c.ACME.Domains...),
		Email:      c.ACME.Email,
	}
	if c.ACME.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: c.ACME.DirectoryURL}
	}
	return m
}
