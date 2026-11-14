package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func acmeBase() Config {
	c := Default()
	c.MQTTTLSAddr = ":8883"
	c.ACME.Domains = []string{"lock.example.com"}
	c.ACME.AcceptTOS = true
	return c
}

func TestACMEValidate(t *testing.T) {
	c := acmeBase()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid ACME config rejected: %v", err)
	}

	bad := map[string]func(*Config){
		"no accept tos":  func(c *Config) { c.ACME.AcceptTOS = false },
		"no mqtt tls":    func(c *Config) { c.MQTTTLSAddr = "" },
		"https conflict": func(c *Config) { c.HTTPSCert = "x"; c.HTTPSKey = "y" },
	}
	for name, mut := range bad {
		c := acmeBase()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	// MQTT TLS with neither file certs nor ACME is still an error.
	c = Default()
	c.MQTTTLSAddr = ":8883"
	if err := c.Validate(); err == nil {
		t.Error("MQTT TLS without cert or ACME should fail")
	}

	// Empty HTTPAddr/CacheDir are filled with defaults.
	c = acmeBase()
	c.ACME.HTTPAddr = ""
	c.ACME.CacheDir = ""
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.ACME.HTTPAddr != ":80" || c.ACME.CacheDir == "" {
		t.Fatalf("ACME defaults not filled: %+v", c.ACME)
	}
}

func TestACMEManager(t *testing.T) {
	d := Default()
	if d.ACMEManager() != nil {
		t.Fatal("ACME disabled by default should give a nil manager")
	}
	c := acmeBase()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	m := c.ACMEManager()
	if m == nil {
		t.Fatal("expected a manager when ACME is enabled")
	}
	if err := m.HostPolicy(context.Background(), "lock.example.com"); err != nil {
		t.Errorf("listed host rejected: %v", err)
	}
	if err := m.HostPolicy(context.Background(), "evil.example.com"); err == nil {
		t.Error("unlisted host should be rejected")
	}
}

func TestACMEChallengeHandlerRedirects(t *testing.T) {
	c := acmeBase()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	h := c.ACMEManager().HTTPHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "http://lock.example.com/status", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("want 302 to https, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.HasPrefix(loc, "https://") {
		t.Fatalf("want an https redirect, got %q", loc)
	}
}

func TestDefaultValidates(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := map[string]func(*Config){
		"no http":          func(c *Config) { c.HTTPAddr = "" },
		"no mqtt":          func(c *Config) { c.MQTTAddr = ""; c.MQTTTLSAddr = "" },
		"tls without cert": func(c *Config) { c.MQTTTLSAddr = ":8883" },
		"half https":       func(c *Config) { c.HTTPSCert = "x" },
	}
	for name, mut := range cases {
		c := Default()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateFillsDefaults(t *testing.T) {
	c := Config{HTTPAddr: ":8080", MQTTAddr: ":1883"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.PublicMQTTPort != 1883 || c.HeartbeatSeconds != 300 {
		t.Fatalf("defaults not filled: %+v", c)
	}
}
