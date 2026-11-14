package config

import "testing"

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
