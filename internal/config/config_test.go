package config

import (
	"testing"
)

func TestDefaultBindIsLoopback(t *testing.T) {
	t.Setenv("BIND_ADDR", "")
	t.Setenv("AUTH_TOKEN", "")
	c := FromEnv()
	if c.BindAddr != "127.0.0.1:8080" {
		t.Fatalf("bind %s", c.BindAddr)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPublicBindRequiresToken(t *testing.T) {
	open := []string{"0.0.0.0:8080", "[::]:8080", ":8080", "192.168.1.10:8080"}
	for _, addr := range open {
		c := Config{BindAddr: addr}
		if err := c.Validate(); err == nil {
			t.Fatalf("%s accepted without a token", addr)
		}
		c.AuthToken = "secret"
		if err := c.Validate(); err != nil {
			t.Fatalf("%s with token: %v", addr, err)
		}
	}
	for _, addr := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if err := (Config{BindAddr: addr}).Validate(); err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if err := (Config{BindAddr: "not-an-addr"}).Validate(); err == nil {
		t.Fatal("accepted a bind address without a port")
	}
}

func TestBuildBindsFromEnv(t *testing.T) {
	t.Setenv("SANDBOX_BUILD_BINDS", " /opt/a : /opt/b ")
	c := FromEnv()
	if len(c.BuildBinds) != 2 || c.BuildBinds[0] != "/opt/a" || c.BuildBinds[1] != "/opt/b" {
		t.Fatalf("binds %#v", c.BuildBinds)
	}
	t.Setenv("SANDBOX_BUILD_BINDS", "")
	if FromEnv().BuildBinds != nil {
		t.Fatalf("empty binds %#v", FromEnv().BuildBinds)
	}
}
