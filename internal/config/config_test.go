package config

import (
	"strings"
	"testing"
)

func TestAuthTokensFileFromEnv(t *testing.T) {
	t.Setenv("AUTH_TOKENS_FILE", "")
	if FromEnv().AuthTokensFile != "" {
		t.Fatal("default path")
	}
	t.Setenv("AUTH_TOKENS_FILE", "/tmp/lgb-tokens-file")
	if FromEnv().AuthTokensFile != "/tmp/lgb-tokens-file" {
		t.Fatalf("path %q", FromEnv().AuthTokensFile)
	}
}

func TestBindAddrDefault(t *testing.T) {
	t.Setenv("BIND_ADDR", "")
	if got := FromEnv().BindAddr; got != "127.0.0.1:8080" {
		t.Fatalf("default %s", got)
	}
	t.Setenv("BIND_ADDR", "0.0.0.0:8080")
	if got := FromEnv().BindAddr; got != "0.0.0.0:8080" {
		t.Fatalf("override %s", got)
	}
}

func TestNumCtxBound(t *testing.T) {
	t.Setenv("OLLAMA_THINK", "")
	t.Setenv("OLLAMA_NUM_CTX", "1048577")
	if err := FromEnv().ModelEnvError(); err == nil || !strings.Contains(err.Error(), "1048576") {
		t.Fatalf("OLLAMA_NUM_CTX 1048577: %v", err)
	}
	t.Setenv("OLLAMA_NUM_CTX", "1048576")
	cfg := FromEnv()
	if err := cfg.ModelEnvError(); err != nil || cfg.NumCtx != 1048576 {
		t.Fatalf("OLLAMA_NUM_CTX 1048576: %d %v", cfg.NumCtx, err)
	}

	if _, err := ApplyModelArgs(Config{}, []string{"--num-ctx", "1048577"}); err == nil || !strings.Contains(err.Error(), "1048576") {
		t.Fatalf("--num-ctx 1048577: %v", err)
	}
	if _, err := ApplyModelArgs(Config{}, []string{"--num-ctx=1048577"}); err == nil {
		t.Fatal("--num-ctx=1048577 accepted")
	}
	got, err := ApplyModelArgs(Config{}, []string{"--num-ctx", "1048576"})
	if err != nil || got.NumCtx != 1048576 {
		t.Fatalf("--num-ctx 1048576: %d %v", got.NumCtx, err)
	}
	got, err = ApplyModelArgs(Config{}, []string{"--num-ctx=1048576"})
	if err != nil || got.NumCtx != 1048576 {
		t.Fatalf("--num-ctx=1048576: %d %v", got.NumCtx, err)
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
