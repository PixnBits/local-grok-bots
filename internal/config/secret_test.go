package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestScrubbedEnvironDropsSecrets(t *testing.T) {
	const token = "unit-auth-token-canary"
	env := []string{
		"PATH=/usr/bin",
		"DATA_DIR=/tmp/data",
		"BIND_ADDR=127.0.0.1:9",
		"AUTH_TOKEN=" + token,
		"AUTH_TOKENS_FILE=/tmp/lgb-tokens-file",
		"XAI_API_KEY=xai-secret",
		"LGB_CANARY_PROC=unit-canary-proc-value",
		"LEAK=" + token,
		"HOME=/tmp",
		"API_KEY=k",
		"TLS_KEY=/var/lib/lgb/tls.key",
		"SIGNING_KEY=k",
		"session_Token=t",
		"db_SECRET=s",
		"DB_PASS=p",
		"GPG_TTY=/dev/pts/1",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"LANG=C",
	}
	got := scrubbedEnviron(env, token)
	m := map[string]string{}
	for _, kv := range got {
		k, v, _ := cutKV(kv)
		m[k] = v
	}
	if m["PATH"] != "/usr/bin" || m["DATA_DIR"] != "/tmp/data" || m["BIND_ADDR"] != "127.0.0.1:9" || m["HOME"] != "/tmp" || m["GPG_TTY"] != "/dev/pts/1" || m["SSH_AUTH_SOCK"] != "/tmp/agent.sock" || m["LANG"] != "C" {
		t.Fatalf("kept %#v", m)
	}
	if m[readyKey] != readyVal {
		t.Fatalf("marker %#v", m)
	}
	for _, k := range []string{"AUTH_TOKEN", "AUTH_TOKENS_FILE", "XAI_API_KEY", "LGB_CANARY_PROC", "LEAK", "API_KEY", "TLS_KEY", "SIGNING_KEY", "session_Token", "db_SECRET", "DB_PASS"} {
		if _, ok := m[k]; ok {
			t.Fatalf("kept %s", k)
		}
	}
}

func TestTLSKeyHeldThroughScrub(t *testing.T) {
	prevKey := heldTLSKey
	t.Cleanup(func() { heldTLSKey = prevKey })
	heldTLSKey = ""

	const key = "/var/lib/lgb/tls.key"
	t.Setenv("TLS_KEY", key)
	t.Setenv("API_KEY", "sekrit")
	t.Setenv("SIGNING_KEY", "sekrit-2")
	t.Setenv("TLS_CERT", "/var/lib/lgb/tls.crt")

	holdTLSKey()
	env := os.Environ()
	got := scrubbedEnviron(env, "")
	m := map[string]string{}
	for _, kv := range got {
		k, v, _ := cutKV(kv)
		m[k] = v
	}
	for _, name := range []string{"TLS_KEY", "API_KEY", "SIGNING_KEY"} {
		if _, ok := m[name]; ok {
			t.Fatalf("scrub kept %s", name)
		}
	}
	if m["TLS_CERT"] != "/var/lib/lgb/tls.crt" {
		t.Fatalf("TLS_CERT %#v", m["TLS_CERT"])
	}
	unsetSecrets("")
	if os.Getenv("TLS_KEY") != "" || os.Getenv("API_KEY") != "" || os.Getenv("SIGNING_KEY") != "" {
		t.Fatal("scrubbed names still set")
	}
	cfg := FromEnv()
	if cfg.TLSKey != key {
		t.Fatalf("config TLS key %q", cfg.TLSKey)
	}
	if CurrentTLSKey() != key {
		t.Fatalf("current %q", CurrentTLSKey())
	}

	dir := t.TempDir()
	local := filepath.Join(dir, "local.toml")
	managed := filepath.Join(dir, "managed.toml")
	if err := os.WriteFile(local, []byte("[backend]\nbackend = \"ollama\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managed, []byte("[daemon]\ntls_cert = \"/managed/cert.pem\"\ntls_key = \"/managed/key.pem\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := policy.Load(policy.Options{
		Path:        local,
		ManagedPath: managed,
		EnvTLSCert:  "/env/cert.pem",
		EnvTLSKey:   cfg.TLSKey,
	})
	if err == nil || !strings.Contains(err.Error(), "TLS_KEY="+key) {
		t.Fatalf("conflict %v", err)
	}
}

func cutKV(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return kv, "", false
}
