package coi

import (
	"strings"
	"testing"
)

func TestScrubEnvDropsSecretsAndPointsHome(t *testing.T) {
	cred := t.TempDir()
	ws := t.TempDir()
	token := "lgbr_" + strings.Repeat("ab", 32)
	base := []string{
		"PATH=/usr/bin:/bin:" + ws + "/bin",
		"LANG=C",
		"LC_ALL=C",
		"HOME=/home/someone",
		"LGB_TOKEN=" + token,
		"LGB_SPOOL=" + ws + "/.lgb",
		"XAI_API_KEY=xai-supersecretvalue123456",
		"AUTH_TOKEN=admin-token-value",
		"FOO=bar",
		"TERM=xterm",
	}
	env, err := ScrubEnv(base, cred, ws)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
		if strings.Contains(v, token) || strings.Contains(v, "xai-supersecret") || strings.Contains(v, "admin-token") {
			t.Fatalf("secret leaked in %s", k)
		}
	}
	if got["HOME"] != cred || got["XDG_CONFIG_HOME"] != cred || got["XDG_DATA_HOME"] != cred || got["XDG_CACHE_HOME"] != cred {
		t.Fatalf("homes %+v", got)
	}
	if got["LANG"] != "C" || got["LC_ALL"] != "C" || got["TERM"] != "xterm" {
		t.Fatalf("allowlist dropped: %+v", got)
	}
	if strings.Contains(got["PATH"], ws) {
		t.Fatalf("workspace on PATH: %s", got["PATH"])
	}
	for _, banned := range []string{"LGB_TOKEN", "LGB_SPOOL", "XAI_API_KEY", "AUTH_TOKEN", "FOO"} {
		if _, ok := got[banned]; ok {
			t.Fatalf("%s was copied", banned)
		}
	}
	if got["HOME"] == "/home/someone" {
		t.Fatal("host home kept")
	}
}
