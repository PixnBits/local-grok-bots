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
		"AUTH_TOKENS_FILE=/tmp/lgb-tokens-file",
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
	if _, ok := got["HOME"]; ok {
		t.Fatalf("HOME set before jail: %+v", got)
	}
	if got["LANG"] != "C" || got["LC_ALL"] != "C" || got["TERM"] != "xterm" {
		t.Fatalf("allowlist dropped: %+v", got)
	}
	if strings.Contains(got["PATH"], ws) || strings.Contains(got["PATH"], cred) {
		t.Fatalf("workspace or cred on PATH: %s", got["PATH"])
	}
	if got["PATH"] != systemPATH() {
		t.Fatalf("PATH %q want %q", got["PATH"], systemPATH())
	}
	for _, banned := range []string{"LGB_TOKEN", "LGB_SPOOL", "XAI_API_KEY", "AUTH_TOKEN", "AUTH_TOKENS_FILE", "FOO", "HOME", "TMPDIR"} {
		if _, ok := got[banned]; ok {
			t.Fatalf("%s was copied", banned)
		}
	}
}

func TestJailEnvDropsAuthTokensFile(t *testing.T) {
	env := pinJailEnv([]string{
		"PATH=/bin",
		"AUTH_TOKEN=admin-token-value",
		"AUTH_TOKENS_FILE=/tmp/lgb-tokens-file",
		"LANG=C",
	}, "/home/x", "grok")
	env = applyFixedEnv(env, []string{"AUTH_TOKENS_FILE=/tmp/other", "AUTH_TOKEN=other", "LANG=C.UTF-8"})
	for _, kv := range env {
		if strings.HasPrefix(kv, "AUTH_TOKEN=") || strings.HasPrefix(kv, "AUTH_TOKENS_FILE=") {
			t.Fatalf("kept %s", kv)
		}
	}
}
