package coi

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/audit"
)

// passEnv is copied from the daemon environment. Credentials are not on it.
var passEnv = map[string]bool{
	"PATH": true, "LANG": true, "TERM": true, "TZ": true,
	"USER": true, "LOGNAME": true, "SHELL": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
}

// ScrubEnv returns the allowlisted environment for a host CLI.
// PATH is pinned to system directories. HOME is not set here; the jail
// points it at a private copy of credential_files. LGB_TOKEN and any
// variable that is not allowlisted, or that carries a token, is dropped.
func ScrubEnv(base []string, credHome, workspace string) ([]string, error) {
	credHome = filepath.Clean(credHome)
	env := map[string]string{}
	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !keepEnv(k) || k == "PATH" || k == "HOME" || k == "TMPDIR" {
			continue
		}
		if strings.HasPrefix(k, "XDG_") || strings.HasPrefix(k, "GROK_") {
			continue
		}
		if audit.RedactText(v) != v || strings.Contains(v, "lgbr_") {
			continue
		}
		env[k] = v
	}
	env["PATH"] = systemPATH()
	delete(env, "LGB_TOKEN")
	delete(env, "LGB_SPOOL")
	delete(env, "LGB_SESSION_MARKER")
	delete(env, "AUTH_TOKEN")
	delete(env, "AUTH_TOKENS_FILE")
	_ = credHome
	_ = workspace
	return envList(env), nil
}

func systemPATH() string {
	candidates := []string{
		"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
	}
	var dirs []string
	for _, d := range candidates {
		st, err := os.Stat(d)
		if err != nil || !st.IsDir() {
			continue
		}
		dirs = append(dirs, d)
	}
	if len(dirs) == 0 {
		return "/usr/bin" + string(os.PathListSeparator) + "/bin"
	}
	return strings.Join(dirs, string(os.PathListSeparator))
}

func envList(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out
}

func envMap(list []string) map[string]string {
	env := map[string]string{}
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			env[k] = v
		}
	}
	return env
}

func keepEnv(k string) bool {
	if strings.HasPrefix(k, "LGB_") || k == "AUTH_TOKEN" || k == "AUTH_TOKENS_FILE" {
		return false
	}
	upper := strings.ToUpper(k)
	for _, p := range []string{"KEY", "TOKEN", "SECRET", "PASS", "CREDENTIAL", "COOKIE", "AUTH"} {
		if strings.Contains(upper, p) {
			return false
		}
	}
	if passEnv[k] || strings.HasPrefix(k, "LC_") {
		return true
	}
	return false
}
