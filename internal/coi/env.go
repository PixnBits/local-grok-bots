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

// ScrubEnv returns the environment for a host CLI.
// HOME and the XDG home variables point at credHome. LGB_TOKEN and any
// variable that is not allowlisted, or that carries a token, is dropped.
func ScrubEnv(base []string, credHome, workspace string) ([]string, error) {
	credHome = filepath.Clean(credHome)
	env := map[string]string{}
	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !keepEnv(k) {
			continue
		}
		if audit.RedactText(v) != v || strings.Contains(v, "lgbr_") {
			continue
		}
		if k == "PATH" {
			v = scrubPath(v, workspace, credHome)
		}
		env[k] = v
	}
	if env["PATH"] == "" {
		env["PATH"] = "/usr/bin" + string(os.PathListSeparator) + "/bin"
	}
	tmp, err := tempDir(workspace, credHome)
	if err != nil {
		return nil, err
	}
	env["HOME"] = credHome
	env["XDG_CONFIG_HOME"] = credHome
	env["XDG_DATA_HOME"] = credHome
	env["XDG_CACHE_HOME"] = credHome
	env["XDG_STATE_HOME"] = credHome
	env["TMPDIR"] = tmp
	delete(env, "LGB_TOKEN")
	delete(env, "LGB_SPOOL")
	delete(env, "LGB_SESSION_MARKER")
	delete(env, "AUTH_TOKEN")
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+env[k])
	}
	return out, nil
}

func keepEnv(k string) bool {
	if strings.HasPrefix(k, "LGB_") || k == "AUTH_TOKEN" {
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

func scrubPath(path, workspace, credHome string) string {
	var keep []string
	for _, p := range filepath.SplitList(path) {
		if p == "" {
			continue
		}
		clean := filepath.Clean(p)
		if workspace != "" && Overlaps(workspace, clean) {
			continue
		}
		if credHome != "" && Overlaps(credHome, clean) {
			continue
		}
		keep = append(keep, p)
	}
	if len(keep) == 0 {
		return "/usr/bin" + string(os.PathListSeparator) + "/bin"
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

func tempDir(workspace, credHome string) (string, error) {
	t := filepath.Clean(os.TempDir())
	if filepath.IsAbs(t) && !Overlaps(workspace, t) && !Overlaps(credHome, t) {
		return t, nil
	}
	p := filepath.Join(credHome, "tmp")
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}
