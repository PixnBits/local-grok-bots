package coi

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const jailHomeName = "coi-home"

// jailProxySock is the only socket path bind-mounted into the Linux jail.
const jailProxySock = "/coi-proxy.sock"

// PlaceholderToken is the dummy bearer written into the jail. The host
// proxy replaces it and never forwards it.
const PlaceholderToken = "coi-placeholder-token"

// grokCompatOff turns off Grok's Claude, Cursor, and Codex compatibility
// scans so a workspace .mcp.json or sibling config is not loaded.
var grokCompatOff = []string{
	"GROK_CLAUDE_AGENTS_ENABLED", "GROK_CLAUDE_HOOKS_ENABLED", "GROK_CLAUDE_MCPS_ENABLED",
	"GROK_CLAUDE_RULES_ENABLED", "GROK_CLAUDE_SKILLS_ENABLED", "GROK_CLAUDE_SESSIONS_ENABLED",
	"GROK_CURSOR_AGENTS_ENABLED", "GROK_CURSOR_HOOKS_ENABLED", "GROK_CURSOR_MCPS_ENABLED",
	"GROK_CURSOR_RULES_ENABLED", "GROK_CURSOR_SKILLS_ENABLED", "GROK_CURSOR_SESSIONS_ENABLED",
	"GROK_CODEX_AGENTS_ENABLED", "GROK_CODEX_HOOKS_ENABLED", "GROK_CODEX_MCPS_ENABLED",
	"GROK_CODEX_RULES_ENABLED", "GROK_CODEX_SKILLS_ENABLED", "GROK_CODEX_SESSIONS_ENABLED",
	"GROK_MANAGED_MCPS_ENABLED",
}

// grokPlaceholder is a synthetic login file. It contains no value from the
// host credential file. Grok reads it; the proxy overwrites Authorization.
const grokPlaceholder = `{"https://auth.x.ai::00000000-0000-4000-8000-000000000001":{"key":"` + PlaceholderToken + `","auth_mode":"oidc","expires_at":"2099-01-01T00:00:00.000000000Z","refresh_token":"coi-placeholder-refresh","oidc_issuer":"https://auth.x.ai","oidc_client_id":"00000000-0000-4000-8000-000000000001"}}
`

type jailSpec struct {
	Bin        string
	Args       []string
	Workspace  string
	Env        []string
	Home       string
	SandboxBin string
	// Forwarder is the daemon binary. When set, the jail runs it as
	// --coi-forward and that process starts Bin.
	Forwarder  string
	ProxySock  string
	BaseEnvs   []string
	BasePrefix string
}

// HomesDir is the private parent for per-call jail homes.
func HomesDir(dataDir string) string {
	return filepath.Join(dataDir, "coi", "homes")
}

// CleanStaleHomes removes leftover coi-home-* directories under
// <data>/coi/homes. It does not scan the host temp directory.
func CleanStaleHomes(dataDir string) {
	if strings.TrimSpace(dataDir) == "" {
		return
	}
	removeStaleHomes(HomesDir(dataDir))
}

func removeStaleHomes(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, jailHomeName+"-") {
			continue
		}
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			continue
		}
		_ = os.RemoveAll(path)
	}
}

func prepareJailHome(stateDir string, tool policy.CLITool, copySecrets bool) (string, error) {
	parent, err := homesParent(stateDir)
	if err != nil {
		return "", err
	}
	home, err := os.MkdirTemp(parent, jailHomeName+"-")
	if err != nil {
		return "", ErrSandboxUnavailable
	}
	if err := os.Chmod(home, 0o700); err != nil {
		_ = os.RemoveAll(home)
		return "", ErrSandboxUnavailable
	}
	if copySecrets {
		if err := copyCredentialFiles(tool.CredentialHome, home, tool.CredentialFiles); err != nil {
			_ = os.RemoveAll(home)
			return "", err
		}
	} else if err := writePlaceholderFiles(home, tool); err != nil {
		_ = os.RemoveAll(home)
		return "", err
	}
	grokDir := filepath.Join(home, ".grok")
	if err := os.MkdirAll(grokDir, 0o700); err != nil {
		_ = os.RemoveAll(home)
		return "", ErrSandboxUnavailable
	}
	return home, nil
}

func homesParent(stateDir string) (string, error) {
	stateDir = filepath.Clean(strings.TrimSpace(stateDir))
	if stateDir == "" || stateDir == "." || !filepath.IsAbs(stateDir) {
		return "", ErrSandboxUnavailable
	}
	dir := HomesDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", ErrSandboxUnavailable
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", ErrSandboxUnavailable
	}
	return dir, nil
}

func copyCredentialFiles(credHome, destHome string, rels []string) error {
	credHome = filepath.Clean(credHome)
	destHome = filepath.Clean(destHome)
	for _, rel := range rels {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(rel))
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
			return fmt.Errorf("credential home is not available")
		}
		src := filepath.Join(credHome, filepath.FromSlash(clean))
		if !hasPathPrefix(credHome, src) {
			return fmt.Errorf("credential home is not available")
		}
		info, err := os.Lstat(src)
		if err != nil {
			return fmt.Errorf("credential home is not available")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(src)
			if err != nil || !hasPathPrefix(credHome, resolved) {
				return fmt.Errorf("credential home is not available")
			}
			st, err := os.Stat(resolved)
			if err != nil || !st.Mode().IsRegular() {
				return fmt.Errorf("credential home is not available")
			}
			src = resolved
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("credential home is not available")
		}
		dst := filepath.Join(destHome, filepath.FromSlash(clean))
		if !hasPathPrefix(destHome, dst) {
			return fmt.Errorf("credential home is not available")
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return fmt.Errorf("credential home is not available")
		}
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("credential home is not available")
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return fmt.Errorf("credential home is not available")
		}
	}
	return nil
}

func daemonArgs(tool policy.CLITool) []string {
	return append([]string{}, tool.FixedArgs...)
}

// jailEntry is the process bwrap or sandbox-exec starts. With a forwarder,
// that process is the daemon binary and Bin is exec'd after the listener is up.
// sock is the proxy socket path visible to that process.
func jailEntry(spec jailSpec, sock string) (entry string, args []string, extras []string) {
	if spec.Forwarder == "" {
		return spec.Bin, append([]string{}, spec.Args...), nil
	}
	if sock == "" {
		sock = jailProxySock
	}
	args = []string{"--coi-forward", "--sock", sock}
	for _, name := range spec.BaseEnvs {
		args = append(args, "--env", name)
	}
	if spec.BasePrefix != "" {
		args = append(args, "--prefix", spec.BasePrefix)
	}
	args = append(args, "--", spec.Bin)
	args = append(args, spec.Args...)
	return spec.Forwarder, args, []string{spec.Bin}
}

func writePlaceholderFiles(home string, tool policy.CLITool) error {
	rels := append([]string{}, tool.CredentialFiles...)
	if strings.EqualFold(tool.Name, "grok") {
		rels = append(rels, ".grok/auth.json")
	}
	seen := map[string]bool{}
	for _, rel := range rels {
		dst, err := destRel(home, rel)
		if err != nil {
			return err
		}
		if seen[dst] {
			continue
		}
		seen[dst] = true
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return ErrSandboxUnavailable
		}
		body := []byte(`{"token":"` + PlaceholderToken + `"}` + "\n")
		if strings.EqualFold(tool.Name, "grok") && filepath.Base(dst) == "auth.json" {
			body = []byte(grokPlaceholder)
		}
		if err := os.WriteFile(dst, body, 0o600); err != nil {
			return ErrSandboxUnavailable
		}
	}
	return nil
}

func destRel(destHome, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", fmt.Errorf("credential home is not available")
	}
	clean := filepath.ToSlash(filepath.Clean(rel))
	if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("credential home is not available")
	}
	dst := filepath.Join(destHome, filepath.FromSlash(clean))
	if !hasPathPrefix(destHome, dst) {
		return "", fmt.Errorf("credential home is not available")
	}
	return dst, nil
}

func applyFixedEnv(env, extra []string) []string {
	m := envMap(env)
	for _, kv := range extra {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || pinnedEnv(k) {
			continue
		}
		m[k] = v
	}
	return envList(m)
}

func pinJailEnv(env []string, home, name string) []string {
	m := envMap(env)
	m["HOME"] = home
	m["XDG_CONFIG_HOME"] = home
	m["XDG_DATA_HOME"] = home
	m["XDG_CACHE_HOME"] = home
	m["XDG_STATE_HOME"] = home
	m["PATH"] = systemPATH()
	m["TMPDIR"] = "/tmp"
	delete(m, "GROK_CONFIG")
	delete(m, "GROK_CONFIG_PATH")
	delete(m, "GROK_SANDBOX")
	delete(m, "LGB_TOKEN")
	delete(m, "LGB_SPOOL")
	delete(m, "AUTH_TOKEN")
	if name == "grok" {
		m["GROK_HOME"] = filepath.Join(home, ".grok")
		m["GROK_DISABLE_AUTOUPDATER"] = "1"
		for _, k := range grokCompatOff {
			m[k] = "false"
		}
	}
	return envList(m)
}

func pinnedEnv(k string) bool {
	switch k {
	case "HOME", "PATH", "TMPDIR", "GROK_HOME", "GROK_CONFIG", "GROK_CONFIG_PATH", "GROK_SANDBOX",
		"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME":
		return true
	}
	return strings.HasPrefix(k, "LGB_") || k == "AUTH_TOKEN"
}

// SandboxReady reports whether the inner CLI jail can start. A missing
// bwrap or sandbox-exec is a denial before the hourly slot is taken.
func SandboxReady(override string) error {
	_, err := sandboxBinary(override, defaultSandboxBin)
	return err
}

func sandboxBinary(override, fallback string) (string, error) {
	path := strings.TrimSpace(override)
	if path == "" {
		if filepath.IsAbs(fallback) {
			path = fallback
		} else {
			found, err := exec.LookPath(fallback)
			if err != nil {
				return "", ErrSandboxUnavailable
			}
			path = found
		}
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return "", ErrSandboxUnavailable
	}
	return path, nil
}

func resolvedFile(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", ErrSandboxUnavailable
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", ErrSandboxUnavailable
	}
	st, err := os.Stat(resolved)
	if err != nil || st.IsDir() {
		return "", ErrSandboxUnavailable
	}
	return resolved, nil
}
