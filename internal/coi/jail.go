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

const grokSandboxTOML = `# Written by local-grok-bots for each COI call. Do not edit.
[profiles.lgb]
extends = "strict"
restrict_network = false
deny = []
`

type jailSpec struct {
	Bin        string
	Args       []string
	Workspace  string
	Env        []string
	Home       string
	SandboxBin string
}

func prepareJailHome(tool policy.CLITool) (string, error) {
	home, err := os.MkdirTemp("", jailHomeName+"-")
	if err != nil {
		return "", ErrSandboxUnavailable
	}
	if err := os.Chmod(home, 0o700); err != nil {
		_ = os.RemoveAll(home)
		return "", ErrSandboxUnavailable
	}
	if err := copyCredentialFiles(tool.CredentialHome, home, tool.CredentialFiles); err != nil {
		_ = os.RemoveAll(home)
		return "", err
	}
	grokDir := filepath.Join(home, ".grok")
	if err := os.MkdirAll(grokDir, 0o700); err != nil {
		_ = os.RemoveAll(home)
		return "", ErrSandboxUnavailable
	}
	if err := os.WriteFile(filepath.Join(grokDir, "sandbox.toml"), []byte(grokSandboxTOML), 0o600); err != nil {
		_ = os.RemoveAll(home)
		return "", ErrSandboxUnavailable
	}
	return home, nil
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
	out := append([]string{}, tool.FixedArgs...)
	if tool.Name == "grok" && !flagPresent(out, "--sandbox") {
		out = append([]string{"--sandbox", "lgb"}, out...)
	}
	return out
}

func flagPresent(args []string, name string) bool {
	name = strings.ToLower(name)
	for _, a := range args {
		n, _, _ := strings.Cut(a, "=")
		if strings.ToLower(n) == name {
			return true
		}
	}
	return false
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
