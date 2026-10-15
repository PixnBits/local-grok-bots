package clisession

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Isolation is the daemon-owned CLI configuration for one turn.
// When a Spec carries one, the CLI gets only Env (nothing is inherited) and
// Claude is told to load no user, project, or local settings and no MCP
// servers beyond the daemon's own.
type Isolation struct {
	// Home is the per-bot HOME. Empty means the daemon user's HOME is kept.
	Home string
	// SettingsPath is the daemon-written Claude --settings file.
	SettingsPath string
	// Env is the full child environment.
	Env []string
	// GrokSandbox is the --sandbox profile for Grok.
	GrokSandbox string
	// GrokDisallow are built-in Grok tools passed to --disallowed-tools.
	GrokDisallow []string
	// ClaudeSandbox is whether the settings file turns Claude's sandbox on.
	ClaudeSandbox bool
}

// IsolationOptions builds an Isolation.
type IsolationOptions struct {
	Backend string
	// StateDir is the per-bot daemon directory for the settings file.
	StateDir string
	// Home is the per-bot HOME. Empty shares the user's HOME.
	Home string
	// UserHome is the daemon user's HOME, used to link credentials.
	UserHome string
	// Base is the daemon environment to filter, usually os.Environ().
	Base []string
	// Extra is policy-set environment. It wins over everything else.
	Extra map[string]string
	// Secrets are daemon values (the admin token) that must never reach the
	// CLI. A variable whose value contains one is dropped, whatever its name.
	Secrets []string
	// Grants map the bot's daemon grants onto CLI settings.
	Grants Grants
	// ClaudeSandbox turns on Claude's Bash sandbox, fail closed.
	ClaudeSandbox bool
	// Protect are extra absolute paths both CLIs are denied (daemon secrets).
	Protect []string
}

// passEnv names variables kept from the daemon environment.
var passEnv = map[string]bool{
	"PATH": true, "LANG": true, "TERM": true, "TZ": true, "USER": true,
	"LOGNAME": true, "SHELL": true, "TMPDIR": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
}

// credEnv names the only backend variables kept: credentials, not overrides.
var credEnv = map[string][]string{
	"claude": {"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"},
	"grok":   {"XAI_API_KEY"},
}

// credFiles are linked from the user's home into an isolated home so login
// still works. Only the credential file is shared, never settings.
var credFiles = map[string][]string{
	"claude": {".claude/.credentials.json"},
	"grok":   {".grok/auth.json"},
}

// grokCompatOff turns off Grok's Claude and Cursor compatibility scans.
var grokCompatOff = []string{
	"GROK_CLAUDE_AGENTS_ENABLED", "GROK_CLAUDE_HOOKS_ENABLED", "GROK_CLAUDE_MCPS_ENABLED",
	"GROK_CLAUDE_RULES_ENABLED", "GROK_CLAUDE_SKILLS_ENABLED",
	"GROK_CURSOR_AGENTS_ENABLED", "GROK_CURSOR_HOOKS_ENABLED", "GROK_CURSOR_MCPS_ENABLED",
	"GROK_CURSOR_RULES_ENABLED", "GROK_CURSOR_SKILLS_ENABLED",
}

// PrepareIsolation creates the per-bot home, links credentials, writes the
// Claude settings file, and builds the scrubbed environment.
func PrepareIsolation(o IsolationOptions) (Isolation, error) {
	backend := strings.ToLower(strings.TrimSpace(o.Backend))
	if backend != "claude" && backend != "grok" {
		return Isolation{}, fmt.Errorf("unknown cli backend %q", o.Backend)
	}
	iso := Isolation{Home: o.Home}
	home := o.UserHome
	if o.Home != "" {
		if !filepath.IsAbs(o.Home) {
			return Isolation{}, fmt.Errorf("cli home must be absolute")
		}
		home = o.Home
		for _, d := range []string{".claude", ".grok"} {
			if err := os.MkdirAll(filepath.Join(o.Home, d), 0o700); err != nil {
				return Isolation{}, err
			}
		}
		if o.UserHome != "" {
			for _, rel := range credFiles[backend] {
				linkCred(filepath.Join(o.UserHome, rel), filepath.Join(o.Home, rel))
			}
		}
	}
	env := map[string]string{}
	for _, kv := range o.Base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// LGB_ is the daemon's own namespace; test doubles read it too.
		if passEnv[k] || strings.HasPrefix(k, "LC_") || strings.HasPrefix(k, "LGB_") {
			env[k] = v
		}
		for _, c := range credEnv[backend] {
			if k == c {
				env[k] = v
			}
		}
	}
	if home != "" {
		env["HOME"] = home
	}
	switch backend {
	case "claude":
		if o.Home != "" {
			env["CLAUDE_CONFIG_DIR"] = filepath.Join(o.Home, ".claude")
		}
		if !filepath.IsAbs(o.StateDir) {
			return Isolation{}, fmt.Errorf("cli state dir must be absolute")
		}
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			return Isolation{}, err
		}
		iso.SettingsPath = filepath.Join(o.StateDir, "claude-settings.json")
		body, err := claudeSettingsJSON(o)
		if err != nil {
			return Isolation{}, err
		}
		if err := os.WriteFile(iso.SettingsPath, body, 0o600); err != nil {
			return Isolation{}, err
		}
		iso.ClaudeSandbox = o.ClaudeSandbox
	case "grok":
		if o.Home != "" {
			env["GROK_HOME"] = filepath.Join(o.Home, ".grok")
		}
		for _, k := range grokCompatOff {
			env[k] = "false"
		}
		env["GROK_DISABLE_AUTOUPDATER"] = "1"
		iso.GrokDisallow = grokDisallowed(o.Grants)
		// The custom profile lives in the per-bot GROK_HOME. With the user's
		// own home the daemon does not write there, and uses built-in strict,
		// which Grok runs unenforced (with a warning) if it can't apply.
		iso.GrokSandbox = "strict"
		if o.Home != "" {
			path := filepath.Join(o.Home, ".grok", "sandbox.toml")
			if err := os.WriteFile(path, []byte(grokSandboxTOML(o)), 0o600); err != nil {
				return Isolation{}, err
			}
			iso.GrokSandbox = GrokProfile
		}
	}
	for k, v := range o.Extra {
		env[k] = v
	}
	delete(env, "AUTH_TOKEN")
	for k, v := range env {
		for _, sec := range o.Secrets {
			if sec != "" && strings.Contains(v, sec) {
				delete(env, k)
			}
		}
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		iso.Env = append(iso.Env, k+"="+env[k])
	}
	return iso, nil
}

func linkCred(src, dst string) {
	if st, err := os.Stat(src); err != nil || !st.Mode().IsRegular() {
		return
	}
	if cur, err := os.Readlink(dst); err == nil && cur == src {
		return
	}
	_ = os.Remove(dst)
	_ = os.Symlink(src, dst)
}

// overrideNames are workspace files a CLI would read as configuration.
var overrideNames = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
	".claude/CLAUDE.local.md", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md",
	"AGENTS.md", ".grok/config.toml", ".cursor/mcp.json", ".cursor/hooks.json",
}

// ScanOverrides lists override files under the workspace, relative to it.
// It looks a few levels deep and skips .git and node_modules.
func ScanOverrides(ws string) []string {
	var out []string
	_ = filepath.WalkDir(ws, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(ws, path)
		if d.IsDir() {
			if rel != "." && (d.Name() == ".git" || d.Name() == "node_modules" || strings.Count(rel, string(filepath.Separator)) >= 3) {
				return filepath.SkipDir
			}
			return nil
		}
		slash := filepath.ToSlash(rel)
		for _, n := range overrideNames {
			if slash == n || strings.HasSuffix(slash, "/"+n) {
				out = append(out, slash)
				break
			}
		}
		if strings.Contains("/"+slash, "/.grok/") && !strings.HasSuffix(slash, ".grok/config.toml") {
			out = append(out, slash)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

// Neutralized reports whether the launch flags and environment keep the CLI
// from loading file. Claude is told to load no setting sources and only the
// daemon's MCP config. Grok has no such flag: with an isolated GROK_HOME the
// workspace is never trusted, so project rules and config are skipped, but
// Grok still discovers .mcp.json. With the user's home, a prior folder
// trust grant could load anything, so nothing is neutralized.
func Neutralized(backend, file string, isolatedHome bool) bool {
	base := filepath.Base(file)
	switch strings.ToLower(backend) {
	case "claude":
		// --setting-sources= and --strict-mcp-config cover the Claude files.
		// Claude does not read the Grok and Cursor files.
		return true
	case "grok":
		if !isolatedHome || base == ".mcp.json" {
			return false
		}
		return true
	}
	return false
}
