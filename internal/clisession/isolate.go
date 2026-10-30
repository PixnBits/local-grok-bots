package clisession

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
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
	// GrokTools is the --tools allowlist. Empty on a Grok turn uses the
	// no-net list, so an unset list does not leave every built-in enabled.
	GrokTools []string
	// ClaudeSandbox is whether the settings file turns Claude's sandbox on.
	ClaudeSandbox bool
	// Protect is the path deny list written into this turn's settings.
	Protect []string
	// ReleaseGate drops this turn's loopback proxy gate and, on Linux, the
	// per-turn egress proxy. Nil is fine. Calling it more than once is safe.
	ReleaseGate func()
	// ForwardBin is the in-jail process that bridges host unix sockets onto
	// 127.0.0.1. Empty means the CLI is started directly.
	ForwardBin string
	// ForwardArgs are that process's arguments. The jail appends "--" and the
	// CLI argv.
	ForwardArgs []string
	// ExtraBinds are host path, jail path pairs. Jail paths are JailProxySock
	// and JailEgressSock.
	ExtraBinds [][2]string
	// PermHookCommand is the quoted lgb-permhook command. Empty keeps
	// disableAllHooks. Claude is not in the Grok jail, so this command
	// uses host paths.
	PermHookCommand string
}

// JailProxySock is the credential proxy inside the Grok network namespace.
const JailProxySock = "/cli-proxy.sock"

// JailEgressSock is the net-grant HTTP proxy inside that namespace.
const JailEgressSock = "/cli-egress.sock"

// BridgeError is a fail-closed refusal when the jail cannot reach the
// credential proxy or the net-grant egress proxy. The daemon audits it as
// cli_bridge_unavailable.
type BridgeError struct{ Err error }

func (e *BridgeError) Error() string {
	return "credential bridge is not available, so the turn was refused"
}

func (e *BridgeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsolationOptions builds an Isolation.
type IsolationOptions struct {
	Backend string
	// StateDir is the per-bot daemon directory for the settings file.
	StateDir string
	// Workspace is the bot directory. A Grok turn seals one session
	// permission file for this path. Empty skips that file.
	Workspace string
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
	// ProxyBase is the Grok chat proxy origin, such as http://127.0.0.1:9.
	// Empty means the CLI is not pointed at the proxy. The value is an origin
	// with no path. The daemon appends /v1.
	ProxyBase string
	// ProxyGate is the per-run placeholder bearer. The loopback proxy
	// replaces it and rejects any other bearer. Required when ProxyBase is set.
	ProxyGate string
	// ClaudeSandbox turns on Claude's Bash sandbox, fail closed.
	ClaudeSandbox bool
	// Protect are extra absolute paths both CLIs are denied (daemon secrets).
	Protect []string
	// PermHookCommand, when set, replaces disableAllHooks with the broker
	// PreToolUse hook. Empty keeps the locked-down settings.
	PermHookCommand string
	// BrokerDeny are absolute paths added to the Claude deny list when the
	// hook is armed: the hook binary, the settings file and its directory,
	// and the broker state directory.
	BrokerDeny []string
	// CredRoot is the trusted directory the Grok login walk starts at.
	// Empty uses StateDir when the bot home is inside it, otherwise the
	// parent of Home. Components below the root are not followed when they
	// are symlinks.
	CredRoot string
}

// passInheritedLGB is false in a production build. Test binaries and the
// lgbtest tag turn it on so fakes can read LGB_CLI_MODE and the other
// LGB_* names they use. LGB_SPOOL and LGB_TOKEN stay out either way.
var passInheritedLGB bool

// EnableTestLGBPassthrough lets a test binary copy LGB_* from the daemon
// environment into the CLI, except LGB_SPOOL and LGB_TOKEN.
func EnableTestLGBPassthrough() { passInheritedLGB = true }

// keepInheritedLGB reports whether one daemon-environment variable may be
// copied into the CLI. The daemon adds LGB_SPOOL and LGB_TOKEN itself.
func keepInheritedLGB(name string) bool {
	if !passInheritedLGB || !strings.HasPrefix(name, "LGB_") {
		return false
	}
	return name != "LGB_SPOOL" && name != "LGB_TOKEN" && name != SessionMarkerEnv
}

// passEnv names variables kept from the daemon environment.
var passEnv = map[string]bool{
	"PATH": true, "LANG": true, "TERM": true, "TZ": true, "USER": true,
	"LOGNAME": true, "SHELL": true, "TMPDIR": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true,
	"http_proxy": true, "https_proxy": true, "no_proxy": true, "all_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true,
}

// grokBaseEnv is the daemon environment a Grok launch may keep.
// HOME and the turn's own variables are set separately.
var grokBaseEnv = map[string]bool{
	"PATH": true, "LANG": true, "TERM": true,
}

// credEnv names the only backend variables kept: credentials, not overrides.
// Grok does not keep XAI_API_KEY. The daemon sets a placeholder and the
// proxy replaces the bearer.
var credEnv = map[string][]string{
	"claude": {"ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"},
}

// credFiles are linked from the user's home into an isolated home so login
// still works. Only the credential file is shared, never settings.
// Grok's login is not linked. The bot home gets a placeholder file.
var credFiles = map[string][]string{
	"claude": {".claude/.credentials.json"},
}

// grokCompatOff turns off Grok's Claude and Cursor compatibility scans.
var grokCompatOff = []string{
	"GROK_CLAUDE_AGENTS_ENABLED", "GROK_CLAUDE_HOOKS_ENABLED", "GROK_CLAUDE_MCPS_ENABLED",
	"GROK_CLAUDE_RULES_ENABLED", "GROK_CLAUDE_SKILLS_ENABLED",
	"GROK_CURSOR_AGENTS_ENABLED", "GROK_CURSOR_HOOKS_ENABLED", "GROK_CURSOR_MCPS_ENABLED",
	"GROK_CURSOR_RULES_ENABLED", "GROK_CURSOR_SKILLS_ENABLED",
}

// SandboxError is a fail-closed sandbox refusal. The daemon audits it as
// cli_sandbox_unavailable, the same event as a missing Claude sandbox.
type SandboxError struct {
	Backend string
	Path    string
	Err     error
}

func (e *SandboxError) Error() string {
	if e == nil || e.Err == nil {
		return "sandbox refused the turn"
	}
	return e.Err.Error()
}

func (e *SandboxError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// grokProfileHome is the directory whose sandbox.toml holds the custom
// profile. With the user's HOME it is a daemon directory, never ~/.grok.
func grokProfileHome(o IsolationOptions) (string, error) {
	if o.Home != "" {
		return filepath.Join(o.Home, ".grok"), nil
	}
	if !filepath.IsAbs(o.StateDir) {
		return "", &SandboxError{Backend: "grok", Err: fmt.Errorf("Grok's sandbox profile needs an absolute state dir, so the turn was refused")}
	}
	return filepath.Join(o.StateDir, "grok-home"), nil
}

// ensureGrokState creates the state directory when it is the trusted root.
// A symlink at that final component is refused. Callers that already have a
// trusted parent create the rest of the path while writing.
func ensureGrokState(o IsolationOptions) error {
	if strings.TrimSpace(o.CredRoot) != "" || o.Home != "" {
		return nil
	}
	state, err := absClean(o.StateDir)
	if err != nil {
		return err
	}
	parent := filepath.Dir(state)
	if parent == state {
		return fmt.Errorf("credential root must be absolute")
	}
	return mkdirNoFollow(parent, filepath.Base(state))
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
	grokKey := GrokPlaceholderToken
	if strings.EqualFold(strings.TrimSpace(o.Backend), "grok") && strings.TrimSpace(o.ProxyBase) != "" {
		grokKey = strings.TrimSpace(o.ProxyGate)
		if !validGrokGate(grokKey) {
			return Isolation{}, fmt.Errorf("grok proxy requires a per-run placeholder key")
		}
	}
	if o.Home != "" {
		if !filepath.IsAbs(o.Home) {
			return Isolation{}, fmt.Errorf("cli home must be absolute")
		}
		home = o.Home
		root, err := isolationRoot(o)
		if err != nil {
			return Isolation{}, err
		}
		for _, d := range []string{".claude", ".grok"} {
			rel, err := relUnder(root, filepath.Join(o.Home, d))
			if err != nil {
				return Isolation{}, err
			}
			if err := mkdirNoFollow(root, rel); err != nil {
				return Isolation{}, err
			}
		}
		if o.UserHome != "" {
			for _, rel := range credFiles[backend] {
				dstRel, err := relUnder(root, filepath.Join(o.Home, rel))
				if err != nil {
					return Isolation{}, err
				}
				if err := linkCredNoFollow(filepath.Join(o.UserHome, rel), root, dstRel); err != nil {
					return Isolation{}, err
				}
			}
		}
	}
	env := map[string]string{}
	for _, kv := range o.Base {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		// LGB_SPOOL and LGB_TOKEN are set by the daemon for one run. Other
		// LGB_* names are not inherited. Tests and the lgbtest tag opt in.
		// Grok keeps only PATH, LANG, and TERM from the daemon. The per-run
		// key, proxy URLs, HOME, and GROK_* variables are set below.
		keep := passEnv[k] || strings.HasPrefix(k, "LC_") || keepInheritedLGB(k)
		if backend == "grok" {
			keep = grokBaseEnv[k] || keepInheritedLGB(k)
		}
		if keep {
			env[k] = v
		}
		if backend != "grok" {
			for _, c := range credEnv[backend] {
				if k == c {
					env[k] = v
				}
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
		body, err := claudeSettingsJSON(o)
		if err != nil {
			return Isolation{}, err
		}
		path, err := writeClaudeSettings(o, body)
		if err != nil {
			return Isolation{}, err
		}
		iso.SettingsPath = path
		iso.ClaudeSandbox = o.ClaudeSandbox
		iso.PermHookCommand = strings.TrimSpace(o.PermHookCommand)
	case "grok":
		for _, k := range grokCompatOff {
			env[k] = "false"
		}
		env["GROK_DISABLE_AUTOUPDATER"] = "1"
		iso.GrokTools = grokAllowedTools(o.Grants)
		// Built-in profiles fail open. The custom profile lives in GROK_HOME:
		// the per-bot home, or a daemon directory when HOME is the user's
		// (that directory is not ~/.grok, so the user's sandbox.toml is untouched).
		grokHome, err := grokProfileHome(o)
		if err != nil {
			return Isolation{}, err
		}
		if err := ensureGrokState(o); err != nil {
			return Isolation{}, err
		}
		env["GROK_HOME"] = grokHome
		root, err := isolationRoot(o)
		if err != nil {
			return Isolation{}, err
		}
		authRel, err := relUnder(root, filepath.Join(grokHome, "auth.json"))
		if err != nil {
			return Isolation{}, err
		}
		if err := placeGrokPlaceholder(o.UserHome, root, authRel, grokKey); err != nil {
			return Isolation{}, err
		}
		tomlRel, err := relUnder(root, filepath.Join(grokHome, "sandbox.toml"))
		if err != nil {
			return Isolation{}, err
		}
		if err := writeFileNoFollow(root, tomlRel, []byte(grokSandboxTOML(o)), 0o600); err != nil {
			if errors.Is(err, ErrCredSymlink) {
				return Isolation{}, err
			}
			return Isolation{}, &SandboxError{Backend: "grok", Err: fmt.Errorf("Grok's sandbox profile could not be written (%v), so the turn was refused", err)}
		}
		if err := SealGrokHome(root, grokHome); err != nil {
			return Isolation{}, err
		}
		if err := ensureWorkspacePermission(root, grokHome, o.Workspace); err != nil {
			return Isolation{}, err
		}
		if err := prepareShellRC(home); err != nil {
			return Isolation{}, err
		}
		if err := prepareHomeSeals(home); err != nil {
			return Isolation{}, err
		}
		iso.GrokSandbox = GrokProfile
	}
	for k, v := range o.Extra {
		if policy.BlockedCLIEnv(k) {
			return Isolation{}, fmt.Errorf("cli environment cannot set %s, so the turn was refused", k)
		}
		env[k] = v
	}
	if backend == "grok" {
		// Policy env must not put a real key or the real API origin back.
		env["XAI_API_KEY"] = grokKey
		if base := strings.TrimRight(strings.TrimSpace(o.ProxyBase), "/"); base != "" {
			chat := base + "/v1"
			env["GROK_CLI_CHAT_PROXY_BASE_URL"] = chat
			env["GROK_XAI_API_BASE_URL"] = chat
			env["XAI_API_BASE_URL"] = chat
		}
	}
	delete(env, "AUTH_TOKEN")
	delete(env, "AUTH_TOKENS_FILE")
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

// ClaudeSettingsPath is the file writeClaudeSettings will replace.
func ClaudeSettingsPath(o IsolationOptions) (string, error) {
	state, err := absClean(o.StateDir)
	if err != nil {
		return "", err
	}
	if r := strings.TrimSpace(o.CredRoot); r != "" {
		root, err := absClean(r)
		if err != nil {
			return "", err
		}
		rel, err := relUnder(root, filepath.Join(state, "claude-settings.json"))
		if err != nil {
			return "", err
		}
		return filepath.Join(root, rel), nil
	}
	return filepath.Join(state, "claude-settings.json"), nil
}

func writeClaudeSettings(o IsolationOptions, body []byte) (string, error) {
	path, err := ClaudeSettingsPath(o)
	if err != nil {
		return "", err
	}
	if r := strings.TrimSpace(o.CredRoot); r != "" {
		root, err := absClean(r)
		if err != nil {
			return "", err
		}
		rel, err := relUnder(root, path)
		if err != nil {
			return "", err
		}
		if err := writeFileNoFollow(root, rel, body, 0o600); err != nil {
			return "", err
		}
		return path, nil
	}
	parent := filepath.Dir(path)
	base := filepath.Base(path)
	if err := mkdirNoFollow(filepath.Dir(parent), filepath.Base(parent)); err != nil {
		return "", err
	}
	rel := filepath.Join(filepath.Base(parent), base)
	if err := writeFileNoFollow(filepath.Dir(parent), rel, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// placeGrokPlaceholder writes the synthetic login into GROK_HOME. It never
// writes the user's ~/.grok/auth.json and never links that file in.
// key is the placeholder bearer. The shared constant is used when the CLI
// is not pointed at the loopback proxy. root is the trusted directory and
// rel is the login path below it.
func placeGrokPlaceholder(userHome, root, rel, key string) error {
	dst := filepath.Join(root, rel)
	if userHome != "" && filepath.Clean(dst) == filepath.Clean(filepath.Join(userHome, ".grok", "auth.json")) {
		return fmt.Errorf("refusing to replace the user grok login")
	}
	return writeGrokAuth(root, rel, key)
}

func isolationRoot(o IsolationOptions) (string, error) {
	if r := strings.TrimSpace(o.CredRoot); r != "" {
		return absClean(r)
	}
	if o.Home != "" {
		home, err := absClean(o.Home)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(o.StateDir) != "" {
			if state, err := absClean(o.StateDir); err == nil && isWithin(state, home) {
				return state, nil
			}
		}
		return filepath.Dir(home), nil
	}
	if strings.TrimSpace(o.StateDir) == "" {
		return "", fmt.Errorf("credential root must be absolute")
	}
	return absClean(o.StateDir)
}

func absClean(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("credential root must be absolute")
	}
	if !filepath.IsAbs(p) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		p = abs
	}
	return filepath.Clean(p), nil
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func relUnder(root, path string) (string, error) {
	root, err := absClean(root)
	if err != nil {
		return "", err
	}
	path, err = absClean(path)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("refusing a credential path outside its root")
	}
	return rel, nil
}

func validGrokGate(s string) bool {
	if len(s) < 16 || len(s) > 128 || s == GrokPlaceholderToken {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// GrokPlaceholderAuth is a synthetic login file. It contains no value from
// the host credential file. The proxy overwrites Authorization.
const GrokPlaceholderAuth = `{"https://auth.x.ai::00000000-0000-4000-8000-000000000001":{"key":"` + GrokPlaceholderToken + `","auth_mode":"oidc","expires_at":"2099-01-01T00:00:00.000000000Z","refresh_token":"coi-placeholder-refresh","oidc_issuer":"https://auth.x.ai","oidc_client_id":"00000000-0000-4000-8000-000000000001"}}
`

// GrokPlaceholderToken is the dummy bearer in GrokPlaceholderAuth and in
// XAI_API_KEY. The host proxy replaces it and never forwards it.
const GrokPlaceholderToken = "coi-placeholder-token"

// writeGrokAuth replaces root/rel with a regular file whose key is the
// placeholder bearer. A hard link is unlinked, so the other name stays.
// A symlink component, including a symlink auth.json, is refused.
func writeGrokAuth(root, rel, key string) error {
	if key == "" {
		key = GrokPlaceholderToken
	}
	body := GrokPlaceholderAuth
	if key != GrokPlaceholderToken {
		body = strings.Replace(GrokPlaceholderAuth, `"`+GrokPlaceholderToken+`"`, `"`+key+`"`, 1)
	}
	return writeFileNoFollow(root, rel, []byte(body), 0o600)
}

// overrideNames are workspace files a CLI would read as configuration.
var overrideNames = []string{
	".claude/settings.json", ".claude/settings.local.json", ".claude/CLAUDE.md",
	".claude/CLAUDE.local.md", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md",
	"AGENTS.md", ".grok/config.toml", ".grok/hooks", ".grok/skills", ".grok/lsp.json",
	".cursor/mcp.json", ".cursor/hooks.json", ".envrc",
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
			if rel != "." {
				slash := filepath.ToSlash(rel)
				for _, n := range overrideNames {
					if slash == n || strings.HasSuffix(slash, "/"+n) {
						out = append(out, slash)
						break
					}
				}
			}
			return nil
		}
		slash := filepath.ToSlash(rel)
		matched := false
		for _, n := range overrideNames {
			if slash == n || strings.HasSuffix(slash, "/"+n) {
				out = append(out, slash)
				matched = true
				break
			}
		}
		if !matched && strings.Contains("/"+slash, "/.grok/") && !strings.HasSuffix(slash, ".grok/config.toml") {
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
