// Package policy is the daemon's confinement policy.
// CLI launch and the shell jail read one value loaded at startup.
package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

const (
	// NetOpen leaves the CLI network as it is today.
	NetOpen = "open"
	// NetProxy sends CLI TCP through the sandbox allowlist proxy.
	NetProxy = "proxy"
	// NetNone gives the CLI no network and no proxy.
	NetNone = "none"
	// NetExplicit is the allowlist proxy plus an upstream corporate proxy.
	// The CLI child does not receive the proxy URL.
	NetExplicit = "explicit-proxy"
)

// CLIPin is an optional check of one CLI binary.
// An empty pin list checks nothing. A configured pin must match before exec.
type CLIPin struct {
	Backend string `json:"backend"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Version string `json:"version,omitempty"`
}

// Policy is the effective confinement policy.
// Slices are empty rather than nil so logs and the API stay stable.
type Policy struct {
	AllowCLIBackends []string `json:"allow_cli_backends"`
	CLINetwork       string   `json:"cli_network"`
	CLINetAllow      []string `json:"cli_net_allow"`
	EnvAllowlist     []string `json:"env_allowlist"`
	DefaultNetAllow  []string `json:"default_net_allow"`
	ForceLocalOnly   bool     `json:"force_local_only"`
	BuildBinds       []string `json:"build_binds"`
	// CLIROBinds are extra read-only paths in the CLI jail.
	// Empty means the jail mounts only its built-in paths.
	CLIROBinds []string `json:"cli_ro_binds"`
	// HTTPProxy, HTTPSProxy, and NoProxy are the corporate proxy settings.
	// They are used only when CLINetwork is proxy or explicit-proxy.
	// Logs and the API show the URL with the password redacted.
	HTTPProxy  string `json:"http_proxy"`
	HTTPSProxy string `json:"https_proxy"`
	NoProxy    string `json:"no_proxy"`
	// CLIPins is empty unless an operator pins a backend binary.
	CLIPins []CLIPin `json:"cli_pins"`
	// AuditLog is empty, "stderr", "syslog", or an absolute file path.
	// Empty writes no audit lines.
	AuditLog string `json:"audit_log"`
	// DLPPatterns, DLPFile, and DLPCommand are the optional content check.
	// All empty leaves the check off.
	DLPPatterns  []string `json:"dlp_patterns"`
	DLPFile      string   `json:"dlp_file"`
	DLPCommand   string   `json:"dlp_command"`
	DLPScanTools bool     `json:"dlp_scan_tools"`
}

// Default is the policy used when no file or environment sets a field.
// CLI backends stay available and their network stays open.
func Default() Policy {
	return Policy{
		AllowCLIBackends: []string{"grok", "claude"},
		CLINetwork:       NetOpen,
		CLINetAllow:      []string{},
		EnvAllowlist:     []string{},
		DefaultNetAllow:  []string{},
		BuildBinds:       []string{},
		CLIROBinds:       []string{},
		CLIPins:          []CLIPin{},
		DLPPatterns:      []string{},
	}
}

// Load reads the policy file, then environment variables, then defaults.
// A file value wins over the environment. presetBinds is the bind list
// already taken from the daemon config; SANDBOX_BUILD_BINDS and the file
// can replace it. proxyAvailable is false when this build has no CLI proxy.
func Load(dataDir, modelURL string, presetBinds []string, proxyAvailable bool) (Policy, error) {
	p := Default()
	if len(presetBinds) > 0 {
		p.BuildBinds = append([]string{}, presetBinds...)
	}
	if err := applyEnv(&p); err != nil {
		return Policy{}, err
	}
	path, named, err := policyPath(dataDir)
	if err != nil {
		return Policy{}, err
	}
	if path != "" {
		if err := applyFile(&p, path); err != nil {
			return Policy{}, err
		}
	} else if named {
		return Policy{}, fmt.Errorf("policy file not found")
	}
	if err := p.Validate(modelURL, proxyAvailable); err != nil {
		return Policy{}, err
	}
	if err := p.checkCLIROBinds(dataDir); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate fails closed on a policy this daemon cannot enforce.
func (p Policy) Validate(modelURL string, proxyAvailable bool) error {
	switch p.CLINetwork {
	case NetOpen, NetNone:
	case NetProxy, NetExplicit:
		if !proxyAvailable {
			return fmt.Errorf("cli_network %s is not available in this build", p.CLINetwork)
		}
		if err := p.checkUpstream(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("cli_network must be open, proxy, none, or explicit-proxy")
	}
	for _, b := range p.AllowCLIBackends {
		switch b {
		case "grok", "claude", "*":
		default:
			return fmt.Errorf("cli backend %q is unknown", b)
		}
	}
	for _, name := range p.EnvAllowlist {
		if err := checkEnvName(name); err != nil {
			return err
		}
	}
	for _, host := range p.CLINetAllow {
		if err := checkHost(host); err != nil {
			return fmt.Errorf("cli_net_allow: %w", err)
		}
	}
	for _, host := range p.DefaultNetAllow {
		if err := checkHost(host); err != nil {
			return fmt.Errorf("default_net_allow: %w", err)
		}
	}
	for _, path := range p.BuildBinds {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\n\r\x00") {
			return fmt.Errorf("build bind %q must be an absolute path", path)
		}
	}
	seenPin := map[string]bool{}
	for _, pin := range p.CLIPins {
		if err := checkPin(pin); err != nil {
			return err
		}
		if seenPin[pin.Backend] {
			return fmt.Errorf("cli pin %s is duplicated", pin.Backend)
		}
		seenPin[pin.Backend] = true
	}
	if err := checkAudit(p.AuditLog); err != nil {
		return err
	}
	if err := p.checkDLP(); err != nil {
		return err
	}
	if p.ForceLocalOnly {
		if err := requireLoopback(modelURL); err != nil {
			return err
		}
	}
	return nil
}

// AllowsBackend reports whether a CLI turn for name may start.
// ForceLocalOnly disables every CLI backend.
func (p Policy) AllowsBackend(name string) bool {
	if p.ForceLocalOnly {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	for _, b := range p.AllowCLIBackends {
		if b == "*" || b == name {
			return true
		}
	}
	return false
}

// NetAllow is the shell allowlist for one bot.
// A bot that lists hosts keeps that list. A net grant with no hosts uses
// DefaultNetAllow. Without the grant, the bot list is returned unchanged.
func (p Policy) NetAllow(grants, botAllow []string) []string {
	if !hasGrant(grants, "net") || len(botAllow) > 0 {
		return append([]string{}, botAllow...)
	}
	return append([]string{}, p.DefaultNetAllow...)
}

// ExtraEnv returns KEY=VALUE entries for allowlisted variables that are set.
// Unset names are skipped. A blocked name or an unsafe value is an error.
func (p Policy) ExtraEnv(lookup func(string) (string, bool)) ([]string, error) {
	var out []string
	for _, name := range p.EnvAllowlist {
		if err := checkEnvName(name); err != nil {
			return nil, err
		}
		val, ok := lookup(name)
		if !ok || val == "" {
			continue
		}
		if len(val) > 1024 || strings.ContainsAny(val, "\n\r\x00") {
			return nil, fmt.Errorf("env %s is not safe to pass", name)
		}
		out = append(out, name+"="+val)
	}
	if out == nil {
		return []string{}, nil
	}
	return out, nil
}

// UsesUpstream reports whether CLI egress should dial through the corporate proxy.
// Open and none ignore the proxy URLs. Proxy uses them only when one is set.
func (p Policy) UsesUpstream() bool {
	mode := strings.ToLower(strings.TrimSpace(p.CLINetwork))
	if mode != NetProxy && mode != NetExplicit {
		return false
	}
	return strings.TrimSpace(p.HTTPProxy) != "" || strings.TrimSpace(p.HTTPSProxy) != ""
}

// Line is the policy as one JSON line. Allowlisted values are not included.
// Proxy passwords are redacted.
func (p Policy) Line() string {
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// MarshalJSON redacts proxy passwords. The dialer still has the original URL.
func (p Policy) MarshalJSON() ([]byte, error) {
	type wire Policy
	w := wire(p)
	w.HTTPProxy = redactProxyURL(p.HTTPProxy)
	w.HTTPSProxy = redactProxyURL(p.HTTPSProxy)
	return json.Marshal(w)
}

// BlockedEnv reports names the jail sets itself or must never receive.
func BlockedEnv(name string) bool {
	switch strings.ToUpper(name) {
	case "XAI_API_KEY", "ANTHROPIC_API_KEY", "SSH_AUTH_SOCK",
		"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
		"LGB_PROXY_SOCK", "LGB_KEY",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TERM", "TZ":
		return true
	default:
		return false
	}
}

func checkEnvName(name string) error {
	if name == "" || BlockedEnv(name) {
		return fmt.Errorf("env %s is not permitted", name)
	}
	for i, r := range name {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("env %s is not permitted", name)
		}
	}
	return nil
}

func checkHost(host string) error {
	if host == "" || strings.ContainsAny(host, " \t/\\") {
		return fmt.Errorf("host %q is invalid", host)
	}
	return nil
}

func hasGrant(grants []string, name string) bool {
	for _, g := range grants {
		if strings.EqualFold(strings.TrimSpace(g), name) {
			return true
		}
	}
	return false
}

func requireLoopback(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("force_local_only requires a loopback model URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("force_local_only requires a loopback model URL")
	}
	if !loopbackHost(u.Hostname()) {
		return fmt.Errorf("force_local_only rejects non-loopback model URL %s", raw)
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func policyPath(dataDir string) (string, bool, error) {
	if v, ok := os.LookupEnv("POLICY_FILE"); ok {
		v = strings.TrimSpace(v)
		if v == "" {
			return "", true, fmt.Errorf("POLICY_FILE is empty")
		}
		st, err := os.Stat(v)
		if err != nil {
			return "", true, fmt.Errorf("policy file: %w", err)
		}
		if st.IsDir() {
			return "", true, fmt.Errorf("policy file is a directory")
		}
		return v, true, nil
	}
	candidate := filepath.Join(dataDir, "policy.yaml")
	st, err := os.Stat(candidate)
	if err != nil {
		return "", false, nil
	}
	if st.IsDir() {
		return "", false, fmt.Errorf("policy file is a directory")
	}
	return candidate, false, nil
}

func applyEnv(p *Policy) error {
	if v, ok := os.LookupEnv("POLICY_CLI_BACKENDS"); ok {
		p.AllowCLIBackends = normBackends(splitComma(v))
	}
	if v, ok := os.LookupEnv("POLICY_CLI_NETWORK"); ok {
		p.CLINetwork = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := os.LookupEnv("POLICY_CLI_NET_ALLOW"); ok {
		p.CLINetAllow = normHosts(splitComma(v))
	}
	if v, ok := os.LookupEnv("POLICY_ENV_ALLOWLIST"); ok {
		p.EnvAllowlist = splitComma(v)
	}
	if v, ok := os.LookupEnv("POLICY_DEFAULT_NET_ALLOW"); ok {
		p.DefaultNetAllow = normHosts(splitComma(v))
	}
	if v, ok := os.LookupEnv("POLICY_FORCE_LOCAL_ONLY"); ok {
		on, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("POLICY_FORCE_LOCAL_ONLY: %w", err)
		}
		p.ForceLocalOnly = on
	}
	if v, ok := os.LookupEnv("SANDBOX_BUILD_BINDS"); ok {
		p.BuildBinds = splitList(v, string(os.PathListSeparator))
	}
	if v, ok := os.LookupEnv("POLICY_CLI_RO_BINDS"); ok {
		p.CLIROBinds = splitList(v, string(os.PathListSeparator))
	}
	if v, ok := lookupProxy("POLICY_HTTP_PROXY", "HTTP_PROXY", "http_proxy"); ok {
		p.HTTPProxy = v
	}
	if v, ok := lookupProxy("POLICY_HTTPS_PROXY", "HTTPS_PROXY", "https_proxy"); ok {
		p.HTTPSProxy = v
	}
	if v, ok := lookupProxy("POLICY_NO_PROXY", "NO_PROXY", "no_proxy"); ok {
		p.NoProxy = v
	}
	if v, ok := os.LookupEnv("POLICY_AUDIT_LOG"); ok {
		p.AuditLog = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("POLICY_DLP_PATTERNS"); ok {
		p.DLPPatterns = splitList(v, ";")
	}
	if v, ok := os.LookupEnv("POLICY_DLP_FILE"); ok {
		p.DLPFile = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("POLICY_DLP_COMMAND"); ok {
		p.DLPCommand = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("POLICY_DLP_SCAN_TOOLS"); ok {
		on, err := parseBool(v)
		if err != nil {
			return fmt.Errorf("POLICY_DLP_SCAN_TOOLS: %w", err)
		}
		p.DLPScanTools = on
	}
	if v, ok := os.LookupEnv("POLICY_CLI_PINS"); ok {
		pins, err := parsePinList(v, ";")
		if err != nil {
			return err
		}
		p.CLIPins = pins
	}
	return nil
}

// CLIPinFor returns the pin for a backend. The second result is false when
// that backend is not pinned.
func (p Policy) CLIPinFor(backend string) (CLIPin, bool) {
	backend = strings.ToLower(strings.TrimSpace(backend))
	for _, pin := range p.CLIPins {
		if pin.Backend == backend {
			return pin, true
		}
	}
	return CLIPin{}, false
}

func parsePinList(raw, sep string) ([]CLIPin, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []CLIPin{}, nil
	}
	var out []CLIPin
	for _, part := range strings.Split(raw, sep) {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("cli pin is empty")
		}
		pin, err := parsePin(part)
		if err != nil {
			return nil, err
		}
		out = append(out, pin)
	}
	if out == nil {
		return []CLIPin{}, nil
	}
	return out, nil
}

func parsePin(raw string) (CLIPin, error) {
	fields := strings.Fields(raw)
	if len(fields) < 2 {
		return CLIPin{}, fmt.Errorf("cli pin %q is incomplete", raw)
	}
	pin := CLIPin{Backend: strings.ToLower(fields[0])}
	for _, field := range fields[1:] {
		key, val, ok := strings.Cut(field, "=")
		if !ok || key == "" || val == "" {
			return CLIPin{}, fmt.Errorf("cli pin %q is invalid", raw)
		}
		switch key {
		case "path":
			pin.Path = val
		case "sha256":
			pin.SHA256 = strings.ToLower(val)
		case "version":
			pin.Version = val
		default:
			return CLIPin{}, fmt.Errorf("cli pin field %q is unknown", key)
		}
	}
	return pin, nil
}

func checkPin(pin CLIPin) error {
	switch pin.Backend {
	case "grok", "claude":
	default:
		return fmt.Errorf("cli pin backend %q is unknown", pin.Backend)
	}
	if pin.Path == "" && pin.SHA256 == "" && pin.Version == "" {
		return fmt.Errorf("cli pin %s needs a path, sha256, or version", pin.Backend)
	}
	if pin.Path != "" && (!filepath.IsAbs(pin.Path) || strings.ContainsAny(pin.Path, "\r\n\x00")) {
		return fmt.Errorf("cli pin %s path must be absolute", pin.Backend)
	}
	if pin.SHA256 != "" && !sha256Hex(pin.SHA256) {
		return fmt.Errorf("cli pin %s sha256 must be 64 hex characters", pin.Backend)
	}
	if pin.Version != "" && !versionToken(pin.Version) {
		return fmt.Errorf("cli pin %s version is invalid", pin.Backend)
	}
	return nil
}

func sha256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// checkCLIROBinds fails closed unless every extra CLI path is an absolute
// path that exists and is safe to mount read-only. An empty list is the
// current jail. The stored list is the cleaned paths.
func (p *Policy) checkCLIROBinds(dataDir string) error {
	if len(p.CLIROBinds) == 0 {
		return nil
	}
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("cli_ro_binds requires a data directory")
	}
	workspace, err := filepath.Abs(filepath.Join(dataDir, "workspace"))
	if err != nil {
		return fmt.Errorf("cli_ro_binds: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return fmt.Errorf("cli_ro_binds requires a home directory")
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return fmt.Errorf("cli_ro_binds: %w", err)
	}
	login := []string{
		filepath.Join(home, ".grok"),
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".claude.json"),
	}
	cleaned := make([]string, 0, len(p.CLIROBinds))
	seen := map[string]bool{}
	for _, raw := range p.CLIROBinds {
		if strings.TrimSpace(raw) == "" || strings.ContainsAny(raw, "\r\n\x00") {
			return fmt.Errorf("cli_ro_binds entry is empty")
		}
		if !filepath.IsAbs(raw) {
			return fmt.Errorf("cli_ro_binds %q must be an absolute path", raw)
		}
		if strings.ContainsAny(raw, "\"\\()") {
			return fmt.Errorf("cli_ro_binds %q contains a reserved character", raw)
		}
		clean := filepath.Clean(raw)
		switch clean {
		case "/usr", "/bin", "/lib", "/lib64", "/etc", "/tmp", "/proc", "/dev", "/lgb-home", "/lgb-proxy":
			return fmt.Errorf("cli_ro_binds %q conflicts with a jail mount", clean)
		}
		if seen[clean] {
			return fmt.Errorf("cli_ro_binds %q is duplicated", clean)
		}
		if err := refuseCLIRO(clean, workspace, login); err != nil {
			return err
		}
		resolved, err := filepath.EvalSymlinks(clean)
		if err != nil {
			return fmt.Errorf("cli_ro_binds %q: %w", clean, err)
		}
		resolved = filepath.Clean(resolved)
		if resolved != clean {
			if err := refuseCLIRO(resolved, workspace, login); err != nil {
				return err
			}
		}
		if _, err := os.Stat(resolved); err != nil {
			return fmt.Errorf("cli_ro_binds %q: %w", clean, err)
		}
		seen[clean] = true
		cleaned = append(cleaned, clean)
	}
	p.CLIROBinds = cleaned
	return nil
}

func refuseCLIRO(path, workspace string, login []string) error {
	if sandbox.RefusedBind(path) {
		return fmt.Errorf("cli_ro_binds %q is refused", path)
	}
	if pathOverlaps(path, workspace) {
		return fmt.Errorf("cli_ro_binds %q overlaps the workspace", path)
	}
	for _, root := range login {
		if pathOverlaps(path, root) {
			return fmt.Errorf("cli_ro_binds %q overlaps a CLI login path", path)
		}
	}
	return nil
}

func pathOverlaps(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if a == b {
		return true
	}
	if rel, err := filepath.Rel(a, b); err == nil && insideRel(rel) {
		return true
	}
	rel, err := filepath.Rel(b, a)
	return err == nil && insideRel(rel)
}

func insideRel(rel string) bool {
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// DLPEnabled reports whether a prompt check is configured.
func (p Policy) DLPEnabled() bool {
	return len(p.DLPPatterns) > 0 || strings.TrimSpace(p.DLPFile) != "" || strings.TrimSpace(p.DLPCommand) != ""
}

func (p Policy) checkDLP() error {
	for _, pattern := range p.DLPPatterns {
		if len(pattern) == 0 || len(pattern) > 256 {
			return fmt.Errorf("dlp pattern is invalid")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("dlp pattern %q: %w", pattern, err)
		}
	}
	if p.DLPFile != "" {
		if !filepath.IsAbs(p.DLPFile) || strings.ContainsAny(p.DLPFile, "\r\n\x00") {
			return fmt.Errorf("dlp_file must be an absolute path")
		}
		body, err := os.ReadFile(p.DLPFile)
		if err != nil {
			return fmt.Errorf("dlp_file: %w", err)
		}
		if len(body) > 64*1024 {
			return fmt.Errorf("dlp_file is too large")
		}
		for i, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			pattern := line
			if strings.HasPrefix(line, "re:") {
				pattern = strings.TrimSpace(strings.TrimPrefix(line, "re:"))
			}
			if len(pattern) == 0 || len(pattern) > 256 {
				return fmt.Errorf("dlp_file line %d is invalid", i+1)
			}
			if strings.HasPrefix(line, "re:") {
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("dlp_file line %d: %w", i+1, err)
				}
			}
		}
	}
	if p.DLPCommand != "" {
		if !filepath.IsAbs(p.DLPCommand) || strings.ContainsAny(p.DLPCommand, "\r\n\x00") {
			return fmt.Errorf("dlp_command must be an absolute path")
		}
		st, err := os.Stat(p.DLPCommand)
		if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
			return fmt.Errorf("dlp_command is not an executable file")
		}
	}
	return nil
}

func checkAudit(dest string) error {
	switch strings.TrimSpace(dest) {
	case "", "stderr", "syslog":
		return nil
	}
	if !filepath.IsAbs(dest) || strings.ContainsAny(dest, "\r\n\x00") {
		return fmt.Errorf("audit_log must be stderr, syslog, or an absolute path")
	}
	return nil
}

func versionToken(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '_', r == '+', r == '-':
		default:
			return false
		}
	}
	return true
}

func lookupProxy(policyKey, upper, lower string) (string, bool) {
	if v, ok := os.LookupEnv(policyKey); ok {
		return strings.TrimSpace(v), true
	}
	if v, ok := os.LookupEnv(upper); ok {
		return strings.TrimSpace(v), true
	}
	if v, ok := os.LookupEnv(lower); ok {
		return strings.TrimSpace(v), true
	}
	return "", false
}

func (p Policy) checkUpstream() error {
	if err := checkProxyURL(p.HTTPProxy); err != nil {
		return fmt.Errorf("http_proxy: %w", err)
	}
	if err := checkProxyURL(p.HTTPSProxy); err != nil {
		return fmt.Errorf("https_proxy: %w", err)
	}
	if p.CLINetwork == NetExplicit && strings.TrimSpace(p.HTTPProxy) == "" && strings.TrimSpace(p.HTTPSProxy) == "" {
		return fmt.Errorf("explicit-proxy requires http_proxy or https_proxy")
	}
	if p.CLINetwork == NetExplicit || strings.TrimSpace(p.HTTPProxy) != "" || strings.TrimSpace(p.HTTPSProxy) != "" {
		if err := checkNoProxy(p.NoProxy); err != nil {
			return fmt.Errorf("no_proxy: %w", err)
		}
	}
	return nil
}

func checkProxyURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00 ") {
		return fmt.Errorf("URL is invalid")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("URL must be http or https")
	}
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		if strings.ContainsAny(user, "\r\n\x00") || strings.ContainsAny(pass, "\r\n\x00") {
			return fmt.Errorf("credentials are not safe")
		}
	}
	return nil
}

func checkNoProxy(raw string) error {
	if strings.ContainsAny(raw, "\r\n\x00/\\") {
		return fmt.Errorf("list is invalid")
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" || part == "*" {
			continue
		}
		host := part
		if h, port, err := net.SplitHostPort(part); err == nil {
			host = h
			if n, nerr := strconv.Atoi(port); nerr != nil || n < 1 || n > 65535 {
				return fmt.Errorf("host %q is invalid", part)
			}
		}
		host = strings.TrimPrefix(host, ".")
		if host == "" || strings.ContainsAny(host, " \t") {
			return fmt.Errorf("host %q is invalid", part)
		}
	}
	return nil
}

func redactProxyURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "redacted"
	}
	return u.Redacted()
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", s)
	}
}

func splitComma(s string) []string {
	return splitList(s, ",")
}

func splitList(s, sep string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}
	}
	var out []string
	for _, p := range strings.Split(s, sep) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func normBackends(in []string) []string {
	out := make([]string, 0, len(in))
	for _, b := range in {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" {
			out = append(out, b)
		}
	}
	return out
}

func normHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(h, ".")))
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}
