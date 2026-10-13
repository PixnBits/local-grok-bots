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
	"strings"
)

const (
	// NetOpen leaves the CLI network as it is today.
	NetOpen = "open"
	// NetProxy sends CLI TCP through the sandbox allowlist proxy.
	NetProxy = "proxy"
	// NetNone gives the CLI no network and no proxy.
	NetNone = "none"
)

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
	return p, nil
}

// Validate fails closed on a policy this daemon cannot enforce.
func (p Policy) Validate(modelURL string, proxyAvailable bool) error {
	switch p.CLINetwork {
	case NetOpen, NetNone:
	case NetProxy:
		if !proxyAvailable {
			return fmt.Errorf("cli_network proxy is not available in this build")
		}
	default:
		return fmt.Errorf("cli_network must be open, proxy, or none")
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

// Line is the policy as one JSON line. Allowlisted values are not included.
func (p Policy) Line() string {
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// BlockedEnv reports names the jail sets itself or must never receive.
func BlockedEnv(name string) bool {
	switch strings.ToUpper(name) {
	case "XAI_API_KEY", "ANTHROPIC_API_KEY", "SSH_AUTH_SOCK",
		"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
		"LGB_PROXY_SOCK", "LGB_KEY",
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
	return nil
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
