// Package policy loads the daemon policy file.
//
// Precedence, highest wins: managed settings, then policy.toml, then built-in
// defaults. A missing or unparseable policy file fail-closes to daemon jail ON
// and CLI backends OFF. A valid managed file still applies over that fallback.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const maxPolicyBytes = 64 * 1024

// Pin is an optional supply-chain check for one CLI binary.
// An empty pin list keeps PATH launch. Prefer path plus SHA-256.
type Pin struct {
	Backend string `toml:"backend" json:"backend"`
	Path    string `toml:"path" json:"path"`
	SHA256  string `toml:"sha256" json:"sha256"`
	Version string `toml:"version" json:"version"`
}

// Policy is the resolved daemon policy.
type Policy struct {
	Backend      string
	CLIPermitted bool
	DaemonJail   bool
	Loaded       bool

	Bind           string
	HasBind        bool
	OllamaHost     string
	HasOllamaHost  bool
	OllamaModel    string
	HasOllamaModel bool
	// OllamaModels empty allows any local model.
	OllamaModels []string
	// Allow empty allows ollama, claude, and grok.
	Allow []string

	Idle           time.Duration
	Imminent       time.Duration
	TurnTimeout    time.Duration
	PermissionMode string
	// ToolAllow, ToolDeny, and ToolAsk are Claude-style tool rules
	// such as "Bash(cat *)".
	ToolAllow []string
	ToolDeny  []string
	ToolAsk   []string
	// UIPrompts lets a connected UI answer a tool check. Off denies
	// the check when no earlier rule resolves it.
	UIPrompts bool
	// PromptTimeout is how long a UI answer may take. Zero means
	// DefaultPromptTimeout.
	PromptTimeout time.Duration
	// OllamaRunTimeout bounds a whole Ollama run. OllamaModelTimeout bounds
	// one model call inside it. Zero means the defaults.
	OllamaRunTimeout   time.Duration
	OllamaModelTimeout time.Duration
	// Max* are ceilings only managed policy sets. Zero means no ceiling.
	// The effective timeout is min(setting or default, ceiling).
	MaxTurnTimeout        time.Duration
	MaxPromptTimeout      time.Duration
	MaxOllamaRunTimeout   time.Duration
	MaxOllamaModelTimeout time.Duration
	// AllowSessionGrants is true only when managed policy set it.
	AllowSessionGrants bool
	// ClaudeTransport is how Claude asks this daemon about a tool.
	// mcp (default) uses the HTTP permission tool. stream_control speaks
	// the stream-json control protocol on stdin. none passes
	// --permission-prompts none and attaches no prompt host.
	ClaudeTransport string
	// ManagedBypass is true only when managed policy set an always-allow mode.
	ManagedBypass bool
	Pins          []Pin
	// CLIOverrides is ignore (the CLI is told not to load workspace config)
	// or refuse (a workspace override file fails the turn).
	CLIOverrides string
	// CLIHome is isolated (a per-bot HOME and config dir under the data dir)
	// or user (the daemon user's own CLI home). Only managed policy sets user.
	CLIHome string
	// CLIClaudeHome is auto (macOS: the user's HOME so the Keychain login is
	// found; elsewhere: isolated), isolated, or user (managed policy only).
	// CLIHome = user still wins for every backend.
	CLIClaudeHome string
	// CLIClaudeSandbox is required (default: Claude's Bash sandbox on, fail
	// closed) or off (managed policy only; the daemon adds no sandbox block).
	CLIClaudeSandbox string
	// CLILGB puts the lgb command (daemon state tools) on a CLI bot's PATH.
	// Default on.
	CLILGB bool
	// CLILGBManageBots lets lgb create and update other bots. Default off.
	CLILGBManageBots bool
	// LGBMinTimerSet is true when policy set cli.lgb.min_timer_interval.
	// LGBMinTimer is that floor. Zero means no floor. When unset, CLI
	// backends use DefaultCLIMinTimer and Ollama uses no floor.
	LGBMinTimerSet bool
	LGBMinTimer    time.Duration
	// LGBMaxSchedSet is true when policy set cli.lgb.max_scheduled_per_hour.
	// LGBMaxSchedPerHour is that cap. Zero means no cap. When unset, CLI
	// backends use DefaultCLIScheduledPerHour and Ollama uses no cap.
	LGBMaxSchedSet     bool
	LGBMaxSchedPerHour int
	// CLIEnv is added to the scrubbed CLI environment. Only managed policy sets it.
	// GROK_* names that select permission or config are refused.
	CLIEnv map[string]string
	// CLITrustSystemConfig is true only when managed policy sets
	// cli.isolation.trust_system_config. Default false: a host file the CLI
	// still reads refuses the turn.
	CLITrustSystemConfig bool
	// NetPorts is the egress port list. Nil means 443 and 80. An empty
	// slice allows no egress port. Local policy can only narrow the list.
	NetPorts           []int
	netPortsAsked      []int
	netPortsAskedSet   bool
	netPortsManaged    []int
	netPortsManagedSet bool
	// ServerTools is the effective allow list of non-function model tool
	// types after managed and local policy. Empty strips every such type.
	// ServerToolsSource is managed, local, or default.
	ServerTools           []string
	ServerToolsSource     string
	serverToolsManaged    []string
	serverToolsManagedSet bool
	serverToolsLocal      []string
	serverToolsLocalSet   bool
	// CLITools are host CLIs the credential broker may run. Empty denies every coi call.
	CLITools []CLITool
	// cliLocal is the local file's CLI table before managed merge.
	cliLocal []cliEntry

	TimersEnabled     bool
	SandboxFailClosed bool
	ConflictPolicy    string

	DLPPatterns []string
	DLPFile     string
	DLPCommand  string
	AuditLog    string
	ManagedPath string

	Warnings []string

	managedBind  bool
	managedHost  bool
	managedModel bool
}

// Options selects the files and the user-level environment to compare
// against managed settings.
type Options struct {
	Path           string
	ManagedPath    string
	EnvBind        string
	EnvOllamaURL   string
	EnvOllamaModel string
}

// Defaults is the built-in policy: Ollama, daemon jail on, CLI allowed only
// when a later layer selects it. Idle kill is 30 minutes with a 2 minute
// user-timer window.
func Defaults() Policy {
	return Policy{
		Backend:           "ollama",
		CLIPermitted:      true,
		DaemonJail:        true,
		Idle:              30 * time.Minute,
		Imminent:          2 * time.Minute,
		PromptTimeout:     DefaultPromptTimeout,
		ClaudeTransport:   TransportMCP,
		CLIOverrides:      OverridesIgnore,
		CLIHome:           HomeIsolated,
		CLIClaudeHome:     HomeAuto,
		CLIClaudeSandbox:  SandboxRequired,
		CLILGB:            true,
		TimersEnabled:     true,
		SandboxFailClosed: true,
		ConflictPolicy:    "refuse",
	}
}

// Load reads policy and optional managed settings.
// A conflict with conflict_policy=refuse is the only returned error.
// Missing or unparseable input fail-closes and is reported in Warnings.
func Load(opts Options) (Policy, error) {
	fallback := func(msg string) Policy {
		p := Defaults()
		p.CLIPermitted = false
		p.DaemonJail = true
		p.Backend = "ollama"
		p.Warnings = []string{msg}
		return p
	}

	path := strings.TrimSpace(opts.Path)
	if path == "" {
		// No file was requested. Built-in defaults stay in force (Ollama, jail on).
		// A configured path that is missing still fail-closes below.
		return overlayManaged(Defaults(), opts, true)
	}
	body, err := readPolicy(path)
	if err != nil {
		msg := fmt.Sprintf("policy file %s is unreadable; fail-closed: daemon jail ON, CLI backends OFF", path)
		if os.IsNotExist(err) {
			msg = fmt.Sprintf("policy file %s is missing; fail-closed: daemon jail ON, CLI backends OFF", path)
		}
		return overlayManaged(fallback(msg), opts, false)
	}
	doc, err := decode(body, path)
	if err != nil {
		p := fallback(fmt.Sprintf("policy file %s is unparseable (%s); fail-closed: daemon jail ON, CLI backends OFF", path, err.Error()))
		return overlayManaged(p, opts, false)
	}
	p := Defaults()
	p.Loaded = true
	p.CLIPermitted = true
	if err := p.apply(doc, false); err != nil {
		p = fallback(fmt.Sprintf("policy file %s is unparseable (%s); fail-closed: daemon jail ON, CLI backends OFF", path, err.Error()))
		return overlayManaged(p, opts, false)
	}
	p.noteEnvOverride(opts)
	return overlayManaged(p, opts, true)
}

func overlayManaged(p Policy, opts Options, fileOK bool) (Policy, error) {
	path := strings.TrimSpace(opts.ManagedPath)
	if path == "" {
		path = strings.TrimSpace(p.ManagedPath)
	}
	if path == "" {
		p.finishEgressPorts()
		p.finishServerTools()
		p.dropIncompleteCLI()
		return p, nil
	}
	body, err := readPolicy(path)
	if err != nil {
		fb := Defaults()
		fb.CLIPermitted = false
		fb.DaemonJail = true
		fb.Backend = "ollama"
		fb.Warnings = []string{fmt.Sprintf("managed policy %s is unreadable; fail-closed: daemon jail ON, CLI backends OFF", path)}
		return fb, nil
	}
	doc, err := decode(body, path)
	if err != nil {
		fb := Defaults()
		fb.CLIPermitted = false
		fb.DaemonJail = true
		fb.Backend = "ollama"
		fb.Warnings = []string{fmt.Sprintf("managed policy %s is unparseable (%s); fail-closed: daemon jail ON, CLI backends OFF", path, err.Error())}
		return fb, nil
	}
	base := p
	if !fileOK {
		base = Defaults()
		base.CLIPermitted = true
		base.Loaded = true
		base.Warnings = []string{"local policy was not applied; managed policy is in effect"}
	}
	if err := base.apply(doc, true); err != nil {
		fb := Defaults()
		fb.CLIPermitted = false
		fb.DaemonJail = true
		fb.Backend = "ollama"
		fb.Warnings = []string{fmt.Sprintf("managed policy %s is unparseable (%s); fail-closed: daemon jail ON, CLI backends OFF", path, err.Error())}
		return fb, nil
	}
	base.markManaged(doc)
	base.Loaded = true
	base.CLIPermitted = true
	if err := base.conflicts(opts); err != nil {
		return Policy{}, err
	}
	base.DaemonJail = !base.UsesCLI()
	base.finishEgressPorts()
	base.finishServerTools()
	base.dropIncompleteCLI()
	return base, nil
}

func (p *Policy) noteEnvOverride(opts Options) {
	if p.HasBind && opts.EnvBind != "" && opts.EnvBind != p.Bind {
		p.Warnings = append(p.Warnings, fmt.Sprintf("BIND_ADDR overridden by policy bind %s", p.Bind))
	}
	if p.HasOllamaHost && opts.EnvOllamaURL != "" && opts.EnvOllamaURL != p.OllamaHost {
		p.Warnings = append(p.Warnings, fmt.Sprintf("OLLAMA_URL overridden by policy host %s", p.OllamaHost))
	}
	if p.HasOllamaModel && opts.EnvOllamaModel != "" && opts.EnvOllamaModel != p.OllamaModel {
		p.Warnings = append(p.Warnings, fmt.Sprintf("OLLAMA_MODEL overridden by policy model %s", p.OllamaModel))
	}
}

func (p *Policy) conflicts(opts Options) error {
	type item struct {
		name string
		env  string
		got  string
		set  bool
	}
	checks := []item{
		{"BIND_ADDR", opts.EnvBind, p.Bind, p.managedBind},
		{"OLLAMA_URL", opts.EnvOllamaURL, p.OllamaHost, p.managedHost},
		{"OLLAMA_MODEL", opts.EnvOllamaModel, p.OllamaModel, p.managedModel},
	}
	var msgs []string
	for _, c := range checks {
		if c.set && strings.TrimSpace(c.env) != "" && c.env != c.got {
			msgs = append(msgs, fmt.Sprintf("%s=%s conflicts with managed value %s", c.name, c.env, c.got))
		}
	}
	if len(msgs) == 0 {
		return nil
	}
	msg := strings.Join(msgs, "; ")
	switch p.ConflictPolicy {
	case "log":
		p.Warnings = append(p.Warnings, "managed policy conflict (log): "+msg)
		return nil
	case "refuse":
		return fmt.Errorf("managed policy conflict: %s", msg)
	default:
		return fmt.Errorf("managed policy conflict: %s", msg)
	}
}

// EffectiveBackend is the backend the daemon will use.
// Fail-closed forces ollama even if a rejected file asked for a CLI.
func (p Policy) EffectiveBackend() string {
	b := strings.ToLower(strings.TrimSpace(p.Backend))
	switch b {
	case "claude", "grok":
		if !p.CLIPermitted {
			return "ollama"
		}
		return b
	default:
		return "ollama"
	}
}

// BotTimerLimits is the floor and hourly cap for timers a bot creates.
// A zero duration or a zero cap means that check is off. Policy values
// apply on every backend. When a key is unset, a CLI backend uses the
// defaults and Ollama uses no limit.
func (p Policy) BotTimerLimits() (min time.Duration, perHour int) {
	if p.LGBMinTimerSet {
		min = p.LGBMinTimer
	} else if p.UsesCLI() {
		min = DefaultCLIMinTimer
	}
	if p.LGBMaxSchedSet {
		perHour = p.LGBMaxSchedPerHour
	} else if p.UsesCLI() {
		perHour = DefaultCLIScheduledPerHour
	}
	return min, perHour
}

// UsesCLI reports whether this turn is a headless CLI process.
// The daemon jail stays off on that path. The CLI's own sandbox, configured by
// the daemon's settings (docs/cli-isolation.md), is the boundary.
func (p Policy) UsesCLI() bool {
	switch p.EffectiveBackend() {
	case "claude", "grok":
		return true
	default:
		return false
	}
}

// AllowsBackend reports whether a turn on backend b is permitted.
func (p Policy) AllowsBackend(b string) bool {
	b = strings.ToLower(strings.TrimSpace(b))
	if b != "ollama" && b != "claude" && b != "grok" {
		return false
	}
	if (b == "claude" || b == "grok") && !p.CLIPermitted {
		return false
	}
	allowed := p.Allow
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == b {
			return true
		}
	}
	return false
}

// AllowsModel checks the optional Ollama model allow-list.
// An empty list allows any model.
func (p Policy) AllowsModel(name string) error {
	if len(p.OllamaModels) == 0 {
		return nil
	}
	for _, m := range p.OllamaModels {
		if m == name {
			return nil
		}
	}
	return fmt.Errorf("ollama model %q is not allowed by policy", name)
}

// DLPEnabled reports whether a prompt scan is configured.
func (p Policy) DLPEnabled() bool {
	return len(p.DLPPatterns) > 0 || strings.TrimSpace(p.DLPFile) != "" || strings.TrimSpace(p.DLPCommand) != ""
}

// Permission is the tool-approval view of a policy.
type Permission struct {
	Mode               string
	Allow              []string
	Deny               []string
	Ask                []string
	UIPrompts          bool
	PromptTimeout      time.Duration
	AllowSessionGrants bool
}

// Default timeouts. Each one is a policy key; see docs/cli-isolation.md.
const (
	DefaultTurnTimeout        = 2 * time.Hour
	DefaultPromptTimeout      = 10 * time.Minute
	DefaultOllamaRunTimeout   = 10 * time.Minute
	DefaultOllamaModelTimeout = 3 * time.Minute
)

func capped(v, def, ceiling time.Duration) time.Duration {
	if v <= 0 {
		v = def
	}
	if ceiling > 0 && v > ceiling {
		v = ceiling
	}
	return v
}

// EffectiveTurnTimeout is the wall clock for one CLI turn: cli.turn_timeout,
// else DefaultTurnTimeout, capped by managed cli.max_turn_timeout.
func (p Policy) EffectiveTurnTimeout() time.Duration {
	return capped(p.TurnTimeout, DefaultTurnTimeout, p.MaxTurnTimeout)
}

// EffectivePromptTimeout is how long a permission or question card waits.
func (p Policy) EffectivePromptTimeout() time.Duration {
	return capped(p.PromptTimeout, DefaultPromptTimeout, p.MaxPromptTimeout)
}

// EffectiveOllamaRunTimeout bounds a whole Ollama run.
func (p Policy) EffectiveOllamaRunTimeout() time.Duration {
	return capped(p.OllamaRunTimeout, DefaultOllamaRunTimeout, p.MaxOllamaRunTimeout)
}

// EffectiveOllamaModelTimeout bounds one Ollama model call.
func (p Policy) EffectiveOllamaModelTimeout() time.Duration {
	return capped(p.OllamaModelTimeout, DefaultOllamaModelTimeout, p.MaxOllamaModelTimeout)
}

// Permission returns tool-approval settings. A non-positive prompt timeout
// is reported as DefaultPromptTimeout; a managed ceiling applies.
func (p Policy) Permission() Permission {
	d := p.EffectivePromptTimeout()
	return Permission{
		Mode:               p.PermissionMode,
		Allow:              append([]string(nil), p.ToolAllow...),
		Deny:               append([]string(nil), p.ToolDeny...),
		Ask:                append([]string(nil), p.ToolAsk...),
		UIPrompts:          p.UIPrompts,
		PromptTimeout:      d,
		AllowSessionGrants: p.AllowSessionGrants,
	}
}

const (
	// TransportMCP is Claude's HTTP permission-prompt tool. It is the default.
	TransportMCP = "mcp"
	// TransportStreamControl speaks can_use_tool on the CLI's stdin/stdout.
	TransportStreamControl = "stream_control"
	// TransportNone passes --permission-prompts none and attaches no host.
	TransportNone = "none"
	// TransportACP is the Grok stdio permission host. It is not a
	// claude_transport value.
	TransportACP = "acp"
)

const (
	// OverridesIgnore tells the CLI not to load workspace config. It is the default.
	OverridesIgnore = "ignore"
	// OverridesRefuse fails the turn when a workspace override file is present.
	OverridesRefuse = "refuse"
	// HomeIsolated gives each bot its own CLI HOME under the data dir. Default.
	HomeIsolated = "isolated"
	// HomeUser runs the CLI with the daemon user's HOME. Managed policy only.
	HomeUser = "user"
	// HomeAuto is the per-OS Claude default: user on darwin, isolated elsewhere.
	HomeAuto = "auto"
	// SandboxRequired turns on Claude's sandbox and fails the turn if it can't run.
	SandboxRequired = "required"
	// SandboxOff leaves Claude's sandbox to the user's managed settings.
	SandboxOff = "off"
	// DefaultCLIMinTimer is the repeating-timer floor for a CLI backend
	// when policy does not set cli.lgb.min_timer_interval.
	DefaultCLIMinTimer = 5 * time.Minute
	// DefaultCLIScheduledPerHour is the per-bot scheduled-turn cap for a
	// CLI backend when policy does not set cli.lgb.max_scheduled_per_hour.
	DefaultCLIScheduledPerHour = 12
)

func (p *Policy) applyIsolation(iso *cliIsoDoc, trusted bool) error {
	if iso.Overrides != nil {
		switch v := strings.ToLower(strings.TrimSpace(*iso.Overrides)); v {
		case "", OverridesIgnore:
			p.CLIOverrides = OverridesIgnore
		case OverridesRefuse:
			p.CLIOverrides = OverridesRefuse
		default:
			return fmt.Errorf("cli.isolation.overrides must be ignore or refuse")
		}
	}
	if iso.Home != nil {
		v := strings.ToLower(strings.TrimSpace(*iso.Home))
		switch v {
		case "", HomeIsolated:
			p.CLIHome = HomeIsolated
		case HomeUser:
			if trusted {
				p.CLIHome = HomeUser
			} else {
				p.Warnings = append(p.Warnings, "cli.isolation.home = \"user\" is ignored; only managed policy can share the user's CLI home")
			}
		default:
			return fmt.Errorf("cli.isolation.home must be isolated or user")
		}
	}
	if iso.ClaudeHome != nil {
		switch v := strings.ToLower(strings.TrimSpace(*iso.ClaudeHome)); v {
		case "", HomeAuto:
			p.CLIClaudeHome = HomeAuto
		case HomeIsolated:
			p.CLIClaudeHome = HomeIsolated
		case HomeUser:
			if trusted {
				p.CLIClaudeHome = HomeUser
			} else {
				p.Warnings = append(p.Warnings, "cli.isolation.claude_home = \"user\" is ignored; only managed policy can share the user's Claude home")
			}
		default:
			return fmt.Errorf("cli.isolation.claude_home must be auto, isolated, or user")
		}
	}
	if iso.ClaudeSandbox != nil {
		switch v := strings.ToLower(strings.TrimSpace(*iso.ClaudeSandbox)); v {
		case "", SandboxRequired:
			p.CLIClaudeSandbox = SandboxRequired
		case SandboxOff:
			if trusted {
				p.CLIClaudeSandbox = SandboxOff
			} else {
				p.Warnings = append(p.Warnings, "cli.isolation.claude_sandbox = \"off\" is ignored; only managed policy can turn off Claude's sandbox")
			}
		default:
			return fmt.Errorf("cli.isolation.claude_sandbox must be required or off")
		}
	}
	if iso.LGB != nil {
		p.CLILGB = *iso.LGB
	}
	if iso.LGBManageBots != nil {
		p.CLILGBManageBots = *iso.LGBManageBots
	}
	if iso.NetPorts != nil {
		ports, err := normPorts(*iso.NetPorts)
		if err != nil {
			return err
		}
		if trusted {
			p.netPortsManaged = ports
			p.netPortsManagedSet = true
		} else {
			p.netPortsAsked = ports
			p.netPortsAskedSet = true
		}
	}
	if iso.TrustSystemConfig != nil {
		if *iso.TrustSystemConfig {
			if trusted {
				p.CLITrustSystemConfig = true
			} else {
				p.Warnings = append(p.Warnings, "cli.isolation.trust_system_config is ignored; only managed policy can trust host CLI config")
			}
		} else {
			p.CLITrustSystemConfig = false
		}
	}
	if iso.Env != nil {
		if !trusted {
			p.Warnings = append(p.Warnings, "cli.isolation.env is ignored; only managed policy can set CLI environment")
			return nil
		}
		env := map[string]string{}
		for k, v := range *iso.Env {
			k = strings.TrimSpace(k)
			if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, 0) {
				return fmt.Errorf("cli.isolation.env has an invalid entry %q", k)
			}
			if BlockedCLIEnv(k) {
				return fmt.Errorf("cli.isolation.env cannot set %s", k)
			}
			env[k] = v
		}
		p.CLIEnv = env
	}
	return nil
}

// BlockedCLIEnv reports a managed environment name that selects CLI
// permission or config. GROK_CONFIG and GROK_CONFIG_* are always blocked.
func BlockedCLIEnv(key string) bool {
	k := strings.ToUpper(strings.TrimSpace(key))
	if k == "GROK_CONFIG" || strings.HasPrefix(k, "GROK_CONFIG_") || k == "GROK_DEFAULT_SELECTED_PERMISSION" {
		return true
	}
	if !strings.HasPrefix(k, "GROK_") {
		return false
	}
	for _, frag := range []string{
		"PERMISSION", "CONFIG", "MODE", "YOLO", "TRUST", "SANDBOX",
		"HOOK", "PLUGIN", "SKILL", "AGENT", "MANAGED", "ALWAYS",
		"REQUIREMENT", "APPROVE", "BYPASS", "HOME",
	} {
		if strings.Contains(k, frag) {
			return true
		}
	}
	return false
}

// DefaultEgressPorts is the built-in CONNECT and forward port list.
func DefaultEgressPorts() []int {
	return []int{443, 80}
}

// EgressPorts is the effective egress port list. Nil policy state means the
// default. An empty list allows no port.
func (p Policy) EgressPorts() []int {
	if p.NetPorts == nil {
		return DefaultEgressPorts()
	}
	out := make([]int, len(p.NetPorts))
	copy(out, p.NetPorts)
	return out
}

func (p *Policy) finishEgressPorts() {
	if p == nil {
		return
	}
	ceiling := DefaultEgressPorts()
	if p.netPortsManagedSet {
		ceiling = p.netPortsManaged
	}
	if !p.netPortsAskedSet {
		if p.netPortsManagedSet {
			p.NetPorts = append([]int(nil), ceiling...)
			if p.NetPorts == nil {
				p.NetPorts = []int{}
			}
		}
		return
	}
	kept, extra := narrowPorts(ceiling, p.netPortsAsked)
	p.NetPorts = kept
	if len(extra) == 0 {
		return
	}
	parts := make([]string, len(extra))
	for i, n := range extra {
		parts[i] = strconv.Itoa(n)
	}
	p.Warnings = append(p.Warnings, "cli.isolation.net_ports "+strings.Join(parts, ", ")+" ignored; local policy can only narrow egress ports")
}

func normPorts(in []int) ([]int, error) {
	out := []int{}
	seen := map[int]bool{}
	for _, n := range in {
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("cli.isolation.net_ports has an invalid port")
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// EffectiveServerTools intersects the policy allow list with a per-bot list.
// botSet false inherits the policy list. A set bot list can only narrow it.
// The source is managed, local, bot, or default: the layer that last reduced
// the set. A lower layer that only tries to add types does not change it.
func (p Policy) EffectiveServerTools(bot []string, botSet bool) ([]string, string) {
	allow := append([]string(nil), p.ServerTools...)
	if allow == nil {
		allow = []string{}
	}
	source := p.ServerToolsSource
	switch source {
	case "managed", "local", "default":
	default:
		source = "default"
	}
	if !botSet {
		return allow, source
	}
	kept, _ := narrowNames(allow, bot)
	if !sameNames(kept, allow) {
		source = "bot"
	}
	return kept, source
}

func (p *Policy) finishServerTools() {
	if p == nil {
		return
	}
	switch {
	case !p.serverToolsManagedSet && !p.serverToolsLocalSet:
		p.ServerTools = []string{}
		p.ServerToolsSource = "default"
	case p.serverToolsManagedSet && !p.serverToolsLocalSet:
		p.ServerTools = append([]string(nil), p.serverToolsManaged...)
		if p.ServerTools == nil {
			p.ServerTools = []string{}
		}
		p.ServerToolsSource = "managed"
	case !p.serverToolsManagedSet && p.serverToolsLocalSet:
		p.ServerTools = append([]string(nil), p.serverToolsLocal...)
		if p.ServerTools == nil {
			p.ServerTools = []string{}
		}
		p.ServerToolsSource = "local"
	default:
		kept, extra := narrowNames(p.serverToolsManaged, p.serverToolsLocal)
		p.ServerTools = kept
		if len(extra) > 0 {
			p.Warnings = append(p.Warnings, "cli.server_tools "+strings.Join(extra, ", ")+" ignored; local policy can only narrow server tools")
		}
		if sameNames(kept, p.serverToolsManaged) {
			p.ServerToolsSource = "managed"
		} else {
			p.ServerToolsSource = "local"
		}
	}
}

// normServerTools checks non-function model tool types. function is rejected.
// Names are matched exactly, in lower case.
func normServerTools(in []string) ([]string, error) {
	if len(in) > 32 {
		return nil, fmt.Errorf("cli.server_tools lists too many names")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			return nil, fmt.Errorf("cli.server_tools contains an empty name")
		}
		if s == "function" {
			return nil, fmt.Errorf("cli.server_tools cannot list function")
		}
		if !serverToolName(s) {
			return nil, fmt.Errorf("cli.server_tools has an invalid name")
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out, nil
}

func serverToolName(s string) bool {
	if s == "" || len(s) > 64 || s[0] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func narrowNames(ceiling, asked []string) (kept, extra []string) {
	have := map[string]bool{}
	for _, n := range ceiling {
		have[n] = true
	}
	want := map[string]bool{}
	for _, n := range asked {
		if !have[n] {
			extra = append(extra, n)
			continue
		}
		want[n] = true
	}
	kept = []string{}
	for _, n := range ceiling {
		if want[n] {
			kept = append(kept, n)
		}
	}
	return kept, extra
}

func sameNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	have := map[string]int{}
	for _, n := range a {
		have[n]++
	}
	for _, n := range b {
		if have[n] == 0 {
			return false
		}
		have[n]--
	}
	return true
}

func narrowPorts(ceiling, asked []int) (kept, extra []int) {
	have := map[int]bool{}
	for _, n := range ceiling {
		have[n] = true
	}
	want := map[int]bool{}
	for _, n := range asked {
		if !have[n] {
			extra = append(extra, n)
			continue
		}
		want[n] = true
	}
	kept = []int{}
	for _, n := range ceiling {
		if want[n] {
			kept = append(kept, n)
		}
	}
	return kept, extra
}

func (p *Policy) applyLGB(doc *cliLGBDoc) error {
	if doc == nil {
		return nil
	}
	if doc.MinTimerInterval != nil {
		d, err := parseMinTimer(*doc.MinTimerInterval)
		if err != nil {
			return err
		}
		p.LGBMinTimerSet = true
		p.LGBMinTimer = d
	}
	if doc.MaxScheduledPerHour != nil {
		if *doc.MaxScheduledPerHour < 0 {
			return fmt.Errorf("cli.lgb.max_scheduled_per_hour must not be negative")
		}
		p.LGBMaxSchedSet = true
		p.LGBMaxSchedPerHour = *doc.MaxScheduledPerHour
	}
	return nil
}

// parseMinTimer accepts a duration such as 5m, 1h, or 1d. Zero (0, 0s, 0d)
// means no floor. Anything shorter than a second, other than zero, is refused.
func parseMinTimer(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("cli.lgb.min_timer_interval is empty")
	}
	if s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") && !strings.ContainsAny(strings.TrimSuffix(s, "d"), "hms.") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("cli.lgb.min_timer_interval must be a duration like 5m, 1h, or 1d, or 0")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("cli.lgb.min_timer_interval must be a duration like 5m, 1h, or 1d, or 0")
	}
	if d > 0 && d < time.Second {
		return 0, fmt.Errorf("cli.lgb.min_timer_interval must be at least 1s, or 0 for no minimum")
	}
	return d, nil
}

// ClaudeUsesUserHome reports whether a Claude turn keeps the user's HOME and
// default config dir on goos. auto picks the user home on darwin, where the
// login lives in the Keychain, and an isolated home elsewhere.
func (p Policy) ClaudeUsesUserHome(goos string) bool {
	if p.CLIHome == HomeUser {
		return true
	}
	switch p.CLIClaudeHome {
	case HomeUser:
		return true
	case HomeIsolated:
		return false
	default:
		return goos == "darwin"
	}
}

// NormClaudeTransport accepts mcp, stream_control, and none.
// An empty value is mcp. Anything else is a config error.
func NormClaudeTransport(v string) (string, error) {
	switch strings.TrimSpace(v) {
	case "", TransportMCP:
		return TransportMCP, nil
	case TransportStreamControl, TransportNone:
		return strings.TrimSpace(v), nil
	default:
		return "", fmt.Errorf("cli.permission.claude_transport must be mcp, stream_control, or none")
	}
}

// IsBypassMode reports an always-allow mode. Those modes are honored only
// when managed policy set them.
func IsBypassMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always", "always-allow", "always_allow", "always-approve",
		"bypass", "bypasspermissions", "dontask", "dont-ask":
		return true
	default:
		return false
	}
}

// CLIPinFor returns the pin that applies to backend, if one was set.
func (p Policy) CLIPinFor(backend string) (Pin, bool) {
	backend = strings.ToLower(strings.TrimSpace(backend))
	for _, pin := range p.Pins {
		if pinMatches(pin, backend) {
			return pin, true
		}
	}
	return Pin{}, false
}

func pinMatches(pin Pin, backend string) bool {
	name := strings.ToLower(strings.TrimSpace(pin.Backend))
	if name == "" && pin.Path != "" {
		name = strings.ToLower(filepath.Base(pin.Path))
	}
	if name == backend {
		return true
	}
	// "claude" matches a binary named "claude-code" only when the backend was set.
	if pin.Backend != "" && strings.HasPrefix(name, backend) {
		return true
	}
	return false
}

func readPolicy(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > maxPolicyBytes {
		return nil, fmt.Errorf("policy file is too large")
	}
	return b, nil
}

func decode(body []byte, path string) (document, error) {
	var doc document
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return document{}, err
		}
		return doc, nil
	}
	dec := toml.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return document{}, err
	}
	return doc, nil
}

type document struct {
	Daemon   daemonDoc   `toml:"daemon" json:"daemon"`
	Backend  backendDoc  `toml:"backend" json:"backend"`
	Ollama   ollamaDoc   `toml:"ollama" json:"ollama"`
	CLI      cliDoc      `toml:"cli" json:"cli"`
	Timers   timersDoc   `toml:"timers" json:"timers"`
	Security securityDoc `toml:"security" json:"security"`
	Managed  managedDoc  `toml:"managed" json:"managed"`
	Tools    toolsDoc    `toml:"tools" json:"tools"`
}

type daemonDoc struct {
	Bind *string `toml:"bind" json:"bind"`
}

type backendDoc struct {
	Backend *string   `toml:"backend" json:"backend"`
	Allow   *[]string `toml:"allow" json:"allow"`
}

type ollamaDoc struct {
	Host            *string   `toml:"host" json:"host"`
	Model           *string   `toml:"model" json:"model"`
	Models          *[]string `toml:"models" json:"models"`
	RunTimeout      flexText  `toml:"run_timeout" json:"run_timeout"`
	ModelTimeout    flexText  `toml:"model_timeout" json:"model_timeout"`
	MaxRunTimeout   flexText  `toml:"max_run_timeout" json:"max_run_timeout"`
	MaxModelTimeout flexText  `toml:"max_model_timeout" json:"max_model_timeout"`
}

type cliDoc struct {
	Idle           *int64      `toml:"idle_timeout_minutes" json:"idle_timeout_minutes"`
	Imminent       *int64      `toml:"imminent_timer_minutes" json:"imminent_timer_minutes"`
	TurnTimeout    flexText    `toml:"turn_timeout" json:"turn_timeout"`
	MaxTurnTimeout flexText    `toml:"max_turn_timeout" json:"max_turn_timeout"`
	PermissionMode *string     `toml:"permission_mode" json:"permission_mode"`
	Permission     *cliPermDoc `toml:"permission" json:"permission"`
	Pins           *[]Pin      `toml:"pins" json:"pins"`
	Isolation      *cliIsoDoc  `toml:"isolation" json:"isolation"`
	LGB            *cliLGBDoc  `toml:"lgb" json:"lgb"`
	// ServerTools lists non-function model tool types a net-granted bot may
	// keep. Empty strips them. Local policy can only narrow a managed list.
	ServerTools *[]string `toml:"server_tools" json:"server_tools"`
}

// cliLGBDoc is [cli.lgb]. Both keys are optional. Zero turns the check off.
type cliLGBDoc struct {
	MinTimerInterval    *string `toml:"min_timer_interval" json:"min_timer_interval"`
	MaxScheduledPerHour *int    `toml:"max_scheduled_per_hour" json:"max_scheduled_per_hour"`
}

type cliIsoDoc struct {
	Overrides         *string            `toml:"overrides" json:"overrides"`
	Home              *string            `toml:"home" json:"home"`
	ClaudeHome        *string            `toml:"claude_home" json:"claude_home"`
	ClaudeSandbox     *string            `toml:"claude_sandbox" json:"claude_sandbox"`
	LGB               *bool              `toml:"lgb" json:"lgb"`
	LGBManageBots     *bool              `toml:"lgb_manage_bots" json:"lgb_manage_bots"`
	Env               *map[string]string `toml:"env" json:"env"`
	NetPorts          *[]int             `toml:"net_ports" json:"net_ports"`
	TrustSystemConfig *bool              `toml:"trust_system_config" json:"trust_system_config"`
}

type cliPermDoc struct {
	Mode               *string   `toml:"mode" json:"mode"`
	Allow              *[]string `toml:"allow" json:"allow"`
	Deny               *[]string `toml:"deny" json:"deny"`
	Ask                *[]string `toml:"ask" json:"ask"`
	UIPrompts          *bool     `toml:"ui_prompts" json:"ui_prompts"`
	PromptTimeout      flexText  `toml:"prompt_timeout" json:"prompt_timeout"`
	MaxPromptTimeout   flexText  `toml:"max_prompt_timeout" json:"max_prompt_timeout"`
	AllowSessionGrants *bool     `toml:"allow_session_grants" json:"allow_session_grants"`
	ClaudeTransport    *string   `toml:"claude_transport" json:"claude_transport"`
}

type timersDoc struct {
	Enabled *bool `toml:"enabled" json:"enabled"`
}

type securityDoc struct {
	FailClosed  *bool     `toml:"fail_closed" json:"fail_closed"`
	Conflict    *string   `toml:"conflict_policy" json:"conflict_policy"`
	DLPPatterns *[]string `toml:"dlp_patterns" json:"dlp_patterns"`
	DLPFile     *string   `toml:"dlp_file" json:"dlp_file"`
	DLPCommand  *string   `toml:"dlp_command" json:"dlp_command"`
	AuditLog    *string   `toml:"audit_log" json:"audit_log"`
}

type managedDoc struct {
	Path *string `toml:"managed_path" json:"managed_path"`
}

// flexText accepts a TOML/JSON string or number for turn_timeout.
type flexText struct {
	Set   bool
	Value string
}

func (f *flexText) UnmarshalText(b []byte) error {
	f.Set = true
	s := strings.TrimSpace(string(b))
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		u, err := strconv.Unquote(s)
		if err != nil {
			// TOML single quotes are literal. Strip them.
			if s[0] == '\'' {
				f.Value = s[1 : len(s)-1]
				return nil
			}
			return err
		}
		f.Value = u
		return nil
	}
	f.Value = s
	return nil
}

func (f *flexText) UnmarshalJSON(b []byte) error {
	f.Set = true
	if string(b) == "null" {
		f.Value = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &f.Value)
	}
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return fmt.Errorf("turn_timeout must be a duration or a number of seconds")
	}
	f.Value = n.String()
	return nil
}

func (p *Policy) apply(doc document, trusted bool) error {
	if doc.Daemon.Bind != nil {
		v := strings.TrimSpace(*doc.Daemon.Bind)
		if v == "" {
			return fmt.Errorf("daemon.bind is empty")
		}
		p.Bind = v
		p.HasBind = true
	}
	if doc.Backend.Backend != nil {
		b := strings.ToLower(strings.TrimSpace(*doc.Backend.Backend))
		switch b {
		case "ollama", "claude", "grok":
			p.Backend = b
		default:
			return fmt.Errorf("backend must be ollama, claude, or grok")
		}
	}
	if doc.Backend.Allow != nil {
		allow, err := normBackends(*doc.Backend.Allow)
		if err != nil {
			return err
		}
		p.Allow = allow
	}
	if doc.Ollama.Host != nil {
		v := strings.TrimSpace(*doc.Ollama.Host)
		if v == "" || !strings.Contains(v, "://") {
			return fmt.Errorf("ollama.host must be an absolute URL")
		}
		p.OllamaHost = v
		p.HasOllamaHost = true
	}
	if doc.Ollama.Model != nil {
		v := strings.TrimSpace(*doc.Ollama.Model)
		if v == "" {
			return fmt.Errorf("ollama.model is empty")
		}
		p.OllamaModel = v
		p.HasOllamaModel = true
	}
	if doc.Ollama.Models != nil {
		var models []string
		for _, m := range *doc.Ollama.Models {
			m = strings.TrimSpace(m)
			if m == "" {
				return fmt.Errorf("ollama.models contains an empty name")
			}
			models = append(models, m)
		}
		p.OllamaModels = models
	}
	if doc.CLI.Idle != nil {
		if *doc.CLI.Idle <= 0 {
			return fmt.Errorf("idle_timeout_minutes must be positive")
		}
		p.Idle = time.Duration(*doc.CLI.Idle) * time.Minute
	}
	if doc.CLI.Imminent != nil {
		if *doc.CLI.Imminent < 0 {
			return fmt.Errorf("imminent_timer_minutes must not be negative")
		}
		p.Imminent = time.Duration(*doc.CLI.Imminent) * time.Minute
	}
	if doc.CLI.TurnTimeout.Set {
		d, err := parseTurnTimeout(doc.CLI.TurnTimeout.Value)
		if err != nil {
			return err
		}
		p.TurnTimeout = d
	}
	timeouts := []struct {
		key     string
		f       flexText
		dst     *time.Duration
		managed bool
	}{
		{"ollama.run_timeout", doc.Ollama.RunTimeout, &p.OllamaRunTimeout, false},
		{"ollama.model_timeout", doc.Ollama.ModelTimeout, &p.OllamaModelTimeout, false},
		{"ollama.max_run_timeout", doc.Ollama.MaxRunTimeout, &p.MaxOllamaRunTimeout, true},
		{"ollama.max_model_timeout", doc.Ollama.MaxModelTimeout, &p.MaxOllamaModelTimeout, true},
		{"cli.max_turn_timeout", doc.CLI.MaxTurnTimeout, &p.MaxTurnTimeout, true},
	}
	if doc.CLI.Permission != nil {
		timeouts = append(timeouts, struct {
			key     string
			f       flexText
			dst     *time.Duration
			managed bool
		}{"cli.permission.max_prompt_timeout", doc.CLI.Permission.MaxPromptTimeout, &p.MaxPromptTimeout, true})
	}
	for _, t := range timeouts {
		if !t.f.Set {
			continue
		}
		d, err := parseTurnTimeout(t.f.Value)
		if err != nil {
			return fmt.Errorf("%s: %w", t.key, err)
		}
		if t.managed && !trusted {
			p.Warnings = append(p.Warnings, t.key+" is ignored; only managed policy can set a timeout ceiling")
			continue
		}
		*t.dst = d
	}
	if doc.CLI.PermissionMode != nil {
		p.setMode(*doc.CLI.PermissionMode, trusted)
	}
	if perm := doc.CLI.Permission; perm != nil {
		if perm.Mode != nil {
			p.setMode(*perm.Mode, trusted)
		}
		if perm.Allow != nil {
			rules, err := normRules(*perm.Allow)
			if err != nil {
				return err
			}
			p.ToolAllow = rules
		}
		if perm.Deny != nil {
			rules, err := normRules(*perm.Deny)
			if err != nil {
				return err
			}
			p.ToolDeny = rules
		}
		if perm.Ask != nil {
			rules, err := normRules(*perm.Ask)
			if err != nil {
				return err
			}
			p.ToolAsk = rules
		}
		if perm.UIPrompts != nil {
			p.UIPrompts = *perm.UIPrompts
		}
		if perm.PromptTimeout.Set {
			d, err := parseTurnTimeout(perm.PromptTimeout.Value)
			if err != nil {
				return fmt.Errorf("prompt_timeout: %w", err)
			}
			p.PromptTimeout = d
		}
		if perm.AllowSessionGrants != nil {
			if trusted {
				p.AllowSessionGrants = *perm.AllowSessionGrants
			} else if *perm.AllowSessionGrants {
				p.Warnings = append(p.Warnings, "allow_session_grants is ignored; only managed policy can enable session grants")
			}
		}
		if perm.ClaudeTransport != nil {
			v, err := NormClaudeTransport(*perm.ClaudeTransport)
			if err != nil {
				return err
			}
			p.ClaudeTransport = v
		}
	}
	if iso := doc.CLI.Isolation; iso != nil {
		if err := p.applyIsolation(iso, trusted); err != nil {
			return err
		}
	}
	if err := p.applyLGB(doc.CLI.LGB); err != nil {
		return err
	}
	if doc.CLI.Pins != nil {
		pins, err := normPins(*doc.CLI.Pins)
		if err != nil {
			return err
		}
		p.Pins = pins
	}
	if doc.CLI.ServerTools != nil {
		names, err := normServerTools(*doc.CLI.ServerTools)
		if err != nil {
			return err
		}
		if trusted {
			p.serverToolsManaged = names
			p.serverToolsManagedSet = true
		} else {
			p.serverToolsLocal = names
			p.serverToolsLocalSet = true
		}
	}
	if doc.Timers.Enabled != nil {
		p.TimersEnabled = *doc.Timers.Enabled
	}
	if doc.Security.FailClosed != nil {
		p.SandboxFailClosed = *doc.Security.FailClosed
	}
	if doc.Security.Conflict != nil {
		v := strings.ToLower(strings.TrimSpace(*doc.Security.Conflict))
		switch v {
		case "refuse", "log":
			p.ConflictPolicy = v
		default:
			return fmt.Errorf("conflict_policy must be refuse or log")
		}
	}
	if doc.Security.DLPPatterns != nil {
		for _, pat := range *doc.Security.DLPPatterns {
			if strings.TrimSpace(pat) == "" {
				return fmt.Errorf("dlp_patterns contains an empty pattern")
			}
		}
		p.DLPPatterns = append([]string(nil), (*doc.Security.DLPPatterns)...)
	}
	if doc.Security.DLPFile != nil {
		v := strings.TrimSpace(*doc.Security.DLPFile)
		if v != "" && !filepath.IsAbs(v) {
			return fmt.Errorf("dlp_file must be an absolute path")
		}
		p.DLPFile = v
	}
	if doc.Security.DLPCommand != nil {
		v := strings.TrimSpace(*doc.Security.DLPCommand)
		if v != "" && !filepath.IsAbs(v) {
			return fmt.Errorf("dlp_command must be an absolute path")
		}
		p.DLPCommand = v
	}
	if doc.Security.AuditLog != nil {
		v := strings.TrimSpace(*doc.Security.AuditLog)
		switch v {
		case "", "stderr", "syslog":
		default:
			if !filepath.IsAbs(v) {
				return fmt.Errorf("audit_log must be stderr, syslog, or an absolute path")
			}
		}
		p.AuditLog = v
	}
	if err := p.applyCLITools(doc.Tools, trusted); err != nil {
		return err
	}
	if doc.Managed.Path != nil {
		v := strings.TrimSpace(*doc.Managed.Path)
		if v != "" && !filepath.IsAbs(v) {
			return fmt.Errorf("managed_path must be an absolute path")
		}
		p.ManagedPath = v
	}
	p.DaemonJail = !p.UsesCLI()
	return nil
}

// markManaged records which identity fields the managed document set.
// apply clears the flags when a value is copied; the caller sets them after.
func (p *Policy) setMode(mode string, trusted bool) {
	mode = strings.TrimSpace(mode)
	if mode == "" {
		p.PermissionMode = ""
		if trusted {
			p.ManagedBypass = false
		}
		return
	}
	if IsBypassMode(mode) {
		if !trusted {
			p.Warnings = append(p.Warnings, fmt.Sprintf("permission mode %q is ignored; only managed policy can set an always-allow mode", mode))
			return
		}
		p.PermissionMode = mode
		p.ManagedBypass = true
		return
	}
	p.PermissionMode = mode
	p.ManagedBypass = false
}

func (p *Policy) markManaged(doc document) {
	if doc.Daemon.Bind != nil {
		p.managedBind = true
	}
	if doc.Ollama.Host != nil {
		p.managedHost = true
	}
	if doc.Ollama.Model != nil {
		p.managedModel = true
	}
}

func normBackends(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, b := range in {
		b = strings.ToLower(strings.TrimSpace(b))
		switch b {
		case "ollama", "claude", "grok":
		default:
			return nil, fmt.Errorf("backend allow-list has %q", b)
		}
		if seen[b] {
			continue
		}
		seen[b] = true
		out = append(out, b)
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// CanonicalRule collapses runs of whitespace and trims a permission pattern.
// "Bash(cat  *)" is the same rule as "Bash(cat *)". A newline or a NUL is
// rejected rather than folded into the pattern. The result is what is stored,
// compared, and matched.
func CanonicalRule(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", fmt.Errorf("permission rule contains a newline")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("permission rule is empty")
	}
	s = strings.Join(strings.Fields(s), " ")
	s = strings.ReplaceAll(s, "( ", "(")
	s = strings.ReplaceAll(s, " )", ")")
	if s == "" {
		return "", fmt.Errorf("permission rule is empty")
	}
	return s, nil
}

func normRules(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, rule := range in {
		rule, err := CanonicalRule(rule)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

func normPins(in []Pin) ([]Pin, error) {
	var out []Pin
	for _, pin := range in {
		pin.Backend = strings.ToLower(strings.TrimSpace(pin.Backend))
		pin.Path = strings.TrimSpace(pin.Path)
		pin.SHA256 = strings.ToLower(strings.TrimSpace(pin.SHA256))
		pin.Version = strings.TrimSpace(pin.Version)
		if pin.Backend != "" {
			switch pin.Backend {
			case "claude", "grok", "ollama":
			default:
				return nil, fmt.Errorf("cli pin backend %q is unknown", pin.Backend)
			}
		}
		if pin.Path != "" && !filepath.IsAbs(pin.Path) {
			return nil, fmt.Errorf("cli pin path must be absolute")
		}
		if pin.SHA256 != "" && !hex64(pin.SHA256) {
			return nil, fmt.Errorf("cli pin sha256 must be 64 hex characters")
		}
		if pin.Path == "" && pin.SHA256 == "" && pin.Version == "" {
			return nil, fmt.Errorf("cli pin is empty")
		}
		out = append(out, pin)
	}
	return out, nil
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func parseTurnTimeout(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("turn_timeout must be positive")
		}
		d := time.Duration(n) * time.Second
		if d > 24*time.Hour {
			return 0, fmt.Errorf("turn_timeout exceeds 24h")
		}
		return d, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("turn_timeout must be seconds or a Go duration")
	}
	if d > 24*time.Hour {
		return 0, fmt.Errorf("turn_timeout exceeds 24h")
	}
	return d, nil
}
