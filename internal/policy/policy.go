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
	Pins           []Pin

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
	if err := p.apply(doc); err != nil {
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
	if err := base.apply(doc); err != nil {
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

// UsesCLI reports whether this turn is a headless CLI process.
// The daemon jail stays off on that path. The CLI's own sandbox is the boundary.
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
}

type daemonDoc struct {
	Bind *string `toml:"bind" json:"bind"`
}

type backendDoc struct {
	Backend *string   `toml:"backend" json:"backend"`
	Allow   *[]string `toml:"allow" json:"allow"`
}

type ollamaDoc struct {
	Host   *string   `toml:"host" json:"host"`
	Model  *string   `toml:"model" json:"model"`
	Models *[]string `toml:"models" json:"models"`
}

type cliDoc struct {
	Idle           *int64   `toml:"idle_timeout_minutes" json:"idle_timeout_minutes"`
	Imminent       *int64   `toml:"imminent_timer_minutes" json:"imminent_timer_minutes"`
	TurnTimeout    flexText `toml:"turn_timeout" json:"turn_timeout"`
	PermissionMode *string  `toml:"permission_mode" json:"permission_mode"`
	Pins           *[]Pin   `toml:"pins" json:"pins"`
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

func (p *Policy) apply(doc document) error {
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
	if doc.CLI.PermissionMode != nil {
		p.PermissionMode = strings.TrimSpace(*doc.CLI.PermissionMode)
	}
	if doc.CLI.Pins != nil {
		pins, err := normPins(*doc.CLI.Pins)
		if err != nil {
			return err
		}
		p.Pins = pins
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
