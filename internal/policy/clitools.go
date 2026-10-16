package policy

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// CLITool is one host CLI the credential broker may run.
// A zero Timeout, MaxOutput, or MaxCallsPerHour denies every call.
type CLITool struct {
	Name            string
	Path            string
	AllowedArgs     []string
	ValueFlags      []string
	CredentialFiles []string
	FixedArgs       []string
	FixedEnv        []string
	SandboxBin      string
	CredentialHome  string
	Bots            []string
	Timeout         time.Duration
	MaxOutput       int64
	MaxCallsPerHour int
	Lock            bool
}

// AllowsBot reports whether id or name is on the grant list.
// The match is exact. An empty list grants nobody.
func (t CLITool) AllowsBot(id, name string) bool {
	for _, b := range t.Bots {
		if b == id || (name != "" && b == name) {
			return true
		}
	}
	return false
}

// COI returns the CLI entry named name.
func (p Policy) COI(name string) (CLITool, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, t := range p.CLITools {
		if t.Name == name {
			return t, true
		}
	}
	return CLITool{}, false
}

// cliEntry is a parsed [[tools.cli]] row. Set flags distinguish an omitted
// field from an explicit zero so local policy can leave a managed value alone.
type cliEntry struct {
	tool       CLITool
	argsSet    bool
	botsSet    bool
	timeoutSet bool
	outputSet  bool
	callsSet   bool
	pathSet    bool
	homeSet    bool
}

type toolsDoc struct {
	CLI        []cliToolDoc `toml:"cli" json:"cli"`
	Ban        *[]string    `toml:"cli_ban" json:"cli_ban"`
	AllowLocal *bool        `toml:"cli_allow_local" json:"cli_allow_local"`
}

func (d toolsDoc) configured() bool {
	return d.CLI != nil || d.Ban != nil || d.AllowLocal != nil
}

type cliToolDoc struct {
	Name            string   `toml:"name" json:"name"`
	Path            string   `toml:"path" json:"path"`
	AllowedArgs     []string `toml:"allowed_args" json:"allowed_args"`
	CredentialHome  string   `toml:"credential_home" json:"credential_home"`
	Bots            []string `toml:"bots" json:"bots"`
	Timeout         *string  `toml:"timeout" json:"timeout"`
	MaxOutput       *int64   `toml:"max_output" json:"max_output"`
	MaxCallsPerHour *int     `toml:"max_calls_per_hour" json:"max_calls_per_hour"`
	Lock            *bool    `toml:"lock" json:"lock"`
}

func (p *Policy) applyCLITools(doc toolsDoc, trusted bool) error {
	if !doc.configured() {
		return nil
	}
	if !trusted {
		if doc.Ban != nil {
			p.Warnings = append(p.Warnings, "tools.cli_ban is ignored; only managed policy can ban a cli")
		}
		if doc.AllowLocal != nil {
			p.Warnings = append(p.Warnings, "tools.cli_allow_local is ignored; only managed policy can forbid local cli entries")
		}
	}
	entries, err := parseCLITools(doc.CLI, trusted)
	if err != nil {
		return err
	}
	if !trusted {
		for i := range entries {
			if entries[i].tool.Lock {
				p.Warnings = append(p.Warnings, fmt.Sprintf("tools.cli %q lock is ignored; only managed policy can lock an entry", entries[i].tool.Name))
				entries[i].tool.Lock = false
			}
		}
		p.cliLocal = entries
		p.CLITools = resolvedCLI(entries)
		return nil
	}
	allowLocal := true
	if doc.AllowLocal != nil {
		allowLocal = *doc.AllowLocal
	}
	merged, warns := mergeCLITools(entries, p.cliLocal, normBan(doc.Ban), allowLocal)
	p.Warnings = append(p.Warnings, warns...)
	p.CLITools = merged
	return nil
}

func (p *Policy) dropIncompleteCLI() {
	if len(p.CLITools) == 0 {
		return
	}
	out := make([]CLITool, 0, len(p.CLITools))
	for _, t := range p.CLITools {
		if t.Name == "" || !filepath.IsAbs(t.Path) || !filepath.IsAbs(t.CredentialHome) {
			name := t.Name
			if name == "" {
				name = "(unnamed)"
			}
			p.Warnings = append(p.Warnings, fmt.Sprintf("tools.cli %q dropped; a cli entry needs an absolute path and credential_home", name))
			continue
		}
		out = append(out, t)
	}
	p.CLITools = out
}

func resolvedCLI(entries []cliEntry) []CLITool {
	out := make([]CLITool, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.tool)
	}
	return out
}

func parseCLITools(rows []cliToolDoc, requireComplete bool) ([]cliEntry, error) {
	if rows == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]cliEntry, 0, len(rows))
	for _, row := range rows {
		e, err := parseCLITool(row, requireComplete)
		if err != nil {
			return nil, err
		}
		if seen[e.tool.Name] {
			return nil, fmt.Errorf("tools.cli %q is listed more than once", e.tool.Name)
		}
		seen[e.tool.Name] = true
		out = append(out, e)
	}
	return out, nil
}

func parseCLITool(row cliToolDoc, requireComplete bool) (cliEntry, error) {
	name := strings.ToLower(strings.TrimSpace(row.Name))
	if !cliNameOK(name) {
		return cliEntry{}, fmt.Errorf("tools.cli name %q must be lowercase letters, digits, '_' or '-'", row.Name)
	}
	e := cliEntry{tool: CLITool{Name: name}}
	if row.Path != "" {
		path, err := absPolicyPath("tools.cli "+name+" path", row.Path)
		if err != nil {
			return cliEntry{}, err
		}
		e.tool.Path = path
		e.pathSet = true
	} else if requireComplete {
		return cliEntry{}, fmt.Errorf("tools.cli %q needs an absolute path", name)
	}
	if row.CredentialHome != "" {
		home, err := absPolicyPath("tools.cli "+name+" credential_home", row.CredentialHome)
		if err != nil {
			return cliEntry{}, err
		}
		e.tool.CredentialHome = home
		e.homeSet = true
	} else if requireComplete {
		return cliEntry{}, fmt.Errorf("tools.cli %q needs an absolute credential_home", name)
	}
	if row.AllowedArgs != nil {
		args, err := normCLIArgs(name, row.AllowedArgs)
		if err != nil {
			return cliEntry{}, err
		}
		e.tool.AllowedArgs = args
		e.argsSet = true
	}
	if row.Bots != nil {
		bots, err := normCLIBots(name, row.Bots)
		if err != nil {
			return cliEntry{}, err
		}
		e.tool.Bots = bots
		e.botsSet = true
	}
	if row.Timeout != nil {
		d, err := parseCLIDuration(*row.Timeout)
		if err != nil {
			return cliEntry{}, fmt.Errorf("tools.cli %q timeout: %w", name, err)
		}
		if d > time.Hour {
			return cliEntry{}, fmt.Errorf("tools.cli %q timeout must be at most 1h", name)
		}
		e.tool.Timeout = d
		e.timeoutSet = true
	}
	if row.MaxOutput != nil {
		if *row.MaxOutput < 0 {
			return cliEntry{}, fmt.Errorf("tools.cli %q max_output must not be negative", name)
		}
		if *row.MaxOutput > 8<<20 {
			return cliEntry{}, fmt.Errorf("tools.cli %q max_output must be at most 8 MiB", name)
		}
		e.tool.MaxOutput = *row.MaxOutput
		e.outputSet = true
	}
	if row.MaxCallsPerHour != nil {
		if *row.MaxCallsPerHour < 0 {
			return cliEntry{}, fmt.Errorf("tools.cli %q max_calls_per_hour must not be negative", name)
		}
		e.tool.MaxCallsPerHour = *row.MaxCallsPerHour
		e.callsSet = true
	}
	if row.Lock != nil && *row.Lock {
		e.tool.Lock = true
	}
	return e, nil
}

func cliNameOK(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func absPolicyPath(label, p string) (string, error) {
	p = strings.TrimSpace(p)
	if strings.ContainsRune(p, 0) || !filepath.IsAbs(p) {
		return "", fmt.Errorf("%s must be an absolute path", label)
	}
	return filepath.Clean(p), nil
}

func normCLIArgs(name string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" || strings.ContainsRune(a, 0) {
			return nil, fmt.Errorf("tools.cli %q has an empty allowed argument", name)
		}
		k := strings.ToLower(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out, nil
}

func normCLIBots(name string, in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, b := range in {
		b = strings.TrimSpace(b)
		if b == "" || strings.ContainsAny(b, "\r\n\x00") {
			return nil, fmt.Errorf("tools.cli %q has an empty bot grant", name)
		}
		if seen[b] {
			continue
		}
		seen[b] = true
		out = append(out, b)
	}
	return out, nil
}

func normBan(in *[]string) map[string]bool {
	if in == nil {
		return nil
	}
	out := map[string]bool{}
	for _, n := range *in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			out[n] = true
		}
	}
	return out
}

func parseCLIDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if s == "0" {
		return 0, nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("must not be negative")
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("must be seconds or a Go duration")
	}
	return d, nil
}

func mergeCLITools(managed, local []cliEntry, ban map[string]bool, allowLocal bool) ([]CLITool, []string) {
	localBy := map[string]cliEntry{}
	var localOrder []cliEntry
	for _, e := range local {
		localBy[e.tool.Name] = e
		localOrder = append(localOrder, e)
	}
	var warns []string
	seen := map[string]bool{}
	out := make([]CLITool, 0, len(managed)+len(local))
	for _, m := range managed {
		seen[m.tool.Name] = true
		loc, hasLocal := localBy[m.tool.Name]
		if !hasLocal {
			out = append(out, m.tool)
			continue
		}
		if ban[m.tool.Name] {
			warns = append(warns, fmt.Sprintf("tools.cli %q dropped; managed policy bans that name", m.tool.Name))
			out = append(out, m.tool)
			continue
		}
		if m.tool.Lock {
			warns = append(warns, fmt.Sprintf("tools.cli %q is locked; local changes were ignored", m.tool.Name))
			out = append(out, m.tool)
			continue
		}
		out = append(out, narrowCLI(m, loc, &warns))
	}
	for _, loc := range localOrder {
		if seen[loc.tool.Name] {
			continue
		}
		if ban[loc.tool.Name] {
			warns = append(warns, fmt.Sprintf("tools.cli %q dropped; managed policy bans that name", loc.tool.Name))
			continue
		}
		if !allowLocal {
			warns = append(warns, fmt.Sprintf("tools.cli %q ignored; managed policy does not allow local cli entries", loc.tool.Name))
			continue
		}
		out = append(out, loc.tool)
	}
	return out, warns
}

func narrowCLI(managed, local cliEntry, warns *[]string) CLITool {
	out := managed.tool
	name := managed.tool.Name
	if local.pathSet && local.tool.Path != managed.tool.Path {
		*warns = append(*warns, fmt.Sprintf("tools.cli %q path ignored; local policy cannot change a managed cli", name))
	}
	if local.homeSet && local.tool.CredentialHome != managed.tool.CredentialHome {
		*warns = append(*warns, fmt.Sprintf("tools.cli %q credential_home ignored; local policy cannot change a managed cli", name))
	}
	if local.argsSet {
		kept, extra := narrowList(managed.tool.AllowedArgs, local.tool.AllowedArgs, true)
		out.AllowedArgs = kept
		if len(extra) > 0 {
			*warns = append(*warns, fmt.Sprintf("tools.cli %q allowed_args %s ignored; local policy can only narrow managed policy", name, strings.Join(extra, ", ")))
		}
	}
	if local.botsSet {
		kept, extra := narrowList(managed.tool.Bots, local.tool.Bots, false)
		out.Bots = kept
		if len(extra) > 0 {
			*warns = append(*warns, fmt.Sprintf("tools.cli %q bots %s ignored; local policy can only narrow managed policy", name, strings.Join(extra, ", ")))
		}
	}
	if local.timeoutSet {
		next, raised := narrowLimit(managed.tool.Timeout, local.tool.Timeout)
		out.Timeout = next
		if raised {
			*warns = append(*warns, fmt.Sprintf("tools.cli %q timeout ignored; local policy can only lower a managed limit", name))
		}
	}
	if local.outputSet {
		next, raised := narrowLimit(time.Duration(managed.tool.MaxOutput), time.Duration(local.tool.MaxOutput))
		out.MaxOutput = int64(next)
		if raised {
			*warns = append(*warns, fmt.Sprintf("tools.cli %q max_output ignored; local policy can only lower a managed limit", name))
		}
	}
	if local.callsSet {
		next, raised := narrowLimit(time.Duration(managed.tool.MaxCallsPerHour), time.Duration(local.tool.MaxCallsPerHour))
		out.MaxCallsPerHour = int(next)
		if raised {
			*warns = append(*warns, fmt.Sprintf("tools.cli %q max_calls_per_hour ignored; local policy can only lower a managed limit", name))
		}
	}
	return out
}

// narrowLimit keeps the managed ceiling when local tries to raise it.
// A managed zero is already a denial; a higher local value does not lift it.
func narrowLimit(managed, local time.Duration) (time.Duration, bool) {
	if managed > 0 && local > managed {
		return managed, true
	}
	if managed == 0 && local > 0 {
		return 0, true
	}
	return local, false
}

// narrowList returns the managed values that local also names, in managed order.
// fold compares arguments case-insensitively. Bots stay case-sensitive.
func narrowList(managed, local []string, fold bool) (kept, extra []string) {
	have := map[string]string{}
	var order []string
	for _, m := range managed {
		k := listKey(m, fold)
		if _, ok := have[k]; ok {
			continue
		}
		have[k] = m
		order = append(order, k)
	}
	want := map[string]bool{}
	for _, l := range local {
		k := listKey(l, fold)
		if _, ok := have[k]; !ok {
			extra = append(extra, l)
			continue
		}
		want[k] = true
	}
	for _, k := range order {
		if want[k] {
			kept = append(kept, have[k])
		}
	}
	if kept == nil {
		kept = []string{}
	}
	return kept, extra
}

func listKey(s string, fold bool) string {
	if fold {
		return strings.ToLower(s)
	}
	return s
}
