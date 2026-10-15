package clisession

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Grants are the bot's daemon grants, mapped onto the CLI's own controls.
type Grants struct {
	Net      bool
	NetAllow []string
	Git      bool
	SSH      bool
}

// credentialPaths are under the user's real HOME. Both CLIs' tools and
// shells are denied them; the CLI process itself still finds its login.
var credentialPaths = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".docker/config.json",
	".kube", ".config/gcloud", ".azure", ".claude/.credentials.json", ".grok/auth.json",
}

// grokSkipDeny are credential paths a Grok deny list leaves out: Grok reads
// its own login from them.
var grokSkipDeny = map[string]bool{".grok/auth.json": true}

// protectedPaths lists absolute paths to deny, from the user's HOME and the
// daemon's own secrets.
func protectedPaths(userHome string, extra []string, skip map[string]bool) []string {
	var out []string
	if userHome != "" {
		for _, rel := range credentialPaths {
			if !skip[rel] {
				out = append(out, filepath.Join(userHome, rel))
			}
		}
	}
	out = append(out, extra...)
	return out
}

// claudeSettingsJSON is the daemon's --settings file. It only adds
// restrictions: it never sets sandbox.enabled false on its own, and its deny
// rules merge with managed ones (deny is evaluated first in every scope).
// Managed settings still win on any key. The user's ~/.claude/settings.json
// sandbox keys are copied in add-only; see mergeUserSandbox. A domain the
// user already listed stays listed. The daemon does not add one.
func claudeSettingsJSON(o IsolationOptions) ([]byte, error) {
	deny := []string{"Skill", "SlashCommand"}
	if !o.Grants.Net {
		deny = append(deny, "WebFetch", "WebSearch")
	}
	if !o.Grants.Git {
		deny = append(deny, "Bash(git push)", "Bash(git push *)")
	}
	if !o.Grants.SSH {
		for _, c := range []string{"ssh", "scp", "sftp", "rsync"} {
			deny = append(deny, "Bash("+c+")", "Bash("+c+" *)")
		}
	}
	paths := protectedPaths(o.UserHome, o.Protect, nil)
	if o.Grants.SSH && o.UserHome != "" {
		paths = without(paths, filepath.Join(o.UserHome, ".ssh"))
	}
	var creds []map[string]string
	for _, p := range paths {
		// //path is an absolute Read/Edit rule; ~ would name the per-bot HOME.
		deny = append(deny, "Read(/"+p+")", "Read(/"+p+"/**)", "Edit(/"+p+")", "Edit(/"+p+"/**)")
		creds = append(creds, map[string]string{"path": p, "mode": "deny"})
	}
	doc := map[string]any{
		"disableAllHooks":            true,
		"enableAllProjectMcpServers": false,
		"permissions": map[string]any{
			"deny":                                deny,
			"blockReadsOutsideWorkingDirectories": true,
		},
	}
	if o.ClaudeSandbox {
		domains := []string{}
		if o.Grants.Net {
			domains = append(domains, o.Grants.NetAllow...)
		}
		sort.Strings(domains)
		doc["sandbox"] = map[string]any{
			"enabled":                  true,
			"failIfUnavailable":        true,
			"allowUnsandboxedCommands": false,
			// Bash still goes through the daemon's prompts inside the sandbox.
			"autoAllowBashIfSandboxed": false,
			"network": map[string]any{
				"strictAllowlist": true,
				"allowedDomains":  domains,
			},
			"credentials": map[string]any{"files": creds},
		}
	}
	user, err := readUserClaudeSettings(o.UserHome)
	if err != nil {
		return nil, err
	}
	if err := mergeUserSandbox(doc, user); err != nil {
		return nil, err
	}
	return json.MarshalIndent(doc, "", "  ")
}

// readUserClaudeSettings reads the real user home's Claude settings.
// A missing file means the user has no sandbox settings to carry.
// Anything unreadable or unparseable refuses the turn: a sandbox may be
// configured there, and --setting-sources= would otherwise drop it.
func readUserClaudeSettings(userHome string) (map[string]any, error) {
	if !filepath.IsAbs(userHome) {
		return nil, &SandboxError{Backend: "claude", Err: fmt.Errorf("user home is unknown, so Claude settings could not be read and the turn was refused")}
	}
	path := filepath.Join(userHome, ".claude", "settings.json")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, userSettingsErr(path, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, userSettingsErr(path, fmt.Errorf("empty file"))
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, userSettingsErr(path, err)
	}
	if doc == nil {
		return nil, userSettingsErr(path, fmt.Errorf("settings are not an object"))
	}
	if raw, ok := doc["sandbox"]; ok && raw != nil {
		if _, ok := raw.(map[string]any); !ok {
			return nil, userSettingsErr(path, fmt.Errorf("sandbox is not an object"))
		}
	}
	return doc, nil
}

func userSettingsErr(path string, err error) error {
	where := "Claude settings"
	if path != "" {
		where = "Claude settings " + path
	}
	return &SandboxError{
		Backend: "claude",
		Path:    path,
		Err:     fmt.Errorf("%s cannot be read or parsed, so the turn was refused (%v)", where, err),
	}
}

// mergeUserSandbox copies the user's sandbox keys into the daemon settings.
// Daemon restrictions may add a deny or a stricter boolean. They never
// remove a user sandbox key and never add an allowlist entry the user did
// not already list. permissions.allow and hooks are not copied.
func mergeUserSandbox(doc, user map[string]any) error {
	if user == nil {
		return nil
	}
	if err := unionPermissionDeny(doc, user); err != nil {
		return err
	}
	raw, ok := user["sandbox"]
	if !ok || raw == nil {
		return nil
	}
	userSB, ok := raw.(map[string]any)
	if !ok {
		return userSettingsErr("", fmt.Errorf("sandbox is not an object"))
	}
	if err := checkUserSandboxShape(userSB); err != nil {
		return err
	}
	daemonSB, _ := doc["sandbox"].(map[string]any)
	merged, err := mergeSandbox(daemonSB, userSB)
	if err != nil {
		return err
	}
	if merged != nil {
		doc["sandbox"] = merged
	}
	return nil
}

func checkUserSandboxShape(sb map[string]any) error {
	for _, key := range []string{"enabled", "failIfUnavailable", "allowUnsandboxedCommands", "autoAllowBashIfSandboxed"} {
		raw, ok := sb[key]
		if !ok || raw == nil {
			continue
		}
		if _, ok := raw.(bool); !ok {
			return userSettingsErr("", fmt.Errorf("sandbox.%s is not a bool", key))
		}
	}
	return nil
}

func mergeSandbox(daemon, user map[string]any) (map[string]any, error) {
	if user == nil {
		return daemon, nil
	}
	out, err := cloneMap(user)
	if err != nil {
		return nil, userSettingsErr("", err)
	}
	if daemon == nil {
		return out, nil
	}
	for _, key := range []struct {
		name       string
		trueStrict bool
	}{
		{"enabled", true},
		{"failIfUnavailable", true},
		{"allowUnsandboxedCommands", false},
		{"autoAllowBashIfSandboxed", false},
	} {
		raw, ok := daemon[key.name]
		if !ok {
			continue
		}
		if err := applyStricterBool(out, key.name, raw, key.trueStrict); err != nil {
			return nil, err
		}
	}
	if err := mergeNetwork(out, daemon["network"]); err != nil {
		return nil, err
	}
	if err := mergeCredentials(out, daemon["credentials"]); err != nil {
		return nil, err
	}
	if err := mergeFilesystem(out, daemon["filesystem"]); err != nil {
		return nil, err
	}
	return out, nil
}

func cloneMap(m map[string]any) (map[string]any, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func applyStricterBool(dst map[string]any, key string, daemonVal any, trueIsStricter bool) error {
	d, ok := daemonVal.(bool)
	if !ok {
		return fmt.Errorf("sandbox %s: daemon value is not a bool", key)
	}
	raw, exists := dst[key]
	if !exists || raw == nil {
		dst[key] = d
		return nil
	}
	u, ok := raw.(bool)
	if !ok {
		return userSettingsErr("", fmt.Errorf("sandbox.%s is not a bool", key))
	}
	if trueIsStricter {
		dst[key] = u || d
		return nil
	}
	dst[key] = u && d
	return nil
}

func mergeNetwork(out map[string]any, daemonNet any) error {
	if daemonNet == nil {
		return nil
	}
	dNet, ok := daemonNet.(map[string]any)
	if !ok {
		return fmt.Errorf("daemon sandbox network is not an object")
	}
	uNet, err := objectField(out, "network")
	if err != nil {
		return err
	}
	out["network"] = uNet
	if raw, ok := dNet["strictAllowlist"]; ok {
		if err := applyStricterBool(uNet, "strictAllowlist", raw, true); err != nil {
			return err
		}
	}
	if raw, ok := dNet["allowLocalBinding"]; ok {
		if err := applyStricterBool(uNet, "allowLocalBinding", raw, false); err != nil {
			return err
		}
	}
	// An allowlist the user wrote is kept whole. Adding the daemon's hosts
	// would loosen it. The daemon's list is used only when the user set none.
	if _, userHas := uNet["allowedDomains"]; !userHas {
		if raw, ok := dNet["allowedDomains"]; ok {
			uNet["allowedDomains"] = raw
		}
	}
	if _, userHas := uNet["allowUnixSockets"]; !userHas {
		if raw, ok := dNet["allowUnixSockets"]; ok {
			uNet["allowUnixSockets"] = raw
		}
	}
	if raw, ok := dNet["deniedDomains"]; ok {
		merged, err := unionStringListField(uNet["deniedDomains"], raw)
		if err != nil {
			return err
		}
		uNet["deniedDomains"] = merged
	}
	return nil
}

func mergeCredentials(out map[string]any, daemonCred any) error {
	if daemonCred == nil {
		return nil
	}
	dCred, ok := daemonCred.(map[string]any)
	if !ok {
		return fmt.Errorf("daemon sandbox credentials is not an object")
	}
	uCred, err := objectField(out, "credentials")
	if err != nil {
		return err
	}
	out["credentials"] = uCred
	if dCred["files"] != nil || uCred["files"] != nil {
		files, err := unionCredFiles(dCred["files"], uCred["files"])
		if err != nil {
			return userSettingsErr("", err)
		}
		uCred["files"] = files
	}
	return nil
}

func mergeFilesystem(out map[string]any, daemonFS any) error {
	if daemonFS == nil {
		return nil
	}
	dFS, ok := daemonFS.(map[string]any)
	if !ok {
		return fmt.Errorf("daemon sandbox filesystem is not an object")
	}
	uFS, err := objectField(out, "filesystem")
	if err != nil {
		return err
	}
	out["filesystem"] = uFS
	for _, key := range []string{"denyRead", "denyWrite"} {
		raw, ok := dFS[key]
		if !ok {
			continue
		}
		merged, err := unionStringListField(uFS[key], raw)
		if err != nil {
			return err
		}
		uFS[key] = merged
	}
	for _, key := range []string{"allowRead", "allowWrite"} {
		if _, userHas := uFS[key]; userHas {
			continue
		}
		if raw, ok := dFS[key]; ok {
			uFS[key] = raw
		}
	}
	return nil
}

func objectField(parent map[string]any, key string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		return map[string]any{}, nil
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, userSettingsErr("", fmt.Errorf("sandbox.%s is not an object", key))
	}
	return obj, nil
}

func unionPermissionDeny(doc, user map[string]any) error {
	raw, ok := user["permissions"]
	if !ok || raw == nil {
		return nil
	}
	perms, ok := raw.(map[string]any)
	if !ok {
		return userSettingsErr("", fmt.Errorf("permissions is not an object"))
	}
	rawDeny, ok := perms["deny"]
	if !ok || rawDeny == nil {
		return nil
	}
	dperms, _ := doc["permissions"].(map[string]any)
	if dperms == nil {
		dperms = map[string]any{}
		doc["permissions"] = dperms
	}
	merged, err := unionStringListField(dperms["deny"], rawDeny)
	if err != nil {
		return userSettingsErr("", fmt.Errorf("permissions.deny is not a list of strings"))
	}
	dperms["deny"] = merged
	return nil
}

func unionStringListField(a, b any) ([]string, error) {
	left, ok := asStringList(a)
	if !ok && a != nil {
		return nil, fmt.Errorf("not a list of strings")
	}
	right, ok := asStringList(b)
	if !ok && b != nil {
		return nil, fmt.Errorf("not a list of strings")
	}
	return unionStrings(left, right), nil
}

func asStringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case nil:
		return nil, true
	case []string:
		return t, true
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func unionStrings(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func unionCredFiles(daemon, user any) ([]map[string]any, error) {
	dList, err := credEntries(daemon)
	if err != nil {
		return nil, err
	}
	uList, err := credEntries(user)
	if err != nil {
		return nil, err
	}
	index := map[string]int{}
	var out []map[string]any
	add := func(e map[string]any) error {
		path, _ := e["path"].(string)
		if path == "" {
			return fmt.Errorf("credentials file missing path")
		}
		if i, ok := index[path]; ok {
			prev := out[i]
			for k, v := range e {
				if _, exists := prev[k]; !exists {
					prev[k] = v
				}
			}
			if e["mode"] == "deny" || prev["mode"] == "deny" {
				prev["mode"] = "deny"
			}
			return nil
		}
		cp := map[string]any{}
		for k, v := range e {
			cp[k] = v
		}
		index[path] = len(out)
		out = append(out, cp)
		return nil
	}
	for _, e := range dList {
		if err := add(e); err != nil {
			return nil, err
		}
	}
	for _, e := range uList {
		if err := add(e); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func credEntries(v any) ([]map[string]any, error) {
	if v == nil {
		return nil, nil
	}
	switch t := v.(type) {
	case []map[string]string:
		out := make([]map[string]any, len(t))
		for i, m := range t {
			e := make(map[string]any, len(m))
			for k, val := range m {
				e[k] = val
			}
			out[i] = e
		}
		return out, nil
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("credentials file entry is not an object")
			}
			out = append(out, m)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("credentials files is not a list")
	}
}

func without(list []string, drop string) []string {
	var out []string
	for _, s := range list {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
}

// GrokProfile is the daemon's custom Grok sandbox profile name. A custom
// profile fails closed: Grok refuses to start if it can't apply it.
const GrokProfile = "lgb"

// grokSandboxTOML writes a profile on top of built-in strict: reads limited
// to the workspace and system paths, writes to the workspace and temp, child
// network blocked unless granted, credential paths kernel-denied.
func grokSandboxTOML(o IsolationOptions) string {
	var deny []string
	skip := map[string]bool{}
	for k := range grokSkipDeny {
		skip[k] = true
	}
	if o.Grants.SSH {
		skip[".ssh"] = true
	}
	for _, p := range protectedPaths(o.UserHome, o.Protect, skip) {
		// Grok refuses to start when a deny path can't be bound, so only
		// existing paths are listed.
		if _, err := os.Lstat(p); err == nil {
			deny = append(deny, p)
		}
	}
	var b strings.Builder
	b.WriteString("# Written by local-grok-bots for each turn. Do not edit.\n")
	fmt.Fprintf(&b, "[profiles.%s]\nextends = \"strict\"\n", GrokProfile)
	fmt.Fprintf(&b, "restrict_network = %t\n", !o.Grants.Net)
	b.WriteString("deny = [")
	for i, p := range deny {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(strconv.Quote(p))
	}
	b.WriteString("]\n")
	return b.String()
}

// grokDisallowed are built-in Grok tools removed unless granted.
func grokDisallowed(g Grants) []string {
	if g.Net {
		return nil
	}
	return []string{"web_fetch", "web_search"}
}
