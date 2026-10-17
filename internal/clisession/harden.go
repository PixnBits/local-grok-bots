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
// shells are denied them. Grok's bot home holds a placeholder, not this file.
var credentialPaths = []string{
	".ssh", ".aws", ".gnupg", ".config/gh", ".netrc", ".docker/config.json",
	".kube", ".config/gcloud", ".azure", ".claude/.credentials.json", ".grok/auth.json",
}

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
	for _, p := range existingRuleFiles(o.StateDir) {
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

// mergeSandbox builds the sandbox block from scratch. From the user's block it
// keeps only keys that restrict: stricter booleans, deny lists, and allowlists
// narrowed to what the daemon (policy) grants. User allowlists never replace
// the daemon's, and unknown keys such as excludedCommands are dropped. A user
// whose sandbox is enabled stays enabled.
func mergeSandbox(daemon, user map[string]any) (map[string]any, error) {
	if user == nil {
		return daemon, nil
	}
	if daemon == nil {
		daemon = map[string]any{}
	}
	out := map[string]any{}
	for _, key := range []struct {
		name       string
		trueStrict bool
	}{
		{"enabled", true},
		{"failIfUnavailable", true},
		{"allowUnsandboxedCommands", false},
		{"autoAllowBashIfSandboxed", false},
	} {
		if err := stricterBool(out, key.name, daemon[key.name], user[key.name], key.trueStrict); err != nil {
			return nil, err
		}
	}
	if err := mergeNetwork(out, daemon["network"], user["network"]); err != nil {
		return nil, err
	}
	if err := mergeCredentials(out, daemon["credentials"], user["credentials"]); err != nil {
		return nil, err
	}
	if err := mergeFilesystem(out, daemon["filesystem"], user["filesystem"]); err != nil {
		return nil, err
	}
	return out, nil
}

// stricterBool writes the stricter of the daemon and user values. A user
// value alone is kept only when it is the restrictive one.
func stricterBool(dst map[string]any, key string, daemonVal, userVal any, trueIsStricter bool) error {
	var d, u *bool
	if daemonVal != nil {
		b, ok := daemonVal.(bool)
		if !ok {
			return fmt.Errorf("sandbox %s: daemon value is not a bool", key)
		}
		d = &b
	}
	if userVal != nil {
		b, ok := userVal.(bool)
		if !ok {
			return userSettingsErr("", fmt.Errorf("sandbox.%s is not a bool", key))
		}
		u = &b
	}
	switch {
	case d != nil && u != nil:
		if trueIsStricter {
			dst[key] = *d || *u
		} else {
			dst[key] = *d && *u
		}
	case d != nil:
		dst[key] = *d
	case u != nil && *u == trueIsStricter:
		dst[key] = *u
	}
	return nil
}

func objectArg(v any, what string, user bool) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		err := fmt.Errorf("sandbox.%s is not an object", what)
		if user {
			return nil, userSettingsErr("", err)
		}
		return nil, err
	}
	return m, nil
}

// intersectAllow narrows a user allowlist to what the daemon grants. Without a
// user list the daemon's list is used; without a daemon list nothing is allowed.
func intersectAllow(dst map[string]any, key string, d, u map[string]any) error {
	dRaw, dHas := d[key]
	uRaw, uHas := u[key]
	if !dHas && !uHas {
		return nil
	}
	dl, ok := asStringList(dRaw)
	if !ok {
		return fmt.Errorf("daemon sandbox %s is not a list of strings", key)
	}
	if !uHas || uRaw == nil {
		if dHas {
			dst[key] = dl
		}
		return nil
	}
	ul, ok := asStringList(uRaw)
	if !ok {
		return userSettingsErr("", fmt.Errorf("sandbox %s is not a list of strings", key))
	}
	grant := map[string]bool{}
	for _, s := range dl {
		grant[s] = true
	}
	out := []string{}
	for _, s := range ul {
		if grant[s] {
			out = append(out, s)
		}
	}
	dst[key] = out
	return nil
}

func mergeNetwork(out map[string]any, daemonNet, userNet any) error {
	if daemonNet == nil && userNet == nil {
		return nil
	}
	dNet, err := objectArg(daemonNet, "network", false)
	if err != nil {
		return err
	}
	uNet, err := objectArg(userNet, "network", true)
	if err != nil {
		return err
	}
	n := map[string]any{}
	if err := stricterBool(n, "strictAllowlist", dNet["strictAllowlist"], uNet["strictAllowlist"], true); err != nil {
		return err
	}
	if err := stricterBool(n, "allowLocalBinding", dNet["allowLocalBinding"], uNet["allowLocalBinding"], false); err != nil {
		return err
	}
	for _, key := range []string{"allowedDomains", "allowUnixSockets"} {
		if err := intersectAllow(n, key, dNet, uNet); err != nil {
			return err
		}
	}
	if dNet["deniedDomains"] != nil || uNet["deniedDomains"] != nil {
		merged, err := unionStringListField(uNet["deniedDomains"], dNet["deniedDomains"])
		if err != nil {
			return userSettingsErr("", err)
		}
		n["deniedDomains"] = merged
	}
	if len(n) > 0 {
		out["network"] = n
	}
	return nil
}

func mergeCredentials(out map[string]any, daemonCred, userCred any) error {
	if daemonCred == nil && userCred == nil {
		return nil
	}
	dCred, err := objectArg(daemonCred, "credentials", false)
	if err != nil {
		return err
	}
	uCred, err := objectArg(userCred, "credentials", true)
	if err != nil {
		return err
	}
	if dCred["files"] == nil && uCred["files"] == nil {
		return nil
	}
	files, err := unionCredFiles(dCred["files"], uCred["files"])
	if err != nil {
		return userSettingsErr("", err)
	}
	out["credentials"] = map[string]any{"files": files}
	return nil
}

func mergeFilesystem(out map[string]any, daemonFS, userFS any) error {
	if daemonFS == nil && userFS == nil {
		return nil
	}
	dFS, err := objectArg(daemonFS, "filesystem", false)
	if err != nil {
		return err
	}
	uFS, err := objectArg(userFS, "filesystem", true)
	if err != nil {
		return err
	}
	f := map[string]any{}
	for _, key := range []string{"denyRead", "denyWrite"} {
		if dFS[key] == nil && uFS[key] == nil {
			continue
		}
		merged, err := unionStringListField(uFS[key], dFS[key])
		if err != nil {
			return userSettingsErr("", err)
		}
		f[key] = merged
	}
	for _, key := range []string{"allowRead", "allowWrite"} {
		if err := intersectAllow(f, key, dFS, uFS); err != nil {
			return err
		}
	}
	if len(f) > 0 {
		out["filesystem"] = f
	}
	return nil
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
	if o.Grants.SSH {
		skip[".ssh"] = true
	}
	var keep []string
	if o.Home != "" {
		keep = append(keep, filepath.Clean(o.Home))
	} else if o.StateDir != "" {
		keep = append(keep, filepath.Join(filepath.Clean(o.StateDir), "grok-home"))
	}
	for _, p := range protectedPaths(o.UserHome, o.Protect, skip) {
		// Grok refuses to start when a deny path can't be bound, so only
		// existing paths are listed.
		if _, err := os.Lstat(p); err == nil {
			deny = append(deny, denyAround(filepath.Clean(p), keep)...)
		}
	}
	deny = append(deny, existingRuleFiles(o.StateDir)...)
	deny = dedupePaths(deny)
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

// grokAllowedTools is the --tools allowlist. Each name is one an ask rule
// can force to prompt. lgb and coi are shell commands, so they need
// run_terminal_command. list_dir is omitted until an ask rule is confirmed
// to make it ask. x_keyword_search and x_semantic_search stay off.
// Web tools are added only with a net grant.
func grokAllowedTools(g Grants) []string {
	out := []string{
		"run_terminal_command",
		"read_file",
		"search_replace",
		"grep",
		"write",
	}
	if g.Net {
		out = append(out, "web_fetch", "web_search")
	}
	return out
}

// grokPermissionTOML forces default mode and a catch-all ask list.
// Without the ask list, read-only tools run with no session/request_permission.
// disable_web_search is sealed with the file. The loopback proxy is what
// refuses a server-side search tool when the bot has no net grant.
func grokPermissionTOML() string {
	return "# Written by local-grok-bots for each turn. Do not edit.\n" +
		"disable_web_search = true\n\n" +
		"[ui]\npermission_mode = \"default\"\n\n" +
		"[permission]\nask = [\"Bash\", \"Read\", \"Grep\", \"Glob\", \"Edit\", \"Write\", \"WebFetch\", \"WebSearch\", \"MCPTool\"]\n"
}

// grokPermissionTOMLPrevious is the last daemon body. Only that exact text
// is rewritten. Any other body stays in place and refuses the turn.
func grokPermissionTOMLPrevious() string {
	return "# Written by local-grok-bots for each turn. Do not edit.\n" +
		"[ui]\npermission_mode = \"default\"\n\n" +
		"[permission]\nask = [\"Bash\", \"Read\", \"Grep\", \"Glob\", \"Edit\", \"Write\", \"WebFetch\", \"WebSearch\", \"MCPTool\"]\n"
}

// existingRuleFiles lists the durable permission files in the bot state
// directory when they are regular files. A missing path is omitted: Grok
// refuses to start when a deny path cannot be bound. A symlink is omitted
// so the deny does not follow it.
func existingRuleFiles(state string) []string {
	state = strings.TrimSpace(state)
	if state == "" {
		return nil
	}
	var out []string
	for _, name := range []string{"user-permissions.json", "grok-permission-rules"} {
		p := filepath.Join(filepath.Clean(state), name)
		st, err := os.Lstat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	return out
}

func dedupePaths(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// denyAround returns p, or, when p contains one of keep (the bot's own HOME
// or GROK_HOME, which Grok must write), every existing entry under p except
// the path down to keep. Denying DATA_DIR/cli whole would make Grok's own
// home read-only and stop it from starting.
func denyAround(p string, keep []string) []string {
	inside := false
	for _, k := range keep {
		if k == p {
			return nil
		}
		if strings.HasPrefix(k, p+string(filepath.Separator)) {
			inside = true
		}
	}
	if !inside {
		return []string{p}
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return []string{p}
	}
	var out []string
	for _, e := range entries {
		out = append(out, denyAround(filepath.Join(p, e.Name()), keep)...)
	}
	return out
}
