package clisession

import (
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
// restrictions: it never sets sandbox.enabled false, never lists a domain
// policy did not grant, and its deny rules merge with managed ones (deny is
// evaluated first in every scope). Managed settings still win on any key.
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
	return json.MarshalIndent(doc, "", "  ")
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
