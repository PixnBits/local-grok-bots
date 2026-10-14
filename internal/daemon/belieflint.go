package daemon

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// Phrases that mean a memory note is claiming which tools the bot has.
var toolBeliefClaim = regexp.MustCompile(`(?i)\b(only have|only has|no access|cannot|can'?t|don'?t have|do not have|don'?t support|missing tool|no tool|lack(s|ing)?)\b`)

// toolNameSet is the names of every tool the daemon provides.
func toolNameSet() map[string]bool {
	m := make(map[string]bool, len(toolDefs()))
	for _, t := range toolDefs() {
		m[t.Name] = true
	}
	return m
}

// memoryClaimsTools reports whether key or value looks like a note about
// tool availability. Such notes go stale the moment tools change.
func memoryClaimsTools(key, value string) bool {
	text := key + " " + value
	if !toolBeliefClaim.MatchString(text) {
		return false
	}
	low := strings.ToLower(text)
	for name := range toolNameSet() {
		if strings.Contains(low, strings.ToLower(name)) {
			return true
		}
	}
	// Broad claim with no specific name still counts when it talks about tools.
	return strings.Contains(low, "tool")
}

var (
	cliPhrase   = regexp.MustCompile(`\b((?:[A-Z][\w.-]*\s+){1,3})CLI\b`)
	backtickCmd = regexp.MustCompile("`([^`\n]{1,80})`")
	// A camel/snake tool-ish token that isn't one of ours.
	toolishName = regexp.MustCompile(`\b([a-z][a-z0-9]*(?:_[a-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]*)\b`)
)

// descriptionWarnings finds phrases in a standing prompt that name CLIs or
// tools the daemon does not provide. They are advisory; saves stay open.
func descriptionWarnings(description string) []string {
	if strings.TrimSpace(description) == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	known := toolNameSet()
	for _, m := range cliPhrase.FindAllStringSubmatch(description, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" {
			continue
		}
		words := strings.Fields(strings.ToLower(name))
		// Only the full CLI name counts as installed (e.g. "grok-build"),
		// not the first word alone — "grok" on PATH is a different program.
		if onPath(strings.Join(words, "-")) || onPath(strings.Join(words, "")) {
			continue
		}
		add(fmt.Sprintf("Description mentions the %q, which is not installed for bots (no %s command on PATH) and is not a daemon tool.", name+" CLI", strings.Join(words, "-")))
	}
	for _, m := range backtickCmd.FindAllStringSubmatch(description, -1) {
		cmd := strings.TrimSpace(m[1])
		if cmd == "" || strings.ContainsAny(cmd, " \t\n;|&") {
			// Multi-word or piped: take the first token.
			fields := strings.FieldsFunc(cmd, func(r rune) bool {
				return r == ' ' || r == '\t' || r == ';' || r == '|' || r == '&'
			})
			if len(fields) == 0 {
				continue
			}
			cmd = fields[0]
		}
		base := cmd
		if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
			base = base[i+1:]
		}
		if known[base] {
			continue
		}
		if onPath(base) || strings.ContainsAny(base, ".") {
			continue
		}
		add(fmt.Sprintf("Description mentions `%s`, which is not on PATH in the workspace jail and is not a daemon tool.", base))
	}
	lowDesc := strings.ToLower(description)
	for _, m := range toolishName.FindAllString(description, -1) {
		if known[m] {
			continue
		}
		// Only flag when the surrounding text talks about using/calling it.
		idx := strings.Index(lowDesc, strings.ToLower(m))
		if idx < 0 {
			continue
		}
		winStart := idx - 40
		if winStart < 0 {
			winStart = 0
		}
		win := lowDesc[winStart : idx+len(m)+40]
		if !strings.Contains(win, "tool") && !strings.Contains(win, "call") &&
			!strings.Contains(win, "use ") && !strings.Contains(win, "using ") &&
			!strings.Contains(win, "invoke") && !strings.Contains(win, "via ") {
			continue
		}
		add(fmt.Sprintf("Description mentions tool-like name %q, which is not in the current tool list.", m))
	}
	return out
}

// onPath reports whether a command exists on the daemon's PATH, which the
// workspace jail shares.
func onPath(cmd string) bool {
	if cmd == "" {
		return false
	}
	p, err := exec.LookPath(cmd)
	return err == nil && p != ""
}
