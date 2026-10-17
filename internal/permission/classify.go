package permission

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// Class is the static, deterministic label for one command or pattern.
// AutoAllow is true only for a low-risk read-only call the hard floor permits
// a user rule to allow. Anything else fails closed.
type Class struct {
	ReadOnly    bool   `json:"read_only"`
	Kind        string `json:"kind"`
	Sensitivity string `json:"sensitivity"`
	Risk        string `json:"risk"`
	Reason      string `json:"reason"`
	AutoAllow   bool   `json:"auto_allow"`
}

// SuggestAfter is how many similar logged requests create a suggestion
// without an explicit analyze call.
const SuggestAfter = 3

var (
	gitReadOnly = map[string]bool{
		"status": true, "log": true, "diff": true, "show": true,
		"rev-parse": true, "blame": true, "ls-files": true,
		"describe": true, "shortlog": true, "version": true,
	}
	gitIrreversible = map[string]bool{
		"push": true, "reset": true, "clean": true,
	}
	ghReadOnly = map[string]bool{
		"pr view": true, "pr diff": true, "pr list": true, "pr checks": true, "pr status": true,
		"issue view": true, "issue list": true,
		"repo view": true,
		"run view":  true, "run list": true,
	}
	fileReadOnly = map[string]bool{
		"cat": true, "ls": true, "head": true, "tail": true, "wc": true,
		"pwd": true, "stat": true, "file": true, "grep": true, "rg": true, "find": true,
	}
	networkBins = map[string]bool{
		"curl": true, "wget": true, "ssh": true, "scp": true, "sftp": true,
		"nc": true, "ncat": true, "netcat": true, "ping": true, "dig": true,
		"nslookup": true, "npm": true, "npx": true, "yarn": true, "pnpm": true,
		"pip": true, "pip3": true, "gem": true, "apt": true, "apt-get": true,
		"brew": true, "docker": true, "kubectl": true, "helm": true,
		"aws": true, "gcloud": true, "az": true, "rsync": true, "ftp": true,
		"telnet": true, "socat": true,
	}
	irreversibleBins = map[string]bool{
		"rm": true, "rmdir": true, "dd": true, "mkfs": true, "shred": true,
		"sudo": true, "doas": true, "su": true,
	}
	writeBins = map[string]bool{
		"tee": true, "mv": true, "cp": true, "install": true, "mkdir": true,
		"touch": true, "truncate": true, "ln": true, "chmod": true, "chown": true,
		"chgrp": true, "sed": true, "tar": true,
	}
)

// ClassifyCall labels one concrete tool call. workspace is the bot directory;
// empty means relative paths are treated as project-local only when they do
// not escape, and absolute paths are not auto-allowed.
func ClassifyCall(tool string, args map[string]any, workspace string) Class {
	name := strings.ToLower(strings.TrimSpace(tool))
	switch name {
	case "read", "grep", "glob", "ls":
		return classifyReadTool(argText(args), workspace)
	case "edit", "write", "multiedit", "notebookedit":
		sens, _ := pathSensitivity(argText(args), workspace)
		return blocked("write", sens, "high", "file write")
	case "webfetch", "websearch":
		return blocked("network", "unknown", "high", "network tool")
	case "bash":
		return classifyBash(argText(args), workspace)
	default:
		return blocked("unknown", "unknown", "high", "tool is not a known read-only command")
	}
}

// CheckUserRule accepts a durable pattern. Allow is stored only when the
// pattern is a known low-risk read-only shape. Ask and deny are stricter and
// are always accepted when the shape is well formed. Concrete calls are
// classified again at decision time, so a glob cannot auto-allow a write.
func CheckUserRule(effect, pattern, workspace string) (Class, error) {
	effect, pattern, err := normalizeRule(effect, pattern)
	if err != nil {
		return Class{}, err
	}
	if effect != "allow" {
		return Class{
			Kind: "stricter", Sensitivity: "project",
			Reason: "ask and deny rules only narrow what a managed allow would permit",
		}, nil
	}
	return eligibleAllow(pattern, workspace)
}

func normalizeRule(effect, pattern string) (string, string, error) {
	effect = strings.ToLower(strings.TrimSpace(effect))
	pattern = strings.TrimSpace(pattern)
	switch effect {
	case "allow", "ask", "deny":
	default:
		return "", "", fmt.Errorf("effect must be allow, ask, or deny")
	}
	if pattern == "" || len(pattern) > 400 || strings.ContainsAny(pattern, "\r\n") {
		return "", "", fmt.Errorf("invalid pattern")
	}
	name, _, _ := splitRule(pattern)
	if strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t") {
		return "", "", fmt.Errorf("invalid pattern")
	}
	return effect, pattern, nil
}

func eligibleAllow(pattern, workspace string) (Class, error) {
	name, glob, scoped := splitRule(pattern)
	if !scoped {
		return Class{}, fmt.Errorf("auto-allow refused: an allow pattern must name the tool and an argument glob")
	}
	switch strings.ToLower(name) {
	case "bash":
		return eligibleBash(glob, workspace)
	case "read", "grep", "glob", "ls":
		return eligibleRead(glob, workspace)
	default:
		return Class{}, fmt.Errorf("auto-allow refused: %s is not a known read-only tool", name)
	}
}

func eligibleBash(glob, workspace string) (Class, error) {
	if shellComposed(glob) {
		return Class{}, fmt.Errorf("auto-allow refused: pattern contains shell composition, redirection, or expansion")
	}
	cmd, ok := literalCommand(glob)
	if !ok {
		return Class{}, fmt.Errorf("auto-allow refused: wildcard must be a trailing glob on a read-only command")
	}
	id, ok := readOnlyIdentity(cmd)
	if !ok || id == "" {
		c := classifyBash(cmd, workspace)
		if c.Reason == "" {
			c.Reason = "command is not a known read-only prefix"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c := classifyBash(cmd, workspace)
	if !c.AutoAllow {
		if c.Reason == "" {
			c.Reason = "command is not low-risk read-only"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c.Reason = "low-risk read-only " + id + "; each later call is rechecked, and shell composition still asks"
	return c, nil
}

func eligibleRead(glob, workspace string) (Class, error) {
	if credentialPath(glob) {
		return Class{}, fmt.Errorf("auto-allow refused: pattern names a credential path")
	}
	lit, ok := literalCommand(glob)
	if !ok {
		return Class{}, fmt.Errorf("auto-allow refused: wildcard must be a trailing glob")
	}
	if strings.TrimSpace(lit) == "" {
		return Class{}, fmt.Errorf("auto-allow refused: path glob needs a project prefix")
	}
	c := classifyReadTool(lit, workspace)
	if !c.AutoAllow {
		if c.Reason == "" {
			c.Reason = "path is not project-local"
		}
		return c, fmt.Errorf("auto-allow refused: %s", c.Reason)
	}
	c.Reason = "read-only path under the workspace; each later call is rechecked"
	return c, nil
}

// literalCommand returns the text before a trailing * or ? glob.
// A wildcard anywhere earlier is rejected.
func literalCommand(glob string) (string, bool) {
	i := strings.IndexAny(glob, "*?")
	if i < 0 {
		return strings.TrimSpace(glob), strings.TrimSpace(glob) != ""
	}
	for _, r := range glob[i:] {
		if r != '*' && r != '?' && !unicode.IsSpace(r) {
			return "", false
		}
	}
	cmd := strings.TrimSpace(glob[:i])
	if cmd == "" {
		return "", false
	}
	return cmd, true
}

func classifyBash(cmd, workspace string) Class {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return blocked("unknown", "unknown", "high", "empty command")
	}
	if shellComposed(cmd) {
		return blocked("mixed", "unknown", "high", "shell composition, redirection, or expansion; classification refused auto-allow")
	}
	toks := splitCmd(cmd)
	if len(toks) == 0 {
		return blocked("unknown", "unknown", "high", "empty command")
	}
	bin := toks[0]
	if credentialAnywhere(toks) {
		return blocked("credential", "credential", "high", "command touches a credential path")
	}
	if networkBins[bin] {
		return blocked("network", "unknown", "high", bin+" is a network command")
	}
	if irreversibleBins[bin] {
		return blocked("irreversible", "unknown", "high", bin+" is irreversible")
	}
	if writeBins[bin] {
		return blocked("write", "unknown", "high", bin+" writes")
	}
	switch bin {
	case "git":
		return classifyGit(toks, workspace)
	case "gh":
		return classifyGH(toks, workspace)
	default:
		if fileReadOnly[bin] {
			return classifyFileRead(toks, workspace)
		}
	}
	return blocked("unknown", "unknown", "high", "command is not a known read-only prefix")
}

func classifyGit(toks []string, workspace string) Class {
	sub := gitSubcommand(toks)
	if sub == "" {
		return blocked("unknown", "unknown", "high", "git subcommand is not statically read-only")
	}
	if gitIrreversible[sub] {
		return blocked("irreversible", "unknown", "high", "git "+sub+" is irreversible")
	}
	if sub == "fetch" || sub == "pull" || sub == "clone" || sub == "ls-remote" {
		return blocked("network", "unknown", "high", "git "+sub+" uses the network")
	}
	if !gitReadOnly[sub] {
		return blocked("write", "unknown", "high", "git "+sub+" is not a known read-only subcommand")
	}
	for _, t := range toks {
		if t == "--output" || strings.HasPrefix(t, "--output=") {
			return blocked("write", "unknown", "high", "git "+sub+" --output writes a file")
		}
	}
	if sens, ok := toksInside(toks, workspace); !ok {
		return blocked(sens, sens, "high", "git "+sub+" path is outside the workspace")
	}
	return allowLow("read-only git " + sub)
}

func classifyGH(toks []string, workspace string) Class {
	if len(toks) < 3 {
		return blocked("unknown", "unknown", "high", "gh command is not a known read-only prefix")
	}
	pair := toks[1] + " " + toks[2]
	if !ghReadOnly[pair] {
		switch toks[1] {
		case "auth":
			return blocked("credential", "credential", "high", "gh auth handles credentials")
		case "api", "ssh":
			return blocked("network", "unknown", "high", "gh "+toks[1]+" uses the network")
		}
		return blocked("unknown", "unknown", "high", "gh "+pair+" is not a known read-only command")
	}
	if sens, ok := toksInside(toks, workspace); !ok {
		return blocked(sens, sens, "high", "gh "+pair+" path is outside the workspace")
	}
	return allowLow("read-only gh " + pair)
}

func classifyFileRead(toks []string, workspace string) Class {
	if toks[0] == "find" && findWrites(toks) {
		return blocked("write", "unknown", "high", "find would write or execute")
	}
	if sens, ok := argsInside(toks[1:], workspace); !ok {
		return blocked(sens, sens, "high", "path is outside the workspace")
	}
	return allowLow("read-only " + toks[0])
}

func classifyReadTool(p, workspace string) Class {
	p = strings.TrimSpace(p)
	if p == "" {
		return blocked("unknown", "unknown", "high", "read tool has no path")
	}
	if credentialPath(p) {
		return blocked("credential", "credential", "high", "path is a credential path")
	}
	sens, inside := pathSensitivity(p, workspace)
	if !inside {
		kind := sens
		if kind == "" || kind == "project" {
			kind = "unknown"
		}
		return blocked(kind, sens, "high", "path is outside the workspace")
	}
	return allowLow("read-only path inside the workspace")
}

func allowLow(reason string) Class {
	return Class{
		ReadOnly: true, Kind: "read_only", Sensitivity: "project",
		Risk: "low", Reason: reason, AutoAllow: true,
	}
}

func blocked(kind, sens, risk, reason string) Class {
	if sens == "" {
		sens = "unknown"
	}
	return Class{Kind: kind, Sensitivity: sens, Risk: risk, Reason: reason}
}

func gitSubcommand(toks []string) string {
	i := 1
	for i < len(toks) {
		t := toks[i]
		switch t {
		case "-C", "--git-dir", "--work-tree":
			i += 2
			continue
		}
		if strings.HasPrefix(t, "-") {
			return ""
		}
		return t
	}
	return ""
}

func findWrites(toks []string) bool {
	for _, t := range toks[1:] {
		switch t {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fls", "-fprint", "-fprintf", "-fprint0":
			return true
		}
	}
	return false
}

func readOnlyIdentity(cmd string) (string, bool) {
	if shellComposed(cmd) {
		return "", false
	}
	toks := splitCmd(cmd)
	if len(toks) == 0 {
		return "", false
	}
	switch toks[0] {
	case "git":
		sub := gitSubcommand(toks)
		if gitReadOnly[sub] {
			return "git " + sub, true
		}
	case "gh":
		if len(toks) >= 3 {
			pair := toks[1] + " " + toks[2]
			if ghReadOnly[pair] {
				return "gh " + pair, true
			}
		}
	default:
		if fileReadOnly[toks[0]] && !(toks[0] == "find" && findWrites(toks)) {
			return toks[0], true
		}
	}
	return "", false
}

// shellComposed is true when an unquoted metacharacter, or an expansion
// inside double quotes, could change what the command does.
func shellComposed(s string) bool {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == '"' {
				quote = 0
				continue
			}
			if c == '$' || c == '`' || c == '\n' || c == '\r' {
				return true
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '\\', ';', '|', '&', '<', '>', '`', '$', '\n', '\r':
			return true
		}
	}
	return quote != 0
}

func splitCmd(s string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	flush()
	return out
}

func credentialAnywhere(toks []string) bool {
	for _, t := range toks {
		if credentialPath(t) {
			return true
		}
	}
	return false
}

func credentialPath(p string) bool {
	for _, s := range splitSegs(p) {
		s = strings.ToLower(s)
		switch s {
		case ".ssh", ".aws", ".gnupg", ".netrc", ".kube", ".azure", ".docker", ".grok",
			"credentials", "credentials.json", "id_rsa", "id_ed25519", "id_ecdsa",
			"auth.json", "admin-token", "policy.toml", ".git-credentials", ".npmrc",
			".pypirc", "cookies", "user-permissions.json", "grok-permission-rules":
			return true
		}
		if s == ".env" || strings.HasPrefix(s, ".env.") || s == "state.db" || strings.HasPrefix(s, "state.db-") {
			return true
		}
		if strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") {
			return true
		}
	}
	return false
}

func splitSegs(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\' || r == ':'
	})
}

func toksInside(toks []string, workspace string) (string, bool) {
	for _, t := range toks {
		if !looksLikePath(t) {
			continue
		}
		sens, inside := pathSensitivity(t, workspace)
		if !inside {
			if sens == "" {
				sens = "unknown"
			}
			return sens, false
		}
	}
	return "project", true
}

func argsInside(args []string, workspace string) (string, bool) {
	prevFlag := ""
	for _, t := range args {
		if strings.HasPrefix(t, "-") {
			prevFlag = t
			continue
		}
		if takesValue(prevFlag) {
			prevFlag = ""
			continue
		}
		prevFlag = ""
		sens, inside := pathSensitivity(t, workspace)
		if !inside {
			if sens == "" {
				sens = "unknown"
			}
			return sens, false
		}
	}
	return "project", true
}

func takesValue(flag string) bool {
	switch flag {
	case "-n", "-c", "-m", "-A", "-B", "-C", "-e", "--regexp", "--max-count",
		"-name", "-path", "-maxdepth", "-mindepth":
		return true
	default:
		return false
	}
}

func looksLikePath(tok string) bool {
	return strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "~") ||
		strings.HasPrefix(tok, "./") || strings.HasPrefix(tok, "../") ||
		strings.Contains(tok, "..") || strings.Contains(tok, `\`)
}

func pathSensitivity(p, workspace string) (sens string, inside bool) {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return "project", true
	}
	if credentialPath(p) {
		return "credential", false
	}
	if isHome(p) && !withinWorkspace(p, workspace) {
		return "home", false
	}
	if isSystem(p) && !withinWorkspace(p, workspace) {
		return "system", false
	}
	if withinWorkspace(p, workspace) {
		return "project", true
	}
	if workspace == "" && !filepath.IsAbs(p) && !strings.Contains(p, "..") && !isHome(p) {
		return "project", true
	}
	if isSystem(p) {
		return "system", false
	}
	if isHome(p) {
		return "home", false
	}
	return "unknown", false
}

func withinWorkspace(p, workspace string) bool {
	if strings.TrimSpace(workspace) == "" || strings.HasPrefix(p, "~") {
		return false
	}
	ws := filepath.Clean(workspace)
	if abs, err := filepath.Abs(ws); err == nil {
		ws = abs
	}
	candidate := p
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(ws, candidate)
	} else if abs, err := filepath.Abs(candidate); err == nil {
		candidate = abs
	}
	candidate = filepath.Clean(candidate)
	return candidate == ws || strings.HasPrefix(candidate, ws+string(filepath.Separator))
}

func isHome(p string) bool {
	if strings.HasPrefix(p, "~") {
		return true
	}
	clean := filepath.Clean(p)
	return strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/Users/") || clean == "/root" || strings.HasPrefix(clean, "/root/")
}

func isSystem(p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	clean := filepath.Clean(p)
	for _, pre := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot", "/System", "/private", "/var/log", "/var/run"} {
		if clean == pre || strings.HasPrefix(clean, pre+"/") {
			return true
		}
	}
	return false
}
