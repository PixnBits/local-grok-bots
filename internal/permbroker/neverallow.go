package permbroker

import (
	"os"
	"strings"
)

const (
	neverAllowActor      = "ceiling_never_allow"
	neverAllowSeverity   = "critical"
	neverAllowCredential = "credential output is never allowed"
	neverAllowHook       = "hook path changes are never allowed"
)

// ceilingActive is a hook broker with a ceiling for this bot. The
// never-allow checks apply only then. A bot with no ceiling still asks.
func (e *Engine) ceilingActive(bot string) bool {
	if e == nil || e.brokerMode != "hook" {
		return false
	}
	_, ok := e.lookupCeiling(bot)
	return ok
}

// neverAllow is a hard deny. Call it under the engine lock, after a deny
// rule and before a one-time approval, an ask rule, or the ceiling.
func (e *Engine) neverAllow(req Request, in inspected) (string, bool) {
	if !e.ceilingActive(req.BotID) {
		return "", false
	}
	cwd, ws := req.Cwd, req.Workspace
	if credentialOutput(req, in, cwd, ws) {
		return neverAllowCredential, true
	}
	env := botEnvLocked(e, req.BotID)
	env = append(env, shellGitLocationEnv(in.Raw)...)
	if hookPathChange(req, in, cwd, ws, env) {
		return neverAllowHook, true
	}
	return "", false
}

func botEnvLocked(e *Engine, bot string) []string {
	if e == nil {
		return nil
	}
	b, ok := e.bots[bot]
	if !ok {
		return nil
	}
	return append([]string(nil), b.Env...)
}

func commandArgvs(in inspected) [][]string {
	var out [][]string
	if len(in.Argv) > 0 {
		out = append(out, in.Argv)
	}
	for _, p := range in.Parts {
		if len(p.Argv) > 0 {
			out = append(out, p.Argv)
		}
	}
	if len(out) == 0 && in.Raw != "" {
		out = append(out, literalCalls(in.Raw)...)
	}
	return out
}

func credentialOutput(req Request, in inspected, cwd, ws string) bool {
	if normTool(req.ToolName) == "read" {
		for _, p := range toolPaths(req.ToolInput) {
			if pathIsCredential(p, cwd, ws) {
				return true
			}
		}
	}
	for _, argv := range commandArgvs(in) {
		if len(argv) == 0 {
			continue
		}
		if ghCredential(argv) || gitCredentialCmd(argv) {
			return true
		}
		if credentialReader(argv[0]) && argvReadsCredential(argv, cwd, ws) {
			return true
		}
	}
	return false
}

// ghCredential is the exact command `gh auth token`, including flags.
// `gh auth status` and `gh secret list` are not this command.
func ghCredential(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "gh" {
		return false
	}
	words := ghCommandWords(argv[1:])
	return len(words) >= 2 && strings.EqualFold(words[0], "auth") && strings.EqualFold(words[1], "token")
}

// ghCredentialFamily is gh auth, gh secret, or gh ssh-key. Those ask.
// They are not the hard deny, and they are not a sole-reason allow.
func ghCredentialFamily(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "gh" {
		return false
	}
	words := ghCommandWords(argv[1:])
	if len(words) == 0 {
		return false
	}
	switch strings.ToLower(words[0]) {
	case "auth", "secret", "ssh-key":
		return true
	default:
		return false
	}
}

func ghCommandWords(args []string) []string {
	var words []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			words = append(words, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name, _, has := splitFlag(a)
			if !has && ghFlagTakesValue(name) && i+1 < len(args) {
				i++
			}
			continue
		}
		words = append(words, a)
	}
	return words
}

func ghFlagTakesValue(name string) bool {
	switch name {
	case "--hostname", "-h", "--user", "-u", "--jq", "--template", "--repo", "-R":
		return true
	default:
		return false
	}
}

// gitCredentialCmd is `git credential fill`, `approve`, or `reject`.
// `git credential-store` is not this command.
func gitCredentialCmd(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	sub, rest, ok := splitGit(argv)
	if !ok {
		sub = recoverGitSub(argv)
		rest = argsAfterSub(argv, sub)
	}
	if sub != "credential" {
		return false
	}
	for _, a := range rest {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			continue
		}
		switch strings.ToLower(a) {
		case "fill", "approve", "reject":
			return true
		default:
			return false
		}
	}
	return false
}

func credentialReader(bin string) bool {
	switch baseName(bin) {
	case "cat", "head", "tail", "less":
		return true
	default:
		return false
	}
}

func argvReadsCredential(argv []string, cwd, ws string) bool {
	for _, a := range argv[1:] {
		if pathIsCredential(a, cwd, ws) {
			return true
		}
	}
	return false
}

func pathIsCredential(p, cwd, ws string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	if ceilingCredentialPath(p) {
		return true
	}
	abs := lexicalAbs(p, cwd, ws)
	if abs != "" {
		if ceilingCredentialPath(abs) {
			return true
		}
		if st, err := os.Lstat(abs); err == nil && st.Mode()&os.ModeSymlink != 0 {
			if tgt, rerr := os.Readlink(abs); rerr == nil && ceilingCredentialPath(tgt) {
				return true
			}
		}
	}
	if resolved, err := ceilingResolveSpelled(p, cwd, ws); err == nil && ceilingCredentialPath(resolved) {
		return true
	}
	return false
}

func ceilingCredentialPath(p string) bool {
	return ceilingTokenFile(p)
}

// ceilingTokenFile is the exact token-file list. A basename match is
// enough for the key names and the dotfiles. hosts.yml counts only under
// a gh directory. .env.example, .env.sample, and .env.template do not.
// *.pem and *.key do not. Those ask through the path class.
func ceilingTokenFile(p string) bool {
	t := strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	if t == "" {
		return false
	}
	base := strings.ToLower(pathBase(t))
	switch base {
	case ".git-credentials", ".netrc", "admin-token", "github.token",
		"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa":
		return true
	}
	if base == ".env" {
		return true
	}
	if strings.HasPrefix(base, ".env.") {
		switch base {
		case ".env.example", ".env.sample", ".env.template":
			return false
		default:
			return true
		}
	}
	low := strings.ToLower(t)
	if base == "hosts.yml" || base == "hosts.yaml" {
		return strings.Contains(low, "/gh/") || strings.HasPrefix(low, "gh/")
	}
	return strings.HasSuffix(low, "/.config/git/credentials") || low == ".config/git/credentials"
}

// secretAskPath is material the ceiling must not auto-approve and must
// not hard-deny. Token files are included so a reader that is not cat,
// head, tail, or less still asks.
func secretAskPath(p string) bool {
	if p == "" || p == "-" {
		return false
	}
	if ceilingTokenFile(p) {
		return true
	}
	base := strings.ToLower(pathBase(p))
	return strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key")
}

func hookPathChange(req Request, in inspected, cwd, ws string, env []string) bool {
	// A hooksPath assignment in the environment asks through the git
	// location check. It is not this hard deny. env is that other check.
	_ = env
	for _, word := range redirectTargets(in.Raw) {
		if word == "\x00" {
			continue
		}
		if hookPathToken(word) || pathResolvesHook(word, cwd, ws) {
			return true
		}
	}
	if writeTool(req.ToolName) {
		for _, p := range toolPaths(req.ToolInput) {
			if hookPathToken(p) || pathResolvesHook(p, cwd, ws) {
				return true
			}
		}
	}
	for _, argv := range commandArgvs(in) {
		if gitHookWrite(argv, cwd, ws) {
			return true
		}
	}
	return false
}

func gitHookWrite(argv []string, cwd, ws string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	if gitConfigSetsHooksPath(argv) {
		return true
	}
	for _, fp := range gitPathFlagPaths(argv) {
		if hookPathToken(fp.value) || pathResolvesHook(fp.value, cwd, ws) {
			return true
		}
	}
	if readOnlyArgv(argv) {
		return false
	}
	for _, a := range positionalsOf(argv[1:]) {
		if hookPathToken(a) || pathResolvesHook(a, cwd, ws) {
			return true
		}
	}
	return false
}

// gitConfigSetsHooksPath is an exact core.hooksPath key on git config
// or on -c / --config. A commit message with that text is not a key.
func gitConfigSetsHooksPath(argv []string) bool {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			break
		}
		name, val, has := splitFlag(a)
		if name != "-c" && name != "--config" {
			continue
		}
		if has {
			if hooksPathKey(val) {
				return true
			}
			continue
		}
		if i+1 < len(argv) && hooksPathKey(argv[i+1]) {
			return true
		}
	}
	sub, rest, ok := splitGit(argv)
	if !ok {
		sub = recoverGitSub(argv)
		rest = argsAfterSub(argv, sub)
	}
	if sub != "config" {
		return false
	}
	return hooksPathKey(configActionKey(rest))
}

// configActionKey is the key operand of git config. A following value
// is not the key, so a value of "core.hooksPath" is not a match.
func configActionKey(rest []string) string {
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if a == "--" {
			if i+1 < len(rest) {
				return rest[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			name, _, has := splitFlag(a)
			if !has && configValueFlag(name) && i+1 < len(rest) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

func configValueFlag(name string) bool {
	switch name {
	case "-f", "--file", "--blob", "--default", "--type", "--comment":
		return true
	default:
		return false
	}
}

func hooksPathKey(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	key, _, _ := strings.Cut(low, "=")
	return key == "core.hookspath"
}

func pathResolvesHook(p, cwd, ws string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	resolved, err := ceilingResolveSpelled(p, cwd, ws)
	return err == nil && hookPathToken(resolved)
}
