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

func ghCredential(argv []string) bool {
	if len(argv) < 2 || baseName(argv[0]) != "gh" {
		return false
	}
	switch strings.ToLower(argv[1]) {
	case "auth", "secret", "ssh-key":
		return true
	default:
		return false
	}
}

func gitCredentialCmd(argv []string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	sub, _, ok := splitGit(argv)
	if !ok {
		sub = recoverGitSub(argv)
	}
	return sub == "credential"
}

func credentialReader(bin string) bool {
	switch baseName(bin) {
	case "cat", "head", "tail", "grep", "jq", "cut", "sort", "uniq", "wc",
		"less", "more", "bat", "od", "hexdump", "strings", "awk", "sed",
		"nl", "tac", "base64", "xxd", "rev":
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
	t := strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	if t == "" {
		return false
	}
	for _, s := range strings.Split(t, "/") {
		s = strings.ToLower(s)
		switch s {
		case ".ssh", ".aws", ".gnupg", ".netrc", ".kube", ".azure", ".docker",
			"credentials", "credentials.json", ".credentials",
			"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
			"auth.json", "admin-token", ".git-credentials", ".npmrc",
			".pypirc", "cookies":
			return true
		}
		if s == ".env" || strings.HasPrefix(s, ".env.") {
			return true
		}
		if strings.HasSuffix(s, ".pem") || strings.HasSuffix(s, ".key") {
			return true
		}
	}
	return false
}

func hookPathChange(req Request, in inspected, cwd, ws string, env []string) bool {
	if hookInEnv(env) {
		return true
	}
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

func hookInEnv(env []string) bool {
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(k), "hookspath") {
			return true
		}
		if gitLocationName(k) && strings.Contains(strings.ToLower(v), "hookspath") {
			return true
		}
	}
	return false
}

func gitHookWrite(argv []string, cwd, ws string) bool {
	if len(argv) == 0 || baseName(argv[0]) != "git" {
		return false
	}
	for _, a := range argv[1:] {
		if tokenNamesHooksPath(a) {
			return true
		}
	}
	if readOnlyArgv(argv) {
		return false
	}
	for _, a := range argv[1:] {
		if a == "--" || (strings.HasPrefix(a, "-") && a != "-") {
			continue
		}
		if hookPathToken(a) || pathResolvesHook(a, cwd, ws) {
			return true
		}
	}
	return false
}

func tokenNamesHooksPath(a string) bool {
	low := strings.ToLower(a)
	if low == "core.hookspath" || strings.HasPrefix(low, "core.hookspath=") {
		return true
	}
	if strings.Contains(low, "core.hookspath") && (strings.HasPrefix(low, "-c") || strings.HasPrefix(low, "--config")) {
		return true
	}
	return false
}

func pathResolvesHook(p, cwd, ws string) bool {
	if p == "" || strings.ContainsRune(p, 0) {
		return false
	}
	resolved, err := ceilingResolveSpelled(p, cwd, ws)
	return err == nil && hookPathToken(resolved)
}
