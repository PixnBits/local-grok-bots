package permbroker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// gitConfigRisk reports a git config key, attribute driver, or hook that
// makes a git command ask. Claude Bash and run_shell both use it. The
// scan reads the bot repo, included files, attribute files, hooks in the
// git directory, the bot and user git config, and the managed environment
// stored for that bot. A missing file is not itself a reason.
func gitConfigRisk(ws string, homes, env []string) string {
	seen := map[string]bool{}
	var files []string
	if strings.TrimSpace(ws) != "" {
		files = append(files, gitConfigPath(ws), filepath.Join(ws, ".gitattributes"))
		if dir, ok := gitDir(ws); ok {
			files = append(files, filepath.Join(dir, "info", "attributes"))
		}
	}
	for _, home := range homes {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		files = append(files,
			filepath.Join(home, ".gitconfig"),
			filepath.Join(home, ".config", "git", "config"),
			filepath.Join(home, ".config", "git", "attributes"),
		)
	}
	for _, f := range files {
		if why := scanGitFile(f, seen, 0, homes, false); why != "" {
			return why
		}
	}
	if why := scanGitEnv(env, seen, homes); why != "" {
		return why
	}
	if strings.TrimSpace(ws) != "" {
		if why := gitHookRisk(ws); why != "" {
			return why
		}
	}
	return ""
}

// gitDir is the git directory for ws. A gitdir file is resolved. A
// symlink or a real directory uses that .git path. core.hooksPath is
// not consulted.
func gitDir(ws string) (string, bool) {
	p := filepath.Join(ws, ".git")
	st, err := os.Lstat(p)
	if err != nil {
		return "", false
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return p, true
	}
	if st.Mode().IsRegular() {
		if dir, ok := gitdirFile(p, ws); ok {
			return dir, true
		}
		return "", false
	}
	if st.IsDir() {
		return p, true
	}
	return "", false
}

func gitdirFile(path, ws string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(string(b))
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if !strings.HasPrefix(strings.ToLower(line), "gitdir:") {
		return "", false
	}
	dir := strings.TrimSpace(line[len("gitdir:"):])
	dir = strings.Trim(dir, `"'`)
	if dir == "" {
		return "", false
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(ws, dir)
	}
	return filepath.Clean(dir), true
}

func gitConfigPath(ws string) string {
	if dir, ok := gitDir(ws); ok {
		return filepath.Join(dir, "config")
	}
	return filepath.Join(ws, ".git", "config")
}

func scanGitFile(path string, seen map[string]bool, depth int, homes []string, missingIsInclude bool) string {
	if depth > 8 {
		return "include"
	}
	abs := path
	if a, err := filepath.Abs(path); err == nil {
		abs = a
	}
	abs = filepath.Clean(abs)
	if seen[abs] {
		return "include"
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		if missingIsInclude {
			return "include"
		}
		return ""
	}
	seen[abs] = true
	if isAttrPath(abs) {
		if why := scanAttr(b); why != "" {
			return why
		}
	}
	return scanConfig(b, filepath.Dir(abs), seen, depth, homes)
}

func isAttrPath(path string) bool {
	base := filepath.Base(path)
	return base == ".gitattributes" || base == "attributes"
}

// scanAttr flags an attribute that names a diff, merge, or filter driver.
// A bare diff, -diff, or binary attribute is not a driver name.
func scanAttr(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, tok := range fields[1:] {
			if why := attrDriver(tok); why != "" {
				return why
			}
		}
	}
	return ""
}

func attrDriver(tok string) string {
	tok = strings.TrimSpace(tok)
	if tok == "" || strings.HasPrefix(tok, "-") || strings.HasPrefix(tok, "!") {
		return ""
	}
	name, val, ok := strings.Cut(tok, "=")
	if !ok || strings.Trim(val, `"'`) == "" {
		return ""
	}
	switch strings.ToLower(name) {
	case "diff", "merge", "filter":
		return strings.ToLower(name)
	default:
		return ""
	}
}

func scanAttrPath(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return scanAttr(b)
}

func scanConfig(b []byte, dir string, seen map[string]bool, depth int, homes []string) string {
	section := ""
	sub := ""
	var includes []string
	includeKind := "include"
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			section, sub = sectionParts(trim)
			if section == "filter" {
				return "filter"
			}
			if section == "includeif" {
				includeKind = "includeIf"
			}
			continue
		}
		key, val, ok := splitKV(trim)
		if !ok {
			continue
		}
		if why := riskyConfig(section, sub, key, val); why != "" {
			if why == "core.attributesFile" {
				if awhy := scanAttrPath(resolveInclude(val, dir, homes)); awhy != "" {
					return awhy
				}
			}
			return why
		}
		if key == "path" && (section == "include" || section == "includeif") {
			includes = append(includes, val)
		}
	}
	for _, p := range includes {
		target := resolveInclude(p, dir, homes)
		if why := scanGitFile(target, seen, depth+1, homes, true); why != "" {
			return why
		}
	}
	if len(includes) > 0 {
		return includeKind
	}
	return ""
}

func sectionParts(line string) (name, sub string) {
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return "", ""
	}
	inner := strings.TrimSpace(line[1:end])
	if inner == "" {
		return "", ""
	}
	i := strings.IndexAny(inner, " \t\"")
	if i < 0 {
		return strings.ToLower(inner), ""
	}
	name = strings.ToLower(strings.TrimSpace(inner[:i]))
	rest := strings.TrimSpace(inner[i:])
	rest = strings.Trim(rest, `"'`)
	return name, strings.ToLower(rest)
}

func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	k := strings.ToLower(strings.TrimSpace(line[:i]))
	v := strings.TrimSpace(line[i+1:])
	v = strings.Trim(v, `"'`)
	if k == "" {
		return "", "", false
	}
	return k, v, true
}

// riskyConfig reports a config key that runs a program or opens a protocol.
// section and sub are already lower case. key is lower case.
func riskyConfig(section, sub, key, val string) string {
	full := key
	if section != "" {
		if sub != "" {
			full = section + "." + sub + "." + key
		} else {
			full = section + "." + key
		}
	}
	return riskyFlat(full, val)
}

func riskyFlat(full, val string) string {
	full = strings.ToLower(strings.TrimSpace(full))
	switch full {
	case "core.hookspath":
		return "core.hooksPath"
	case "core.fsmonitor":
		return "core.fsmonitor"
	case "core.sshcommand":
		return "core.sshCommand"
	case "core.pager":
		return "core.pager"
	case "core.editor":
		return "core.editor"
	case "core.attributesfile":
		return "core.attributesFile"
	case "core.askpass":
		return "core.askPass"
	case "core.gitproxy":
		return "core.gitProxy"
	case "diff.external":
		return "diff.external"
	case "credential.helper":
		return "credential.helper"
	case "sequence.editor":
		return "sequence.editor"
	case "uploadpack.packobjectshook":
		return "uploadpack.packObjectsHook"
	case "gpg.program":
		return "gpg.program"
	case "protocol.allow":
		if strings.EqualFold(strings.TrimSpace(val), "always") {
			return "protocol.allow"
		}
		return ""
	case "protocol.ext.allow":
		if strings.EqualFold(strings.TrimSpace(val), "never") {
			return ""
		}
		return "protocol.ext.allow"
	}
	if full == "filter" || strings.HasPrefix(full, "filter.") {
		return "filter"
	}
	if strings.HasPrefix(full, "diff.") && strings.HasSuffix(full, ".textconv") {
		return "diff.textconv"
	}
	if strings.HasPrefix(full, "diff.") && strings.HasSuffix(full, ".command") {
		return "diff.command"
	}
	if strings.HasPrefix(full, "merge.") && strings.HasSuffix(full, ".driver") {
		return "merge.driver"
	}
	if strings.HasPrefix(full, "alias.") && len(full) > len("alias.") {
		return "alias"
	}
	if strings.HasPrefix(full, "gpg.") && strings.HasSuffix(full, ".program") {
		return "gpg.program"
	}
	if strings.HasPrefix(strings.ToLower(full), "url.ext::") || (strings.HasPrefix(full, "url.") && strings.HasPrefix(strings.ToLower(strings.TrimSpace(val)), "ext::")) {
		if strings.HasSuffix(full, ".pushinsteadof") {
			return "url.pushInsteadOf"
		}
		if strings.HasSuffix(full, ".insteadof") {
			return "url.insteadOf"
		}
	}
	return ""
}

func resolveInclude(p, dir string, homes []string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, `"'`)
	if p == "~" || strings.HasPrefix(p, "~/") {
		home := ""
		for _, h := range homes {
			if strings.TrimSpace(h) != "" {
				home = h
				break
			}
		}
		if home == "" {
			home = os.Getenv("HOME")
		}
		if p == "~" {
			p = home
		} else if home != "" {
			p = filepath.Join(home, p[2:])
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return filepath.Clean(p)
}

func scanGitEnv(env []string, seen map[string]bool, homes []string) string {
	vals := map[string]string{}
	for _, e := range env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !strings.HasPrefix(k, "GIT_") {
			continue
		}
		vals[k] = v
	}
	if n, err := strconv.Atoi(strings.TrimSpace(vals["GIT_CONFIG_COUNT"])); err == nil && n > 0 && n < 64 {
		for i := 0; i < n; i++ {
			key := vals["GIT_CONFIG_KEY_"+strconv.Itoa(i)]
			val := vals["GIT_CONFIG_VALUE_"+strconv.Itoa(i)]
			if why := riskyFlat(key, val); why != "" {
				return why
			}
			low := strings.ToLower(key)
			if low == "include.path" || strings.HasPrefix(low, "includeif.") {
				return "include"
			}
		}
	}
	if p := vals["GIT_CONFIG_PARAMETERS"]; p != "" {
		if why := riskyInText(p); why != "" {
			return why
		}
	}
	for _, name := range []string{"GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"} {
		if p := strings.TrimSpace(vals[name]); p != "" {
			if why := scanGitFile(p, seen, 0, homes, false); why != "" {
				return why
			}
		}
	}
	if dir := strings.TrimSpace(vals["GIT_DIR"]); dir != "" {
		if why := scanGitFile(filepath.Join(dir, "config"), seen, 0, homes, false); why != "" {
			return why
		}
	}
	return ""
}

func riskyInText(s string) string {
	low := strings.ToLower(s)
	switch {
	case strings.Contains(low, "hookspath"):
		return "core.hooksPath"
	case strings.Contains(low, "fsmonitor"):
		return "core.fsmonitor"
	case strings.Contains(low, "sshcommand"):
		return "core.sshCommand"
	case strings.Contains(low, "credential.helper"):
		return "credential.helper"
	case strings.Contains(low, "diff.external"):
		return "diff.external"
	case strings.Contains(low, "core.pager"):
		return "core.pager"
	case strings.Contains(low, "core.editor"):
		return "core.editor"
	case strings.Contains(low, "textconv"):
		return "diff.textconv"
	case strings.Contains(low, "askpass"):
		return "core.askPass"
	case strings.Contains(low, "gitproxy"):
		return "core.gitProxy"
	case strings.Contains(low, "attributesfile"):
		return "core.attributesFile"
	case strings.Contains(low, "gpg.program"), strings.Contains(low, ".program"):
		return "gpg.program"
	case strings.Contains(low, "sequence.editor"):
		return "sequence.editor"
	case strings.Contains(low, "packobjectshook"):
		return "uploadpack.packObjectsHook"
	case strings.Contains(low, "ext::"):
		return "url.insteadOf"
	case strings.Contains(low, "includeif"), strings.Contains(low, "include.path"):
		return "include"
	case strings.Contains(low, "filter."):
		return "filter"
	case strings.Contains(low, "alias."):
		return "alias"
	default:
		return ""
	}
}

// gitHookRisk reports a hook in the git directory that can run.
// A name ending in .sample is not a reason. core.hooksPath is not read.
func gitHookRisk(ws string) string {
	dir, ok := gitDir(ws)
	if !ok {
		return ""
	}
	entries, err := os.ReadDir(filepath.Join(dir, "hooks"))
	if err != nil {
		return ""
	}
	for _, ent := range entries {
		name := ent.Name()
		if name == "" || strings.HasSuffix(name, ".sample") {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, "hooks", name))
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "git hook"
		}
		if info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
			return "git hook"
		}
	}
	return ""
}
