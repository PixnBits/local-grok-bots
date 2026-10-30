package permbroker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// gitConfigRisk reports a git config key that makes every Claude git
// command ask. The scan reads the bot repo, included files, attribute
// files, the bot and user git config, and the managed CLI environment.
// A missing file is not itself a reason. run_shell is not scanned; the
// jail git wrapper supplies that config.
func gitConfigRisk(ws string, homes, env []string) string {
	seen := map[string]bool{}
	var files []string
	if strings.TrimSpace(ws) != "" {
		files = append(files,
			gitConfigPath(ws),
			filepath.Join(ws, ".git", "info", "attributes"),
			filepath.Join(ws, ".gitattributes"),
		)
	}
	for _, home := range homes {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		files = append(files,
			filepath.Join(home, ".gitconfig"),
			filepath.Join(home, ".config", "git", "config"),
		)
	}
	for _, f := range files {
		if why := scanGitFile(f, seen, 0, homes, false); why != "" {
			return why
		}
	}
	return scanGitEnv(env, seen, homes)
}

func gitConfigPath(ws string) string {
	p := filepath.Join(ws, ".git")
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		return filepath.Join(p, "config")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return filepath.Join(p, "config")
	}
	line := strings.TrimSpace(string(b))
	if !strings.HasPrefix(strings.ToLower(line), "gitdir:") {
		return filepath.Join(p, "config")
	}
	dir := strings.TrimSpace(line[len("gitdir:"):])
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(ws, dir)
	}
	return filepath.Join(dir, "config")
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

func scanAttr(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "filter=") {
			return "filter"
		}
	}
	return ""
}

func scanConfig(b []byte, dir string, seen map[string]bool, depth int, homes []string) string {
	section := ""
	var includes []string
	includeKind := "include"
	for _, line := range strings.Split(string(b), "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			section = sectionName(trim)
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
		full := key
		if section != "" {
			full = section + "." + key
		}
		if why := riskyKey(full); why != "" {
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

func sectionName(line string) string {
	end := strings.IndexByte(line, ']')
	if end < 0 {
		return ""
	}
	inner := strings.TrimSpace(line[1:end])
	if i := strings.IndexAny(inner, " \t\""); i >= 0 {
		inner = inner[:i]
	}
	return strings.ToLower(strings.TrimSpace(inner))
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

func riskyKey(full string) string {
	switch strings.ToLower(strings.TrimSpace(full)) {
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
	case "diff.external":
		return "diff.external"
	case "credential.helper":
		return "credential.helper"
	}
	low := strings.ToLower(full)
	if low == "filter" || strings.HasPrefix(low, "filter.") {
		return "filter"
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
			if why := riskyKey(key); why != "" {
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
	case strings.Contains(low, "includeif"), strings.Contains(low, "include.path"):
		return "include"
	case strings.Contains(low, "filter."):
		return "filter"
	default:
		return ""
	}
}
