package github

import "strings"

// RepoConfigDenied reports whether a workspace .git/config text contains a
// key the host must not honor. The text is parsed in process. Git is not
// invoked. An unreadable or unparseable file is denied so a hidden key cannot
// slip through. An empty file is not denied.
//
// Denied keys are any key in url.*, credential*, http.*, gpg.*, include*, and
// includeIf*, plus core.fsmonitor and core.askpass. A remote URL under
// [remote] is not one of those sections.
func RepoConfigDenied(text string) bool {
	if text == "" {
		return false
	}
	if strings.ContainsRune(text, 0) {
		return true
	}
	joined, ok := joinConfigLines(text)
	if !ok {
		return true
	}
	section := ""
	seenSection := false
	for _, line := range strings.Split(joined, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			name, ok := configSection(trim)
			if !ok {
				return true
			}
			section = name
			seenSection = true
			continue
		}
		if !seenSection {
			return true
		}
		key, ok := configKey(trim)
		if !ok {
			return true
		}
		if configKeyDenied(section, key) {
			return true
		}
	}
	return false
}

func configKeyDenied(section, key string) bool {
	sec := strings.ToLower(section)
	switch {
	case sec == "url" || strings.HasPrefix(sec, "url."):
		return true
	case sec == "http" || strings.HasPrefix(sec, "http."):
		return true
	case sec == "credential" || strings.HasPrefix(sec, "credential"):
		return true
	case sec == "gpg" || strings.HasPrefix(sec, "gpg"):
		return true
	case sec == "include" || strings.HasPrefix(sec, "include"):
		return true
	}
	if strings.EqualFold(sec, "core") {
		k := strings.ToLower(key)
		if k == "fsmonitor" || k == "askpass" {
			return true
		}
	}
	return false
}

func configSection(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if len(s) < 3 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", false
	}
	body := strings.TrimSpace(s[1 : len(s)-1])
	if body == "" {
		return "", false
	}
	i := 0
	for i < len(body) && configNameByte(body[i]) {
		i++
	}
	if i == 0 {
		return "", false
	}
	name := body[:i]
	rest := strings.TrimSpace(body[i:])
	if rest == "" {
		return name, true
	}
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", false
	}
	inner := rest[1 : len(rest)-1]
	if strings.ContainsAny(inner, "\r\n") {
		return "", false
	}
	return name, true
}

func configKey(line string) (string, bool) {
	s := strings.TrimSpace(line)
	if s == "" {
		return "", false
	}
	name := s
	if i := strings.IndexByte(s, '='); i >= 0 {
		name = s[:i]
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if !configNameByte(name[i]) {
			return "", false
		}
	}
	return name, true
}

func configNameByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

// joinConfigLines folds backslash continuations. A trailing continuation is denied.
func joinConfigLines(text string) (string, bool) {
	text = strings.TrimPrefix(text, "\uFEFF")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	// A final newline is the line ending, not a continuation line.
	text = strings.TrimSuffix(text, "\n")
	raw := strings.Split(text, "\n")
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		line := raw[i]
		for strings.HasSuffix(line, "\\") && !strings.HasSuffix(line, "\\\\") {
			line = line[:len(line)-1]
			i++
			if i >= len(raw) {
				return "", false
			}
			line += raw[i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), true
}
