package github

import "strings"

// RepoConfigDenied reports whether a workspace .git/config text contains a
// key the host must not honor. The text is parsed in process. Git is not
// invoked. An unreadable or unparseable file is denied so a hidden key cannot
// slip through. An empty file is not denied.
//
// This denylist is a convenience check. The bare mirror, which is written by
// the daemon and does not copy this file, is the control that decides what
// host git can run. Denied keys are url.*, credential*, http.*, gpg.*,
// include*, includeIf*, alias.*, filter.*, diff.external, remote.*.pushurl,
// and core.fsmonitor, core.askpass, core.sshCommand, and core.hooksPath.
// A remote URL under [remote] is not one of those keys.
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
	k := strings.ToLower(key)
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
	case sec == "alias" || sec == "filter":
		return true
	case sec == "diff" && k == "external":
		return true
	case sec == "remote" && k == "pushurl":
		return true
	}
	if sec == "core" {
		switch k {
		case "fsmonitor", "askpass", "sshcommand", "hookspath":
			return true
		}
	}
	return false
}

// RemoteConfigURL returns the url of [remote "name"] in a git config text.
// The section and the url key match without regard to case. The remote name
// matches exactly. The last value wins. One pair of double quotes around the
// value is removed. Includes are not opened. A name that contains a quote, a
// bracket, or a control character returns "". A header or a pair that cannot
// be parsed returns "".
func RemoteConfigURL(text, name string) string {
	if name == "" || strings.ContainsAny(name, "\"[]\r\n\t\x00") {
		return ""
	}
	if strings.ContainsRune(text, 0) {
		return ""
	}
	joined, ok := joinConfigLines(text)
	if !ok {
		return ""
	}
	section := ""
	sub := ""
	seen := false
	url := ""
	for _, line := range strings.Split(joined, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, "[") {
			sec, subsection, ok := configHeader(trim)
			if !ok {
				return ""
			}
			section = sec
			sub = subsection
			seen = true
			continue
		}
		if !seen {
			return ""
		}
		key, val, ok := configPair(trim)
		if !ok {
			return ""
		}
		if strings.EqualFold(section, "remote") && sub == name && strings.EqualFold(key, "url") {
			url = val
		}
	}
	return url
}

func configHeader(line string) (section, subsection string, ok bool) {
	s := strings.TrimSpace(line)
	if len(s) < 3 || s[0] != '[' || s[len(s)-1] != ']' {
		return "", "", false
	}
	body := strings.TrimSpace(s[1 : len(s)-1])
	if body == "" {
		return "", "", false
	}
	i := 0
	for i < len(body) && configNameByte(body[i]) {
		i++
	}
	if i == 0 {
		return "", "", false
	}
	section = body[:i]
	rest := strings.TrimSpace(body[i:])
	if rest == "" {
		return section, "", true
	}
	if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
		return "", "", false
	}
	inner := rest[1 : len(rest)-1]
	if strings.ContainsAny(inner, "\"[]\r\n\x00") || strings.Contains(inner, "\\") {
		return "", "", false
	}
	return section, inner, true
}

func configPair(line string) (key, val string, ok bool) {
	s := strings.TrimSpace(line)
	key, ok = configKey(s)
	if !ok {
		return "", "", false
	}
	i := strings.IndexByte(s, '=')
	if i < 0 {
		return key, "", true
	}
	val = strings.TrimSpace(s[i+1:])
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	if strings.ContainsAny(val, "\r\n\x00") {
		return "", "", false
	}
	return key, val, true
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
