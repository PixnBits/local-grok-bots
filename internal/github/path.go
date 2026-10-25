package github

import (
	"net/url"
	"path"
	"strings"
)

// Route is one allowlisted GitHub request after the local prefix is removed.
// Path is the upstream path. Query is empty or a git service query.
type Route struct {
	Service string
	Owner   string
	Repo    string
	Path    string
	Query   string
}

// Classify checks a local proxy path. service is "github" or "api" after the
// /github or /api prefix has been removed, so path starts at the upstream
// path. allow maps lower-case owner/repo to true. A path outside that set,
// a traversal, or an unexpected query is refused.
func Classify(service, rawPath, rawQuery string, allow map[string]bool) (Route, error) {
	norm, ok := normalizePath(rawPath)
	if !ok || !querySafe(rawQuery) {
		return Route{}, ErrRepo
	}
	switch service {
	case "github":
		return classifyGit(norm, rawQuery, allow)
	case "api":
		return classifyAPI(norm, rawQuery, allow)
	default:
		return Route{}, ErrRepo
	}
}

func classifyGit(norm, rawQuery string, allow map[string]bool) (Route, error) {
	parts := splitParts(norm)
	if len(parts) < 3 {
		return Route{}, ErrRepo
	}
	owner, ok := ownerPart(parts[0])
	if !ok {
		return Route{}, ErrRepo
	}
	repo, ok := repoPart(parts[1])
	if !ok {
		return Route{}, ErrRepo
	}
	tail := strings.Join(parts[2:], "/")
	switch tail {
	case "info/refs", "git-upload-pack", "git-receive-pack":
	default:
		return Route{}, ErrRepo
	}
	query := ""
	if tail == "info/refs" {
		switch rawQuery {
		case "", "service=git-upload-pack", "service=git-receive-pack":
			query = rawQuery
		default:
			return Route{}, ErrRepo
		}
	} else if rawQuery != "" {
		return Route{}, ErrRepo
	}
	route := Route{Service: "github", Owner: owner, Repo: repo, Path: norm, Query: query}
	if !allowListed(allow, owner, repo) {
		return route, ErrNotAllowed
	}
	return route, nil
}

func classifyAPI(norm, rawQuery string, allow map[string]bool) (Route, error) {
	if rawQuery != "" {
		return Route{}, ErrRepo
	}
	parts := splitParts(norm)
	if len(parts) < 3 || len(parts) > 16 || parts[0] != "repos" {
		return Route{}, ErrRepo
	}
	owner, ok := ownerPart(parts[1])
	if !ok {
		return Route{}, ErrRepo
	}
	repo, ok := repoPart(parts[2])
	if !ok || strings.HasSuffix(strings.ToLower(parts[2]), ".git") {
		return Route{}, ErrRepo
	}
	for _, seg := range parts[3:] {
		if !apiSeg(seg) {
			return Route{}, ErrRepo
		}
	}
	route := Route{Service: "api", Owner: owner, Repo: repo, Path: norm, Query: ""}
	if !allowListed(allow, owner, repo) {
		return route, ErrNotAllowed
	}
	return route, nil
}

// allowListed matches owner/repo with EqualFold. Keys may already be lower
// case. A mixed-case allowlist entry still matches a mixed-case path.
func allowListed(allow map[string]bool, owner, repo string) bool {
	if len(allow) == 0 {
		return false
	}
	want := owner + "/" + repo
	if allow[want] {
		return true
	}
	for key, ok := range allow {
		if ok && strings.EqualFold(key, want) {
			return true
		}
	}
	return false
}

func splitParts(norm string) []string {
	return strings.Split(strings.Trim(norm, "/"), "/")
}

func ownerPart(seg string) (string, bool) {
	low := strings.ToLower(seg)
	if !partOK(low) {
		return "", false
	}
	return low, true
}

func repoPart(seg string) (string, bool) {
	raw := seg
	low := strings.ToLower(raw)
	if strings.HasSuffix(low, ".git") {
		raw = raw[:len(raw)-len(".git")]
		low = low[:len(low)-len(".git")]
	}
	if raw == "" || strings.HasSuffix(low, ".git") || !partOK(low) {
		return "", false
	}
	return low, true
}

func apiSeg(s string) bool {
	if s == "" || len(s) > 200 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-', c == '+', c == '~':
		default:
			return false
		}
	}
	return true
}

// normalizePath returns a decoded absolute path with no dot segments, empty
// segments, or encoded separators.
func normalizePath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		switch {
		case u.RawPath != "":
			raw = u.RawPath
		case u.EscapedPath() != "":
			raw = u.EscapedPath()
		default:
			raw = u.Path
		}
	}
	cur := raw
	for i := 0; i < 4; i++ {
		if badPath(cur) {
			return "", false
		}
		if !strings.Contains(cur, "%") {
			break
		}
		next, err := url.PathUnescape(cur)
		if err != nil || next == cur {
			if err != nil {
				return "", false
			}
			break
		}
		cur = next
	}
	if strings.Contains(cur, "%") || badPath(cur) {
		return "", false
	}
	trimmed := strings.TrimRight(cur, "/")
	if trimmed == "" {
		trimmed = "/"
	}
	if path.Clean(trimmed) != trimmed {
		return "", false
	}
	return trimmed, true
}

func badPath(s string) bool {
	if s == "" || !strings.HasPrefix(s, "/") || strings.ContainsAny(s, "\\?#\x00") {
		return true
	}
	lower := strings.ToLower(s)
	if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
		return true
	}
	if strings.Contains(s, "//") {
		return true
	}
	for _, seg := range strings.Split(strings.TrimRight(s, "/"), "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

func querySafe(q string) bool {
	if strings.ContainsAny(q, "\r\n\x00#\\") {
		return false
	}
	cur := q
	for i := 0; i < 3; i++ {
		if strings.Contains(cur, "..") {
			return false
		}
		lower := strings.ToLower(cur)
		if strings.Contains(lower, "%2e") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%00") {
			return false
		}
		next, err := url.QueryUnescape(cur)
		if err != nil {
			return false
		}
		if strings.ContainsAny(next, "/\\") {
			return false
		}
		if next == cur {
			return true
		}
		cur = next
	}
	return !strings.Contains(cur, "..")
}
