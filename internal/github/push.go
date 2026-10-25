package github

import (
	"errors"
	"net/url"
	"strings"
)

// Push argument failures. The text is safe to show and to audit.
var (
	ErrPushOption = errors.New("push option denied")
	ErrPushForce  = errors.New("force push denied")
	ErrPushDelete = errors.New("branch delete denied")
	ErrPushTag    = errors.New("tag push denied")
	ErrPushRemote = errors.New("remote denied")
	ErrPushSpec   = errors.New("refspec denied")
)

// PushArgs is a git push argv after the leading git/push words are removed.
// URL is set when the argv contained one remote URL. Names are the other
// positionals, in order. The caller decides which names are remote names.
type PushArgs struct {
	URL   string
	Names []string
}

// ParsePushArgs fail-closes. Flags that are not on the explicit allow list,
// including force, delete, tags, mirror, and dry-run, are errors. A refspec
// whose source starts with + or is empty is an error.
// On error the returned PushArgs is the zero value. Callers must not use it.
func ParsePushArgs(args []string) (PushArgs, error) {
	i := 0
	if i < len(args) && args[i] == "git" {
		i++
	}
	if i < len(args) && args[i] == "push" {
		i++
	}
	var first error
	var out PushArgs
	sawURL := false
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	take := func(tok string) {
		if tok == "" || strings.ContainsAny(tok, "\r\n\t\x00") {
			note(ErrPushSpec)
			return
		}
		if looksRemoteURL(tok) {
			if sawURL {
				note(ErrPushRemote)
				return
			}
			sawURL = true
			if _, _, err := ParseGitHubRemote(tok); err != nil {
				out.URL = tok
				note(err)
				return
			}
			out.URL = tok
			return
		}
		if _, _, err := SplitRefspec(tok); err != nil {
			note(err)
			return
		}
		out.Names = append(out.Names, tok)
	}
	for i < len(args) {
		a := args[i]
		i++
		if a == "--" {
			for _, tok := range args[i:] {
				take(tok)
			}
			break
		}
		if a == "" || strings.HasPrefix(a, "-") {
			note(pushFlag(a))
			continue
		}
		take(a)
	}
	if first != nil {
		return PushArgs{}, first
	}
	return out, nil
}

// PushAuditRemote returns the first positional token of a git push argv.
// The token is a URL or a remote name. It returns "" when there is no
// positional token, or when that token contains CR, LF, a tab, or NUL.
// Callers use it only to label a denial.
func PushAuditRemote(args []string) string {
	tok, ok := firstPushPositional(args)
	if !ok || strings.ContainsAny(tok, "\r\n\t\x00") {
		return ""
	}
	return tok
}

func firstPushPositional(args []string) (string, bool) {
	i := 0
	if i < len(args) && args[i] == "git" {
		i++
	}
	if i < len(args) && args[i] == "push" {
		i++
	}
	for i < len(args) {
		a := args[i]
		i++
		if a == "--" {
			if i >= len(args) {
				return "", false
			}
			return args[i], true
		}
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", false
}

func pushFlag(a string) error {
	switch a {
	case "-q", "--quiet", "-v", "--verbose", "--progress", "--no-progress",
		"--porcelain", "--thin", "--no-thin", "-u", "--set-upstream",
		"-4", "-6", "--ipv4", "--ipv6":
		return nil
	case "-f", "--force", "--force-with-lease", "--force-if-includes":
		return ErrPushForce
	case "--delete", "-d":
		return ErrPushDelete
	case "--tags", "--follow-tags":
		return ErrPushTag
	case "--all", "--mirror":
		return ErrPushSpec
	}
	if strings.HasPrefix(a, "--force") {
		return ErrPushForce
	}
	if strings.HasPrefix(a, "--") || !strings.HasPrefix(a, "-") || len(a) < 2 {
		return ErrPushOption
	}
	for _, c := range a[1:] {
		switch c {
		case 'q', 'v', 'u', 'p', '4', '6':
		case 'f':
			return ErrPushForce
		case 'd':
			return ErrPushDelete
		default:
			return ErrPushOption
		}
	}
	return nil
}

func looksRemoteURL(s string) bool {
	return strings.Contains(s, "://") || strings.HasPrefix(s, "git@")
}

// SplitRefspec rejects force, delete, and tag shapes. A token with no colon
// is src and dst of that token. HEAD is left for the caller to resolve.
func SplitRefspec(spec string) (src, dst string, err error) {
	if spec == "" || strings.HasPrefix(spec, "+") || strings.ContainsAny(spec, "\r\n\t\x00 ") {
		if strings.HasPrefix(spec, "+") {
			return "", "", ErrPushForce
		}
		return "", "", ErrPushSpec
	}
	if strings.Count(spec, ":") > 1 {
		return "", "", ErrPushSpec
	}
	src, dst, ok := strings.Cut(spec, ":")
	if !ok {
		dst = src
	}
	if src == "" || dst == "" {
		return "", "", ErrPushDelete
	}
	if tagRef(src) || tagRef(dst) {
		return "", "", ErrPushTag
	}
	return src, dst, nil
}

func tagRef(s string) bool {
	return s == "refs/tags" || strings.HasPrefix(s, "refs/tags/")
}

// ParseGitHubRemote accepts https://github.com/owner/repo with an optional
// .git suffix. Userinfo, another host, and another scheme are refused.
func ParseGitHubRemote(raw string) (owner, repo string, err error) {
	if strings.ContainsAny(raw, "\r\n\t\x00 ") || strings.HasPrefix(raw, "git@") {
		return "", "", ErrPushRemote
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.User != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "github.com") {
		return "", "", ErrPushRemote
	}
	if u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return "", "", ErrPushRemote
	}
	path := strings.Trim(u.EscapedPath(), "/")
	path = strings.TrimSuffix(path, ".git")
	name, nerr := NormalizeRepo(path)
	if nerr != nil {
		return "", "", ErrPushRemote
	}
	owner, repo, _ = strings.Cut(name, "/")
	return owner, repo, nil
}

// BranchOf returns the branch name of a ref. refs/heads/X and a plain name
// are accepted. Other refs/ forms are refused. HEAD is not a branch name.
func BranchOf(ref string) (string, error) {
	if ref == "" || ref == "HEAD" {
		return "", ErrPushSpec
	}
	if strings.HasPrefix(ref, "refs/") {
		rest, ok := strings.CutPrefix(ref, "refs/heads/")
		if !ok || rest == "" {
			return "", ErrPushSpec
		}
		ref = rest
	}
	if !BranchOK(ref) {
		return "", ErrPushSpec
	}
	return ref, nil
}

// BranchOK is the branch charset used in a rebuilt refspec.
func BranchOK(s string) bool {
	if s == "" || len(s) > 200 || s == "HEAD" {
		return false
	}
	if strings.Contains(s, "..") || strings.Contains(s, "//") || strings.Contains(s, "@{") {
		return false
	}
	if s[0] == '-' || s[0] == '/' || s[0] == '.' || s[len(s)-1] == '/' || s[len(s)-1] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '/':
		default:
			return false
		}
	}
	return true
}

// RemoteURL is the only URL the host push client is given.
func RemoteURL(owner, repo string) string {
	return "https://github.com/" + owner + "/" + repo + ".git"
}
