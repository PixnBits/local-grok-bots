// Package github is the host-side GitHub allowlist, token, and proxy.
// The token stays in the daemon. It is not mounted into a jail.
package github

import (
	"errors"
	"strings"
)

// ErrRepo means a repository name is not owner/repo.
var ErrRepo = errors.New("invalid github repo")

// ErrNotAllowed means the path names an owner/repo outside the allowlist.
var ErrNotAllowed = errors.New("github repo is not allowlisted")

// ErrAuthor means a commit author cannot be embedded safely.
var ErrAuthor = errors.New("invalid git author")

const namePlaceholder = "{name}"

// NormalizeRepos keeps owner/repo names. Matching is case-insensitive, so
// the stored form is lower case. An empty input is an empty list.
func NormalizeRepos(in []string) ([]string, error) {
	if len(in) > 64 {
		return nil, ErrRepo
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		repo, err := NormalizeRepo(raw)
		if err != nil {
			return nil, err
		}
		if seen[repo] {
			continue
		}
		seen[repo] = true
		out = append(out, repo)
	}
	return out, nil
}

// NormalizeRepo checks one owner/repo string.
func NormalizeRepo(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n\t\x00") {
		return "", ErrRepo
	}
	raw = strings.TrimSpace(raw)
	owner, repo, ok := strings.Cut(raw, "/")
	if !ok || strings.Contains(repo, "/") {
		return "", ErrRepo
	}
	owner = strings.ToLower(owner)
	repo = strings.ToLower(repo)
	if !partOK(owner) || !partOK(repo) {
		return "", ErrRepo
	}
	if strings.HasSuffix(repo, ".git") {
		return "", ErrRepo
	}
	return owner + "/" + repo, nil
}

func partOK(s string) bool {
	if s == "" || len(s) > 100 {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	if s[0] == '.' || s[0] == '-' || s[len(s)-1] == '.' {
		return false
	}
	return true
}

// ValidAuthorTemplate reports whether email is safe to expand with {name}.
// An empty template is valid: CommitAuthor uses the noreply default.
func ValidAuthorTemplate(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return true
	}
	if strings.Count(email, "{") != strings.Count(email, namePlaceholder) || strings.Contains(email, "}") && strings.Count(email, "}") != strings.Count(email, namePlaceholder) {
		return false
	}
	if strings.Contains(email, "\n") || strings.Contains(email, "\r") {
		return false
	}
	probe := strings.ReplaceAll(email, namePlaceholder, "bot")
	return emailOK(probe)
}

// ValidAuthorName reports whether name can be a git user.name.
func ValidAuthorName(name string) bool {
	return nameOK(strings.TrimSpace(name))
}

// CommitAuthor resolves the git identity. policyName overrides the bot name
// when set. template is expanded with {name}; empty means {name}@users.noreply.
// A value that fails the charset check returns ErrAuthor and no strings that
// a shell script could embed.
func CommitAuthor(botName, policyName, template string) (name, email string, err error) {
	if strings.ContainsAny(botName, "\r\n\t\x00") || strings.ContainsAny(policyName, "\r\n\t\x00") || strings.ContainsAny(template, "\r\n\t\x00") {
		return "", "", ErrAuthor
	}
	name = strings.TrimSpace(policyName)
	if name == "" {
		name = strings.TrimSpace(botName)
	}
	if !nameOK(name) {
		return "", "", ErrAuthor
	}
	template = strings.TrimSpace(template)
	if template == "" {
		template = namePlaceholder + "@users.noreply"
	}
	if !ValidAuthorTemplate(template) {
		return "", "", ErrAuthor
	}
	email = strings.ReplaceAll(template, namePlaceholder, name)
	if !emailOK(email) {
		return "", "", ErrAuthor
	}
	return name, email, nil
}

func nameOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	if s[0] == '.' || s[0] == '-' {
		return false
	}
	return true
}

func emailOK(s string) bool {
	if len(s) == 0 || len(s) > 254 || strings.ContainsAny(s, " \t'\"\\$`;|&<>(){}[]!*?#\r\n") {
		return false
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || strings.Contains(domain, "@") {
		return false
	}
	if !localOK(local) || !domainOK(domain) {
		return false
	}
	return true
}

func localOK(s string) bool {
	if s == "" || len(s) > 64 || strings.Contains(s, "..") {
		return false
	}
	if s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '+':
		default:
			return false
		}
	}
	return true
}

func domainOK(s string) bool {
	if s == "" || len(s) > 190 || !strings.Contains(s, ".") || strings.Contains(s, "..") {
		return false
	}
	labels := strings.Split(s, ".")
	for _, lab := range labels {
		if lab == "" || len(lab) > 63 {
			return false
		}
		if lab[0] == '-' || lab[len(lab)-1] == '-' {
			return false
		}
		for i := 0; i < len(lab); i++ {
			c := lab[i]
			switch {
			case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-':
			default:
				return false
			}
		}
	}
	return true
}
