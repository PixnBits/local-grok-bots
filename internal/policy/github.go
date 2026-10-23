package policy

import (
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/github"
)

// GitHub is the effective GitHub ceiling after managed and local policy merge.
// Repos empty means no repository is allowed. Source is managed, local,
// default, or disabled.
type GitHub struct {
	TokenFile   string
	Repos       []string
	AuthorEmail string
	AuthorName  string
	Source      string
}

type githubLayer struct {
	tokenFile      string
	tokenSet       bool
	repos          []string
	reposSet       bool
	authorEmail    string
	authorEmailSet bool
	authorName     string
	authorNameSet  bool
}

type githubDoc struct {
	TokenFile   *string   `toml:"token_file" json:"token_file"`
	Repos       *[]string `toml:"repos" json:"repos"`
	AuthorEmail *string   `toml:"author_email" json:"author_email"`
	AuthorName  *string   `toml:"author_name" json:"author_name"`
}

func (p *Policy) takeGitHub(doc *githubDoc, trusted bool) {
	if p == nil || doc == nil {
		return
	}
	layer, err := parseGitHub(doc)
	if err != nil {
		p.Warnings = append(p.Warnings, "github settings ignored: "+err.Error()+"; GitHub stays disabled")
		if trusted {
			p.githubManagedBad = true
		} else {
			p.githubLocalBad = true
		}
		return
	}
	if trusted {
		p.githubManaged = layer
		p.githubManagedSet = true
	} else {
		p.githubLocal = layer
		p.githubLocalSet = true
	}
}

func parseGitHub(doc *githubDoc) (githubLayer, error) {
	var layer githubLayer
	if doc.TokenFile != nil {
		v := strings.TrimSpace(*doc.TokenFile)
		if v != "" && (!filepath.IsAbs(v) || strings.ContainsAny(v, "\r\n\x00")) {
			return githubLayer{}, errGitHub("token_file must be an absolute path")
		}
		layer.tokenFile = v
		layer.tokenSet = true
	}
	if doc.Repos != nil {
		repos, err := github.NormalizeRepos(*doc.Repos)
		if err != nil {
			return githubLayer{}, errGitHub("repos must be owner/repo names")
		}
		layer.repos = repos
		layer.reposSet = true
	}
	if doc.AuthorEmail != nil {
		v := strings.TrimSpace(*doc.AuthorEmail)
		if !github.ValidAuthorTemplate(v) {
			return githubLayer{}, errGitHub("author_email is not a safe template")
		}
		layer.authorEmail = v
		layer.authorEmailSet = true
	}
	if doc.AuthorName != nil {
		v := strings.TrimSpace(*doc.AuthorName)
		if v != "" && !github.ValidAuthorName(v) {
			return githubLayer{}, errGitHub("author_name has an unsafe character")
		}
		layer.authorName = v
		layer.authorNameSet = true
	}
	return layer, nil
}

type gitHubErr string

func (e gitHubErr) Error() string { return string(e) }

func errGitHub(msg string) error { return gitHubErr(msg) }

// finishGitHub intersects repository lists. Managed is the ceiling. Local
// policy can only narrow it. A bad managed table disables GitHub.
func (p *Policy) finishGitHub() {
	if p == nil {
		return
	}
	if p.githubManagedBad {
		p.GitHub = GitHub{Source: "disabled", Repos: []string{}}
		return
	}
	local := p.githubLocal
	useLocal := p.githubLocalSet && !p.githubLocalBad
	if !useLocal {
		local = githubLayer{}
	}
	token := ""
	email := ""
	name := ""
	if useLocal {
		if local.tokenSet {
			token = local.tokenFile
		}
		if local.authorEmailSet {
			email = local.authorEmail
		}
		if local.authorNameSet {
			name = local.authorName
		}
	}
	if p.githubManagedSet {
		if p.githubManaged.tokenSet {
			token = p.githubManaged.tokenFile
		}
		if p.githubManaged.authorEmailSet {
			email = p.githubManaged.authorEmail
		}
		if p.githubManaged.authorNameSet {
			name = p.githubManaged.authorName
		}
	}
	repos, source := mergeGitHubRepos(p, local, useLocal)
	if repos == nil {
		repos = []string{}
	}
	p.GitHub = GitHub{
		TokenFile:   token,
		Repos:       repos,
		AuthorEmail: email,
		AuthorName:  name,
		Source:      source,
	}
}

func mergeGitHubRepos(p *Policy, local githubLayer, useLocal bool) ([]string, string) {
	managedSet := p.githubManagedSet && p.githubManaged.reposSet
	localSet := useLocal && local.reposSet
	switch {
	case !managedSet && !localSet:
		return []string{}, "default"
	case managedSet && !localSet:
		return append([]string{}, p.githubManaged.repos...), "managed"
	case !managedSet && localSet:
		return append([]string{}, local.repos...), "local"
	default:
		kept, extra := narrowNames(p.githubManaged.repos, local.repos)
		if len(extra) > 0 {
			p.Warnings = append(p.Warnings, "github.repos "+strings.Join(extra, ", ")+" ignored; local policy can only narrow github repos")
		}
		source := "managed"
		if !sameNames(kept, p.githubManaged.repos) {
			source = "local"
		}
		return kept, source
	}
}

// EffectiveGitHubRepos intersects the policy ceiling with a bot's github_allow.
// An empty bot list allows nothing. It does not inherit the policy list.
func (p Policy) EffectiveGitHubRepos(bot []string) []string {
	if len(bot) == 0 || len(p.GitHub.Repos) == 0 {
		return []string{}
	}
	kept, _ := narrowNames(p.GitHub.Repos, bot)
	if kept == nil {
		return []string{}
	}
	return kept
}
