package daemon

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

func (a *App) botWarnings(b store.Bot) []string {
	w := descriptionWarnings(b.Description)
	var pol policy.Policy
	if a != nil {
		pol = a.effPol(b.ID)
	}
	w = append(w, githubConfigWarnings(pol, b.Grants, b.GitHubAllow)...)
	if len(w) == 0 {
		return nil
	}
	return w
}

func githubConfigWarnings(pol policy.Policy, grants, allow []string) []string {
	var out []string
	if len(allow) > 0 {
		if len(pol.GitHub.Repos) == 0 {
			out = append(out, fmt.Sprintf("The policy [github].repos ceiling is empty, so these github_allow repositories cannot be used: %s.", joinRepoNames(allow)))
		} else {
			ceiling := map[string]bool{}
			for _, raw := range pol.GitHub.Repos {
				if name, err := github.NormalizeRepo(raw); err == nil {
					ceiling[name] = true
				}
			}
			var missing []string
			for _, raw := range allow {
				name, err := github.NormalizeRepo(raw)
				if err != nil {
					name = strings.ToLower(strings.TrimSpace(raw))
				}
				if name == "" || ceiling[name] {
					continue
				}
				missing = append(missing, name)
			}
			if len(missing) > 0 {
				out = append(out, fmt.Sprintf("The policy [github].repos ceiling does not include %s from this bot's github_allow.", strings.Join(missing, ", ")))
			}
		}
	}
	path := strings.TrimSpace(pol.GitHub.TokenFile)
	if path != "" && (len(allow) > 0 || granted(grants, "github")) {
		if msg := tokenFileWarning(path); msg != "" {
			out = append(out, msg)
		}
	}
	return out
}

func joinRepoNames(allow []string) string {
	names := make([]string, 0, len(allow))
	for _, raw := range allow {
		name, err := github.NormalizeRepo(raw)
		if err != nil {
			name = strings.ToLower(strings.TrimSpace(raw))
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return strings.Join(names, ", ")
}

// readTokenForWarn reads a token file for the bot-page warning. Tests count
// calls. The push path keeps using readGitHubToken.
var readTokenForWarn = github.ReadToken

type tokenWarnID struct {
	dev, ino uint64
	size     int64
	mtime    int64
	mode     uint32
	uid      uint32
	missing  bool
}

type tokenWarnEnt struct {
	id  tokenWarnID
	msg string
}

var (
	tokenWarnMu sync.Mutex
	tokenWarns  = map[string]tokenWarnEnt{}
)

func tokenFileWarning(path string) string {
	id, ok := tokenWarnStat(path)
	if ok {
		tokenWarnMu.Lock()
		if ent, hit := tokenWarns[path]; hit && ent.id == id {
			msg := ent.msg
			tokenWarnMu.Unlock()
			return msg
		}
		tokenWarnMu.Unlock()
	}
	msg := ""
	if _, err := readTokenForWarn(path); err != nil {
		msg = tokenWarningText(path, github.TokenFailureReason(err))
	}
	if ok {
		tokenWarnMu.Lock()
		tokenWarns[path] = tokenWarnEnt{id: id, msg: msg}
		tokenWarnMu.Unlock()
	}
	return msg
}

func tokenWarnStat(path string) (tokenWarnID, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return tokenWarnID{missing: true}, true
		}
		return tokenWarnID{}, false
	}
	dev, ino, uid, ok := tokenFileID(fi)
	if !ok {
		return tokenWarnID{}, false
	}
	return tokenWarnID{
		dev: dev, ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano(),
		mode: uint32(fi.Mode()), uid: uid,
	}, true
}

func tokenWarningText(path, reason string) string {
	switch reason {
	case "missing":
		return fmt.Sprintf("The policy [github].token_file %s is missing.", path)
	case "mode":
		return fmt.Sprintf("The policy [github].token_file %s is not mode 0600.", path)
	case "token file: not owned by daemon":
		return fmt.Sprintf("The policy [github].token_file %s is not owned by the daemon user.", path)
	case "type":
		return fmt.Sprintf("The policy [github].token_file %s is not a regular file.", path)
	case "permission denied":
		return fmt.Sprintf("The policy [github].token_file %s is not readable.", path)
	case "read error":
		return fmt.Sprintf("The policy [github].token_file %s could not be read.", path)
	case "shape":
		return fmt.Sprintf("The policy [github].token_file %s is not a valid token file.", path)
	case "size":
		return fmt.Sprintf("The policy [github].token_file %s is empty or too large.", path)
	case "check":
		return fmt.Sprintf("The policy [github].token_file %s failed its permission check.", path)
	default:
		return fmt.Sprintf("The policy [github].token_file %s could not be read.", path)
	}
}
