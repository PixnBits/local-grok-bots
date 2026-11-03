package daemon

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/github"
	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/store"
)

// daemonUserName is the account this process runs as, looked up once.
// A failed lookup uses the numeric user id.
var daemonUserName = sync.OnceValue(func() string {
	u, err := user.Current()
	if err == nil && u != nil {
		if name := strings.TrimSpace(u.Username); name != "" {
			return name
		}
	}
	return strconv.Itoa(os.Geteuid())
})

func (a *App) botWarnings(b store.Bot) []store.Warning {
	var w []store.Warning
	for _, text := range descriptionWarnings(b.Description) {
		if text == "" {
			continue
		}
		w = append(w, store.Warning{Field: "description", Text: text})
	}
	var pol policy.Policy
	if a != nil {
		pol = a.effPol(b.ID)
	}
	w = append(w, githubConfigWarnings(pol, b.Grants, b.GitHubAllow)...)
	w = append(w, broadHostWarnings(b.NetAllow)...)
	if len(w) == 0 {
		return nil
	}
	return w
}

func broadHostWarnings(allow []string) []store.Warning {
	for _, raw := range allow {
		h := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(raw, ".")))
		if h == "storage.googleapis.com" {
			return []store.Warning{{
				Field: "net_allow",
				Text:  "storage.googleapis.com gives this bot access to all of Google Cloud Storage, not just your project. Remove it unless the bot needs it.",
				Link: &store.WarningLink{
					Href:  "https://github.com/PixnBits/local-grok-bots/issues/33",
					Label: "Why this matters (GitHub issue #33)",
				},
			}}
		}
	}
	return nil
}

func githubConfigWarnings(pol policy.Policy, grants, allow []string) []store.Warning {
	var out []store.Warning
	if len(allow) > 0 {
		names := repoNames(allow)
		if len(pol.GitHub.Repos) == 0 {
			if len(names) > 0 {
				out = append(out, store.Warning{Field: "github_allow", Text: emptyCeilingText(names)})
			}
		} else {
			ceiling := map[string]bool{}
			for _, raw := range pol.GitHub.Repos {
				if name, err := github.NormalizeRepo(raw); err == nil {
					ceiling[name] = true
				}
			}
			var missing []string
			for _, name := range names {
				if name == "" || ceiling[name] {
					continue
				}
				missing = append(missing, name)
			}
			if len(missing) > 0 {
				out = append(out, store.Warning{Field: "github_allow", Text: ceilingGapText(missing)})
			}
		}
	}
	path := strings.TrimSpace(pol.GitHub.TokenFile)
	if path != "" && (len(allow) > 0 || granted(grants, "github")) {
		if msg := tokenFileWarning(path); msg != "" {
			out = append(out, store.Warning{Field: "github_token", Text: msg})
		}
	}
	return out
}

func repoNames(allow []string) []string {
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
	return names
}

func emptyCeilingText(names []string) string {
	list := strings.Join(names, ", ")
	if len(names) == 1 {
		return fmt.Sprintf("The policy allows no GitHub repositories, so this bot can't use %s. Add it to `repos` under `[github]` in policy.toml.", list)
	}
	return fmt.Sprintf("The policy allows no GitHub repositories, so this bot can't use %s. Add them to `repos` under `[github]` in policy.toml.", list)
}

func ceilingGapText(missing []string) string {
	list := strings.Join(missing, ", ")
	if len(missing) == 1 {
		return fmt.Sprintf("%s isn't in the policy's GitHub repository list, so this bot can't use it. Add it to `repos` under `[github]` in policy.toml, or remove it here.", list)
	}
	return fmt.Sprintf("%s aren't in the policy's GitHub repository list, so this bot can't use them. Add them to `repos` under `[github]` in policy.toml, or remove them here.", list)
}

// readTokenForWarn reads a token file for the bot-page warning. Tests count
// calls. The push path keeps using readGitHubToken.
var readTokenForWarn = github.ReadToken

type tokenWarnID struct {
	dev, ino    uint64
	size        int64
	mtime       int64
	csec, cnsec int64
	mode        uint32
	uid         uint32
	missing     bool
}

type tokenWarnEnt struct {
	id  tokenWarnID
	msg string
	at  time.Time
}

var (
	tokenWarnMu sync.Mutex
	tokenWarns  = map[string]tokenWarnEnt{}
)

func tokenFileWarning(path string) string {
	id, ok := tokenWarnStat(path)
	if ok {
		tokenWarnMu.Lock()
		if ent, hit := tokenWarns[path]; hit && ent.id == id && time.Since(ent.at) < 60*time.Second {
			msg := ent.msg
			tokenWarnMu.Unlock()
			return msg
		}
		tokenWarnMu.Unlock()
	}
	msg := ""
	if _, err := readTokenForWarn(path); err != nil {
		var size int64
		if ok {
			size = id.size
		}
		msg = tokenWarningText(path, github.TokenFailureReason(err), size)
	}
	if ok {
		tokenWarnMu.Lock()
		tokenWarns[path] = tokenWarnEnt{id: id, msg: msg, at: time.Now()}
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
	csec, cnsec, cok := tokenCtime(fi)
	if !cok {
		return tokenWarnID{}, false
	}
	return tokenWarnID{
		dev: dev, ino: ino, size: fi.Size(), mtime: fi.ModTime().UnixNano(),
		csec: csec, cnsec: cnsec,
		mode: uint32(fi.Mode()), uid: uid,
	}, true
}

func tokenWarningText(path, reason string, size int64) string {
	who := daemonUserName()
	var msg string
	switch reason {
	case "missing":
		msg = fmt.Sprintf("The GitHub token file %s doesn't exist. Create it, or fix `token_file` in policy.toml. GitHub actions fail until then.", path)
	case "mode":
		msg = fmt.Sprintf("The GitHub token file %s can be read by other users. Run `chmod 600 %s`.", path, path)
	case "token file: not owned by daemon":
		msg = fmt.Sprintf("The GitHub token file %s belongs to another user. Run `sudo chown %s %s`, then `chmod 600 %s`.", path, who, path, path)
	case "permission denied":
		msg = fmt.Sprintf("The daemon can't open the GitHub token file %s. Run `chmod 600 %s`. If that doesn't help, make sure %s can open the folder it's in.", path, path, who)
	case "type":
		msg = fmt.Sprintf("The GitHub token file %s is a folder, a link, or another special file. Point `token_file` in policy.toml at the token file itself.", path)
	case "shape":
		msg = fmt.Sprintf("The GitHub token file %s doesn't hold a valid token. Put just the token on one line, with no spaces.", path)
	case "size":
		// size is the Lstat length. Zero and unknown both use the empty-file text.
		if size > 0 {
			msg = fmt.Sprintf("The GitHub token file %s is too big to be a token. Put just one token in it.", path)
		} else {
			msg = fmt.Sprintf("The GitHub token file %s is empty. Put your token in it.", path)
		}
	default:
		msg = fmt.Sprintf("The daemon couldn't read the GitHub token file %s. Check that the path is right and that the file is a plain file you own, then run `chmod 600 %s`.", path, path)
	}
	return msg + " This applies to every bot with GitHub access."
}
