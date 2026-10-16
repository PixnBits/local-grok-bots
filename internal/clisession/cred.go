package clisession

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// grokAuthRel are the login paths under a bot's cli directory.
var grokAuthRel = []string{
	filepath.Join("home", ".grok", "auth.json"),
	filepath.Join("grok-home", "auth.json"),
}

// ScrubStaleGrokAuth removes auth.json entries under dataDir/cli that are a
// hard link or symlink to realPath, or that contain that file's key or
// refresh token. A file that does not match, including a placeholder, is
// left in place. realPath itself is never removed. The only remaining name
// of that inode is not unlinked. An empty cli directory does not read realPath.
// A symlink directory is not entered.
func ScrubStaleGrokAuth(dataDir, realPath string) error {
	return scrubTree(dataDir, realPath)
}

// RemoveBotGrokAuth deletes the bot's Grok login files, including a
// placeholder. A hard link is unlinked. A final symlink is removed without
// following it. A symlink directory on the way there fails with
// ErrCredSymlink. An unsafe id does nothing.
func RemoveBotGrokAuth(dataDir, botID string) error {
	if !safeBotID(botID) {
		return nil
	}
	var first error
	for _, rel := range grokAuthRel {
		p := filepath.Join("cli", botID, rel)
		err := removeFileNoFollow(dataDir, p)
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

// RemoveBotCLI removes dataDir/cli/<botID>. A symlink entry is unlinked and
// is not entered. A symlink in a parent of that directory fails with
// ErrCredSymlink. An unsafe id does nothing. A missing directory is success.
func RemoveBotCLI(dataDir, botID string) error {
	if !safeBotID(botID) {
		return nil
	}
	err := removeTreeNoFollow(dataDir, filepath.Join("cli", botID))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func safeBotID(id string) bool {
	return id != "" && id == filepath.Base(id) && !strings.Contains(id, "..") && !strings.ContainsAny(id, `/\`)
}

func loginSecrets(b []byte) []string {
	var doc map[string]map[string]any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, ent := range doc {
		if ent == nil {
			continue
		}
		for _, field := range []string{"key", "refresh_token"} {
			s, _ := ent[field].(string)
			if len(s) < 8 || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}
