package clisession

import (
	"encoding/json"
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
	_, err := ScrubStaleGrokAuthNotes(dataDir, realPath)
	return err
}

// ScrubStaleGrokAuthNotes is ScrubStaleGrokAuth plus symlink unlink/skip notes.
func ScrubStaleGrokAuthNotes(dataDir, realPath string) ([]SymlinkNote, error) {
	return scrubTree(dataDir, realPath)
}

// RemoveBotGrokAuth deletes the bot's Grok login files, including a
// placeholder. A hard link is unlinked. A final symlink is removed without
// following it. A symlink directory on the way there fails with
// ErrCredSymlink. An unsafe id does nothing.
func RemoveBotGrokAuth(dataDir, botID string) error {
	_, err := RemoveBotGrokAuthNotes(dataDir, botID)
	return err
}

// RemoveBotGrokAuthNotes is RemoveBotGrokAuth plus symlink unlink/skip notes.
func RemoveBotGrokAuthNotes(dataDir, botID string) ([]SymlinkNote, error) {
	if !safeBotID(botID) {
		return nil, nil
	}
	var notes []SymlinkNote
	var first error
	for _, rel := range grokAuthRel {
		p := filepath.Join("cli", botID, rel)
		n, err := removeFileNoted(dataDir, p)
		notes = append(notes, n...)
		if err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return notes, first
}

// RemoveBotCLI removes dataDir/cli/<botID>. A symlink entry is unlinked and
// is not entered. A symlink in a parent of that directory fails with
// ErrCredSymlink. An unsafe id does nothing. A missing directory is success.
func RemoveBotCLI(dataDir, botID string) error {
	_, err := RemoveBotCLINotes(dataDir, botID)
	return err
}

// RemoveBotCLINotes is RemoveBotCLI plus symlink unlink/skip notes.
func RemoveBotCLINotes(dataDir, botID string) ([]SymlinkNote, error) {
	if !safeBotID(botID) {
		return nil, nil
	}
	notes, err := removeTreeNoted(dataDir, filepath.Join("cli", botID))
	if err != nil && !os.IsNotExist(err) {
		return notes, err
	}
	return notes, nil
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
	return readRegularNoFollow(path)
}
