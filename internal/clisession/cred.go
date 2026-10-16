package clisession

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
func ScrubStaleGrokAuth(dataDir, realPath string) error {
	cli := filepath.Join(dataDir, "cli")
	bots, err := os.ReadDir(cli)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	realPath = filepath.Clean(realPath)
	var realInfo os.FileInfo
	var realBytes []byte
	var secrets []string
	if realPath != "" && realPath != "." {
		if st, err := os.Stat(realPath); err == nil && st.Mode().IsRegular() {
			realInfo = st
			if b, err := readLimited(realPath); err == nil {
				realBytes = b
				secrets = loginSecrets(b)
			}
		}
	}
	var first error
	for _, bot := range bots {
		if !safeBotID(bot.Name()) {
			continue
		}
		botDir := filepath.Join(cli, bot.Name())
		lst, err := os.Lstat(botDir)
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			continue
		}
		for _, rel := range grokAuthRel {
			p := filepath.Join(botDir, rel)
			if realPath != "" && filepath.Clean(p) == realPath {
				continue
			}
			if !staleGrokAuth(p, realPath, realInfo, realBytes, secrets) {
				continue
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
				first = err
			}
		}
	}
	return first
}

// RemoveBotGrokAuth deletes the bot's Grok login files, including a
// placeholder. A hard link is unlinked. A symlink is removed without
// following it. An unsafe id does nothing.
func RemoveBotGrokAuth(dataDir, botID string) error {
	if !safeBotID(botID) {
		return nil
	}
	var first error
	for _, rel := range grokAuthRel {
		p := filepath.Join(dataDir, "cli", botID, rel)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

func safeBotID(id string) bool {
	return id != "" && id == filepath.Base(id) && !strings.Contains(id, "..") && !strings.ContainsAny(id, `/\`)
}

func staleGrokAuth(path, realPath string, realInfo os.FileInfo, realBytes []byte, secrets []string) bool {
	lst, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if lst.Mode()&os.ModeSymlink != 0 && (linkPointsAt(path, realPath) || sameFile(realInfo, path)) {
		return true
	}
	// A hard link has another name (nlink > 1). The last name is the user's
	// file, including a bind of that inode, and must stay.
	if lst.Mode().IsRegular() && sameFile(realInfo, path) {
		st, err := os.Stat(path)
		return err == nil && linkCount(st) > 1
	}
	if lst.Mode()&os.ModeSymlink == 0 && !lst.Mode().IsRegular() {
		return false
	}
	b, err := readLimited(path)
	if err != nil {
		return false
	}
	if len(realBytes) > 0 && bytes.Equal(b, realBytes) {
		return true
	}
	for _, s := range secrets {
		if s != "" && bytes.Contains(b, []byte(s)) {
			return true
		}
	}
	return false
}

func sameFile(real os.FileInfo, path string) bool {
	if real == nil {
		return false
	}
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	return os.SameFile(real, st)
}

func linkCount(st os.FileInfo) uint64 {
	if st == nil {
		return 0
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(sys.Nlink)
}

func linkPointsAt(link, real string) bool {
	if real == "" {
		return false
	}
	target, err := os.Readlink(link)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	}
	return filepath.Clean(target) == filepath.Clean(real)
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
