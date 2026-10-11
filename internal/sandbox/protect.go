package sandbox

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CheckWrite rejects workspace paths the daemon must not leave for a later
// trusted process to execute: git hooks, shell rc files, and git config.
func CheckWrite(root, absPath string) error {
	rel, err := relInside(root, absPath)
	if err != nil {
		return err
	}
	if writeBlocked(rel) {
		return fmt.Errorf("write blocked: %s", rel)
	}
	return nil
}

func relInside(root, absPath string) (string, error) {
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, absPath)
	if err != nil || escapes(rel) {
		return "", fmt.Errorf("path escapes workspace")
	}
	return rel, nil
}

func writeBlocked(rel string) bool {
	if underHooks(rel) || isGitConfigRel(rel) || isUserGitConfig(rel) {
		return true
	}
	base := filepath.Base(filepath.ToSlash(rel))
	return rcName(base)
}

func rcName(base string) bool {
	switch base {
	case ".bashrc", ".bash_profile", ".bash_login", ".profile",
		".zshrc", ".zshenv", ".zprofile", ".zlogin", ".kshrc",
		".cshrc", ".tcshrc", ".inputrc", ".gitconfig", ".netrc", ".pgpass":
		return true
	default:
		return false
	}
}

func splitRel(rel string) []string {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." || rel == "" {
		return nil
	}
	return strings.Split(rel, "/")
}

func underHooks(rel string) bool {
	parts := splitRel(rel)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == ".git" && parts[i+1] == "hooks" {
			return true
		}
	}
	return false
}

func isGitConfigRel(rel string) bool {
	parts := splitRel(rel)
	return len(parts) >= 2 && parts[len(parts)-2] == ".git" && parts[len(parts)-1] == "config"
}

func isUserGitConfig(rel string) bool {
	parts := splitRel(rel)
	if len(parts) >= 3 && parts[len(parts)-3] == ".config" && parts[len(parts)-2] == "git" && parts[len(parts)-1] == "config" {
		return true
	}
	return false
}

func interesting(rel string) bool {
	if underHooks(rel) || isGitConfigRel(rel) || isUserGitConfig(rel) {
		return true
	}
	return rcName(filepath.Base(rel))
}

// dangerousConfig reports git settings that execute a command later.
func dangerousConfig(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(val)
		switch key {
		case "sshcommand", "hookspath", "fsmonitor", "fsmonitorhookversion", "editor":
			return true
		}
		if strings.HasPrefix(val, "!") {
			return true
		}
	}
	return false
}

type snapFile struct {
	exists bool
	link   bool
	data   []byte
	mode   os.FileMode
}

type treeSnap struct {
	root  string
	files map[string]snapFile
}

func takeSnap(root string) *treeSnap {
	s := &treeSnap{root: root, files: map[string]snapFile{}}
	_ = walkInteresting(root, func(rel string, fi fs.FileInfo) {
		s.files[rel] = readSnap(filepath.Join(root, rel), fi)
	})
	return s
}

func walkInteresting(root string, fn func(rel string, fi fs.FileInfo)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || escapes(rel) || !interesting(rel) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		fn(rel, info)
		return nil
	})
}

func readSnap(path string, fi fs.FileInfo) snapFile {
	sf := snapFile{exists: true, mode: fi.Mode()}
	if fi.Mode()&os.ModeSymlink != 0 {
		sf.link = true
		t, err := os.Readlink(path)
		if err == nil {
			sf.data = []byte(t)
		}
		return sf
	}
	if fi.Size() > 256*1024 {
		sf.data = []byte("too-large")
		return sf
	}
	b, err := os.ReadFile(path)
	if err == nil {
		sf.data = b
	}
	return sf
}

func (s *treeSnap) restore() error {
	if s == nil {
		return nil
	}
	after := map[string]snapFile{}
	_ = walkInteresting(s.root, func(rel string, fi fs.FileInfo) {
		after[rel] = readSnap(filepath.Join(s.root, rel), fi)
	})
	var blocked []string
	seen := map[string]bool{}
	for rel, now := range after {
		seen[rel] = true
		old := s.files[rel]
		if isGitConfigRel(rel) || isUserGitConfig(rel) {
			if dangerousConfig(string(now.data)) && (!old.exists || !bytes.Equal(old.data, now.data)) {
				putBack(s.root, rel, old)
				blocked = append(blocked, rel)
			}
			continue
		}
		if underHooks(rel) {
			// Git does not run *.sample names. Templates may be executable.
			if !old.exists && strings.HasSuffix(filepath.Base(rel), ".sample") && !now.link {
				continue
			}
			if old.exists && !now.link && !old.link && bytes.Equal(old.data, now.data) && old.mode.Perm()&0111 == now.mode.Perm()&0111 {
				continue
			}
			putBack(s.root, rel, old)
			blocked = append(blocked, rel)
			continue
		}
		if old.exists && old.link == now.link && bytes.Equal(old.data, now.data) {
			continue
		}
		putBack(s.root, rel, old)
		blocked = append(blocked, rel)
	}
	for rel, old := range s.files {
		if !old.exists || seen[rel] {
			continue
		}
		if (isGitConfigRel(rel) || isUserGitConfig(rel)) && !dangerousConfig(string(old.data)) {
			putBack(s.root, rel, old)
			continue
		}
		putBack(s.root, rel, old)
		blocked = append(blocked, rel)
	}
	if len(blocked) == 0 {
		return nil
	}
	sort.Strings(blocked)
	return fmt.Errorf("write blocked: %s", strings.Join(blocked, ", "))
}

func putBack(root, rel string, old snapFile) {
	path := filepath.Join(root, rel)
	if !old.exists {
		_ = os.Remove(path)
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.Remove(path)
	if old.link {
		_ = os.Symlink(string(old.data), path)
		return
	}
	mode := old.mode.Perm()
	if mode == 0 {
		mode = 0o644
	}
	_ = os.WriteFile(path, old.data, mode)
}

// refusedBind reports toolchain paths that would mount credentials or rc files.
func refusedBind(p string) bool {
	p = filepath.Clean(p)
	if strings.Contains(p, "/.ssh/") || strings.HasSuffix(p, "/.ssh") {
		return true
	}
	base := filepath.Base(p)
	if rcName(base) {
		return true
	}
	if p == "/etc/gitconfig" || strings.HasSuffix(p, "/.config/git/config") {
		return true
	}
	return false
}
