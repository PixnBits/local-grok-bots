package permbroker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HookPin is the hook binary recorded when policy loads.
// A later launch compares the file with this pin.
type HookPin struct {
	Path  string
	Sum   string
	Dev   uint64
	Ino   uint64
	UID   uint32
	Mode  os.FileMode
	Size  int64
	Mtime int64
}

// PinHook records the hook file's content and identity.
func PinHook(path string) (HookPin, error) {
	clean := filepath.Clean(path)
	st, err := os.Lstat(clean)
	if err != nil {
		return HookPin{}, fmt.Errorf("hook binary: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return HookPin{}, fmt.Errorf("hook binary is not a regular file")
	}
	sum, err := hashFile(clean)
	if err != nil {
		return HookPin{}, err
	}
	dev, ino, uid, ok := fileIdentity(st)
	if !ok {
		return HookPin{}, fmt.Errorf("hook binary owner cannot be read")
	}
	return HookPin{
		Path: clean, Sum: sum, Dev: dev, Ino: ino, UID: uid,
		Mode: st.Mode().Perm(), Size: st.Size(), Mtime: st.ModTime().UnixNano(),
	}, nil
}

// Diff reports whether path still matches the pin.
// A difference uses a fixed sentence so the turn error and the audit row match.
func (p HookPin) Diff(path string) error {
	cur, err := PinHook(path)
	if err != nil || cur.Path != p.Path || cur.Sum != p.Sum || cur.Dev != p.Dev || cur.Ino != p.Ino || cur.UID != p.UID || cur.Mode != p.Mode || cur.Size != p.Size || cur.Mtime != p.Mtime {
		return fmt.Errorf("permission broker hook changed since startup")
	}
	return nil
}

// CheckHookBinary refuses a hook the jail could replace.
// The file must be an absolute regular file, not a symlink, executable,
// and not group or world writable. The owner must be the daemon user or
// root. Every parent directory up to / must not be group or world writable,
// including a sticky directory. A symlink path component is resolved and
// the resolved directories are checked the same way. The path must not sit
// inside a jail-writable root. Owner-writable is allowed outside those roots.
// When the broker is enabled, a missing or unusable binary refuses the
// turn. When the broker is off, the launch keeps its locked-down settings.
func CheckHookBinary(path string, jailRoots []string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook path must be absolute")
	}
	clean := filepath.Clean(path)
	if err := jailContains(clean, jailRoots); err != nil {
		return err
	}
	st, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("hook binary: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("hook binary is a symlink")
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("hook binary is not a file")
	}
	if st.Mode()&0o022 != 0 {
		return fmt.Errorf("hook binary is group or world writable")
	}
	if st.Mode()&0o111 == 0 {
		return fmt.Errorf("hook binary is not executable")
	}
	_, _, uid, ok := fileIdentity(st)
	if !ok {
		return fmt.Errorf("hook binary owner cannot be read")
	}
	if uid != 0 && uid != uint32(os.Getuid()) {
		return fmt.Errorf("hook binary owner is not the daemon user or root")
	}
	if err := checkParentChain(clean, jailRoots); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return fmt.Errorf("hook path cannot be resolved")
	}
	resolved = filepath.Clean(resolved)
	if err := jailContains(resolved, jailRoots); err != nil {
		return err
	}
	if resolved != clean {
		if err := checkParentChain(resolved, jailRoots); err != nil {
			return err
		}
	}
	return nil
}

func jailContains(path string, jailRoots []string) error {
	for _, root := range jailRoots {
		if root == "" {
			continue
		}
		if underRoot(path, root) {
			return fmt.Errorf("hook path is inside a jail-writable directory")
		}
	}
	return nil
}

// checkParentChain walks lexical parents from the file's directory through /.
// A symlink component is not mode-checked itself; EvalSymlinks checks the target.
func checkParentChain(path string, jailRoots []string) error {
	dir := filepath.Dir(filepath.Clean(path))
	for {
		if err := checkOneDir(dir, jailRoots); err != nil {
			return err
		}
		if dir == "/" || dir == "." {
			return nil
		}
		next := filepath.Dir(dir)
		if next == dir {
			return nil
		}
		dir = next
	}
}

func checkOneDir(dir string, jailRoots []string) error {
	if err := jailContains(dir, jailRoots); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("hook parent: %w", err)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	if !st.IsDir() {
		return fmt.Errorf("hook parent is not a directory")
	}
	// A sticky bit does not make a group or world writable directory acceptable.
	if st.Mode()&0o022 != 0 {
		return fmt.Errorf("hook parent directory is group or world writable")
	}
	return nil
}

func underRoot(path, root string) bool {
	root = filepath.Clean(root)
	if root == "" || root == "/" || root == "." {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("hook binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hook binary: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HookCommand is the shell command written into Claude's settings.
// Both paths are POSIX single-quoted so the shell receives them unchanged.
func HookCommand(bin, sock string) string {
	return posixSingleQuote(bin) + " " + posixSingleQuote(sock)
}

func posixSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
