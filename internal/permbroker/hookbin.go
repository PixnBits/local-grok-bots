package permbroker

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CheckHookBinary refuses a hook the jail could replace.
// The file must be an absolute regular file, not a symlink, executable,
// and not group or world writable. Owner-writable is allowed when the
// path is outside the jail-writable roots (the bot workspace and home).
// A missing or unusable binary keeps the daemon on its locked-down
// settings instead of arming the broker.
func CheckHookBinary(path string, jailRoots []string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook path must be absolute")
	}
	clean := filepath.Clean(path)
	for _, root := range jailRoots {
		if root == "" {
			continue
		}
		if underRoot(clean, root) {
			return fmt.Errorf("hook path is inside a jail-writable directory")
		}
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

// HookCommand is the shell command written into Claude's settings.
// Both paths are quoted so a space cannot change the program.
func HookCommand(bin, sock string) string {
	return strconv.Quote(bin) + " " + strconv.Quote(sock)
}
