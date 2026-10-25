package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

func mkdir(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return err
	}
	return sandbox.OwnPath(path, 0o750)
}

// ownNewDir chowns a directory the daemon created inside the workspace.
// The mode is 0700. World-writable modes are refused by OwnPath.
func ownNewDir(path string) error {
	return sandbox.OwnPath(path, 0o700)
}

// ownFile gives an existing workspace file to the jail user without changing its mode.
func ownFile(path string) error {
	return sandbox.OwnPath(path, 0)
}

// ownWorkspaceParents chowns each directory the daemon created between root
// and the parent of full. full itself is left unchanged when it is a file.
func ownWorkspaceParents(root, full string) error {
	root = filepath.Clean(root)
	full = filepath.Clean(full)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("path")
	}
	cur := root
	parts := strings.Split(rel, string(os.PathSeparator))
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("path")
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if i == len(parts)-1 {
			return nil
		}
		if !st.IsDir() {
			return errors.New("path")
		}
		if err := ownNewDir(cur); err != nil {
			return err
		}
	}
	return nil
}
