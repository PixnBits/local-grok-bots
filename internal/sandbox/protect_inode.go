package sandbox

import (
	"path/filepath"
	"strings"
)

// ProtectInode is one protected path, or an ancestor directory of one,
// recorded before a turn. Path is the path that was stat'd. Dev and Ino
// are from lstat (no follow). IsDir is true only for a real directory.
// A symlink is not a directory.
type ProtectInode struct {
	Path  string
	Dev   uint64
	Ino   uint64
	IsDir bool
}

// SnapshotProtect records each path and every ancestor directory up to,
// but not including, "/". Missing paths are omitted. The caller passes
// the shell protect list. Ancestor paths are for the inode set and the
// directory re-stat. They are not added to the path-overlap set: a
// shared parent such as a temp directory must stay mountable for a
// sibling of a secret.
func SnapshotProtect(paths []string) []ProtectInode {
	seen := map[string]struct{}{}
	var out []ProtectInode
	add := func(p string) {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || p == "/" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		dev, ino, isDir, err := lstatInode(p)
		if err != nil {
			return
		}
		out = append(out, ProtectInode{Path: p, Dev: dev, Ino: ino, IsDir: isDir})
	}
	for _, p := range paths {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" || p == "." || p == "/" {
			continue
		}
		add(p)
		for {
			parent := filepath.Dir(p)
			if parent == p || parent == "/" || parent == "." {
				break
			}
			add(parent)
			p = parent
		}
	}
	return out
}

// ProtectChanged returns the first directory in the snapshot that is
// missing, no longer a directory, or has a different device or inode.
// Regular files are ignored so state.db-wal and similar churn does not
// refuse every bind. An lstat error fails closed. An empty result means
// the directory entries still match.
func ProtectChanged(snap []ProtectInode) string {
	for _, ent := range snap {
		if !ent.IsDir {
			continue
		}
		dev, ino, isDir, err := lstatInode(ent.Path)
		if err != nil || !isDir || dev != ent.Dev || ino != ent.Ino {
			return ent.Path
		}
	}
	return ""
}

// protectDirsChanged reports whether ProtectChanged found a directory.
func protectDirsChanged(snap []ProtectInode) bool {
	return ProtectChanged(snap) != ""
}
