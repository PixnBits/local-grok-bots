package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxCapture = 16 * 1024

func truncate(s string) string {
	if len(s) > maxCapture {
		return s[:maxCapture] + "\n…(truncated)"
	}
	return s
}

func exitCode(err error) string {
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Sprintf("%d", ee.ExitCode())
	}
	return err.Error()
}

// Resolve keeps path inside root, rejecting traversal and symlink escapes.
func Resolve(root, p string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	root = filepath.Clean(root)
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("path required")
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("invalid path")
	}
	p = filepath.Clean(p)
	if filepath.IsAbs(p) {
		rel, err := filepath.Rel(root, p)
		if err != nil || escapes(rel) {
			return "", fmt.Errorf("path escapes workspace")
		}
		p = rel
	}
	if escapes(p) {
		return "", fmt.Errorf("path escapes workspace")
	}
	cur := root
	for _, part := range strings.Split(p, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", fmt.Errorf("path escapes workspace")
		}
		next := filepath.Join(cur, part)
		fi, err := os.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) {
				cur = next
				continue
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(next)
			if err != nil {
				return "", err
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(next), target)
			}
			target = filepath.Clean(target)
			rel, err := filepath.Rel(root, target)
			if err != nil || escapes(rel) {
				return "", fmt.Errorf("path escapes workspace")
			}
			cur = target
			continue
		}
		cur = next
	}
	rel, err := filepath.Rel(root, cur)
	if err != nil || escapes(rel) {
		return "", fmt.Errorf("path escapes workspace")
	}
	return cur, nil
}

func escapes(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
