package sandbox

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed ghbridge.c.txt
var bridgeSrc string

// ensureBridge compiles the in-jail HTTP bridge once and caches the binary.
// Without gcc, GitHub fetch stays unavailable.
func ensureBridge() (string, error) {
	sum := sha256.Sum256([]byte(bridgeSrc))
	dest := filepath.Join(os.TempDir(), fmt.Sprintf("lgb-ghbridge-%x", sum[:8]))
	if st, err := os.Stat(dest); err == nil && st.Size() > 0 && st.Mode()&0o111 != 0 {
		return dest, nil
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		return "", fmt.Errorf("gcc not available: %w", err)
	}
	dir, err := os.MkdirTemp("", "lgb-cc-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "ghbridge.c")
	if err := os.WriteFile(src, []byte(bridgeSrc), 0o644); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "ghbridge")
	cmd := exec.Command("gcc", "-O2", "-o", out, src)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("github bridge compile: %v %s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return "", err
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return dest, nil
}

func githubSockOK(path string) bool {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
		return false
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeSocket == 0 {
		return false
	}
	return true
}
