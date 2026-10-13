//go:build linux

package sandbox

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed preload.c.txt
var preloadSrc string

// ensurePreload compiles the connect interceptor once and caches the .so.
// Without gcc the shell still runs, and the network namespace stays closed.
func ensurePreload() (string, error) {
	sum := sha256.Sum256([]byte(preloadSrc))
	dest := filepath.Join(os.TempDir(), fmt.Sprintf("lgb-preload-%x.so", sum[:8]))
	if st, err := os.Stat(dest); err == nil && st.Size() > 0 {
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
	src := filepath.Join(dir, "preload.c")
	if err := os.WriteFile(src, []byte(preloadSrc), 0o644); err != nil {
		return "", err
	}
	out := filepath.Join(dir, "preload.so")
	cmd := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-pthread", "-o", out, src, "-ldl")
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("preload compile: %v %s", err, b)
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
