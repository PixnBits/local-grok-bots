//go:build darwin

package sandbox

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed preload_darwin.c.txt
var preloadSrc string

// ensurePreload compiles the connect interceptor once and caches the dylib.
// Without a compiler the shell still runs, and Seatbelt keeps the network closed.
func ensurePreload() (string, error) {
	sum := sha256.Sum256([]byte(preloadSrc))
	dest := filepath.Join(os.TempDir(), fmt.Sprintf("lgb-preload-%x.dylib", sum[:8]))
	if st, err := os.Stat(dest); err == nil && st.Size() > 0 {
		return dest, nil
	}
	cc, err := compiler()
	if err != nil {
		return "", err
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
	out := filepath.Join(dir, "preload.dylib")
	cmd := exec.Command(cc, "-dynamiclib", "-O2", "-o", out, src)
	if b, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("preload compile: %v %s", err, b)
	}
	sign := exec.Command("codesign", "--force", "--sign", "-", out)
	if b, err := sign.CombinedOutput(); err != nil {
		return "", fmt.Errorf("preload sign: %v %s", err, b)
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

func compiler() (string, error) {
	for _, name := range []string{"cc", "clang", "gcc"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("cc not available")
}
