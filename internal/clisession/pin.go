package clisession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

const maxPinnedBinary = 512 << 20

// verifyPin checks a resolved CLI path when that backend is pinned.
// No pin is success. A mismatch fails closed and does not exec the turn.
func verifyPin(ctx context.Context, pol policy.Policy, backend, path string) error {
	pin, ok := pol.CLIPinFor(backend)
	if !ok {
		return nil
	}
	if pin.Path != "" && !sameFilePath(pin.Path, path) {
		return fmt.Errorf("cli pin: %s path mismatch", backend)
	}
	target, err := pinnedTarget(path)
	if err != nil {
		return fmt.Errorf("cli pin: %s %w", backend, err)
	}
	if pin.SHA256 != "" {
		sum, err := hashFile(target)
		if err != nil {
			return fmt.Errorf("cli pin: %s hash unreadable", backend)
		}
		if sum != pin.SHA256 {
			return fmt.Errorf("cli pin: %s hash mismatch", backend)
		}
	}
	if pin.Version != "" {
		if err := versionMatches(ctx, target, pin.Version); err != nil {
			return fmt.Errorf("cli pin: %s %s", backend, err.Error())
		}
	}
	return nil
}

func pinnedTarget(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("binary is not a regular file")
	}
	if st.Size() > maxPinnedBinary {
		return "", fmt.Errorf("binary is too large")
	}
	return abs, nil
}

func sameFilePath(pin, got string) bool {
	a, errA := filepath.Abs(pin)
	b, errB := filepath.Abs(got)
	if errA != nil || errB != nil {
		return false
	}
	if a == b {
		return true
	}
	ar, errA := filepath.EvalSymlinks(a)
	br, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ar == br
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxPinnedBinary+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func versionMatches(ctx context.Context, path, want string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if len(out) > 8192 {
		out = out[:8192]
	}
	if err != nil && len(out) == 0 {
		return fmt.Errorf("version check failed")
	}
	if !versionFound(string(out), want) {
		return fmt.Errorf("version mismatch")
	}
	return nil
}

func versionFound(output, want string) bool {
	if want == "" {
		return false
	}
	rest := output
	for {
		i := strings.Index(rest, want)
		if i < 0 {
			return false
		}
		before := i == 0 || !versionChar(rest[i-1])
		end := i + len(want)
		after := end >= len(rest) || !versionChar(rest[end])
		if before && after {
			return true
		}
		rest = rest[i+1:]
	}
}

func versionChar(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '.' || b == '_' || b == '+' || b == '-'
}
