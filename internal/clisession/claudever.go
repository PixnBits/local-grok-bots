package clisession

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MinClaudeBrokerVersion is the oldest Claude Code release whose
// PreToolUse onFailure=block is honored. Older releases, and a binary
// whose version cannot be read, are not armed.
const MinClaudeBrokerVersion = "2.1.295"

type claudeVerKey struct {
	path  string
	size  int64
	mtime int64
}

var claudeVersionCache sync.Map

// CheckClaudeBrokerVersion runs path --version and refuses a release
// older than MinClaudeBrokerVersion. The result is cached for one
// path, size, and mtime. The error text names the version problem.
func CheckClaudeBrokerVersion(ctx context.Context, path string) error {
	ver, err := claudeBrokerVersion(ctx, path)
	if err != nil || ver == "" {
		return fmt.Errorf("version cannot be read")
	}
	if versionLess(ver, MinClaudeBrokerVersion) {
		return fmt.Errorf("version %s is older than %s", ver, MinClaudeBrokerVersion)
	}
	return nil
}

func claudeBrokerVersion(ctx context.Context, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil || !st.Mode().IsRegular() {
		return "", fmt.Errorf("version cannot be read")
	}
	key := claudeVerKey{path: abs, size: st.Size(), mtime: st.ModTime().UnixNano()}
	if v, ok := claudeVersionCache.Load(key); ok {
		ver, _ := v.(string)
		if ver == "" {
			return "", fmt.Errorf("version cannot be read")
		}
		return ver, nil
	}
	ver, err := probeClaudeVersion(ctx, abs)
	if err != nil || ver == "" {
		return "", fmt.Errorf("version cannot be read")
	}
	claudeVersionCache.Store(key, ver)
	return ver, nil
}

func probeClaudeVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	// Inherit the environment so a test double can report the version
	// the test asked for. A clean environment would hide that.
	out, err := cmd.CombinedOutput()
	if len(out) > 8192 {
		out = out[:8192]
	}
	tok := claudeVersionToken(string(out))
	if tok == "" {
		if err == nil {
			err = fmt.Errorf("version cannot be read")
		}
		return "", err
	}
	return tok, nil
}

func claudeVersionToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		if i > 0 && versionChar(s[i-1]) {
			continue
		}
		j := i
		parts := 0
		for parts < 3 {
			start := j
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			if j == start {
				break
			}
			parts++
			if parts == 3 {
				if j < len(s) && versionChar(s[j]) {
					break
				}
				return s[i:j]
			}
			if j >= len(s) || s[j] != '.' {
				break
			}
			j++
		}
	}
	return ""
}

func versionLess(a, b string) bool {
	ap := versionParts(a)
	bp := versionParts(b)
	if ap == nil || bp == nil {
		return true
	}
	for i := 0; i < 3; i++ {
		if ap[i] != bp[i] {
			return ap[i] < bp[i]
		}
	}
	return false
}

func versionParts(s string) []int {
	raw := strings.Split(s, ".")
	if len(raw) != 3 {
		return nil
	}
	out := make([]int, 3)
	for i, p := range raw {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil
		}
		out[i] = n
	}
	return out
}
