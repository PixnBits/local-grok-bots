package clisession

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// claudeVersionLine is the first stdout line of `claude --version`.
// Trailing whitespace is trimmed before the match. Anything else is refused.
var claudeVersionLine = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+) \(Claude Code\)$`)

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
	// Stderr is ignored. A non-zero exit is a refusal even when stdout
	// looks like a version line.
	cmd.Stderr = io.Discard
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("version cannot be read")
	}
	if len(out) > 8192 {
		out = out[:8192]
	}
	line := string(out)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(line, " \t\r")
	m := claudeVersionLine.FindStringSubmatch(line)
	if m == nil {
		return "", fmt.Errorf("version cannot be read")
	}
	return m[1] + "." + m[2] + "." + m[3], nil
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
