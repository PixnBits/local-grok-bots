package clisession

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// allowedGrokVersions is the only list of grok releases a turn may run.
const allowedGrokVersions = "1.0.52,1.0.62"

// VersionError refuses a turn because the grok binary is not an allowed release.
// Error text stays generic. Version is for the audit record.
type VersionError struct {
	Version string
}

func (e *VersionError) Error() string {
	return "cli version is not allowed, so the turn was refused"
}

func grokVersionAllowed(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, a := range strings.Split(allowedGrokVersions, ",") {
		if v == strings.TrimSpace(a) {
			return true
		}
	}
	return false
}

type grokVerKey struct {
	path  string
	size  int64
	mtime int64
}

var grokVersionCache sync.Map

func checkGrokVersion(ctx context.Context, path, pinSHA string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return &VersionError{Version: "unknown"}
	}
	resolved := abs
	if real, err := filepath.EvalSymlinks(abs); err == nil && real != "" {
		resolved = real
	}
	st, err := os.Stat(resolved)
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxPinnedBinary {
		return &VersionError{Version: "unknown"}
	}
	// Hash before any version probe, including a cached version.
	sum, err := hashFile(resolved)
	if err != nil || sum == "" {
		return &VersionError{Version: "unknown"}
	}
	pinSHA = strings.TrimSpace(pinSHA)
	if pinSHA != "" && !strings.EqualFold(sum, pinSHA) {
		return fmt.Errorf("cli pin: grok hash mismatch")
	}
	key := grokVerKey{path: resolved, size: st.Size(), mtime: st.ModTime().UnixNano()}
	if v, ok := grokVersionCache.Load(key); ok {
		ver, _ := v.(string)
		if grokVersionAllowed(ver) {
			return nil
		}
		if ver == "" {
			ver = "unknown"
		}
		return &VersionError{Version: ver}
	}
	ver, err := probeGrokVersion(ctx, resolved)
	if err != nil || ver == "" {
		return &VersionError{Version: "unknown"}
	}
	grokVersionCache.Store(key, ver)
	if !grokVersionAllowed(ver) {
		return &VersionError{Version: ver}
	}
	return nil
}

func probeGrokVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = []string{"PATH=/opt/homebrew/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.CombinedOutput()
	if len(out) > 8192 {
		out = out[:8192]
	}
	tok := grokVersionToken(string(out))
	if tok == "" {
		if err == nil {
			err = fmt.Errorf("version check failed")
		}
		return "", err
	}
	return tok, nil
}

// grokVersionToken returns the first bounded major.minor.patch token.
func grokVersionToken(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		if i > 0 && versionChar(s[i-1]) {
			continue
		}
		j := i
		parts := 0
		ok := true
		for parts < 3 {
			if j >= len(s) || s[j] < '0' || s[j] > '9' {
				ok = false
				break
			}
			for j < len(s) && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			parts++
			if parts == 3 {
				break
			}
			if j >= len(s) || s[j] != '.' {
				ok = false
				break
			}
			j++
		}
		if ok && parts == 3 && (j >= len(s) || !versionChar(s[j])) {
			return s[i:j]
		}
	}
	return ""
}
