package sandbox

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	jailGoMod   = "/lgb/go/mod"
	jailGoCache = "/lgb/go/cache"
)

// applyJailGoEnv sets the toolchain environment and, on Linux, bind-mounts
// the module and build caches. Cache directories stay under the bot data
// directory when that path is safe. Otherwise they stay in the prep directory.
// GOPROXY and GOTOOLCHAIN come from the request, which policy has already
// narrowed. Empty values use the defaults. GOSUMDB is off.
func applyJailGoEnv(p *prepared, req Request, workspace, rw string) error {
	if p == nil {
		return fmt.Errorf("go env unavailable")
	}
	hostMod, hostCache, err := ensureGoCaches(p.dir, req.BotGoRoot, workspace)
	if err != nil {
		return err
	}
	proxy := strings.TrimSpace(req.GoProxy)
	if proxy == "" {
		proxy = "off"
	}
	tool := strings.TrimSpace(req.GoToolchain)
	if tool == "" {
		tool = "local"
	}
	flags := req.GoFlags
	mod := jailGoMod
	cache := jailGoCache
	if runtime.GOOS == "linux" {
		if err := os.MkdirAll(filepath.Join(rw, "go", "mod"), 0o755); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(rw, "go", "cache"), 0o755); err != nil {
			return err
		}
		p.mounts = append(p.mounts,
			mount{Src: hostMod, Dst: jailGoMod, RO: false},
			mount{Src: hostCache, Dst: jailGoCache, RO: false},
		)
	} else {
		mod = hostMod
		cache = hostCache
	}
	lines := []string{
		"GOMODCACHE=" + mod,
		"GOCACHE=" + cache,
		"GOPROXY=" + proxy,
		"GOTOOLCHAIN=" + tool,
		"GOFLAGS=" + flags,
		"GOSUMDB=off",
	}
	p.env = append(p.env, lines...)
	p.goLines = append([]string(nil), lines...)
	p.extra = append(p.extra, Event{
		Kind: "jail_go_env",
		Detail: fmt.Sprintf("GOMODCACHE=%s GOCACHE=%s GOPROXY=%s GOTOOLCHAIN=%s GOFLAGS=%s GOSUMDB=off",
			mod, cache, redactGoProxy(proxy), tool, flags),
	})
	return nil
}

func ensureGoCaches(prepDir, botRoot, workspace string) (string, string, error) {
	root := ""
	fromBot := false
	if usableGoRoot(botRoot, workspace) {
		root = filepath.Clean(botRoot)
		fromBot = true
	}
	if root == "" {
		root = filepath.Join(prepDir, "go-host")
	}
	mod := filepath.Join(root, "go", "mod")
	cache := filepath.Join(root, "go", "cache")
	if err := os.MkdirAll(mod, 0o700); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", "", err
	}
	if !cachesOutsideWorkspace(root, workspace, fromBot) {
		return "", "", fmt.Errorf("go cache directory is not available")
	}
	return mod, cache, nil
}

func usableGoRoot(root, workspace string) bool {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return false
	}
	root = filepath.Clean(root)
	ws := filepath.Clean(strings.TrimSpace(workspace))
	if ws != "" && (pathHolds(ws, root) || pathHolds(root, ws)) {
		return false
	}
	if symlinkOnPath(root) {
		return false
	}
	return true
}

func cachesOutsideWorkspace(root, workspace string, lexical bool) bool {
	root = filepath.Clean(root)
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	real = filepath.Clean(real)
	if lexical && real != root {
		return false
	}
	ws := filepath.Clean(strings.TrimSpace(workspace))
	if ws == "" {
		return true
	}
	if pathHolds(ws, real) || pathHolds(real, ws) {
		return false
	}
	if wsReal, werr := filepath.EvalSymlinks(ws); werr == nil {
		wsReal = filepath.Clean(wsReal)
		if pathHolds(wsReal, real) || pathHolds(real, wsReal) {
			return false
		}
	}
	return true
}

func symlinkOnPath(path string) bool {
	path = filepath.Clean(path)
	cur := path
	for {
		st, err := os.Lstat(cur)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return true
		}
		if cur == string(filepath.Separator) || cur == "." {
			return false
		}
		next := filepath.Dir(cur)
		if next == cur {
			return false
		}
		cur = next
	}
}

func redactGoProxy(raw string) string {
	var b strings.Builder
	var entry strings.Builder
	write := func() {
		if entry.Len() == 0 {
			return
		}
		b.WriteString(redactProxyEntry(strings.TrimSpace(entry.String())))
		entry.Reset()
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == ',' || c == '|' {
			write()
			b.WriteByte(c)
			continue
		}
		entry.WriteByte(c)
	}
	write()
	return b.String()
}

func redactProxyEntry(s string) string {
	if s == "" || s == "off" || s == "direct" || s == "passthrough" || !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		if strings.Contains(s, "@") {
			return "redacted"
		}
		return s
	}
	u.User = nil
	return u.String()
}
