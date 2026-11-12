package sandbox

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
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
// directory when that path is safe. Otherwise they stay in the prep directory
// and the event says the cache is ephemeral. GOPROXY and GOTOOLCHAIN come
// from the request, which policy has already narrowed. Empty values use the
// defaults. GOSUMDB is off. GOENV=off ignores a go env file. The go wrapper
// sets the same values again so a command prefix cannot replace them.
func applyJailGoEnv(p *prepared, req Request, workspace, rw string) error {
	if p == nil {
		return fmt.Errorf("go env unavailable")
	}
	hostMod, hostCache, ephemeral, err := ensureGoCaches(p.dir, req.BotGoRoot, workspace)
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
		"GOENV=off",
		"GOWORK=off",
	}
	p.env = append(p.env, lines...)
	p.goLines = append([]string(nil), lines...)
	detail := fmt.Sprintf("GOMODCACHE=%s GOCACHE=%s GOPROXY=%s GOTOOLCHAIN=%s GOFLAGS=%s GOSUMDB=off",
		mod, cache, redactGoProxy(proxy), tool, flags)
	ev := Event{Kind: "jail_go_env", Detail: detail}
	if ephemeral {
		ev.Detail += " cache=ephemeral"
		ev.Notice = "Go build cache is ephemeral for this command"
	}
	p.extra = append(p.extra, ev)
	return nil
}

// goWrap is the jail go binary. It sets the policy values after the
// caller's environment and ignores the go env file.
func goWrap(proxy, toolchain, flags, sum, mod, cache, goroot string) string {
	if strings.TrimSpace(sum) == "" {
		sum = "off"
	}
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("export GOENV=off\n")
	b.WriteString("export GOWORK=off\n")
	if goroot = strings.TrimSpace(goroot); goroot != "" {
		b.WriteString("export GOROOT=" + shSingle(goroot) + "\n")
	}
	b.WriteString("export GOPROXY=" + shSingle(proxy) + "\n")
	b.WriteString("export GOTOOLCHAIN=" + shSingle(toolchain) + "\n")
	b.WriteString("export GOFLAGS=" + shSingle(flags) + "\n")
	b.WriteString("export GOSUMDB=" + shSingle(sum) + "\n")
	b.WriteString("export GOMODCACHE=" + shSingle(mod) + "\n")
	b.WriteString("export GOCACHE=" + shSingle(cache) + "\n")
	b.WriteString("exec /lgb/bin/go \"$@\"\n")
	return b.String()
}

func shSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// installGoWrap mounts the wrapper over each go binary on the jail PATH.
// The real binary is at /lgb/bin/go. A missing go binary leaves the
// environment pins in place and mounts nothing.
func installGoWrap(p *prepared, ro, rw string, req Request) error {
	if p == nil {
		return fmt.Errorf("go env unavailable")
	}
	real, targets := jailGoBins()
	if real == "" || len(targets) == 0 {
		return nil
	}
	proxy := strings.TrimSpace(req.GoProxy)
	if proxy == "" {
		proxy = "off"
	}
	tool := strings.TrimSpace(req.GoToolchain)
	if tool == "" {
		tool = "local"
	}
	mod := envValue(p.env, "GOMODCACHE")
	cache := envValue(p.env, "GOCACHE")
	if mod == "" {
		mod = jailGoMod
	}
	if cache == "" {
		cache = jailGoCache
	}
	if err := writeExec(filepath.Join(ro, "gowrap"), goWrap(proxy, tool, req.GoFlags, "off", mod, cache, goRootOf(real))); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(rw, "bin"), 0o755); err != nil {
		return err
	}
	touch(filepath.Join(rw, "bin", "go"))
	p.mounts = append(p.mounts, mount{Src: real, Dst: "/lgb/bin/go", RO: true})
	wrap := filepath.Join(ro, "gowrap")
	for _, dst := range targets {
		p.mounts = append(p.mounts, mount{Src: wrap, Dst: dst, RO: true})
	}
	return nil
}

func jailGoBins() (real string, targets []string) {
	seen := map[string]bool{}
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			return
		}
		st, err := os.Lstat(p)
		if err != nil || st.IsDir() {
			return
		}
		seen[p] = true
		targets = append(targets, p)
	}
	if p, err := exec.LookPath("go"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			real = abs
			add(abs)
		}
	}
	for _, dir := range strings.Split(jailPATH(), ":") {
		add(filepath.Join(dir, "go"))
	}
	if real == "" && len(targets) > 0 {
		real = targets[0]
	}
	return real, targets
}

// goRootOf is the toolchain root for the real go binary. A binary mounted
// at /lgb/bin/go cannot infer GOROOT from its path, so the wrapper sets it.
func goRootOf(real string) string {
	if real != "" {
		cmd := exec.Command(real, "env", "GOROOT")
		cmd.Env = append(os.Environ(), "GOENV=off")
		if out, err := cmd.Output(); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				return s
			}
		}
	}
	return strings.TrimSpace(runtime.GOROOT())
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, line := range env {
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

func ensureGoCaches(prepDir, botRoot, workspace string) (string, string, bool, error) {
	root := ""
	fromBot := false
	if usableGoRoot(botRoot, workspace) {
		root = filepath.Clean(botRoot)
		fromBot = true
	}
	ephemeral := !fromBot
	if root == "" {
		root = filepath.Join(prepDir, "go-host")
	}
	mod := filepath.Join(root, "go", "mod")
	cache := filepath.Join(root, "go", "cache")
	if err := os.MkdirAll(mod, 0o700); err != nil {
		return "", "", false, err
	}
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return "", "", false, err
	}
	if !cachesOutsideWorkspace(root, workspace, fromBot) {
		return "", "", false, fmt.Errorf("go cache directory is not available")
	}
	return mod, cache, ephemeral, nil
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
