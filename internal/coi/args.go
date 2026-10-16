package coi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrNotAllowed is an argument the allowlist does not name.
	ErrNotAllowed = errors.New("argument is not allowed")
	// ErrBlocked is a config, token, or debug style argument.
	ErrBlocked = errors.New("argument is blocked")
	// ErrCredHome is an argument that mentions the credential home.
	ErrCredHome = errors.New("argument references the credential home")
	// ErrOutside is a path outside the bot workspace.
	ErrOutside = errors.New("path is outside the workspace")
	// ErrNoArgs is an empty invocation. The allowlist is deny-by-default.
	ErrNoArgs = errors.New("no arguments allowed")
	// ErrSandboxUnavailable means the inner CLI jail could not start.
	ErrSandboxUnavailable = errors.New("sandbox is not available")
	// ErrProxyUnavailable means the egress proxy could not start or has no token.
	ErrProxyUnavailable = errors.New("proxy is not available")
	// ErrJailCredentials means real credential files would enter the jail
	// without a managed opt-in.
	ErrJailCredentials = errors.New("jail credentials are not allowed")
)

// blockedWord is a whole token or split word that prints or changes credentials.
// --always-approve and --sandbox are blocked even when listed. The daemon may
// prepend --always-approve through fixed_args. It does not prepend --sandbox:
// the daemon jail is the only sandbox. update is blocked as a token so the
// CLI cannot self-update; --no-auto-update is also blocked here and belongs in
// fixed_args.
var blockedWord = map[string]bool{
	"config": true, "auth": true, "login": true, "logout": true,
	"whoami": true, "token": true, "tokens": true, "env": true,
	"credential": true, "credentials": true, "secret": true, "secrets": true,
	"password": true, "passwd": true, "debug": true,
	"update": true, "always-approve": true, "sandbox": true,
}

// CheckArgs allows only listed subcommands and flags.
// The first positional and every flag must be listed. Later positionals are
// operands. Blocked words and the credential home lose even when listed.
// Flags in valueFlags take the next word as a value; every other flag is
// boolean and does not swallow the next word. Values, including --flag=value,
// get the blocked-word check. Every value is also resolved as a path from the
// workspace. protected are extra roots, such as other credential homes and
// the COI data directory. The inner CLI sandbox is the real filesystem boundary.
func CheckArgs(allowed, args []string, workspace, credHome string, valueFlags []string, protected ...string) error {
	if len(allowed) == 0 || len(args) == 0 {
		return ErrNoArgs
	}
	allow := map[string]bool{}
	for _, a := range allowed {
		allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	value := map[string]bool{}
	for _, a := range valueFlags {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			value[a] = true
		}
	}
	roots := protectedRoots(credHome, protected)
	flags, positionals, err := splitArgs(args, value)
	if err != nil {
		return err
	}
	saw := false
	for _, f := range flags {
		if argBlocked(f.name) || argBlocked(f.value) {
			return ErrBlocked
		}
		if !allow[strings.ToLower(f.name)] {
			return ErrNotAllowed
		}
		saw = true
		if err := vetValue(f.value, workspace, roots); err != nil {
			return err
		}
	}
	for i, p := range positionals {
		if err := vetValue(p, workspace, roots); err != nil {
			return err
		}
		if argBlocked(p) {
			return ErrBlocked
		}
		if i == 0 {
			if !allow[strings.ToLower(p)] {
				return ErrNotAllowed
			}
			saw = true
		}
	}
	if !saw {
		return ErrNoArgs
	}
	return nil
}

func protectedRoots(credHome string, extra []string) []string {
	out := make([]string, 0, 1+len(extra))
	if home := strings.TrimSpace(credHome); home != "" {
		out = append(out, home)
	}
	out = append(out, extra...)
	return out
}

type flagArg struct {
	name  string
	value string
}

func splitArgs(args []string, valueFlags map[string]bool) ([]flagArg, []string, error) {
	var flags []flagArg
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.ContainsRune(a, 0) {
			return nil, nil, ErrNotAllowed
		}
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		name, val, has := strings.Cut(a, "=")
		if strings.HasPrefix(name, "--") {
			// long flag
		} else if len(name) != 2 {
			// A cluster such as -abc is not a single allowlisted flag.
			return nil, nil, ErrNotAllowed
		}
		f := flagArg{name: name}
		if has {
			f.value = val
		} else if valueFlags[strings.ToLower(name)] && i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
			i++
			f.value = args[i]
		}
		flags = append(flags, f)
	}
	return flags, pos, nil
}

func argBlocked(s string) bool {
	if s == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimLeft(s, "-"))
	if blockedWord[lower] {
		return true
	}
	for _, w := range words(s) {
		if blockedWord[w] {
			return true
		}
	}
	return false
}

func words(s string) []string {
	s = strings.ToLower(strings.TrimLeft(s, "-"))
	return strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

func vetValue(v, workspace string, roots []string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "~") || hasDotDot(v) {
		return ErrOutside
	}
	if mentionsAny(v, roots) {
		return ErrCredHome
	}
	resolved, ok := resolvePath(workspace, v)
	if !ok {
		return ErrOutside
	}
	if mentionsAny(resolved, roots) || insideAny(resolved, roots) {
		return ErrCredHome
	}
	if !hasPathPrefix(workspace, resolved) {
		return ErrOutside
	}
	return nil
}

func hasDotDot(v string) bool {
	for _, seg := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func mentionsAny(v string, roots []string) bool {
	for _, root := range roots {
		if mentionsCred(v, root) {
			return true
		}
	}
	return false
}

func insideAny(path string, roots []string) bool {
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" || root == "." || root == string(filepath.Separator) || !filepath.IsAbs(root) {
			continue
		}
		if hasPathPrefix(root, path) {
			return true
		}
	}
	return false
}

func mentionsCred(v, credHome string) bool {
	credHome = filepath.Clean(credHome)
	if credHome == "" || credHome == "." || credHome == string(filepath.Separator) {
		return false
	}
	if strings.Contains(filepath.Clean(v), credHome) || strings.Contains(v, credHome) {
		return true
	}
	return false
}

func resolvePath(workspace, raw string) (string, bool) {
	full := raw
	if !filepath.IsAbs(full) {
		full = filepath.Join(workspace, full)
	}
	return resolveExisting(filepath.Clean(full))
}

func resolveExisting(full string) (string, bool) {
	if r, err := filepath.EvalSymlinks(full); err == nil {
		return filepath.Clean(r), true
	} else if !os.IsNotExist(err) {
		return "", false
	}
	var tail []string
	cur := full
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", false
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		if _, err := os.Lstat(parent); err == nil {
			r, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return "", false
			}
			return filepath.Clean(filepath.Join(append([]string{r}, tail...)...)), true
		} else if !os.IsNotExist(err) {
			return "", false
		}
		cur = parent
	}
}

func hasPathPrefix(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if root == path {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Overlaps reports whether a and b are the same path or one contains the other.
func Overlaps(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return hasPathPrefix(a, b) || hasPathPrefix(b, a)
}

// Covers reports whether path is a root or a path inside one.
// A symlink is covered when its target is.
func Covers(roots []string, path string) bool {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "" || path == "." || !filepath.IsAbs(path) {
		return false
	}
	cands := []string{path}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		resolved = filepath.Clean(resolved)
		if resolved != path {
			cands = append(cands, resolved)
		}
	}
	for _, root := range roots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "" || root == "." || root == string(filepath.Separator) || !filepath.IsAbs(root) {
			continue
		}
		for _, cand := range cands {
			if hasPathPrefix(root, cand) {
				return true
			}
		}
	}
	return false
}
