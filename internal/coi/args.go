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
)

// blockedWord is a whole word that prints or changes credentials.
var blockedWord = map[string]bool{
	"config": true, "auth": true, "login": true, "logout": true,
	"whoami": true, "token": true, "tokens": true, "env": true,
	"credential": true, "credentials": true, "secret": true, "secrets": true,
	"password": true, "passwd": true, "debug": true,
}

// CheckArgs allows only listed subcommands and flags.
// The first positional and every flag must be listed. Later positionals are
// operands. Blocked words and the credential home lose even when listed.
// A path operand or flag value must stay inside the workspace.
func CheckArgs(allowed, args []string, workspace, credHome string) error {
	if len(allowed) == 0 || len(args) == 0 {
		return ErrNoArgs
	}
	allow := map[string]bool{}
	for _, a := range allowed {
		allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	flags, positionals, err := splitArgs(args)
	if err != nil {
		return err
	}
	saw := false
	for _, f := range flags {
		if argBlocked(f.name) {
			return ErrBlocked
		}
		if !allow[strings.ToLower(f.name)] {
			return ErrNotAllowed
		}
		saw = true
		if err := vetValue(f.value, workspace, credHome); err != nil {
			return err
		}
	}
	for i, p := range positionals {
		if err := vetValue(p, workspace, credHome); err != nil {
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

type flagArg struct {
	name  string
	value string
}

func splitArgs(args []string) ([]flagArg, []string, error) {
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
		} else if i+1 < len(args) && args[i+1] != "--" && !strings.HasPrefix(args[i+1], "-") {
			i++
			f.value = args[i]
		}
		flags = append(flags, f)
	}
	return flags, pos, nil
}

func argBlocked(s string) bool {
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

func vetValue(v, workspace, credHome string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "~") {
		return ErrOutside
	}
	if mentionsCred(v, credHome) {
		return ErrCredHome
	}
	if !looksLikePath(v) {
		return nil
	}
	if !pathInside(workspace, v) {
		return ErrOutside
	}
	if resolved, ok := resolvePath(workspace, v); ok && mentionsCred(resolved, credHome) {
		return ErrCredHome
	}
	return nil
}

func looksLikePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.ContainsAny(s, `/\`)
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

func pathInside(workspace, raw string) bool {
	workspace = filepath.Clean(workspace)
	if !filepath.IsAbs(workspace) {
		return false
	}
	full := raw
	if !filepath.IsAbs(full) {
		full = filepath.Join(workspace, full)
	}
	full = filepath.Clean(full)
	if !hasPathPrefix(workspace, full) {
		return false
	}
	resolved, ok := resolveExisting(full)
	if !ok {
		return false
	}
	return hasPathPrefix(workspace, resolved)
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
