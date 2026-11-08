package permbroker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// maxSymlinkFollow is the ceiling hop cap. One hop is one symlink read.
const maxSymlinkFollow = 40

const maxPathComponents = 1024

var (
	errSymlinkLoop         = errors.New("symlink loop")
	errSymlinkHops         = errors.New("symlink hop cap")
	errSymlinkDangling     = errors.New("dangling symlink")
	errPathUnresolved      = errors.New("unresolved path")
	errPathUnrepresentable = errors.New("unrepresentable path")
)

type walkState struct {
	hops int
	seen map[string]struct{}
}

// resolvePath walks an absolute path from the real root, one component at
// a time. A symlink target is resolved against the parent already resolved.
// A missing final component that is not itself a symlink is a new file.
// A dangling link, a loop, the hop cap, or an unreadable component is an error.
func resolvePath(path string) (string, error) {
	if err := refuseUnrepresentable(path); err != nil {
		return "", err
	}
	if path == "" || !filepath.IsAbs(path) {
		return "", errPathUnresolved
	}
	st := &walkState{seen: map[string]struct{}{}}
	return walkParts(pathRoot(path), pathParts(path), st, false)
}

// resolveFrom walks a relative spelled path from an already-resolved base.
func resolveFrom(base, spelled string) (string, error) {
	if err := refuseUnrepresentable(base); err != nil {
		return "", err
	}
	if err := refuseUnrepresentable(spelled); err != nil {
		return "", err
	}
	if base == "" || !filepath.IsAbs(base) || spelled == "" {
		return "", errPathUnresolved
	}
	if filepath.IsAbs(spelled) {
		return resolvePath(spelled)
	}
	realBase, err := resolvePath(base)
	if err != nil {
		return "", err
	}
	st := &walkState{seen: map[string]struct{}{}}
	return walkParts(realBase, pathParts(spelled), st, false)
}

func pathRoot(path string) string {
	vol := filepath.VolumeName(path)
	if vol != "" && !strings.HasSuffix(vol, string(filepath.Separator)) {
		return vol + string(filepath.Separator)
	}
	if vol != "" {
		return vol
	}
	return string(filepath.Separator)
}

// pathParts splits on the OS separator and does not rewrite bytes.
// On Unix a backslash is a name byte, the same as the kernel.
func pathParts(path string) []string {
	return strings.Split(path, string(filepath.Separator))
}

// unrepresentablePath is true when the bytes cannot be a kernel name.
// A NUL is the case Go can hold and the kernel cannot.
func unrepresentablePath(path string) bool {
	return strings.ContainsRune(path, 0)
}

func refuseUnrepresentable(path string) error {
	if unrepresentablePath(path) {
		return errPathUnrepresentable
	}
	return nil
}

func walkParts(cur string, parts []string, st *walkState, inLink bool) (string, error) {
	if len(parts) > maxPathComponents {
		return "", errPathUnresolved
	}
	for len(parts) > 0 {
		name := parts[0]
		parts = parts[1:]
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		if strings.ContainsRune(name, 0) {
			return "", errPathUnresolved
		}
		next := filepath.Join(cur, name)
		info, err := os.Lstat(next)
		if err != nil {
			if os.IsNotExist(err) {
				if inLink {
					return "", errSymlinkDangling
				}
				return joinNew(cur, append([]string{name}, parts...))
			}
			return "", errPathUnresolved
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, ferr := followLink(next, cur, st)
			if ferr != nil {
				return "", ferr
			}
			if len(parts) > 0 {
				stInfo, serr := os.Lstat(target)
				if serr != nil || !stInfo.IsDir() {
					return "", errPathUnresolved
				}
			}
			cur = target
			continue
		}
		if len(parts) > 0 && !info.IsDir() {
			return "", errPathUnresolved
		}
		cur = next
	}
	return cur, nil
}

func joinNew(cur string, parts []string) (string, error) {
	for _, name := range parts {
		if name == "" || name == "." {
			continue
		}
		if strings.ContainsRune(name, 0) {
			return "", errPathUnresolved
		}
		if name == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		cur = filepath.Join(cur, name)
	}
	return cur, nil
}

func followLink(link, parent string, st *walkState) (string, error) {
	if st.seen == nil {
		st.seen = map[string]struct{}{}
	}
	if _, ok := st.seen[link]; ok {
		return "", errSymlinkLoop
	}
	st.seen[link] = struct{}{}
	st.hops++
	if st.hops > maxSymlinkFollow {
		return "", errSymlinkHops
	}
	raw, err := os.Readlink(link)
	if err != nil {
		return "", errPathUnresolved
	}
	if err := refuseUnrepresentable(raw); err != nil {
		return "", err
	}
	if raw == "" {
		return "", errSymlinkDangling
	}
	var start string
	var parts []string
	if filepath.IsAbs(raw) {
		start = pathRoot(raw)
		parts = pathParts(raw)
	} else {
		start = parent
		parts = pathParts(raw)
	}
	got, err := walkParts(start, parts, st, true)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(got); err != nil {
		return "", errSymlinkDangling
	}
	return got, nil
}
