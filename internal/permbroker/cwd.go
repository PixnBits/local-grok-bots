package permbroker

import (
	"os"
	"path/filepath"
)

// canonCwd is the directory a once-token is bound to. A trailing slash,
// a dot segment, and a symlink to the same directory compare equal.
// A path that does not exist keeps the cleaned lexical form.
func canonCwd(p string) string {
	if p == "" {
		return ""
	}
	p = filepath.Clean(p)
	if _, err := os.Lstat(p); err != nil {
		return p
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return filepath.Clean(real)
}
