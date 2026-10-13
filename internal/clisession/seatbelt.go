package clisession

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

// cliSeatbelt is the macOS profile for one CLI turn. Network stays open.
// The only home paths that can be written are the CLI login directories.
func cliSeatbelt(ws, home, tmp, binDir string) sandbox.Seatbelt {
	reads := sandbox.ExistingReadRoots()
	if binDir != "" && !covered(binDir, reads) {
		reads = append(reads, binDir)
	}
	writes := []string{ws}
	if tmp != "" {
		writes = append(writes, tmp)
	}
	var meta []string
	if home != "" {
		meta = append(meta, home)
		for _, name := range []string{".grok", ".claude"} {
			writes = append(writes, filepath.Join(home, name))
		}
		writes = append(writes, filepath.Join(home, ".claude.json"))
	}
	return sandbox.Seatbelt{
		Read:    reads,
		Write:   writes,
		Meta:    meta,
		OpenNet: true,
	}
}

func covered(path string, roots []string) bool {
	path = filepath.Clean(path)
	for _, root := range roots {
		root = filepath.Clean(root)
		if path == root || strings.HasPrefix(path, root+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func cliChildEnv(home, tmp string) []string {
	if home == "" {
		home = tmp
	}
	env := []string{
		"PATH=" + cliPATH(),
		"HOME=" + home,
		"TMPDIR=" + tmp,
	}
	if name := currentName(); name != "" {
		env = append(env, "USER="+name, "LOGNAME="+name)
	}
	return append(env, localePairs()...)
}

func ensureCLIState(home string) {
	for _, name := range []string{".grok", ".claude"} {
		p := filepath.Join(home, name)
		st, err := os.Lstat(p)
		if err == nil {
			if st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
				continue
			}
			continue
		}
		if os.IsNotExist(err) {
			_ = os.MkdirAll(p, 0o700)
		}
	}
}
