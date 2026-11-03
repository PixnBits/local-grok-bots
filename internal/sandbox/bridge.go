package sandbox

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
)

//go:embed ghbridge.c.txt
var bridgeSrc string

func ghBridgeBin() cachedBin {
	return cachedBin{
		name: "lgb-ghbridge",
		src:  bridgeSrc,
		build: func() ([]byte, error) {
			return gccBytes("ghbridge.c", []byte(bridgeSrc), "ghbridge", "github bridge compile",
				[]string{"-O2"}, nil)
		},
	}
}

// ensureBridge compiles the in-jail HTTP bridge once and caches the binary.
// Without gcc, GitHub fetch stays unavailable.
func ensureBridge() (string, error) {
	return ensureCached(ghBridgeBin())
}

func ensureBridgeIn(dir string) (string, error) {
	return ensureCachedIn(dir, ghBridgeBin())
}

func githubSockOK(path string) bool {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00") {
		return false
	}
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode()&os.ModeSocket == 0 {
		return false
	}
	return true
}
