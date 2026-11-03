package sandbox

import (
	_ "embed"
)

//go:embed preload.c.txt
var preloadSrc string

func preloadBin() cachedBin {
	return cachedBin{
		name: "lgb-preload",
		src:  preloadSrc,
		suf:  ".so",
		build: func() ([]byte, error) {
			return gccBytes("preload.c", []byte(preloadSrc), "preload.so", "preload compile",
				[]string{"-shared", "-fPIC", "-O2", "-pthread"}, []string{"-ldl"})
		},
	}
}

// ensurePreload compiles the connect interceptor once and caches the .so.
// Without gcc the shell still runs, and the network namespace stays closed.
func ensurePreload() (string, error) {
	return ensureCached(preloadBin())
}

func ensurePreloadIn(dir string) (string, error) {
	return ensureCachedIn(dir, preloadBin())
}
