package sandbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

// shellRun binaries (netbridge, ghbridge, the preload .so) are cached outside
// the jail. The daemon sets the directory at startup. Tests and other callers
// that leave it unset get a private per-user directory, never a shared /tmp file.
var (
	binCacheMu sync.Mutex
	binBuildMu sync.Mutex
	cacheDir   string
	// binBodies holds bytes built in this process, keyed by cache path.
	// A file left on disk by a previous process is not an entry.
	binBodies = map[string][]byte{}
	// cacheFileUID is the owner check for the cache directory and for a
	// regular file already at a cache path. Tests replace it.
	cacheFileUID = fileUID
	// cacheTempPath is the exclusive temporary name used to publish one file.
	// Tests point it at a planted symlink.
	cacheTempPath = func(dest string) string {
		return dest + ".tmp." + tmpHex()
	}
)

// CacheDir is the directory selected by SetCacheDir. It is empty until
// that call succeeds.
func CacheDir() string {
	binCacheMu.Lock()
	defer binCacheMu.Unlock()
	return cacheDir
}

// SetCacheDir selects the directory ensureNetBridge, ensureBridge, and
// ensurePreload publish into. dir is created mode 0700. An existing directory
// must be a real directory owned by the effective uid; a group-writable
// directory the process owns is narrowed to 0700. A symlink or another user's
// directory is refused. The bytes given to a jail come from memory, not from
// a later read of this directory.
func SetCacheDir(dir string) error {
	if err := prepareCacheDir(dir); err != nil {
		return err
	}
	binCacheMu.Lock()
	cacheDir = dir
	binCacheMu.Unlock()
	return nil
}

func activeCacheDir() (string, error) {
	binCacheMu.Lock()
	dir := cacheDir
	binCacheMu.Unlock()
	if dir != "" {
		if err := prepareCacheDir(dir); err != nil {
			return "", err
		}
		return dir, nil
	}
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		dir = filepath.Join(base, "local-grok-bots", "sandbox")
		if err := prepareCacheDir(dir); err == nil {
			binCacheMu.Lock()
			if cacheDir == "" {
				cacheDir = dir
			}
			dir = cacheDir
			binCacheMu.Unlock()
			return dir, nil
		}
	}
	dir, err := os.MkdirTemp("", "lgb-sandbox-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	if err := prepareCacheDir(dir); err != nil {
		return "", err
	}
	binCacheMu.Lock()
	if cacheDir == "" {
		cacheDir = dir
	}
	dir = cacheDir
	binCacheMu.Unlock()
	return dir, nil
}

// prepareCacheDir creates dir at mode 0700 or checks an existing one.
// The owner is checked before any chmod, so a directory owned by someone
// else is left unchanged.
func prepareCacheDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("sandbox cache dir")
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("sandbox cache dir")
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("sandbox cache dir")
		}
		fi, err = os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("sandbox cache dir")
		}
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("sandbox cache dir")
	}
	uid, ok := cacheFileUID(fi)
	if !ok || os.Geteuid() < 0 || int(uid) != os.Geteuid() {
		return fmt.Errorf("sandbox cache dir")
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("sandbox cache dir")
		}
		fi, err = os.Lstat(dir)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("sandbox cache dir")
		}
	}
	return nil
}

type cachedBin struct {
	name  string
	src   string
	suf   string
	build func() ([]byte, error)
}

func (b cachedBin) dest(dir string) string {
	sum := sha256.Sum256([]byte(b.src))
	return filepath.Join(dir, fmt.Sprintf("%s-%x%s", b.name, sum[:8], b.suf))
}

func ensureCached(b cachedBin) ([]byte, error) {
	dir, err := activeCacheDir()
	if err != nil {
		return nil, err
	}
	return ensureCachedIn(dir, b)
}

func ensureCachedIn(dir string, b cachedBin) ([]byte, error) {
	if err := prepareCacheDir(dir); err != nil {
		return nil, err
	}
	dest := b.dest(dir)
	// The first use in this process builds from source. A file already
	// on disk, including one with a matching sidecar, is not trusted.
	if body, ok := cachedBody(dest); ok {
		return body, nil
	}
	binBuildMu.Lock()
	defer binBuildMu.Unlock()
	if body, ok := cachedBody(dest); ok {
		return body, nil
	}
	if b.build == nil {
		return nil, fmt.Errorf("sandbox cache")
	}
	body, err := b.build()
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("sandbox cache empty")
	}
	if err := publishCached(dest, body); err != nil {
		return nil, err
	}
	storeCached(dest, body)
	stored, ok := cachedBody(dest)
	if !ok {
		return nil, fmt.Errorf("sandbox cache")
	}
	return stored, nil
}

// resetBinaryCache drops in-process bytes so the next ensure builds again.
// Tests use it as a fresh process. It does not change the cache directory.
func resetBinaryCache() {
	binCacheMu.Lock()
	binBodies = map[string][]byte{}
	binCacheMu.Unlock()
}

func cachedBody(dest string) ([]byte, bool) {
	binCacheMu.Lock()
	defer binCacheMu.Unlock()
	body, ok := binBodies[dest]
	if !ok || len(body) == 0 {
		return nil, false
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, true
}

func storeCached(dest string, body []byte) {
	cp := make([]byte, len(body))
	copy(cp, body)
	binCacheMu.Lock()
	binBodies[dest] = cp
	binCacheMu.Unlock()
}

// publishCached writes body without adopting bytes that were already on disk.
// A regular file owned by someone else is left unchanged. A symlink or any
// other non-regular file is not opened. A regular file this process owns is
// read only to see whether it already matches body.
func publishCached(dest string, body []byte) error {
	fi, err := os.Lstat(dest)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("sandbox cache")
	}
	if err == nil && fi.Mode().IsRegular() {
		uid, ok := cacheFileUID(fi)
		if !ok || os.Geteuid() < 0 || int(uid) != os.Geteuid() {
			return fmt.Errorf("sandbox cache owner")
		}
		if verifyDisk(dest, body) == nil {
			return writeSidecar(dest, body)
		}
	}
	if err := writeNoFollow(dest, body, 0o700); err != nil {
		return err
	}
	return writeSidecar(dest, body)
}

func verifyDisk(path string, body []byte) error {
	disk, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if sha256.Sum256(disk) != sha256.Sum256(body) {
		return fmt.Errorf("sandbox cache mismatch")
	}
	return nil
}

func writeSidecar(dest string, body []byte) error {
	sum := sha256.Sum256(body)
	return writeNoFollow(dest+".sha256", []byte(hex.EncodeToString(sum[:])+"\n"), 0o600)
}

func writeNoFollow(dest string, data []byte, mode os.FileMode) error {
	tmp := cacheTempPath(dest)
	if err := rejectFollow(tmp); err != nil {
		return err
	}
	f, err := openExclusive(tmp, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func tmpHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func gccBytes(srcName string, src []byte, outName, label string, before, after []string) ([]byte, error) {
	if _, err := exec.LookPath("gcc"); err != nil {
		return nil, fmt.Errorf("gcc not available: %w", err)
	}
	dir, err := os.MkdirTemp("", "lgb-cc-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	srcPath := filepath.Join(dir, srcName)
	if err := os.WriteFile(srcPath, src, 0o644); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, outName)
	args := append([]string{}, before...)
	args = append(args, "-o", out, srcPath)
	args = append(args, after...)
	cmd := exec.Command("gcc", args...)
	if msg, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("%s: %v %s", label, err, msg)
	}
	return os.ReadFile(out)
}
