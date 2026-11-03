package sandbox

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// shellRun binaries (netbridge, ghbridge, the preload .so) are cached outside
// the jail. The daemon sets the directory at startup. Tests and other callers
// that leave it unset get a private per-user directory, never a shared /tmp file.
var (
	binCacheMu sync.Mutex
	binBuildMu sync.Mutex
	cacheDir   string
	binMemos   = map[string][32]byte{}
)

// SetCacheDir selects the directory ensureNetBridge, ensureBridge, and
// ensurePreload reuse. dir is created mode 0700. An existing directory must
// be a real directory owned by the effective uid; a group-writable directory
// the process owns is narrowed to 0700. A symlink or another user's directory
// is refused.
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
	uid, ok := fileUID(fi)
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

func ensureCached(b cachedBin) (string, error) {
	dir, err := activeCacheDir()
	if err != nil {
		return "", err
	}
	return ensureCachedIn(dir, b)
}

func ensureCachedIn(dir string, b cachedBin) (string, error) {
	if err := prepareCacheDir(dir); err != nil {
		return "", err
	}
	dest := b.dest(dir)
	if reusable(dest) {
		return dest, nil
	}
	binBuildMu.Lock()
	defer binBuildMu.Unlock()
	if reusable(dest) {
		return dest, nil
	}
	if b.build == nil {
		return "", fmt.Errorf("sandbox cache")
	}
	body, err := b.build()
	if err != nil {
		return "", err
	}
	if len(body) == 0 {
		return "", fmt.Errorf("sandbox cache empty")
	}
	sum := sha256.Sum256(body)
	if err := writeNoFollow(dest, body, 0o700); err != nil {
		return "", err
	}
	if err := writeNoFollow(dest+".sha256", []byte(hex.EncodeToString(sum[:])+"\n"), 0o600); err != nil {
		return "", err
	}
	binCacheMu.Lock()
	binMemos[dest] = sum
	binCacheMu.Unlock()
	return dest, nil
}

// reusable accepts a cached binary only when it is a regular file owned by
// the effective uid, not group or other writable, and its bytes match the
// sidecar hash and any in-process hash recorded for this path.
func reusable(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	uid, ok := fileUID(fi)
	if !ok || os.Geteuid() < 0 || int(uid) != os.Geteuid() {
		return false
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) == 0 {
		return false
	}
	sum := sha256.Sum256(body)
	side, err := os.ReadFile(path + ".sha256")
	if err != nil || strings.TrimSpace(string(side)) != hex.EncodeToString(sum[:]) {
		return false
	}
	binCacheMu.Lock()
	memo, have := binMemos[path]
	binCacheMu.Unlock()
	if have && memo != sum {
		return false
	}
	if !have {
		binCacheMu.Lock()
		binMemos[path] = sum
		binCacheMu.Unlock()
	}
	return true
}

func writeNoFollow(dest string, data []byte, mode os.FileMode) error {
	tmp := fmt.Sprintf("%s.tmp.%s", dest, tmpHex())
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
