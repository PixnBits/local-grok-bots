package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// adminTokenFile is the generated admin token under DATA_DIR.
const adminTokenFile = "admin-token"

// adminTokenMax is the largest admin-token file this daemon will read.
const adminTokenMax = 4 << 10

// adminTokenTempPath is the exclusive temp path for a new admin token.
// Tests replace it to plant a symlink at a known name.
var adminTokenTempPath = func(dir string) (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return filepath.Join(dir, adminTokenFile+".tmp-"+hex.EncodeToString(buf[:])), nil
}

// ensureAdminToken returns the token the HTTP API requires. AUTH_TOKEN wins.
// With a CLI backend and no AUTH_TOKEN, a token is generated once and kept
// 0600 in DATA_DIR, so a CLI's shell on this host can't drive the API
// (approve its own permissions, edit bots). Ollama-only setups keep the old
// behavior: no token unless one is set. A file that exists but is unusable
// is an error; it is not replaced.
func ensureAdminToken(dataDir, envToken string, usesCLI bool) (token, path string, err error) {
	if envToken != "" || !usesCLI {
		return envToken, "", nil
	}
	path = filepath.Join(dataDir, adminTokenFile)
	if t, ok, rerr := readAdminToken(path); rerr != nil {
		return "", "", rerr
	} else if ok {
		return t, path, nil
	}
	if err := prepareAdminDir(dataDir); err != nil {
		return "", "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	if err := writeAdminToken(dataDir, path, token); err != nil {
		return "", "", err
	}
	return token, path, nil
}

// readAdminToken opens the token file the same way as AUTH_TOKENS_FILE.
// A missing file reports ok false so the caller can generate one. Any other
// failure, including an empty, short, or non-printable file, is an error.
// The error names path and never the file bytes.
func readAdminToken(path string) (string, bool, error) {
	b, err := readProtectedFile(path, adminTokenMax, "admin token", "")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		if path != "" && !strings.Contains(err.Error(), path) {
			return "", false, fmt.Errorf("%w: %s", err, path)
		}
		return "", false, err
	}
	tok := trimASCIISpace(string(b))
	if !printableToken(tok) {
		return "", false, fmt.Errorf("admin token: %s is empty, short, or not printable ASCII", path)
	}
	return tok, true, nil
}

// prepareAdminDir refuses a DATA_DIR that is missing the ownership and mode
// a token file needs. It creates the directory only when it does not exist.
func prepareAdminDir(dataDir string) error {
	var st unix.Stat_t
	err := unix.Lstat(dataDir, &st)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("admin token: %s: %w", dataDir, err)
		}
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return fmt.Errorf("admin token: %s: %w", dataDir, err)
		}
		if err := unix.Lstat(dataDir, &st); err != nil {
			return fmt.Errorf("admin token: %s: %w", dataDir, err)
		}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("admin token: %s is a symlink", dataDir)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("admin token: %s is not a directory", dataDir)
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("admin token: %s owner mismatch", dataDir)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("admin token: %s is group or other writable", dataDir)
	}
	return nil
}

func writeAdminToken(dir, final, token string) error {
	tmp, err := adminTokenTempPath(dir)
	if err != nil {
		return fmt.Errorf("admin token: %w", err)
	}
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("admin token: %w", err)
	}
	payload := []byte(token + "\n")
	if err := writeFull(fd, payload); err != nil {
		unix.Close(fd)
		unix.Unlink(tmp)
		return fmt.Errorf("admin token: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		unix.Unlink(tmp)
		return fmt.Errorf("admin token: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		unix.Unlink(tmp)
		return fmt.Errorf("admin token: %w", err)
	}
	if err := unix.Rename(tmp, final); err != nil {
		unix.Unlink(tmp)
		return fmt.Errorf("admin token: %w", err)
	}
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("admin token: %w", err)
	}
	ferr := unix.Fsync(dfd)
	cerr := unix.Close(dfd)
	if ferr != nil {
		return fmt.Errorf("admin token: %w", ferr)
	}
	if cerr != nil {
		return fmt.Errorf("admin token: %w", cerr)
	}
	return nil
}

func writeFull(fd int, p []byte) error {
	for len(p) > 0 {
		n, err := unix.Write(fd, p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("short write")
		}
	}
	return nil
}
