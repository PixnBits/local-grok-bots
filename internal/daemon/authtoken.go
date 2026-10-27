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

// euid is the daemon's effective uid. Tests replace it.
var euid = os.Geteuid

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

// ensureAdminToken returns the token the HTTP API requires.
// An existing admin-token file is always read. AUTH_TOKEN wins when it
// is set. A new file is written only for a CLI backend with no AUTH_TOKEN.
// A file that exists but is unusable is an error; it is not replaced.
func ensureAdminToken(dataDir, envToken string, usesCLI bool) (token, path string, err error) {
	path = filepath.Join(dataDir, adminTokenFile)
	t, ok, rerr := readAdminToken(path)
	if rerr != nil {
		return "", "", rerr
	}
	if ok {
		if envToken != "" {
			return envToken, "", nil
		}
		return t, path, nil
	}
	if envToken != "" || !usesCLI {
		return envToken, "", nil
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

// prepareAdminDir requires DATA_DIR to be a real directory owned by the
// effective uid and not group or other writable. A missing path is created
// mode 0700 and is not chmodded when it already exists. New calls this on
// every start, before any token is read. ensureAdminToken calls it again
// before creating a token.
func prepareAdminDir(dataDir string) error {
	var st unix.Stat_t
	err := unix.Lstat(dataDir, &st)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("DATA_DIR %s: %w", dataDir, err)
		}
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return fmt.Errorf("DATA_DIR %s: %w", dataDir, err)
		}
		if err := unix.Lstat(dataDir, &st); err != nil {
			return fmt.Errorf("DATA_DIR %s: %w", dataDir, err)
		}
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("DATA_DIR %s is a symlink", dataDir)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("DATA_DIR %s is not a directory", dataDir)
	}
	if int(st.Uid) != euid() {
		return fmt.Errorf("DATA_DIR %s owner mismatch", dataDir)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("DATA_DIR %s is group or other writable", dataDir)
	}
	if err := cleanAdminTokenTemps(dataDir); err != nil {
		return err
	}
	return nil
}

// cleanAdminTokenTemps removes regular DATA_DIR/admin-token.tmp-* files
// owned by the effective uid. It uses Lstat and does not follow symlinks.
// Directories, symlinks, and other non-regular entries are left in place.
func cleanAdminTokenTemps(dir string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("DATA_DIR %s: %w", dir, err)
	}
	prefix := adminTokenFile + ".tmp-"
	id := euid()
	for _, ent := range ents {
		name := ent.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		path := filepath.Join(dir, name)
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			continue
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			continue
		}
		if int(st.Uid) != id {
			continue
		}
		if err := unix.Unlink(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("DATA_DIR %s: %w", path, err)
		}
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
