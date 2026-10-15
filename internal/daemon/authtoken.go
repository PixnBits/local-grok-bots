package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// adminTokenFile is the generated admin token under DATA_DIR.
const adminTokenFile = "admin-token"

// ensureAdminToken returns the token the HTTP API requires. AUTH_TOKEN wins.
// With a CLI backend and no AUTH_TOKEN, a token is generated once and kept
// 0600 in DATA_DIR, so a CLI's shell on this host can't drive the API
// (approve its own permissions, edit bots). Ollama-only setups keep the old
// behavior: no token unless one is set.
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
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", "", err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		return "", "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", "", fmt.Errorf("admin token: %w", err)
	}
	return token, path, nil
}

// readAdminToken opens the token file without following a symlink, fixes its
// mode on the open file, and reports whether it held a usable token.
func readAdminToken(path string) (string, bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("admin token: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", false, err
	}
	if !st.Mode().IsRegular() {
		return "", false, fmt.Errorf("admin token: %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := f.Chmod(0o600); err != nil {
			return "", false, err
		}
	}
	b, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", false, err
	}
	if t := strings.TrimSpace(string(b)); len(t) >= 32 {
		return t, true, nil
	}
	return "", false, nil
}
