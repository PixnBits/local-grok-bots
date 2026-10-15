package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	if b, rerr := os.ReadFile(path); rerr == nil {
		st, serr := os.Stat(path)
		if serr != nil {
			return "", "", serr
		}
		if st.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(path, 0o600); err != nil {
				return "", "", err
			}
		}
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t, path, nil
		}
	} else if !errors.Is(rerr, fs.ErrNotExist) {
		return "", "", rerr
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
