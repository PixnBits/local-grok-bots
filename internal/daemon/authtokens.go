package daemon

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// defaultTokenName is the name of AUTH_TOKEN or the generated admin token.
	defaultTokenName = "default"
	// authTokensMax is the largest AUTH_TOKENS_FILE this daemon will read.
	authTokensMax = 64 << 10
)

// namedToken is one access token. val is compared, never logged.
type namedToken struct {
	name string
	val  string
}

var authTokenName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// loadAuthTokens reads AUTH_TOKENS_FILE. An empty path means no file.
// The name "default" is reserved. defaultToken, when set, also occupies
// that value. A file that yields no tokens is an error. The file is not modified.
func loadAuthTokens(path, defaultToken string) ([]namedToken, error) {
	if path == "" {
		return nil, nil
	}
	b, err := readAuthTokensFile(path)
	if err != nil {
		return nil, err
	}
	toks, err := parseAuthTokens(string(b), defaultToken)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, errors.New("auth tokens: AUTH_TOKENS_FILE has no tokens")
	}
	return toks, nil
}

// readAuthTokensFile opens path without following a symlink and refuses
// anything that is not a small, owner-only regular file. O_NONBLOCK makes
// a FIFO return instead of waiting for a writer. The flag is cleared after
// fstat shows a regular file.
func readAuthTokensFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errors.New("auth tokens: symlink")
		}
		if lst, lerr := os.Lstat(path); lerr == nil && lst.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("auth tokens: symlink")
		}
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, errors.New("auth tokens: not a regular file")
	}
	if st.Mode&0o077 != 0 {
		unix.Close(fd)
		return nil, errors.New("auth tokens: mode allows group or other access")
	}
	if int(st.Uid) != os.Geteuid() {
		unix.Close(fd)
		return nil, errors.New("auth tokens: owner mismatch")
	}
	if st.Size > int64(authTokensMax) {
		unix.Close(fd)
		return nil, errors.New("auth tokens: file exceeds 64 KiB")
	}
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, fl&^unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, authTokensMax+1))
	if err != nil {
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	if int64(len(b)) > authTokensMax {
		return nil, errors.New("auth tokens: file exceeds 64 KiB")
	}
	return b, nil
}

// authTokensPaths is the cleaned absolute path of AUTH_TOKENS_FILE and, when
// it differs, the cleaned symlink target. An empty path or a path that cannot
// be made absolute yields nothing.
func authTokensPaths(path string) []string {
	if path == "" {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil
	}
	abs = filepath.Clean(abs)
	out := []string{abs}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return out
	}
	resolved = filepath.Clean(resolved)
	if resolved != abs {
		out = append(out, resolved)
	}
	return out
}

// checkAuthTokensLocation refuses an AUTH_TOKENS_FILE whose path or symlink
// target sits in the workspace or in DATA_DIR/cli, where a bot can read its
// own home and CLI state. Both roots are known from config.
func checkAuthTokensLocation(path, workspace, dataDir string) error {
	if path == "" {
		return nil
	}
	roots, err := botVisibleDirs(workspace, dataDir)
	if err != nil {
		return err
	}
	for _, p := range authTokensPaths(path) {
		for _, root := range roots {
			if pathInside(root, p) {
				return errors.New("auth tokens: AUTH_TOKENS_FILE is inside the workspace or a bot home")
			}
		}
	}
	return nil
}

func botVisibleDirs(workspace, dataDir string) ([]string, error) {
	data, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	ws, err := filepath.Abs(workspace)
	if err != nil {
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	var roots []string
	for _, root := range []string{filepath.Clean(ws), filepath.Join(filepath.Clean(data), "cli")} {
		roots = append(roots, root)
		resolved, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		resolved = filepath.Clean(resolved)
		if resolved != root {
			roots = append(roots, resolved)
		}
	}
	return roots, nil
}

func pathInside(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if root == "" || path == "" || root == "." || path == "." {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func parseAuthTokens(text, defaultToken string) ([]namedToken, error) {
	seenName := map[string]struct{}{defaultTokenName: {}}
	seenVal := map[string]struct{}{}
	if defaultToken != "" {
		seenVal[defaultToken] = struct{}{}
	}
	var out []namedToken
	lineNo := 0
	for _, line := range strings.Split(text, "\n") {
		lineNo++
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("auth tokens: line %d: invalid line", lineNo)
		}
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)
		if !authTokenName.MatchString(name) {
			return nil, fmt.Errorf("auth tokens: line %d: invalid name", lineNo)
		}
		if !printableToken(val) {
			return nil, fmt.Errorf("auth tokens: line %d: invalid token", lineNo)
		}
		if _, dup := seenName[name]; dup {
			return nil, fmt.Errorf("auth tokens: line %d: duplicate name", lineNo)
		}
		if _, dup := seenVal[val]; dup {
			return nil, fmt.Errorf("auth tokens: line %d: duplicate token", lineNo)
		}
		seenName[name] = struct{}{}
		seenVal[val] = struct{}{}
		out = append(out, namedToken{name: name, val: val})
	}
	return out, nil
}

// printableToken accepts at least 32 bytes of printable ASCII, excluding space.
func printableToken(val string) bool {
	if len(val) < 32 {
		return false
	}
	for i := 0; i < len(val); i++ {
		if val[i] < 0x21 || val[i] > 0x7E {
			return false
		}
	}
	return true
}

// matchNamedToken compares presented with every token. It hashes both sides
// so the compare length is fixed, and it does not return on the first match.
func matchNamedToken(presented string, tokens []namedToken) (string, bool) {
	got := sha256.Sum256([]byte(presented))
	var name string
	matched := 0
	for _, tok := range tokens {
		want := sha256.Sum256([]byte(tok.val))
		eq := subtle.ConstantTimeCompare(got[:], want[:])
		if eq == 1 && matched == 0 {
			name = tok.name
		}
		matched |= eq
	}
	return name, matched == 1
}

func (a *App) configuredTokens() []namedToken {
	if a == nil {
		return nil
	}
	var out []namedToken
	if a.cfg.AuthToken != "" {
		out = append(out, namedToken{name: defaultTokenName, val: a.cfg.AuthToken})
	}
	out = append(out, a.accessTokens...)
	return out
}

func (a *App) tokensConfigured() bool {
	return a != nil && (a.cfg.AuthToken != "" || len(a.accessTokens) > 0)
}

// authSecrets are token values that must not appear in a child environment.
func (a *App) authSecrets() []string {
	toks := a.configuredTokens()
	out := make([]string, 0, len(toks))
	for _, tok := range toks {
		if tok.val != "" {
			out = append(out, tok.val)
		}
	}
	return out
}
