package daemon

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode"
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
// defaultToken, when set, occupies the name "default" and its value.
// The file is not modified.
func loadAuthTokens(path, defaultToken string) ([]namedToken, error) {
	if path == "" {
		return nil, nil
	}
	b, err := readAuthTokensFile(path)
	if err != nil {
		return nil, err
	}
	return parseAuthTokens(string(b), defaultToken)
}

// readAuthTokensFile opens path without following a symlink and refuses
// anything that is not a small, owner-only regular file.
func readAuthTokensFile(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errors.New("auth tokens: symlink")
		}
		if lst, lerr := os.Lstat(path); lerr == nil && lst.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("auth tokens: symlink")
		}
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("auth tokens: not a regular file")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("auth tokens: mode allows group or other access")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return nil, errors.New("auth tokens: owner mismatch")
	}
	if st.Size() > authTokensMax {
		return nil, errors.New("auth tokens: file exceeds 64 KiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, authTokensMax+1))
	if err != nil {
		return nil, fmt.Errorf("auth tokens: %w", err)
	}
	if int64(len(b)) > authTokensMax {
		return nil, errors.New("auth tokens: file exceeds 64 KiB")
	}
	return b, nil
}

func parseAuthTokens(text, defaultToken string) ([]namedToken, error) {
	seenName := map[string]struct{}{}
	seenVal := map[string]struct{}{}
	if defaultToken != "" {
		seenName[defaultTokenName] = struct{}{}
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
		if len(val) < 32 || strings.IndexFunc(val, unicode.IsSpace) >= 0 {
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
