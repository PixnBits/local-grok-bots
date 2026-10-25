package github

import (
	"errors"
	"os"
	"strings"
)

// ErrToken means the token file was refused. The error text never includes
// the token bytes.
var ErrToken = errors.New("github token refused")

type tokenError struct {
	reason string
}

func (e *tokenError) Error() string {
	if e == nil || e.reason == "" {
		return ErrToken.Error()
	}
	return ErrToken.Error() + ": " + e.reason
}

func (e *tokenError) Unwrap() error { return ErrToken }

func errToken(reason string) error {
	return &tokenError{reason: reason}
}

// tokenHook, when set, replaces the file read. Tests in this package set it.
// The returned token is still shape-checked. Hook errors are not forwarded,
// so a hook cannot put the token into an error string.
var tokenHook func(path string) (string, error)

// tokenCheck, when set, replaces the owner and mode decision. Symlink, type,
// size, and shape checks still run. Production leaves it nil.
var tokenCheck func(uid uint32, perm uint32) error

// tokenEUID is the daemon's effective uid. Tests replace it.
var tokenEUID = os.Geteuid

// tokenOwner is the file uid the owner check sees. Tests replace it.
var tokenOwner = func(uid uint32) uint32 { return uid }

// ReadToken reads a mode-0600 token file owned by the daemon's effective uid.
// A root daemon still requires a root-owned file. A symlink, any other owner,
// the wrong mode, or an unreadable file fails closed. The token is at most
// 4096 bytes. Trailing spaces, tabs, and newlines are removed. A leading or
// inner space, tab, or newline is refused.
func ReadToken(path string) (string, error) {
	if tokenHook != nil {
		tok, err := tokenHook(path)
		if err != nil {
			return "", ErrToken
		}
		if !TokenShape(tok) {
			return "", errToken("shape")
		}
		return tok, nil
	}
	return readTokenFile(path)
}

// checkTokenFile accepts a file only when its mode is exactly 0600 and its
// owner is the daemon's effective uid. A negative euid fails closed. A root
// daemon therefore still requires uid 0, and a non-root daemon refuses a
// root-owned file.
func checkTokenFile(owner, perm uint32) error {
	if perm != 0o600 {
		return errToken("mode")
	}
	id := tokenEUID()
	if id < 0 || uint32(id) != owner {
		return errToken("owner")
	}
	return nil
}

// TokenShape reports whether tok can be sent as a bearer token.
// It rejects empty values, newlines, and whitespace so the value cannot
// break a header or be confused with a sentence.
func TokenShape(tok string) bool {
	if tok == "" || len(tok) > 4096 {
		return false
	}
	if strings.ContainsAny(tok, " \t\r\n\x00") {
		return false
	}
	return true
}

// tokenFromBytes accepts a file body. Trailing spaces, tabs, CR, and LF are
// removed. Any leading or inner whitespace is a shape failure. The error
// never contains the bytes.
func tokenFromBytes(b []byte) (string, error) {
	if len(b) == 0 || len(b) > 4096 {
		return "", errToken("size")
	}
	s := strings.TrimRight(string(b), " \t\r\n")
	if strings.ContainsAny(s, " \t\r\n") || !TokenShape(s) {
		return "", errToken("shape")
	}
	return s, nil
}

// TokenFailureReason is a fixed audit phrase for a token read error.
// It never copies err.Error(), so a wrapped value cannot leak token bytes.
func TokenFailureReason(err error) string {
	var te *tokenError
	if err == nil || !errors.As(err, &te) {
		return "token"
	}
	switch te.reason {
	case "owner":
		return "token file: not owned by daemon"
	case "mode":
		return "mode"
	case "shape":
		return "shape"
	case "denied":
		return "permission denied"
	case "read", "path", "missing":
		return "missing"
	case "size":
		return "size"
	case "type":
		return "type"
	case "check":
		return "check"
	default:
		return "token"
	}
}

// TokenFailureBody is the 503 text for a token read error. It is a fixed
// phrase and never copies err.Error().
func TokenFailureBody(err error) string {
	return "github token unavailable: " + tokenBodyPhrase(err)
}

func tokenBodyPhrase(err error) string {
	var te *tokenError
	if err == nil || !errors.As(err, &te) {
		return "token"
	}
	switch te.reason {
	case "owner":
		return "not owned by daemon"
	case "denied":
		return "permission denied"
	case "read", "path", "missing":
		return "missing"
	case "mode", "shape", "size", "type", "check":
		return te.reason
	default:
		return "token"
	}
}
