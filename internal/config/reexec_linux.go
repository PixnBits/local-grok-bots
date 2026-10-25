//go:build linux

package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// secretPayload is the one-shot record on the pipe created for re-exec.
// AuthToken is a pointer so a missing field is distinct from an empty token.
type secretPayload struct {
	AuthToken  *string `json:"t"`
	Nonce      string  `json:"n"`
	TokensFile *string `json:"f,omitempty"`
}

// ReexecIfNeeded replaces this process once so /proc/self/environ no longer
// holds secrets read at startup. The token and a one-time nonce travel on a
// pipe this process created. The marker names that pipe. A preset marker
// without a matching payload exits instead of skipping the scrub.
func ReexecIfNeeded() {
	if raw := os.Getenv(readyKey); raw != "" {
		tok, file, err := readReadyAuth(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
			os.Exit(1)
		}
		heldAuth = tok
		heldTokensFile = file
		return
	}
	heldAuth = os.Getenv("AUTH_TOKEN")
	heldTokensFile = os.Getenv("AUTH_TOKENS_FILE")
	reexecWithAuth(heldAuth, heldTokensFile)
}

func reexecWithAuth(token, tokensFile string) {
	fail := func() {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
	r, w, err := os.Pipe()
	if err != nil {
		fail()
	}
	nonce, err := newNonce()
	if err != nil {
		fail()
	}
	payload := secretPayload{AuthToken: &token, TokensFile: &tokensFile, Nonce: nonce}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		fail()
	}
	if err := w.Close(); err != nil {
		fail()
	}
	fd := int(r.Fd())
	// Leave the pipe on the fd the runtime assigned. Clearing close-on-exec
	// lets syscall.Exec keep it. Dup onto fd 3 would clobber whatever is there.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		fail()
	}
	exe, err := os.Executable()
	if err != nil {
		fail()
	}
	argv := append([]string{exe}, os.Args[1:]...)
	env := scrubbedEnvironMarker(os.Environ(), token, nonce+"."+strconv.Itoa(fd))
	if err := syscall.Exec(exe, argv, env); err != nil {
		fail()
	}
}

func newNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func readReadyAuth(marker string) (string, string, error) {
	nonce, fd, err := parseReadyMarker(marker)
	if err != nil {
		return "", "", err
	}
	f := os.NewFile(uintptr(fd), "env")
	if f == nil {
		return "", "", errors.New("missing env pipe")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !pipeOrMemfd(fd, st) {
		return "", "", errors.New("env pipe is not a pipe")
	}
	var p secretPayload
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err := dec.Decode(&p); err != nil {
		return "", "", err
	}
	if p.AuthToken == nil {
		return "", "", errors.New("token missing")
	}
	if subtle.ConstantTimeCompare([]byte(p.Nonce), []byte(nonce)) != 1 {
		return "", "", errors.New("nonce mismatch")
	}
	file := ""
	if p.TokensFile != nil {
		file = *p.TokensFile
	}
	return *p.AuthToken, file, nil
}

func parseReadyMarker(raw string) (string, int, error) {
	nonce, fdText, ok := strings.Cut(raw, ".")
	if !ok || len(nonce) != 32 || fdText == "" {
		return "", 0, errors.New("marker is not ready")
	}
	for _, c := range nonce {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return "", 0, errors.New("marker is not ready")
		}
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < 3 || fd > 1<<20 {
		return "", 0, errors.New("marker is not ready")
	}
	return nonce, fd, nil
}

func pipeOrMemfd(fd int, st os.FileInfo) bool {
	if st == nil {
		return false
	}
	if st.Mode()&os.ModeNamedPipe != 0 {
		return true
	}
	if !st.Mode().IsRegular() {
		return false
	}
	link, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	return err == nil && strings.Contains(link, "memfd:")
}
