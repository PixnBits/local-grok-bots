//go:build linux

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type secretPayload struct {
	AuthToken string `json:"t"`
}

// ReexecIfNeeded replaces this process once so /proc/self/environ no longer
// holds secrets read at startup. The token is passed on fd 3.
func ReexecIfNeeded() {
	if os.Getenv(readyKey) == readyVal {
		heldAuth = readAuthFromFD()
		return
	}
	heldAuth = os.Getenv("AUTH_TOKEN")
	reexecWithAuth(heldAuth)
}

func reexecWithAuth(token string) {
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
	if err := json.NewEncoder(w).Encode(secretPayload{AuthToken: token}); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
	_ = w.Close()
	src := int(r.Fd())
	if err := unix.Dup3(src, secretFD, 0); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
	if src != secretFD {
		_ = r.Close()
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
	argv := append([]string{exe}, os.Args[1:]...)
	env := scrubbedEnviron(os.Environ(), token)
	if err := syscall.Exec(exe, argv, env); err != nil {
		fmt.Fprintln(os.Stderr, "local-grok-bots: cannot scrub environment")
		os.Exit(1)
	}
}

func readAuthFromFD() string {
	f := os.NewFile(uintptr(secretFD), "env")
	if f == nil {
		return ""
	}
	defer f.Close()
	var p secretPayload
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err := dec.Decode(&p); err != nil {
		return ""
	}
	return p.AuthToken
}
