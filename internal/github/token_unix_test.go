//go:build unix

package github

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIOTokenReason(t *testing.T) {
	if TokenFailureReason(ioTokenReason(unix.ENOENT)) != "missing" {
		t.Fatal(TokenFailureReason(ioTokenReason(unix.ENOENT)))
	}
	if TokenFailureBody(ioTokenReason(unix.ENOENT)) != "github token unavailable: missing" {
		t.Fatal(TokenFailureBody(ioTokenReason(unix.ENOENT)))
	}
	if TokenFailureReason(ioTokenReason(unix.ENOTDIR)) != "missing" {
		t.Fatal(TokenFailureReason(ioTokenReason(unix.ENOTDIR)))
	}
	if TokenFailureBody(ioTokenReason(unix.ENOTDIR)) != "github token unavailable: missing" {
		t.Fatal(TokenFailureBody(ioTokenReason(unix.ENOTDIR)))
	}
	for _, err := range []error{unix.EACCES, unix.EPERM} {
		if TokenFailureReason(ioTokenReason(err)) != "permission denied" {
			t.Fatalf("%v -> %s", err, TokenFailureReason(ioTokenReason(err)))
		}
		if TokenFailureBody(ioTokenReason(err)) != "github token unavailable: permission denied" {
			t.Fatalf("body %s", TokenFailureBody(ioTokenReason(err)))
		}
	}
	for _, err := range []error{unix.EIO, unix.EAGAIN} {
		if TokenFailureReason(ioTokenReason(err)) != "read error" {
			t.Fatalf("%v -> %s", err, TokenFailureReason(ioTokenReason(err)))
		}
		if TokenFailureBody(ioTokenReason(err)) != "github token unavailable: read error" {
			t.Fatalf("body %s", TokenFailureBody(ioTokenReason(err)))
		}
	}
}

func TestReadTokenOtherOwnerModeIsOwner(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	prevEUID, prevOwner := tokenEUID, tokenOwner
	t.Cleanup(func() {
		tokenCheck, tokenHook = prevCheck, prevHook
		tokenEUID, tokenOwner = prevEUID, prevOwner
	})
	tokenCheck, tokenHook = nil, nil
	tokenEUID = func() int { return 1000 }
	tokenOwner = func(uint32) uint32 { return 1001 }

	path := filepath.Join(t.TempDir(), "token")
	const body = "ghp_examplesecretvalue\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := readTokenFile(path)
	if TokenFailureReason(err) != "token file: not owned by daemon" {
		t.Fatalf("reason %q err %v", TokenFailureReason(err), err)
	}
	if strings.Contains(err.Error(), "ghp_examplesecretvalue") || strings.Contains(err.Error(), "mode") {
		t.Fatal(err)
	}
}

func TestReadTokenCheckSeamSkipsOwner(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	prevEUID, prevOwner := tokenEUID, tokenOwner
	t.Cleanup(func() {
		tokenCheck, tokenHook = prevCheck, prevHook
		tokenEUID, tokenOwner = prevEUID, prevOwner
	})
	tokenHook = nil
	tokenEUID = func() int { return 1000 }
	tokenOwner = func(uint32) uint32 { return 1001 }
	tokenCheck = func(uint32, uint32) error { return nil }

	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("ghp_examplesecretvalue\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readTokenFile(path)
	if err != nil || got != "ghp_examplesecretvalue" {
		t.Fatalf("%q %v", got, err)
	}
}
