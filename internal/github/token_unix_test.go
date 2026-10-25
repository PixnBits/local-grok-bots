//go:build unix

package github

import (
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
	for _, err := range []error{unix.EACCES, unix.EPERM} {
		if TokenFailureReason(ioTokenReason(err)) != "permission denied" {
			t.Fatalf("%v -> %s", err, TokenFailureReason(ioTokenReason(err)))
		}
		if TokenFailureBody(ioTokenReason(err)) != "github token unavailable: permission denied" {
			t.Fatalf("body %s", TokenFailureBody(ioTokenReason(err)))
		}
	}
	if TokenFailureReason(ioTokenReason(unix.EIO)) != "missing" {
		t.Fatal("generic read")
	}
}
