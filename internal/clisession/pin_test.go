package clisession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestPinHashMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("#!/bin/sh\necho ok\n"))
	good := hex.EncodeToString(sum[:])
	pol := policy.Policy{Pins: []policy.Pin{{Path: bin, SHA256: good}}}
	if err := verifyPin(context.Background(), pol, "claude", bin); err != nil {
		t.Fatal(err)
	}
	pol.Pins[0].SHA256 = hex.EncodeToString(make([]byte, 32))
	if err := verifyPin(context.Background(), pol, "claude", bin); err == nil {
		t.Fatal("expected hash mismatch")
	}
}
