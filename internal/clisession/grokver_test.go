package clisession

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/policy"
)

func TestGrokVersionAllowList(t *testing.T) {
	if allowedGrokVersions != "1.0.52,1.0.62" {
		t.Fatal(allowedGrokVersions)
	}
	for _, v := range []string{"1.0.52", "1.0.62"} {
		if !grokVersionAllowed(v) {
			t.Fatal(v)
		}
	}
	for _, v := range []string{"", "1.0.53", "1.0.520", "1.0.5", "9.9.9"} {
		if grokVersionAllowed(v) {
			t.Fatal(v)
		}
	}
	got := grokVersionToken("grok 1.0.62 (abc) [stable]\n")
	if got != "1.0.62" {
		t.Fatal(got)
	}
	if grokVersionToken("grok 1.0.520\n") != "1.0.520" {
		t.Fatal(grokVersionToken("grok 1.0.520\n"))
	}
	if grokVersionToken("no version here") != "" {
		t.Fatal("token")
	}
}

func TestGrokVersionRefusesBeforeStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grok")
	body := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo grok 9.9.9; exit 0; fi\necho should-not-run\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := (ExecRunner{}).Run(context.Background(), Spec{
		Backend: "grok", Bin: path, Prompt: "hi", Workspace: t.TempDir(),
		Isolate: &Isolation{GrokSandbox: GrokProfile},
	}, nil)
	var ve *VersionError
	if !errors.As(err, &ve) || ve.Version != "9.9.9" {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "9.9.9") || strings.Contains(err.Error(), "should-not-run") {
		t.Fatalf("error text %q", err.Error())
	}
}

func TestVersionHashBeforeProbe(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grok")
	stamp := filepath.Join(dir, "stamp")
	body := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo probed > \"" + stamp + "\"; echo grok 1.0.62; exit 0; fi\necho should-not-run\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := hashFile(path)
	if err != nil || sum == "" {
		t.Fatal(err)
	}
	_, err = (ExecRunner{Policy: policy.Policy{Pins: []policy.Pin{{
		Backend: "grok", Path: path, SHA256: "deadbeef",
	}}}}).Run(context.Background(), Spec{
		Backend: "grok", Bin: path, Prompt: "hi", Workspace: t.TempDir(),
		Isolate: &Isolation{GrokSandbox: GrokProfile},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "cli pin: grok hash mismatch") {
		t.Fatalf("%v", err)
	}
	if _, statErr := os.Stat(stamp); !os.IsNotExist(statErr) {
		t.Fatal(statErr)
	}
	_, err = (ExecRunner{Policy: policy.Policy{Pins: []policy.Pin{{
		Backend: "grok", Path: path, SHA256: sum,
	}}}}).Run(context.Background(), Spec{
		Backend: "grok", Bin: path, Prompt: "hi", Workspace: t.TempDir(),
		Isolate: &Isolation{GrokSandbox: GrokProfile},
	}, nil)
	if _, statErr := os.Stat(stamp); statErr != nil {
		t.Fatal(statErr)
	}
	if err != nil && strings.Contains(err.Error(), "hash mismatch") {
		t.Fatal(err)
	}
}
