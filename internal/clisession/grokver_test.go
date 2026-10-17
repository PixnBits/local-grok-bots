package clisession

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
