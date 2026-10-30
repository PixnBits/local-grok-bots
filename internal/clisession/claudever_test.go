package clisession

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeVerClaude(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestClaudeBrokerVersionLine(t *testing.T) {
	ctx := context.Background()
	ok := writeVerClaude(t, "printf '%s\\n' '2.1.314 (Claude Code)'\n")
	if err := CheckClaudeBrokerVersion(ctx, ok); err != nil {
		t.Fatal(err)
	}
	spaced := writeVerClaude(t, "printf '%s\\n' '2.1.314 (Claude Code)   '\n")
	if err := CheckClaudeBrokerVersion(ctx, spaced); err != nil {
		t.Fatal(err)
	}
	refused := []struct {
		name string
		body string
	}{
		{name: "warning first", body: "printf '%s\\n' 'Warning: 3.0.0 x' '2.1.100 (Claude Code)'\n"},
		{name: "stderr only", body: "printf '%s\\n' '2.1.314 (Claude Code)' >&2\n"},
		{name: "nonzero", body: "printf '%s\\n' '2.1.314 (Claude Code)'\nexit 1\n"},
		{name: "v prefix", body: "printf '%s\\n' 'v2.1.400'\n"},
		{name: "beta", body: "printf '%s\\n' '2.1.295-beta'\n"},
		{name: "short", body: "printf '%s\\n' '2.1'\n"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			path := writeVerClaude(t, tc.body)
			err := CheckClaudeBrokerVersion(ctx, path)
			if err == nil || !strings.Contains(err.Error(), "version cannot be read") {
				t.Fatalf("%v", err)
			}
		})
	}
	old := writeVerClaude(t, "printf '%s\\n' '2.1.294 (Claude Code)'\n")
	err := CheckClaudeBrokerVersion(ctx, old)
	if err == nil || !strings.Contains(err.Error(), "2.1.294") {
		t.Fatalf("%v", err)
	}
}

func TestResolveLaunchPathUsesGivenPATH(t *testing.T) {
	newDir := t.TempDir()
	oldDir := t.TempDir()
	newBin := filepath.Join(newDir, "claude")
	oldBin := filepath.Join(oldDir, "claude")
	for _, path := range []string{newBin, oldBin} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", newDir)
	got, err := ResolveLaunchPath("claude", []string{"PATH=" + oldDir})
	if err != nil || got != oldBin {
		t.Fatalf("given PATH %s %v", got, err)
	}
	got, err = ResolveLaunchPath("claude", nil)
	if err != nil || got != newBin {
		t.Fatalf("process PATH %s %v", got, err)
	}
	got, err = ResolveLaunchPath(oldBin, []string{"PATH=" + newDir})
	if err != nil || got != oldBin {
		t.Fatalf("absolute %s %v", got, err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(wd, oldDir)
	if err != nil || filepath.IsAbs(rel) {
		t.Fatalf("rel %s %v", rel, err)
	}
	got, err = ResolveLaunchPath("claude", []string{"PATH=" + rel + string(os.PathListSeparator) + newDir})
	if err == nil || got != "" {
		t.Fatalf("relative candidate %s %v", got, err)
	}
	if spec := (Spec{}); len(LaunchEnv(spec)) == 0 {
		t.Fatal("nil isolate")
	}
	empty := LaunchEnv(Spec{Isolate: &Isolation{}})
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty isolate env %#v", empty)
	}
	gotEnv := LaunchEnv(Spec{Isolate: &Isolation{Env: []string{"PATH=" + oldDir}}})
	if len(gotEnv) != 1 || gotEnv[0] != "PATH="+oldDir {
		t.Fatalf("launch env %v", gotEnv)
	}
}
