//go:build linux

package clisession

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodedPermissionIsReadOnlyOverSessions(t *testing.T) {
	user := t.TempDir()
	state := t.TempDir()
	home := filepath.Join(state, "home")
	ws := t.TempDir()
	iso, err := PrepareIsolation(IsolationOptions{
		Backend: "grok", StateDir: state, Home: home, UserHome: user, Workspace: ws,
	})
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(ws, "grok")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	args, err := grokBwrapArgs(bin, []string{"agent"}, Spec{Workspace: ws, Isolate: &iso})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, "\n")
	var gh string
	for _, e := range iso.Env {
		if strings.HasPrefix(e, "GROK_HOME=") {
			gh = strings.TrimPrefix(e, "GROK_HOME=")
		}
	}
	perm := filepath.Join(gh, "sessions", url.PathEscape(ws), "permission.toml")
	sess := filepath.Join(gh, "sessions")
	sessAt := strings.Index(joined, "--bind\n"+sess+"\n"+sess)
	permAt := strings.Index(joined, "--ro-bind\n"+perm+"\n"+perm)
	if sessAt < 0 || permAt < 0 || permAt < sessAt {
		t.Fatalf("sessions %d permission %d", sessAt, permAt)
	}
	st, err := os.Stat(perm)
	if err != nil || st.Size() != 0 {
		t.Fatalf("placeholder %v %v", st, err)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	if !strings.Contains(joined, "--ro-bind\n"+gitconfig+"\n"+gitconfig) {
		t.Fatal("home seal missing")
	}
}
