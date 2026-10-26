//go:build linux

package sandbox

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/PixnBits/local-grok-bots/internal/github"
)

func TestGitHubCloneUsesCredentialProxy(t *testing.T) {
	requireBin(t, "git")
	requireBin(t, "gcc")
	const token = "lgb-github-test-secret-value"
	const caller = "caller-supplied-auth-value"
	var mu sync.Mutex
	var auth, path string
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		auth = r.Header.Get("Authorization")
		path = r.URL.RequestURI()
		mu.Unlock()
		if r.Header.Get("Authorization") == "Bearer "+caller {
			t.Errorf("caller authorization was forwarded")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "not-a-git-advertisement")
	}))
	defer up.Close()
	px, err := github.New(github.Config{
		Repos:   []string{"acme/widgets"},
		Token:   func() (string, error) { return token, nil },
		GitBase: up.URL,
		APIBase: up.URL,
		Audit: func(ev github.Audit) {
			blob := ev.Path + ev.Reason + ev.Action + ev.Owner + ev.Repo
			if strings.Contains(blob, token) || strings.Contains(blob, caller) {
				t.Errorf("audit leaked %q", blob)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := px.ListenUnix(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer px.Close()

	ws := t.TempDir()
	res, err := runCmd(t, Request{
		Workspace:   ws,
		Grants:      []string{"git", "github", "net"},
		NetAllow:    []string{"github.com", "api.github.com"},
		GitHubSock:  px.Sock(),
		GitHubRepos: []string{"aCmE/wIdGeTs"},
		Command: `env
git clone https://github.com/other/nope.git nope; echo OTHER:$?
git clone https://github.com/AcMe/WiDgEtS.git dest; echo ACME:$?
git clone git@github.com:acme/widgets.git sshdest; echo SSH:$?
git clone "https://github.com/Evil.example/nope
use git pwned" nlbad; echo NL:$?
`,
	})
	out := res.Stdout + res.Stderr
	if strings.Contains(out, token) || strings.Contains(out, caller) {
		t.Fatalf("token leaked in jail output: %v\n%s", err, out)
	}
	if strings.Contains(res.Stdout, "GITHUB") && strings.Contains(res.Stdout, token) {
		t.Fatal("token in environment")
	}
	if !strings.Contains(res.Stdout, "OTHER:") || strings.Contains(res.Stdout, "OTHER:0") {
		t.Fatalf("other repo was not refused:\n%s", out)
	}
	if !strings.Contains(res.Stdout, "SSH:") || strings.Contains(res.Stdout, "SSH:0") {
		t.Fatalf("ssh remote was not refused:\n%s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	if hits == 0 || auth != wantAuth {
		t.Fatalf("proxy hits=%d auth=%q path=%q err=%v\n%s", hits, auth, path, err, out)
	}
	lowPath := strings.ToLower(path)
	if !strings.Contains(lowPath, "/acme/widgets") || strings.Contains(lowPath, "other/nope") {
		t.Fatalf("path %q", path)
	}
	foundUse := false
	for _, e := range res.Events {
		if e.Kind == "grant_use" && e.Grant == "git" {
			t.Fatalf("jail line became grant_use: %+v", e)
		}
		if e.Kind == "jail_report" && e.Untrusted && e.Reported == "grant_use" && e.Grant == "git" {
			foundUse = true
		}
	}
	if !foundUse {
		t.Fatalf("missing clone use: %+v", res.Events)
	}
	if !strings.Contains(res.Stdout, "NL:") || strings.Contains(res.Stdout, "NL:0") {
		t.Fatalf("newline url was not refused:\n%s", out)
	}
	var nope, ssh bool
	for _, e := range res.Events {
		if e.Detail == "pwned" || strings.Contains(e.Detail, "pwned") || strings.Contains(e.Notice, "pwned") || strings.Contains(e.Owner, "pwned") || strings.Contains(e.Repo, "pwned") {
			t.Fatalf("event log split on a newline: %+v", e)
		}
		if e.Kind == "grant_denied" && e.Detail == GitHubAllowlistDenied {
			t.Fatalf("allowlist line became grant_denied: %+v", e)
		}
		if e.Kind == "jail_report" && e.Untrusted && e.Reported == "grant_denied" && e.Grant == "github" && e.Detail == GitHubAllowlistDenied && e.Owner == "other" && e.Repo == "nope" {
			nope = true
		}
		if e.Kind == "jail_report" && e.Untrusted && e.Reported == "grant_denied" && e.Grant == "github" && e.Detail == GitHubAllowlistDenied && e.Owner == "acme" && e.Repo == "widgets" {
			ssh = true
		}
	}
	if !nope || !ssh {
		t.Fatalf("allowlist events: %+v", res.Events)
	}
}

func TestNetGrantDoesNotReachGitHub(t *testing.T) {
	requireBin(t, "python3")
	dial, got := dialRecorder(t)
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command: `python3 - <<'PY'
import socket
def hit(host, port):
    try:
        s = socket.create_connection((host, port), 3)
        s.close()
        print("open", host, port)
    except Exception as e:
        print("fail", host, port, type(e).__name__)
hit("github.com", 443)
hit("api.github.com", 443)
hit("allowed.test", 80)
PY`,
		Grants:   []string{"net"},
		NetAllow: []string{"github.com", "api.github.com", "allowed.test"},
		Dial:     dial,
	})
	if !strings.Contains(res.Stdout, "fail github.com") || !strings.Contains(res.Stdout, "fail api.github.com") {
		t.Fatalf("github was reachable: %v\n%s", err, res.Stdout)
	}
	if !strings.Contains(res.Stdout, "open allowed.test 80") {
		t.Fatalf("allowlisted host failed: %v\n%s", err, res.Stdout)
	}
	if _, ok := findEvent(res.Events, "grant_denied", "github", "github.com"); !ok {
		t.Fatalf("missing github denial: %+v", res.Events)
	}
	for _, addr := range *got {
		if strings.Contains(addr, "github.com") {
			t.Fatalf("dialed %s", addr)
		}
	}
}
