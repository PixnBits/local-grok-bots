package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stdinJSON(cmd string) string {
	b, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess",
		"cwd":             "/work",
		"tool_name":       "Bash",
		"tool_input":      map[string]string{"command": cmd},
		"tool_use_id":     "toolu_test",
	})
	if err != nil {
		panic(err)
	}
	return string(b)
}

func runHook(args []string, stdin string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func assertDeny(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if code != 2 {
		t.Fatalf("exit %d, want 2\nstdout %s\nstderr %s", code, stdout, stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout json: %v %s", err, stdout)
	}
	hook, _ := doc["hookSpecificOutput"].(map[string]any)
	if hook["permissionDecision"] != "deny" || hook["hookEventName"] != "PreToolUse" {
		t.Fatalf("stdout %+v", doc)
	}
	if strings.TrimSpace(stderr) == "" {
		t.Fatal("stderr reason empty")
	}
}

func TestGolden_DaemonStopped(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "no-such.sock")
	code, stdout, stderr := runHook([]string{sock}, stdinJSON("echo hi"))
	assertDeny(t, code, stdout, stderr)
}

func TestGolden_DaemonHangPastDeadline(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "hang.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	start := time.Now()
	code, stdout, stderr := runHook([]string{sock}, stdinJSON("echo hi"))
	elapsed := time.Since(start)
	assertDeny(t, code, stdout, stderr)
	if elapsed >= 10*time.Second {
		t.Fatalf("hook returned in %s, want well under the 30s settings timeout", elapsed)
	}
}

func TestGolden_GarbageEmptyUnknownOversizedVerdict(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"garbage", "this is not json"},
		{"empty", "{}"},
		{"unknown", `{"verdict":"ask","reason":"no"}`},
		{"wrong-case", `{"verdict":"ALLOW","reason":"no"}`},
		{"extra", `{"verdict":"allow","reason":"no","extra":true}`},
		{"oversized", strings.Repeat("x", maxReply+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "s.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
				_, _ = c.Write([]byte(tc.body))
			}()
			code, stdout, stderr := runHook([]string{sock}, stdinJSON("echo hi"))
			assertDeny(t, code, stdout, stderr)
		})
	}
}

func TestHookAllowsOnlyExactAllow(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
		_, _ = c.Write([]byte(`{"verdict":"allow","reason":"approved"}`))
	}()
	code, stdout, stderr := runHook([]string{sock}, stdinJSON("echo hi"))
	if code != 0 {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if !strings.Contains(stdout, `"permissionDecision":"allow"`) {
		t.Fatalf("stdout %s", stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("allow wrote stderr %q", stderr)
	}
}

func TestHookRejectsBadInvocation(t *testing.T) {
	code, stdout, stderr := runHook(nil, stdinJSON("echo hi"))
	assertDeny(t, code, stdout, stderr)
	code, stdout, stderr = runHook([]string{"relative.sock"}, stdinJSON("echo hi"))
	assertDeny(t, code, stdout, stderr)
	code, stdout, stderr = runHook([]string{"/tmp/a.sock", "extra"}, stdinJSON("echo hi"))
	assertDeny(t, code, stdout, stderr)
}
