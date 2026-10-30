//go:build linux

package permbroker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGolden_PeerDescendantOfRegisteredCLI(t *testing.T) {
	e := testEngine(t)
	e.NoteTurn("bot", "sess", "run", "task")
	helper := buildPeerHelper(t)
	payload := filepath.Join(t.TempDir(), "req.json")
	body, _ := json.Marshal(map[string]any{
		"op": "evaluate", "hook_event_name": "PreToolUse", "cwd": "/work",
		"tool_name": "Bash", "tool_input": map[string]string{"command": "git status"},
	})
	if err := os.WriteFile(payload, body, 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp("", "pb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	sock := filepath.Join(parent, "s")
	ln, err := e.Listen("bot", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	e.ClearHookIDs()
	if err := e.NoteHookFile(helper); err != nil {
		t.Fatal(err)
	}
	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	sleep := exec.Command(sleepBin, "30")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sleep.Process.Kill()
		_, _ = sleep.Process.Wait()
	})
	e.RegisterLaunch("bot", sleep.Process.Pid)
	unrelated := runPeer(t, helper, sock, payload)
	if unrelated.Verdict != VerdictDeny || !strings.Contains(unrelated.Reason, "permission broker unavailable") {
		t.Fatalf("unrelated %+v", unrelated)
	}
	if len(e.ListPending()) != 0 {
		t.Fatal("unrelated process reached the engine")
	}
	child := runPeerUnder(t, e, helper, sock, payload)
	if child.Verdict != VerdictDeny || !strings.Contains(child.Reason, "pending approval ") {
		t.Fatalf("descendant %+v", child)
	}
	if len(e.ListPending()) == 0 {
		t.Fatal("descendant did not reach the engine")
	}
}

func TestGolden_SocketPeerMustBeHookUnderBotCLI(t *testing.T) {
	e := testEngine(t)
	e.NoteTurn("bot", "sess", "run", "task")
	helper := buildPeerHelper(t)
	payload := filepath.Join(t.TempDir(), "req.json")
	body, _ := json.Marshal(map[string]any{
		"op": "evaluate", "hook_event_name": "PreToolUse", "cwd": "/work",
		"tool_name": "Bash", "tool_input": map[string]string{"command": "git status"},
	})
	if err := os.WriteFile(payload, body, 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.MkdirTemp("", "pb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	sock := filepath.Join(parent, "s")
	ln, err := e.Listen("bot", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	e.mu.Lock()
	e.tokens = append(e.tokens, token{
		BotID: "bot", SessionID: "sess", Tool: ToolShell,
		Hash: hashParts(ToolShell, []string{"git", "status"}), Cwd: "/work",
		Expires: e.now().Add(time.Hour),
	})
	e.mu.Unlock()

	sleepBin, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	sleep := exec.Command(sleepBin, "30")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sleep.Process.Kill()
		_, _ = sleep.Process.Wait()
	})
	e.ClearHookIDs()
	if err := e.NoteHookFile(sleepBin); err != nil {
		t.Fatal(err)
	}
	e.RegisterLaunch("bot", sleep.Process.Pid)
	foreign := runPeer(t, helper, sock, payload)
	if foreign.Verdict != VerdictDeny || !strings.Contains(foreign.Reason, "permission broker unavailable") {
		t.Fatalf("foreign %+v", foreign)
	}
	if len(e.ListPending()) != 0 {
		t.Fatal("foreign created a pending item")
	}
	e.mu.Lock()
	left := len(e.tokens)
	e.tokens = nil
	e.mu.Unlock()
	if left != 1 {
		t.Fatalf("token used: %d", left)
	}
	audit, err := os.ReadFile(filepath.Join(e.dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), "permission broker unavailable") {
		t.Fatalf("audit %s", audit)
	}

	e.ClearHookIDs()
	if err := e.NoteHookFile(helper); err != nil {
		t.Fatal(err)
	}
	allowed := runPeerUnder(t, e, helper, sock, payload)
	if allowed.Verdict != VerdictDeny || !strings.Contains(allowed.Reason, "pending approval ") {
		t.Fatalf("hook under cli %+v", allowed)
	}
	if len(e.ListPending()) == 0 {
		t.Fatal("registered hook did not reach the engine")
	}
}

func buildPeerHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module h\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package main
import (
  "io"
  "net"
  "os"
)
func main() {
  c, err := net.Dial("unix", os.Args[1])
  if err != nil { os.Stderr.WriteString(err.Error()); os.Exit(2) }
  f, err := os.Open(os.Args[2])
  if err != nil { os.Exit(2) }
  b, _ := io.ReadAll(f)
  f.Close()
  if _, err = c.Write(b); err != nil { os.Exit(2) }
  if uc, ok := c.(*net.UnixConn); ok { _ = uc.CloseWrite() }
  io.Copy(os.Stdout, c)
  c.Close()
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "h")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off")
	if buf, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, buf)
	}
	return out
}

func runPeer(t *testing.T, helper, sock, payload string) wireReply {
	t.Helper()
	cmd := exec.Command("sh", "-c", `read dummy; exec "$1" "$2" "$3"`, "sh", helper, sock, payload)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	if _, err := stdin.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	_ = cmd.Wait()
	var rep wireReply
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &rep); err != nil {
		t.Fatalf("reply %q: %v", out.String(), err)
	}
	return rep
}

func runPeerUnder(t *testing.T, e *Engine, helper, sock, payload string) wireReply {
	t.Helper()
	cmd := exec.Command("sh", "-c", `read dummy; exec "$1" "$2" "$3"`, "sh", helper, sock, payload)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	e.RegisterLaunch("bot", cmd.Process.Pid)
	if _, err := stdin.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	_ = cmd.Wait()
	var rep wireReply
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &rep); err != nil {
		t.Fatalf("reply %q: %v", out.String(), err)
	}
	return rep
}
