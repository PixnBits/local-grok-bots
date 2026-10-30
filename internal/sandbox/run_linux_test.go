//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCommandArgvStaysShellWhenNotDropped(t *testing.T) {
	got := commandArgv("printf ok")
	uid, _ := JailIDs()
	if jailDrops(uid) {
		if len(got) != 5 || got[0] != "/bin/sh" || got[1] != "-c" || got[3] != "sh" || got[4] != "printf ok" {
			t.Fatalf("argv %q", got)
		}
		if strings.Contains(got[2], "printf ok") {
			t.Fatal("command was placed in the shell script")
		}
		if !strings.Contains(got[2], "/usr/bin/setpriv") || !strings.Contains(got[2], "--reuid=") {
			t.Fatalf("script %q", got[2])
		}
		return
	}
	want := []string{"/bin/sh", "-c", "printf ok"}
	if len(got) != len(want) {
		t.Fatalf("argv %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv %q", got)
		}
	}
	if strings.Contains(strings.Join(got, " "), "setpriv") {
		t.Fatalf("argv %q", got)
	}
}

func TestDroppedArgvKeepsCommandApart(t *testing.T) {
	const marker = "marker-not-in-script"
	got := droppedArgv(65534, 65534, marker, false)
	if len(got) != 5 || got[4] != marker {
		t.Fatalf("argv %q", got)
	}
	if strings.Contains(got[2], marker) {
		t.Fatal("command was placed in the shell script")
	}
	if !strings.Contains(got[2], "--reuid=65534") || !strings.Contains(got[2], "--regid=65534") {
		t.Fatalf("script %q", got[2])
	}
	if !strings.Contains(got[2], "max_user_namespaces") {
		t.Fatalf("script %q", got[2])
	}
}

func TestRootWithoutBwrapRefusesShell(t *testing.T) {
	prevE, prevL := EUID, LookPath
	t.Cleanup(func() { EUID, LookPath = prevE, prevL })

	EUID = func() int { return 0 }
	LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "", errors.New("not found")
		}
		return exec.LookPath(name)
	}
	ws := t.TempDir()
	_, _, err := launch(context.Background(), &prepared{workspace: ws, command: "git status", dir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "shell sandbox unavailable: root requires bwrap") {
		t.Fatalf("launch %v", err)
	}
	res, err := Run(context.Background(), Request{
		Workspace: ws,
		Command:   "git status",
		Grants:    []string{"git", "github"},
	})
	if err == nil || !strings.Contains(err.Error(), "shell sandbox unavailable: root requires bwrap") {
		t.Fatalf("run_shell %v", err)
	}
	if res.Stdout != "" || res.Stderr != "" || len(res.Events) != 0 {
		t.Fatalf("git and github grants ran: %#v", res)
	}

	LookPath = func(name string) (string, error) {
		if name == "bwrap" {
			return "/usr/bin/bwrap", nil
		}
		return "", errors.New("not found")
	}
	if msg := RootJailWarning(); msg != "" {
		t.Fatalf("root with bwrap refused: %s", msg)
	}

	EUID = func() int { return 1000 }
	LookPath = func(string) (string, error) { return "", errors.New("not found") }
	if msg := RootJailWarning(); msg != "" {
		t.Fatalf("non-root refused: %s", msg)
	}
}

func TestRemountFailureIsFatal(t *testing.T) {
	prev := mountCall
	t.Cleanup(func() { mountCall = prev })
	mountCall = func(src, dst, fstype string, flags uintptr, data string) error {
		if flags&unix.MS_REMOUNT != 0 {
			return errors.New("rejected")
		}
		return nil
	}
	if err := bindReadOnly("/bin", "/jail/bin"); err == nil || !strings.Contains(err.Error(), "remount") {
		t.Fatalf("host remount %v", err)
	}
	jail := t.TempDir()
	src := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := bindIntoJail(jail, mount{Src: src, Dst: "/lgb/bin/git", RO: true})
	if err == nil || !strings.Contains(err.Error(), "remount") {
		t.Fatalf("file remount %v", err)
	}
	mountCall = func(string, string, string, uintptr, string) error { return nil }
	if err := remountReadOnly("/jail/usr", true); err != nil {
		t.Fatal(err)
	}
}

func TestIDMapIncludesJailUser(t *testing.T) {
	if idMapBody(0) != "0 0 1\n" {
		t.Fatalf("root map %q", idMapBody(0))
	}
	if idMapBody(65534) != "0 0 1\n65534 65534 1\n" {
		t.Fatalf("overflow map %q", idMapBody(65534))
	}
	if idMapBody(-1) != "" {
		t.Fatal("negative id mapped")
	}
	pid, err := childPID([]byte("{\n    \"child-pid\": 42,\n    \"user-namespace\": 7\n}\n"))
	if err != nil || pid != 42 {
		t.Fatalf("pid %d %v", pid, err)
	}
	if _, err := childPID([]byte("{\"child-pid\": 1}")); err == nil {
		t.Fatal("pid 1 accepted")
	}
	if _, err := childPID([]byte("nope")); err == nil {
		t.Fatal("bad info accepted")
	}
}
