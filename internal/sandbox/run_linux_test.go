//go:build linux

package sandbox

import (
	"strings"
	"testing"
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
	got := droppedArgv(65534, 65534, marker)
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
