//go:build linux

package sandbox

import (
	"os"
	"strings"
	"testing"
)

func TestGolden_UnshareFallbackNoProcWithoutPid(t *testing.T) {
	pid := false
	for _, arg := range unshareNamespaceArgs() {
		if arg == "--pid" || arg == "--mount-proc" {
			pid = true
		}
	}
	for _, m := range unshareFallbackMounts() {
		if m.Dst == "/proc" || m.Src == "/proc" {
			if !pid {
				t.Fatalf("proc mount %+v without a pid namespace", m)
			}
		}
		if m.Dst == "/dev" {
			t.Fatalf("full /dev mount %+v", m)
		}
	}
	// The plan above must match enterJail: it may not mount proc either.
	src, err := os.ReadFile("jail_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), `"proc"`) && !pid {
		t.Fatal("enterJail mounts proc without a pid namespace")
	}
	sawNull := false
	for _, m := range unshareFallbackMounts() {
		if m.Src == "/dev/null" && m.Dst == "/dev/null" {
			sawNull = true
		}
	}
	if !sawNull {
		t.Fatal("unshare fallback does not bind /dev/null")
	}
}
