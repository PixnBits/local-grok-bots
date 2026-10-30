//go:build linux

package sandbox

import "testing"

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
