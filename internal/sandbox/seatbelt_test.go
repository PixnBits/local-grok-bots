package sandbox

import (
	"strings"
	"testing"
)

func TestSeatbeltProfileDefaults(t *testing.T) {
	prof, err := seatbeltProfile(seatbeltSpec{Workspace: "/Users/a/ws", Tmp: "/private/var/folders/x/T/lgb-prep-1/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)\n(deny default)\n",
		`(allow file-read* file-write* (subpath "/Users/a/ws") (subpath "/private/var/folders/x/T/lgb-prep-1/tmp"))`,
		`(deny file-write* (regex #"^/Users/a/ws/(.*/)?\.git/hooks(/|$)"))`,
	} {
		if !strings.Contains(prof, want) {
			t.Fatalf("profile missing %q:\n%s", want, prof)
		}
	}
	if strings.Contains(prof, "network") {
		t.Fatalf("network allowed without grant:\n%s", prof)
	}
	if strings.Index(prof, "(deny file-write* (regex") < strings.Index(prof, "(allow file-read* file-write*") {
		t.Fatal("hooks deny must follow the workspace allow")
	}
	if strings.Contains(prof, `(subpath "/private/etc")`) || strings.Contains(prof, `"/Users"`) {
		t.Fatalf("profile opens host config or home:\n%s", prof)
	}
}

func TestSeatbeltProfileNetAndReadOnly(t *testing.T) {
	prof, err := seatbeltProfile(seatbeltSpec{Workspace: "/w", Tmp: "/t", ReadOnly: []string{"/opt/sdk"}, AllowNet: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, "(allow network-outbound)") {
		t.Fatalf("net grant not applied:\n%s", prof)
	}
	if !strings.Contains(prof, `(allow file-read* (subpath "/opt/sdk"))`) {
		t.Fatalf("read-only bind missing:\n%s", prof)
	}
	if strings.Contains(prof, `file-write* (subpath "/opt/sdk")`) {
		t.Fatal("read-only bind is writable")
	}
}

func TestSeatbeltProfileQuoting(t *testing.T) {
	prof, err := seatbeltProfile(seatbeltSpec{Workspace: `/w/a"b\c.d+`, Tmp: "/t"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(prof, `(subpath "/w/a\"b\\c.d+")`) {
		t.Fatalf("string not escaped:\n%s", prof)
	}
	if !strings.Contains(prof, `#"^/w/a\"b\\c\.d\+/(.*/)?`) {
		t.Fatalf("regex not escaped:\n%s", prof)
	}
}

func TestSeatbeltProfileRejectsBadPaths(t *testing.T) {
	for _, s := range []seatbeltSpec{
		{Workspace: "rel", Tmp: "/t"},
		{Workspace: "/w/../etc", Tmp: "/t"},
		{Workspace: "/w\n(allow default)", Tmp: "/t"},
		{Workspace: "/", Tmp: "/t"},
		{Workspace: "/w", Tmp: "/t", ReadOnly: []string{"x"}},
	} {
		if _, err := seatbeltProfile(s); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}
