package sandbox

import (
	"os"
	"testing"
)

func TestOwnPathRefusesWorldWritable(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o777, 0o002, 0o022, 0o752} {
		if err := OwnPath(dir, mode); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o002 != 0 {
		t.Fatalf("mode changed to %o", st.Mode().Perm())
	}
}

func TestOwnPathUsesJailIDs(t *testing.T) {
	dir := t.TempDir()
	var got string
	var uid, gid int
	oldC, oldE := Chown, EUID
	Chown = func(path string, u, g int) error {
		got, uid, gid = path, u, g
		return nil
	}
	EUID = func() int { return 0 }
	t.Cleanup(func() { Chown, EUID = oldC, oldE })
	if err := OwnPath(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o750 || st.Mode().Perm()&0o002 != 0 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	wantU, wantG := JailIDs()
	if got != dir || uid != wantU || gid != wantG {
		t.Fatalf("chown %s %d:%d want %s %d:%d", got, uid, gid, dir, wantU, wantG)
	}
}

func TestOwnPathSkipsChownWhenNotRoot(t *testing.T) {
	dir := t.TempDir()
	called := false
	oldC, oldE := Chown, EUID
	Chown = func(string, int, int) error {
		called = true
		return nil
	}
	EUID = func() int { return 1000 }
	t.Cleanup(func() { Chown, EUID = oldC, oldE })
	for _, mode := range []os.FileMode{0o700, 0o750} {
		if err := OwnPath(dir, mode); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode || st.Mode().Perm()&0o002 != 0 {
			t.Fatalf("mode %o", st.Mode().Perm())
		}
	}
	if called {
		t.Fatal("chown called")
	}
}
