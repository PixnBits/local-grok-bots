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
	old := Chown
	Chown = func(path string, u, g int) error {
		got, uid, gid = path, u, g
		return nil
	}
	t.Cleanup(func() { Chown = old })
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

func TestOwnPathSkipsHostChownWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root calls the host chown")
	}
	dir := t.TempDir()
	if err := OwnPath(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}
