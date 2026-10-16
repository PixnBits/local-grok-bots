package coi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckArgsAllowAndBlock(t *testing.T) {
	ws := t.TempDir()
	cred := filepath.Join(t.TempDir(), "creds")
	if err := os.Mkdir(cred, 0o700); err != nil {
		t.Fatal(err)
	}
	allow := []string{"edit", "--model", "-p", "--print-config", "--debug"}
	valueFlags := []string{"-p", "--model"}
	ok := [][]string{
		{"edit", "main.go"},
		{"edit", "src/main.go"},
		{"-p", "fix the bug"},
		{"--model", "grok-4", "edit"},
	}
	for _, args := range ok {
		if err := CheckArgs(allow, args, ws, cred, valueFlags); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	blocked := [][]string{
		{"config"},
		{"auth"},
		{"login"},
		{"logout"},
		{"whoami"},
		{"token"},
		{"env"},
		{"--print-config"},
		{"--debug"},
		{"--token", "x"},
		{"edit", "--config"},
		{"edit", cred + "/auth.json"},
		{"-p", "see " + cred},
		{"edit", "/etc/passwd"},
		{"edit", "../outside"},
		{"edit", "~/.ssh"},
		{"-abc"},
		{"--model"},
	}
	// --model alone is allowlisted, so it is not in the deny list. The last
	// entry is replaced below. Keep the deny list free of allowed calls.
	blocked = blocked[:len(blocked)-1]
	wants := []error{
		ErrBlocked, ErrBlocked, ErrBlocked, ErrBlocked, ErrBlocked, ErrBlocked, ErrBlocked,
		ErrBlocked, ErrBlocked, ErrBlocked, ErrBlocked,
		ErrCredHome, ErrCredHome,
		ErrOutside, ErrOutside, ErrOutside,
		ErrNotAllowed,
	}
	if len(blocked) != len(wants) {
		t.Fatalf("cases %d wants %d", len(blocked), len(wants))
	}
	for i, args := range blocked {
		err := CheckArgs(allow, args, ws, cred, valueFlags)
		if !errors.Is(err, wants[i]) {
			t.Fatalf("%v: got %v want %v", args, err, wants[i])
		}
	}
	if err := CheckArgs(nil, []string{"edit"}, ws, cred, nil); !errors.Is(err, ErrNoArgs) {
		t.Fatalf("empty allowlist: %v", err)
	}
	if err := CheckArgs(allow, nil, ws, cred, valueFlags); !errors.Is(err, ErrNoArgs) {
		t.Fatalf("no args: %v", err)
	}
	outside := filepath.Join(ws, "escape")
	if err := os.Symlink(cred, outside); err != nil {
		t.Fatal(err)
	}
	if err := CheckArgs(allow, []string{"edit", "./escape"}, ws, cred, valueFlags); !errors.Is(err, ErrOutside) && !errors.Is(err, ErrCredHome) {
		t.Fatalf("symlink: %v", err)
	}
}

func TestCheckArgsTreatsBareNamesAsPaths(t *testing.T) {
	root := t.TempDir()
	ws := filepath.Join(root, "ws")
	cred := filepath.Join(root, "cred")
	coiDir := filepath.Join(root, "data", "coi")
	outside := filepath.Join(root, "outside.txt")
	for _, d := range []string{ws, cred, coiDir, filepath.Dir(outside)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "notes"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, link := range []struct{ name, dest string }{
		{"outlink", outside},
		{"credlink", cred},
		{"coidir", coiDir},
		{"alias", filepath.Join(ws, "notes")},
	} {
		if err := os.Symlink(link.dest, filepath.Join(ws, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	allow := []string{"edit", "-p"}
	values := []string{"-p"}
	ok := [][]string{
		{"edit", "notes"},
		{"edit", "alias"},
		{"edit", "newfile"},
		{"-p", "fix the bug"},
	}
	for _, args := range ok {
		if err := CheckArgs(allow, args, ws, cred, values, coiDir); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := CheckArgs(allow, []string{"edit", "outlink"}, ws, cred, values, coiDir); !errors.Is(err, ErrOutside) {
		t.Fatalf("outside link: %v", err)
	}
	if err := CheckArgs(allow, []string{"edit", "credlink"}, ws, cred, values, coiDir); !errors.Is(err, ErrCredHome) {
		t.Fatalf("credential link: %v", err)
	}
	if err := CheckArgs(allow, []string{"edit", "coidir"}, ws, cred, values, coiDir); !errors.Is(err, ErrCredHome) {
		t.Fatalf("coi link: %v", err)
	}
	if err := CheckArgs(allow, []string{"edit", "sub/../notes"}, ws, cred, values, coiDir); !errors.Is(err, ErrOutside) {
		t.Fatalf("parent segment: %v", err)
	}
	if err := CheckArgs(allow, []string{"-p", `foo\..\notes`}, ws, cred, values, coiDir); !errors.Is(err, ErrOutside) {
		t.Fatalf("backslash parent: %v", err)
	}
}

func TestCheckArgsRejectsUnlistedFlag(t *testing.T) {
	ws := t.TempDir()
	if err := CheckArgs([]string{"edit"}, []string{"edit", "--force"}, ws, "/var/empty-cred", nil); !errors.Is(err, ErrNotAllowed) {
		t.Fatal(err)
	}
}

func TestCheckArgsBlocksValueBypasses(t *testing.T) {
	ws := t.TempDir()
	cred := filepath.Join(t.TempDir(), "creds")
	if err := os.Mkdir(cred, 0o700); err != nil {
		t.Fatal(err)
	}
	allow := []string{"-p", "--cwd", "--always-approve", "--sandbox", "update", "edit"}
	valueFlags := []string{"-p", "--cwd", "--sandbox"}
	cases := []struct {
		args []string
		want error
	}{
		{[]string{"-p", "login"}, ErrBlocked},
		{[]string{"--cwd=update"}, ErrBlocked},
		{[]string{"--always-approve"}, ErrBlocked},
		{[]string{"--sandbox", "x"}, ErrBlocked},
		{[]string{"--sandbox=lgb"}, ErrBlocked},
		{[]string{"update"}, ErrBlocked},
		{[]string{"edit", "update"}, ErrBlocked},
		{[]string{"-p", "fix the bug"}, nil},
	}
	for _, tc := range cases {
		err := CheckArgs(allow, tc.args, ws, cred, valueFlags)
		if tc.want == nil {
			if err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) {
			t.Fatalf("%v: got %v want %v", tc.args, err, tc.want)
		}
	}
	// A boolean -p must not swallow the next word, so login is still blocked.
	err := CheckArgs([]string{"-p", "login"}, []string{"-p", "login"}, ws, cred, nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("boolean swallow: %v", err)
	}
}
