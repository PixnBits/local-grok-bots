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
