package github

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tokenSecret = "lgb-github-test-secret-value"

func TestReadTokenOwnerMatchesEUID(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	prevEUID, prevOwner := tokenEUID, tokenOwner
	tokenCheck, tokenHook = nil, nil
	tokenEUID = os.Geteuid
	tokenOwner = func(uid uint32) uint32 { return uid }
	t.Cleanup(func() {
		tokenCheck, tokenHook = prevCheck, prevHook
		tokenEUID, tokenOwner = prevEUID, prevOwner
	})

	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte(tokenSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(good, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadToken(good)
	if err != nil || got != tokenSecret || strings.Contains(errString(err), tokenSecret) {
		t.Fatalf("owner==euid: %q %v", got, err)
	}

	// Another owner fails, including a root-owned file when euid is not root.
	tokenEUID = func() int { return 1000 }
	tokenOwner = func(uint32) uint32 { return 1001 }
	_, err = ReadToken(good)
	if !errors.Is(err, ErrToken) || !strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("other owner: %v", err)
	}
	tokenOwner = func(uint32) uint32 { return 0 }
	_, err = ReadToken(good)
	if !errors.Is(err, ErrToken) || !strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("root owner, non-root euid: %v", err)
	}

	// A root daemon still accepts only a root-owned file.
	tokenEUID = func() int { return 0 }
	tokenOwner = func(uint32) uint32 { return 0 }
	got, err = ReadToken(good)
	if err != nil || got != tokenSecret {
		t.Fatalf("root: %q %v", got, err)
	}
	tokenOwner = func(uint32) uint32 { return 1000 }
	_, err = ReadToken(good)
	if !errors.Is(err, ErrToken) || !strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("root euid, other owner: %v", err)
	}

	tokenEUID = os.Geteuid
	tokenOwner = func(uid uint32) uint32 { return uid }

	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(tokenSecret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(loose)
	if !errors.Is(err, ErrToken) || !strings.Contains(err.Error(), "mode") || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("mode: %v", err)
	}

	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(link)
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := ReadToken("relative"); !errors.Is(err, ErrToken) {
		t.Fatalf("relative: %v", err)
	}
	if _, err := ReadToken(dir); !errors.Is(err, ErrToken) {
		t.Fatalf("dir: %v", err)
	}
}

func TestReadTokenShapeAndHook(t *testing.T) {
	prevCheck, prevHook := tokenCheck, tokenHook
	t.Cleanup(func() { tokenCheck, tokenHook = prevCheck, prevHook })

	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	write := func(body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	tokenHook = nil
	tokenCheck = func(uint32, uint32) error { return nil }
	write(tokenSecret+"\n", 0o600)
	got, err := ReadToken(path)
	if err != nil || got != tokenSecret {
		t.Fatalf("read %q %v", got, err)
	}
	write(tokenSecret+"\r\n", 0o600)
	got, err = ReadToken(path)
	if err != nil || got != tokenSecret {
		t.Fatalf("crlf %q %v", got, err)
	}
	for _, body := range []string{
		tokenSecret + " ",
		tokenSecret + "\t",
		tokenSecret + "\n\n",
		tokenSecret + "\r\n\r\n",
		tokenSecret + " \t\r\n",
		tokenSecret + "\n \n",
		tokenSecret + "\r\n \t",
	} {
		write(body, 0o600)
		got, err = ReadToken(path)
		if err != nil || got != tokenSecret || strings.Contains(errString(err), tokenSecret) {
			t.Fatalf("trailing %q -> %q %v", body, got, err)
		}
	}
	for _, body := range []string{"", "\n", " \n", tokenSecret + "\nmore\n", " " + tokenSecret + "\n", "has space\n", "tab\there\n", tokenSecret + " x\n"} {
		write(body, 0o600)
		_, err = ReadToken(path)
		if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
			t.Fatalf("accepted %q: %v", body, err)
		}
		if !strings.Contains(err.Error(), "shape") && body != "" {
			t.Fatalf("shape reason %q: %v", body, err)
		}
	}
	big := strings.Repeat("a", 4097)
	write(big, 0o600)
	if _, err := ReadToken(path); !errors.Is(err, ErrToken) {
		t.Fatalf("oversize: %v", err)
	}

	tokenCheck = func(uint32, uint32) error { return errors.New("leak " + tokenSecret) }
	write(tokenSecret+"\n", 0o600)
	_, err = ReadToken(path)
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) || strings.Contains(err.Error(), "leak") {
		t.Fatalf("check error leaked: %v", err)
	}

	tokenCheck = nil
	tokenHook = func(string) (string, error) { return tokenSecret, nil }
	got, err = ReadToken("/no/such")
	if err != nil || got != tokenSecret {
		t.Fatalf("hook %q %v", got, err)
	}
	tokenHook = func(string) (string, error) { return "", errors.New("leak " + tokenSecret) }
	_, err = ReadToken("/no/such")
	if !errors.Is(err, ErrToken) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("hook error leaked: %v", err)
	}
	tokenHook = func(string) (string, error) { return "bad token", nil }
	if _, err := ReadToken("/no/such"); !errors.Is(err, ErrToken) {
		t.Fatalf("hook shape: %v", err)
	}
}

func TestTokenReadDistinguishesMissingAndDenied(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-token")
	_, err := ReadToken(missing)
	if TokenFailureReason(err) != "missing" || TokenFailureBody(err) != "github token unavailable: missing" {
		t.Fatalf("missing %v body %q", err, TokenFailureBody(err))
	}
	if strings.Contains(err.Error(), "no-such") {
		t.Fatalf("path leaked: %v", err)
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.WriteFile(locked, []byte(tokenSecret+"\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	_, err = ReadToken(locked)
	reason := TokenFailureReason(err)
	if os.Geteuid() == 0 {
		if reason != "mode" && reason != "permission denied" {
			t.Fatalf("root read %q %v", reason, err)
		}
	} else if reason != "permission denied" {
		t.Fatalf("denied %q %v", reason, err)
	}
	if reason == "missing" || strings.Contains(TokenFailureBody(err), tokenSecret) || strings.Contains(err.Error(), tokenSecret) {
		t.Fatalf("locked %q %v", TokenFailureBody(err), err)
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestTokenFailureReasonOmitsBytes(t *testing.T) {
	if TokenFailureReason(errToken("owner")) != "token file: not owned by daemon" {
		t.Fatal(TokenFailureReason(errToken("owner")))
	}
	if TokenFailureReason(errToken("mode")) != "mode" || TokenFailureReason(errToken("shape")) != "shape" {
		t.Fatal("mode or shape")
	}
	if TokenFailureReason(errToken("read")) != "missing" || TokenFailureReason(errToken("path")) != "missing" || TokenFailureReason(errToken("missing")) != "missing" {
		t.Fatal("missing")
	}
	if TokenFailureReason(errToken("denied")) != "permission denied" || TokenFailureBody(errToken("denied")) != "github token unavailable: permission denied" {
		t.Fatal("permission denied")
	}
	if TokenFailureBody(errToken("owner")) != "github token unavailable: not owned by daemon" {
		t.Fatal(TokenFailureBody(errToken("owner")))
	}
	if TokenFailureBody(errToken("missing")) != "github token unavailable: missing" || TokenFailureBody(errToken("mode")) != "github token unavailable: mode" || TokenFailureBody(errToken("shape")) != "github token unavailable: shape" {
		t.Fatal("body phrase")
	}
	leak := errors.New("bad " + tokenSecret)
	if strings.Contains(TokenFailureBody(leak), tokenSecret) || strings.Contains(TokenFailureBody(errToken("owner")), tokenSecret) {
		t.Fatal("body leaked")
	}
	if TokenFailureReason(leak) != "token" || strings.Contains(TokenFailureReason(leak), tokenSecret) {
		t.Fatal(TokenFailureReason(leak))
	}
	if strings.Contains(TokenFailureReason(errToken("owner")), tokenSecret) {
		t.Fatal("owner reason leaked")
	}
}
