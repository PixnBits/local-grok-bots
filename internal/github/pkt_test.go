package github

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvertisedOID(t *testing.T) {
	zero := strings.Repeat("0", 40)
	feature := strings.Repeat("a", 40)
	body := pktLine("# service=git-upload-pack\n") + "0000" +
		pktLine(feature+" refs/heads/feature\x00report-status object-format=sha1\n") +
		pktLine(strings.Repeat("b", 40)+" refs/heads/other\n") + "0000"
	got, err := AdvertisedOID([]byte(body), "refs/heads/feature")
	if err != nil || got != feature {
		t.Fatalf("feature %q %v", got, err)
	}
	got, err = AdvertisedOID([]byte(body), "refs/heads/missing")
	if err != nil || got != zero {
		t.Fatalf("missing %q %v", got, err)
	}
	empty := pktLine("# service=git-upload-pack\n") + "0000" +
		pktLine(zero+" capabilities^{}\x00report-status object-format=sha1\n") + "0000"
	got, err = AdvertisedOID([]byte(empty), "refs/heads/feature")
	if err != nil || got != zero {
		t.Fatalf("empty %q %v", got, err)
	}
	sha := pktLine(strings.Repeat("0", 64)+" capabilities^{}\x00object-format=sha256\n") + "0000"
	got, err = AdvertisedOID([]byte(sha), "refs/heads/feature")
	if err != nil || got != strings.Repeat("0", 64) {
		t.Fatalf("sha256 %q %v", got, err)
	}
	if _, err := AdvertisedOID([]byte("0000"), "refs/heads/feature"); err != nil {
		t.Fatal(err)
	}
	if _, err := AdvertisedOID([]byte(pktLine(feature+" refs/heads/feature\n")), "refs/heads/feature"); err == nil {
		t.Fatal("missing flush accepted")
	}
	if _, err := AdvertisedOID([]byte(body), ""); err == nil {
		t.Fatal("empty ref accepted")
	}
}

func TestAdvertisedOIDMatchesGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Fatal(err)
	}
	bare := t.TempDir()
	git := func(dir string, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = []string{
			"PATH=" + execPath(),
			"HOME=" + t.TempDir(),
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return out
	}
	git(bare, "init", "--bare")
	git(bare, "symbolic-ref", "HEAD", "refs/heads/main")
	adv := git(bare, "receive-pack", "--stateless-rpc", "--advertise-refs", ".")
	wrapped := []byte(pktLine("# service=git-upload-pack\n") + "0000")
	wrapped = append(wrapped, adv...)
	got, err := AdvertisedOID(wrapped, "refs/heads/feature")
	if err != nil || got != strings.Repeat("0", 40) {
		t.Fatalf("empty repo %q %v", got, err)
	}
	work := t.TempDir()
	git(work, "init")
	git(work, "checkout", "-b", "feature")
	if err := os.WriteFile(filepath.Join(work, "readme.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(work, "add", "readme.txt")
	git(work, "commit", "-m", "note")
	git(work, "push", bare, "feature:refs/heads/feature")
	want := strings.TrimSpace(string(git(bare, "rev-parse", "refs/heads/feature")))
	adv = git(bare, "receive-pack", "--stateless-rpc", "--advertise-refs", ".")
	wrapped = append([]byte(pktLine("# service=git-upload-pack\n")+"0000"), adv...)
	got, err = AdvertisedOID(wrapped, "refs/heads/feature")
	if err != nil || got != want {
		t.Fatalf("advertised %q want %q %v", got, want, err)
	}
}

func execPath() string {
	p := strings.TrimSpace(os.Getenv("PATH"))
	if p == "" {
		return "/usr/bin:/bin"
	}
	return p
}
