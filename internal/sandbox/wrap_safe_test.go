package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitWrapForcesSafeConfig(t *testing.T) {
	script := gitWrap(gitWrapOpts{Grant: true, Name: "Ada", Email: "bot@localhost"})
	for _, needle := range []string{
		"core.fsmonitor=",
		"core.fsmonitorHookVersion=",
		"GIT_ALLOW_PROTOCOL=https:ssh",
		"GIT_ALLOW_PROTOCOL=https:ssh:http",
		"--no-ext-diff",
		"--no-textconv",
		"core.hooksPath=/dev/null",
	} {
		if !strings.Contains(script, needle) {
			t.Fatalf("missing %s", needle)
		}
	}
	path := filepath.Join(t.TempDir(), "gitwrap")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-n", path).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n: %v\n%s", err, out)
	}
}
