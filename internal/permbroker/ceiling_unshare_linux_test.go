//go:build linux

package permbroker

import (
	"os/exec"
	"testing"
)

// skipIfNoUnshare skips when unshare is missing or cannot make a nested
// user and mount namespace. A normal host where the probe works still runs.
func skipIfNoUnshare(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is not installed")
	}
	if err := exec.Command("unshare", "-rm", "true").Run(); err != nil {
		t.Skip("unshare cannot create a nested user/mount namespace in this environment")
	}
}
