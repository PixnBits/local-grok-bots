//go:build linux

package clisession

import (
	"fmt"
	"os/exec"
)

// confinedCommand runs bin under bubblewrap. The workspace is bind-mounted
// at its host path. The daemon user's CLI login directories are the only
// home paths mounted. The child environment is cleared.
func confinedCommand(bin string, args []string, workspace string) (*exec.Cmd, func(), error) {
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, nil, fmt.Errorf("cli confinement unavailable: bwrap not on PATH")
	}
	wrapArgs, err := confineArgs(bin, args, workspace)
	if err != nil {
		return nil, nil, err
	}
	cmd := exec.Command(bwrap, wrapArgs...)
	// Absolute bwrap path. A minimal env so the wrapper itself does not
	// carry API keys or an SSH agent socket in its own environ.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd, func() {}, nil
}
