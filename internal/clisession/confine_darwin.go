//go:build darwin

package clisession

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// confinedCommand runs bin under sandbox-exec. The workspace is writable.
// The login directories under the user home are the only other writable
// home paths. The child environment is built fresh, so API keys and the
// SSH agent are not inherited. cleanup removes the profile and temp dir
// after the process has exited.
func confinedCommand(bin string, args []string, workspace string) (*exec.Cmd, func(), error) {
	ws, home, err := absWorkspace(workspace)
	if err != nil {
		return nil, nil, err
	}
	sb, err := exec.LookPath("sandbox-exec")
	if err != nil {
		return nil, nil, fmt.Errorf("cli confinement unavailable: sandbox-exec not on PATH")
	}
	absBin, err := filepath.Abs(bin)
	if err != nil {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "lgb-cli-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	if home != "" {
		ensureCLIState(home)
	}
	text, err := cliSeatbelt(ws, home, tmp, filepath.Dir(absBin)).Render()
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	profilePath := filepath.Join(tmp, "seatbelt.sb")
	if err := os.WriteFile(profilePath, []byte(text), 0o644); err != nil {
		cleanup()
		return nil, nil, err
	}
	cmd := exec.Command(sb, append([]string{"-f", profilePath, absBin}, args...)...)
	cmd.Dir = ws
	cmd.Env = cliChildEnv(home, tmp)
	return cmd, cleanup, nil
}
