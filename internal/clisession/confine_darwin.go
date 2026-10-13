//go:build darwin

package clisession

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/PixnBits/local-grok-bots/internal/policy"
	"github.com/PixnBits/local-grok-bots/internal/sandbox"
)

// applyLaunch runs bin under sandbox-exec. The workspace is writable.
// The login directories under the user home are the only other writable
// home paths. The child environment is built fresh, so API keys and the
// SSH agent are not inherited. cleanup removes the profile and temp dir
// after the process has exited.
func applyLaunch(bin string, args []string, workspace string, plan confinePlan) (*exec.Cmd, func(), error) {
	if err := sandbox.UnsupportedRlimits(runtime.GOOS, plan.Rlimits); err != nil {
		return nil, nil, err
	}
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
	net := cliNet{Open: !plan.UnshareNet, ProxySock: plan.ProxySock, ROBinds: plan.ROBinds, ReadOnly: plan.WorkspaceReadonly}
	if plan.PreloadSrc != "" {
		net.ExtraRead = filepath.Dir(plan.PreloadSrc)
	}
	text, err := cliSeatbelt(ws, home, tmp, filepath.Dir(absBin), net).Render()
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
	env, err := appendExtraEnv(cliChildEnv(home, tmp), plan.ExtraEnv)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if plan.ProxySock != "" {
		env = append(env,
			"LGB_PROXY_SOCK="+plan.ProxySock,
			"DYLD_INSERT_LIBRARIES="+plan.PreloadSrc,
		)
	}
	cmd.Env = env
	return cmd, cleanup, nil
}

func confinedCommand(bin string, args []string, workspace string) (*exec.Cmd, func(), error) {
	return launch{}.command(nil, bin, args, workspace)
}

func appendExtraEnv(base, extra []string) ([]string, error) {
	out := append([]string{}, base...)
	for _, entry := range extra {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || policy.BlockedEnv(key) {
			return nil, fmt.Errorf("env %s is not permitted", key)
		}
		out = append(out, entry)
	}
	return out, nil
}
