//go:build unix

package daemon

import (
	"bytes"
	"os/exec"
	"syscall"
	"time"
)

// runFakeHook starts the hook in its own process group.
// LGB_FAKE_HOOK=kill always falls through, which is what a SIGKILL of the
// hook is: a non-blocking error, not exit 2.
// LGB_FAKE_HOOK=timeout waits LGB_FAKE_HOOK_TIMEOUT_MS (default 200) and
// then falls through. It does not wait the 30s settings timeout.
func runFakeHook(command string, stdin []byte, mode string) (block, allow bool) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return false, false
	}
	if mode == "kill" {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
		return false, false
	}
	budget := 5 * time.Second
	if mode == "timeout" {
		budget = fakeHookBudget()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if mode == "timeout" {
			return false, false
		}
		return classifyHook(err, stdout.Bytes())
	case <-time.After(budget):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return false, false
	}
}

func fakeHookBudget() time.Duration {
	ms := 200
	if v := osGetenvInt("LGB_FAKE_HOOK_TIMEOUT_MS"); v > 0 {
		ms = v
	}
	return time.Duration(ms) * time.Millisecond
}
