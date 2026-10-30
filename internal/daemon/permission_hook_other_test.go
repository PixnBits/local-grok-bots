//go:build !unix

package daemon

import "time"

// runFakeHook has no process-group kill off Unix. The hook is not run.
// Fall through so a killed or timed-out hook does not allow the tool.
func runFakeHook(command string, stdin []byte, mode string) (block, allow bool) {
	return false, false
}

func fakeHookBudget() time.Duration { return 200 * time.Millisecond }
