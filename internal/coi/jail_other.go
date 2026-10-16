//go:build !linux && !darwin

package coi

import "os/exec"

func wrapCommand(jailSpec) (*exec.Cmd, error) {
	return nil, ErrSandboxUnavailable
}
