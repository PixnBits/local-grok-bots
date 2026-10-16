//go:build !linux && !darwin

package coi

import "os/exec"

const defaultSandboxBin = ""

func wrapCommand(jailSpec) (*exec.Cmd, error) {
	return nil, ErrSandboxUnavailable
}
