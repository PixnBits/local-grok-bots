//go:build !unix

package coi

import "os/exec"

func detach(cmd *exec.Cmd) {}

func killTree(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
