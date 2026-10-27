//go:build !unix

package daemon

import "os/exec"

func configureWhisperProc(cmd *exec.Cmd) {}

func killWhisperGroupOS(pid int) error { return nil }
