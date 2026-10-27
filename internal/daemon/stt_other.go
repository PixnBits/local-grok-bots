//go:build !unix

package daemon

import "os/exec"

func configureWhisperProc(cmd *exec.Cmd) {}
