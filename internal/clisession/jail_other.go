//go:build !linux

package clisession

import (
	"context"
	"fmt"
	"os/exec"
)

func grokHostJail() bool { return false }

func wrapGrokJail(ctx context.Context, bin string, args []string, spec Spec) (*exec.Cmd, error) {
	_ = ctx
	_ = bin
	_ = args
	_ = spec
	return nil, fmt.Errorf("process jail is unavailable")
}
