//go:build !linux && !darwin

package sandbox

import (
	"context"
	"fmt"
	"runtime"
)

// HandleArgs has no jailed stage outside Linux.
func HandleArgs(args []string) bool { return false }

// launch fails closed where no shell sandbox is implemented.
func launch(ctx context.Context, p *prepared) (string, string, error) {
	return "", "", fmt.Errorf("shell sandbox unavailable on %s", runtime.GOOS)
}
