//go:build !linux

package daemon

import (
	"fmt"
	"os"
)

func shrinkStdinPipe() int {
	fmt.Fprintf(os.Stderr, "fake claude pipe size is not set on this OS\n")
	os.Exit(1)
	return 0
}
