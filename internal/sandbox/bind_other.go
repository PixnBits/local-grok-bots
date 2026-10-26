//go:build !linux

package sandbox

import "os"

// openBuildBind is a no-op outside Linux. Build binds keep the resolved
// path and the platform's existing non-bwrap mount behaviour.
func openBuildBind(string, []string) (*os.File, error) {
	return nil, nil
}
