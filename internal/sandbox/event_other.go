//go:build !unix

package sandbox

import "os"

func openEventsFile(path string) (*os.File, error) {
	return os.Open(path)
}
