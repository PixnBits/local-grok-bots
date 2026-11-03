//go:build unix && !linux && !darwin

package daemon

import "os"

func tokenCtime(os.FileInfo) (sec, nsec int64, ok bool) {
	return 0, 0, false
}
