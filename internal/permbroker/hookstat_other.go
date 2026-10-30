//go:build !unix

package permbroker

import "os"

func fileIdentity(os.FileInfo) (dev, ino uint64, uid uint32, ok bool) {
	return 0, 0, 0, false
}
