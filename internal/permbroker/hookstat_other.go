//go:build !unix

package permbroker

import "os"

func fileIdentity(os.FileInfo) (dev, ino uint64, uid uint32, ok bool) {
	return 0, 0, 0, false
}

// nlinkOf has no Stat_t here. Report one link so a missing field does not
// refuse every regular file. Unix builds read the real count.
func nlinkOf(os.FileInfo) (uint64, bool) { return 1, true }
