package clisession

import (
	"errors"
	"os"
)

// ErrCredSymlink means a directory component under the credential root is a
// symlink. The walk stops. It does not follow that directory.
var ErrCredSymlink = errors.New("cli credential directory is a symlink")

// WriteFileInDir writes name inside dir. Missing directories are created.
// A symlink in any component, including name, is refused and not followed.
// The bytes go to a new sibling opened with O_CREAT|O_EXCL|O_NOFOLLOW and
// renamed into place.
func WriteFileInDir(dir, name string, data []byte, mode os.FileMode) error {
	return writeFileInDir(dir, name, data, mode)
}

// errNotRegular means an open found a non-regular file (fifo, device, dir).
var errNotRegular = errors.New("not a regular file")

// Symlink note events. The path field is the walk path, never the link target.
const (
	EventSymlinkUnlinked = "cli_symlink_unlinked"
	EventSymlinkSkipped  = "cli_symlink_skipped"
)

// SymlinkNote records a symlink the walk unlinked or skipped.
// Rel is relative to the trusted root. It is not the target.
type SymlinkNote struct {
	Event string
	Rel   string
}

func noteSymlink(notes *[]SymlinkNote, event, rel string) {
	if notes == nil || event == "" || rel == "" {
		return
	}
	*notes = append(*notes, SymlinkNote{Event: event, Rel: rel})
}
