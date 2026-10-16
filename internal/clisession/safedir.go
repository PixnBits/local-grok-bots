package clisession

import "errors"

// ErrCredSymlink means a directory component under the credential root is a
// symlink. The walk stops. It does not follow that directory.
var ErrCredSymlink = errors.New("cli credential directory is a symlink")
