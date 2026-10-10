package daemon

import "os"

func mkdir(path string) error {
	return os.MkdirAll(path, 0o755)
}
