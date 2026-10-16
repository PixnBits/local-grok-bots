//go:build !unix

package clisession

import (
	"errors"
	"os"
)

type dirFD struct {
	fd int
}

func openConfiguredRoot(path string) (*dirFD, error) {
	return nil, errors.New("credential directory walk is unavailable")
}

func (d *dirFD) close() {}

func (d *dirFD) dup() (*dirFD, error) {
	return nil, errors.New("credential directory walk is unavailable")
}

func (d *dirFD) names() ([]string, error) {
	return nil, errors.New("credential directory walk is unavailable")
}

func (d *dirFD) openDir(name string) (*dirFD, error) {
	return nil, errors.New("credential directory walk is unavailable")
}

func (d *dirFD) walk(rel string, create bool) (*dirFD, error) {
	return nil, errors.New("credential directory walk is unavailable")
}

func (d *dirFD) removeEntry(name string) error {
	return errors.New("credential directory walk is unavailable")
}

func mkdirNoFollow(root, rel string) error {
	return errors.New("credential directory walk is unavailable")
}

func writeFileNoFollow(root, rel string, data []byte, mode os.FileMode) error {
	return errors.New("credential directory walk is unavailable")
}

func removeFileNoFollow(root, rel string) error {
	return errors.New("credential directory walk is unavailable")
}

func removeTreeNoFollow(root, rel string) error {
	return errors.New("credential directory walk is unavailable")
}

func scrubTree(dataDir, realPath string) error {
	return errors.New("credential directory walk is unavailable")
}
