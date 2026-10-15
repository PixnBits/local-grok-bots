//go:build !unix

package daemon

import "errors"

type spoolDir struct{}

func openSpoolDir(string) (*spoolDir, error) {
	return nil, errors.New("lgb is not supported on this OS")
}
func (d *spoolDir) names() ([]string, error)           { return nil, errSpoolFile }
func (d *spoolDir) read(string, int64) ([]byte, error) { return nil, errSpoolFile }
func (d *spoolDir) write(string, []byte) error         { return errSpoolFile }
func (d *spoolDir) remove(string)                      {}
func (d *spoolDir) close()                             {}

const lgbSupported = false
