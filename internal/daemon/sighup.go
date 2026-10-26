package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
)

// sighupIgnoreLine is one log line per SIGHUP when AUTH_TOKENS_FILE is unset.
const sighupIgnoreLine = "local-grok-bots: SIGHUP ignored; AUTH_TOKENS_FILE is not set"

// WatchSIGHUP handles each value from hup until ctx is done.
// A non-empty tokens file calls reload. An empty path logs
// sighupIgnoreLine and does not reload or change the protected-path
// snapshot. One signal produces one log line when the file is unset.
// A failed reload must not refresh the snapshot; reload does that only
// after a successful read.
func WatchSIGHUP(ctx context.Context, hup <-chan os.Signal, tokensFile string, reload func(), logw io.Writer) {
	if logw == nil {
		logw = os.Stderr
	}
	set := strings.TrimSpace(tokensFile) != ""
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-hup:
			if !ok {
				return
			}
			if !set {
				fmt.Fprintln(logw, sighupIgnoreLine)
				continue
			}
			if reload != nil {
				reload()
			}
		}
	}
}
