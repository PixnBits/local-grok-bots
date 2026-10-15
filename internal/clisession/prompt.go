package clisession

import (
	"errors"
	"os"
	"strings"
)

// ErrPermissionPrompt is returned when a headless CLI asks for approval and
// there is no controlling terminal to answer it. The turn ends. It does not wait.
var ErrPermissionPrompt = errors.New("permission prompt requires a TTY or an explicit permission_mode")

func (e ExecRunner) interactive() bool {
	if e.HasTTY != nil {
		return e.HasTTY()
	}
	return hasControllingTTY()
}

// hasControllingTTY reports whether this process can open /dev/tty.
// That is the same check on Linux and macOS. A service manager has no terminal.
func hasControllingTTY() bool {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// permissionText reports a CLI asking a person for approval.
// Structured stream events and a few plain prompt lines count.
// Ordinary model text stays inside JSON token events and does not match.
func permissionText(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	if strings.HasPrefix(line, "{") {
		ev, ok := Parse(line)
		return ok && ev.Kind == "permission"
	}
	l := strings.ToLower(line)
	return strings.Contains(l, "permission prompt") ||
		strings.Contains(l, "session/request_permission") ||
		strings.Contains(l, "do you want to allow") ||
		strings.Contains(l, "do you want to proceed") ||
		strings.Contains(l, "waiting for permission")
}

// lineWatch splits stderr and reports a permission prompt as soon as the
// line is complete, or as soon as the phrase is present if the CLI does not
// write a newline before it waits.
type lineWatch struct {
	pending strings.Builder
	onLine  func(string)
	fired   bool
}

func (w *lineWatch) Write(p []byte) (int, error) {
	if w == nil || w.fired {
		return len(p), nil
	}
	w.pending.Write(p)
	s := w.pending.String()
	for {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			break
		}
		w.consider(s[:i])
		s = s[i+1:]
		if w.fired {
			w.pending.Reset()
			return len(p), nil
		}
	}
	w.pending.Reset()
	if len(s) > 64*1024 {
		s = s[len(s)-64*1024:]
	}
	w.pending.WriteString(s)
	if !w.fired && w.pending.Len() > 0 {
		w.consider(w.pending.String())
	}
	return len(p), nil
}

func (w *lineWatch) consider(line string) {
	if w.fired || !permissionText(line) {
		return
	}
	w.fired = true
	if w.onLine != nil {
		w.onLine(line)
	}
}
