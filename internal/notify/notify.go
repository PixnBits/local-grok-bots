package notify

import (
	"os/exec"
	"runtime"
	"strings"
)

// Command is the desktop notification for a platform. ok is false when the
// platform has no notifier. Missing binaries are not an error: Send fails open.
func Command(goos, title, body string) (bin string, args []string, ok bool) {
	title = oneLine(title, 120)
	body = oneLine(body, 200)
	switch goos {
	case "linux":
		return "notify-send", []string{title, body}, true
	case "darwin":
		script := "display notification " + appleString(body) + " with title " + appleString(title)
		return "osascript", []string{"-e", script}, true
	default:
		return "", nil, false
	}
}

// Send runs the platform notifier. It does nothing if the tool is missing.
func Send(title, body string) {
	bin, args, ok := Command(runtime.GOOS, title, body)
	if !ok {
		return
	}
	if _, err := exec.LookPath(bin); err != nil {
		return
	}
	_ = exec.Command(bin, args...).Run()
}

func appleString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func oneLine(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
