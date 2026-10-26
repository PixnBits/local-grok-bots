//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJailEventsRenameSymlink(t *testing.T) {
	requireBin(t, "bwrap")
	const marker = "HOST-ONLY-EVENT-MARKER"
	host := t.TempDir()
	if err := os.WriteFile(filepath.Join(host, "log"), []byte("block "+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := runCmd(t, Request{
		Workspace: t.TempDir(),
		Command:   "mv /lgb/events /lgb/ev2 && ln -s /lgb/ev2 /lgb/events && printf 'block from-jail\\n' >> /lgb/ev2/log",
	})
	if err != nil {
		t.Fatalf("jail: %v\n%s", err, res.Stderr)
	}
	sawJail := false
	for _, ev := range res.Events {
		if strings.Contains(ev.Detail, marker) || strings.Contains(ev.Notice, marker) {
			t.Fatalf("host log was read: %+v", res.Events)
		}
		if ev.Kind == "jail_report" && ev.Detail == "from-jail" {
			sawJail = true
		}
	}
	if !sawJail {
		t.Fatalf("original directory was not read: %+v", res.Events)
	}
}
