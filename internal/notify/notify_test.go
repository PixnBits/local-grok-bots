package notify

import (
	"strings"
	"testing"
)

func TestCommand(t *testing.T) {
	bin, args, ok := Command("linux", "Ada", "done\nnow")
	if !ok || bin != "notify-send" || len(args) != 2 || args[0] != "Ada" || args[1] != "done now" {
		t.Fatalf("%s %#v %v", bin, args, ok)
	}
	bin, args, ok = Command("darwin", `Ada "x"`, `line\two`)
	if !ok || bin != "osascript" || len(args) != 2 || args[0] != "-e" {
		t.Fatalf("%s %#v", bin, args)
	}
	if !strings.Contains(args[1], `display notification "line\\two" with title "Ada \"x\""`) {
		t.Fatalf("script %s", args[1])
	}
	if _, _, ok := Command("windows", "t", "b"); ok {
		t.Fatal("windows should fail open")
	}
}
