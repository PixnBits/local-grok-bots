package sandbox

import (
	"strings"
	"testing"
)

func TestSeatbeltDeniesByDefault(t *testing.T) {
	text, err := (Seatbelt{
		Read:  []string{"/usr", "/bin"},
		Write: []string{"/tmp/ws"},
	}).Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "(deny default)") {
		t.Fatal(text)
	}
	if !strings.Contains(text, "(subpath \"/tmp/ws\")") || !strings.Contains(text, "(subpath \"/private/tmp/ws\")") {
		t.Fatalf("workspace aliases missing:\n%s", text)
	}
	if !strings.Contains(text, "file-read* file-write*") {
		t.Fatal(text)
	}
	if strings.Contains(text, "(allow network-outbound)\n") {
		t.Fatalf("network was opened:\n%s", text)
	}
	if strings.Contains(text, "/etc/passwd") || strings.Contains(text, "(subpath \"/Users") {
		t.Fatalf("host path leaked:\n%s", text)
	}
}

func TestSeatbeltOpenNetAndProxySocket(t *testing.T) {
	open, err := (Seatbelt{OpenNet: true, Write: []string{"/var/ws"}}).Render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(open, "(allow network-outbound)\n") {
		t.Fatal(open)
	}
	closed, err := (Seatbelt{ProxySockets: []string{"/tmp/proxy.sock"}}).Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(closed, "(allow network-outbound)\n") {
		t.Fatalf("bare outbound was allowed:\n%s", closed)
	}
	if !strings.Contains(closed, "unix-socket") || !strings.Contains(closed, "/tmp/proxy.sock") {
		t.Fatal(closed)
	}
}

func TestSeatbeltRejectsProfileBreakout(t *testing.T) {
	_, err := (Seatbelt{Write: []string{`/tmp/bad")`}}).Render()
	if err == nil {
		t.Fatal("accepted a path that closes the profile string")
	}
}

func TestReadRootsSkipHome(t *testing.T) {
	for _, p := range ReadRootCandidates() {
		if strings.Contains(p, "/home/") || strings.Contains(p, "/Users/") || strings.HasPrefix(p, "/Users") {
			t.Fatalf("read root %s is a home path", p)
		}
	}
	joined := " " + strings.Join(ReadRootCandidates(), " ") + " "
	if !strings.Contains(joined, " /opt/homebrew ") || !strings.Contains(joined, " /usr ") {
		t.Fatal(joined)
	}
}
