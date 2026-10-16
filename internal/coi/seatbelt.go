package coi

import (
	"fmt"
	"path/filepath"
	"strings"
)

// coiSeatbeltProfile is the macOS sandbox-exec profile for one inner CLI.
// Writes are limited to the workspace and the private HOME. The credential
// home is not listed, so deny-default hides it. Network is allowed so the
// CLI can reach its API; filesystem isolation is the control.
func coiSeatbeltProfile(workspace, home, bin string) (string, error) {
	for _, p := range []string{workspace, home, bin} {
		if err := checkSBPath(p); err != nil {
			return "", err
		}
	}
	if workspace == "/" || home == "/" {
		return "", fmt.Errorf("seatbelt: refusing / as a writable root")
	}
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")
	b.WriteString("(allow process-fork)\n(allow process-exec)\n")
	b.WriteString("(allow signal (target same-sandbox))\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow file-read-metadata)\n")
	b.WriteString("(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\") (global-name \"com.apple.system.logger\") (global-name \"com.apple.system.notification_center\"))\n")
	b.WriteString("(allow file-read* (literal \"/\")")
	for _, p := range []string{
		"/usr", "/bin", "/sbin", "/System",
		"/Library/Apple", "/Library/Developer/CommandLineTools",
		"/private/var/db/dyld", "/private/var/db/timezone", "/private/etc/ssl",
	} {
		fmt.Fprintf(&b, " (subpath %s)", sbQuote(p))
	}
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"} {
		fmt.Fprintf(&b, " (literal %s)", sbQuote(p))
	}
	b.WriteString(")\n")
	fmt.Fprintf(&b, "(allow file-read* (literal %s))\n", sbQuote(bin))
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %s) (subpath %s))\n", sbQuote(workspace), sbQuote(home))
	b.WriteString("(allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\"))\n")
	b.WriteString("(allow network-outbound)\n(allow system-socket)\n")
	b.WriteString("(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.trustd\") (global-name \"com.apple.trustd.agent\"))\n")
	return b.String(), nil
}

func checkSBPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("seatbelt: path must be absolute and clean: %q", p)
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("seatbelt: control character in path %q", p)
		}
	}
	return nil
}

func sbQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
