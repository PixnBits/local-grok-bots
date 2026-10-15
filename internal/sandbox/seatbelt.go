package sandbox

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// seatbeltSpec describes the macOS sandbox-exec profile for one shell command.
// Paths must already be resolved with filepath.EvalSymlinks, because Seatbelt
// matches real paths (/tmp is /private/tmp on macOS).
type seatbeltSpec struct {
	Workspace string
	Tmp       string
	ReadOnly  []string
	AllowNet  bool
}

// seatbeltSystemRead is what /bin/sh and common tools need to load and run.
// It stands in for the read-only /usr, /bin and /lib binds of the Linux jail.
var seatbeltSystemRead = []string{
	"/usr",
	"/bin",
	"/sbin",
	"/System",
	"/Library/Apple",
	"/Library/Developer/CommandLineTools",
	"/opt/homebrew",
	"/private/var/db/dyld",
	"/private/var/db/timezone",
	"/private/etc/ssl",
}

// seatbeltProfile renders an SBPL profile with the Linux jail's semantics:
// deny by default, read the system and the workspace, write only the
// workspace and a private temp dir, never write .git/hooks, and no network
// unless AllowNet is set.
func seatbeltProfile(s seatbeltSpec) (string, error) {
	for _, p := range append([]string{s.Workspace, s.Tmp}, s.ReadOnly...) {
		if err := checkSBPath(p); err != nil {
			return "", err
		}
	}
	if s.Workspace == "/" || s.Tmp == "/" {
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
	for _, p := range seatbeltSystemRead {
		fmt.Fprintf(&b, " (subpath %s)", sbString(p))
	}
	for _, p := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/dtracehelper"} {
		fmt.Fprintf(&b, " (literal %s)", sbString(p))
	}
	b.WriteString(")\n")
	for _, p := range s.ReadOnly {
		fmt.Fprintf(&b, "(allow file-read* (subpath %s))\n", sbString(p))
	}
	fmt.Fprintf(&b, "(allow file-read* file-write* (subpath %s) (subpath %s))\n", sbString(s.Workspace), sbString(s.Tmp))
	b.WriteString("(allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))\n")
	// Later rules win in SBPL, so this deny overrides the workspace allow.
	hooks := "^" + regexp.QuoteMeta(s.Workspace) + "/(.*/)?\\.git/hooks(/|$)"
	fmt.Fprintf(&b, "(deny file-write* (regex %s))\n", sbRegex(hooks))
	if s.AllowNet {
		b.WriteString("(allow network-outbound)\n(allow system-socket)\n")
		b.WriteString("(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.trustd\") (global-name \"com.apple.trustd.agent\"))\n")
	}
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

// sbString quotes s as an SBPL string literal.
func sbString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// sbRegex quotes re as an SBPL regex literal.
func sbRegex(re string) string {
	return `#"` + strings.ReplaceAll(re, `"`, `\"`) + `"`
}
