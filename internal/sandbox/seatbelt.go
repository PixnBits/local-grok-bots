package sandbox

import (
	"fmt"
	"os"
	"strings"
)

// Seatbelt is a sandbox-exec profile. Read paths are read-only.
// Write paths are readable and writable. OpenNet allows outbound
// network and localhost bind. Otherwise only ProxySockets are reachable.
type Seatbelt struct {
	Read         []string
	Write        []string
	Meta         []string
	OpenNet      bool
	ProxySockets []string
	// DenyExec lists absolute binaries the process must not run.
	// Wrappers on PATH replace them. The copies live on other paths.
	DenyExec []string
}

// ReadRootCandidates are the system prefixes a jail may read.
// Home directories are not in this list. Callers skip the ones that
// are not directories on this machine.
func ReadRootCandidates() []string {
	return []string{
		"/usr",
		"/bin",
		"/sbin",
		"/System",
		"/Library",
		"/Library/Developer",
		"/opt/homebrew",
		"/usr/local",
		"/opt/local",
		"/private/var/db",
		"/private/var/select",
		"/System/Volumes/Preboot",
	}
}

// ExistingReadRoots returns the candidates that are directories here.
func ExistingReadRoots() []string {
	var out []string
	for _, p := range ReadRootCandidates() {
		st, err := os.Stat(p)
		if err == nil && st.IsDir() {
			out = append(out, p)
		}
	}
	return out
}

// Render writes an SBPL profile. A path that could break out of the
// quoted profile is rejected.
func (s Seatbelt) Render() (string, error) {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(deny default)\n")
	b.WriteString("(allow process-exec)\n")
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(allow signal)\n")
	b.WriteString("(allow sysctl-read)\n")
	b.WriteString("(allow system-socket)\n")
	b.WriteString("(allow mach-lookup)\n")
	b.WriteString("(allow ipc-posix-shm)\n")
	b.WriteString("(allow ipc-posix-sem)\n")
	b.WriteString("(allow file-ioctl)\n")
	b.WriteString("(allow file-map-executable)\n")
	b.WriteString("(allow file-read* file-write*\n")
	for _, lit := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/dtracehelper"} {
		fmt.Fprintf(&b, "  (literal %q)\n", lit)
	}
	b.WriteString("  (regex #\"^/dev/fd/[0-9]+$\")\n")
	b.WriteString("  (regex #\"^/dev/std(in|out|err)$\")\n")
	b.WriteString(")\n")
	if err := writePaths(&b, "file-read-metadata", s.Meta, "literal", false); err != nil {
		return "", err
	}
	if err := writePaths(&b, "file-read*", s.Read, "subpath", true); err != nil {
		return "", err
	}
	if err := writePaths(&b, "file-read* file-write*", s.Write, "subpath", true); err != nil {
		return "", err
	}
	denied := uniquePaths(s.DenyExec)
	if len(denied) > 0 {
		b.WriteString("(deny process-exec\n")
		for _, p := range denied {
			if err := sbPathOK(p); err != nil {
				return "", err
			}
			fmt.Fprintf(&b, "  (literal %q)\n", p)
		}
		b.WriteString(")\n")
	}
	if s.OpenNet {
		b.WriteString("(allow network-outbound)\n")
		b.WriteString("(allow network-bind (local ip \"localhost:*\"))\n")
		b.WriteString("(allow network-inbound (local ip \"localhost:*\"))\n")
		return b.String(), nil
	}
	for _, sock := range expandPaths(s.ProxySockets) {
		if err := sbPathOK(sock); err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "(allow network-outbound (to unix-socket (path-literal %q)))\n", sock)
	}
	return b.String(), nil
}

func writePaths(b *strings.Builder, ops string, paths []string, match string, expand bool) error {
	list := uniquePaths(paths)
	if expand {
		list = expandPaths(paths)
	}
	if len(list) == 0 {
		return nil
	}
	fmt.Fprintf(b, "(allow %s\n", ops)
	for _, p := range list {
		if err := sbPathOK(p); err != nil {
			return err
		}
		fmt.Fprintf(b, "  (%s %q)\n", match, p)
	}
	b.WriteString(")\n")
	return nil
}

// StripSeatbeltWarning drops the sandbox-exec deprecation banner.
// The jail still ran. The banner is not a failure.
func StripSeatbeltWarning(s string) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "sandbox-exec is deprecated") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func sbPathOK(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("sandbox path must be absolute")
	}
	if strings.ContainsAny(path, "\"\\()\n\r") {
		return fmt.Errorf("sandbox path contains a reserved character")
	}
	return nil
}

func expandPaths(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		for _, one := range pathAliases(p) {
			if seen[one] {
				continue
			}
			seen[one] = true
			out = append(out, one)
		}
	}
	return out
}

func uniquePaths(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// pathAliases adds the /private prefix macOS uses for /tmp, /var, and /etc.
func pathAliases(path string) []string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	out := []string{path}
	for _, prefix := range []string{"/tmp/", "/var/", "/etc/"} {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			alt := "/private" + path
			if alt != path {
				out = append(out, alt)
			}
		}
	}
	if strings.HasPrefix(path, "/private/tmp/") || strings.HasPrefix(path, "/private/var/") || strings.HasPrefix(path, "/private/etc/") {
		alt := strings.TrimPrefix(path, "/private")
		if alt != path {
			out = append(out, alt)
		}
	}
	return out
}
