//go:build linux

package permbroker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// mountinfoPath is the mount table. Tests point it at a missing file.
var mountinfoPath = "/proc/self/mountinfo"

type mountEnt struct {
	id    int
	point string
}

// mountMismatch asks when the resolved path's mount id differs from the
// workspace root, or when the mount table cannot be read. ok is false
// when the table is missing or has no row for a path.
func mountMismatch(target, root string) (differ bool, ok bool) {
	b, err := os.ReadFile(mountinfoPath)
	if err != nil || len(strings.TrimSpace(string(b))) == 0 {
		return true, false
	}
	ents, parsed := parseMountinfo(b)
	if !parsed || len(ents) == 0 {
		return true, false
	}
	tID, okT := mountIDFor(ents, nearestExisting(target))
	rID, okR := mountIDFor(ents, nearestExisting(root))
	if !okT || !okR {
		return true, false
	}
	return tID != rID, true
}

func parseMountinfo(b []byte) ([]mountEnt, bool) {
	var out []mountEnt
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil, false
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, false
		}
		out = append(out, mountEnt{id: id, point: unescapeMount(fields[4])})
	}
	return out, len(out) > 0
}

func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (int(s[i+1]-'0') << 6) | (int(s[i+2]-'0') << 3) | int(s[i+3]-'0')
			b.WriteByte(byte(v))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}

func mountIDFor(ents []mountEnt, path string) (int, bool) {
	path = filepath.Clean(path)
	if path == "" {
		return 0, false
	}
	bestLen := -1
	bestID := 0
	found := false
	for _, e := range ents {
		mp := filepath.Clean(e.point)
		if mp == "" {
			continue
		}
		if mp == path || strings.HasPrefix(path, mp+string(filepath.Separator)) || (mp == string(filepath.Separator) && strings.HasPrefix(path, string(filepath.Separator))) {
			if len(mp) > bestLen {
				bestLen = len(mp)
				bestID = e.id
				found = true
			}
		}
	}
	return bestID, found
}

func nearestExisting(p string) string {
	cur := strings.TrimSpace(p)
	if cur == "" {
		return ""
	}
	for {
		if st, err := os.Lstat(cur); err == nil && st != nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cur
		}
		cur = parent
	}
}
