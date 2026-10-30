package permbroker

import (
	"path/filepath"
	"strings"
)

// criticalReason is card copy for a path that made the level critical.
// It does not change the level. Other critical commands get an empty string.
func criticalReason(level Level, argv []string, raw string) string {
	if level != LevelCritical {
		return ""
	}
	fields := append([]string{}, argv...)
	fields = append(fields, strings.Fields(raw)...)
	for _, f := range fields {
		if f == "~" || strings.HasPrefix(f, "~/") {
			return "Touches your home directory"
		}
	}
	for _, f := range fields {
		if strings.HasPrefix(f, "/") {
			return "Reads outside the workspace: " + filepath.Clean(f)
		}
	}
	return ""
}
