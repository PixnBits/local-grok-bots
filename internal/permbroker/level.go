package permbroker

// Level is the friction class of one command. Tables set it. They do
// not allow the command.
type Level string

const (
	LevelUnclassified Level = "unclassified"
	LevelLow          Level = "low"
	LevelMedium       Level = "medium"
	LevelHigh         Level = "high"
	LevelCritical     Level = "critical"
)

// Rank orders levels. Unknown names rank below unclassified so a typo
// cannot outrank a shipped level by accident. Callers treat a negative
// rank as a config error.
func Rank(l Level) int {
	switch l {
	case LevelUnclassified, "":
		return 0
	case LevelLow:
		return 1
	case LevelMedium:
		return 2
	case LevelHigh:
		return 3
	case LevelCritical:
		return 4
	default:
		return -1
	}
}

func parseLevel(s string) (Level, bool) {
	l := Level(s)
	if Rank(l) < 0 || l == "" {
		return "", false
	}
	return l, true
}

func maxLevel(a, b Level) Level {
	if Rank(b) > Rank(a) {
		return b
	}
	return a
}
