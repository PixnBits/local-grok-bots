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

// classifierRaises reports whether a classifier level is stricter than
// the table level. Unclassified ranks with medium: low and medium do
// not replace an unclassified row. Only high or critical does.
// An empty reply is not a level.
func classifierRaises(table, got Level) bool {
	if got == "" {
		return false
	}
	g := frictionRank(got)
	t := frictionRank(table)
	if g < 0 || t < 0 {
		return false
	}
	return g > t
}

// frictionRank is the order a classifier may raise. It is not Rank:
// unclassified sits with medium, so a "safer" model reply cannot lower it.
func frictionRank(l Level) int {
	switch l {
	case LevelLow:
		return 1
	case "", LevelUnclassified, LevelMedium:
		return 2
	case LevelHigh:
		return 3
	case LevelCritical:
		return 4
	default:
		return -1
	}
}
