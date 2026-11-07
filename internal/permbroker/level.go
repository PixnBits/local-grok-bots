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

// AllowCeilingLevel parses a per-bot auto-approval ceiling.
// The names are the lowercase words low, medium, high, and critical.
// There is no case folding and no trimming. Unclassified is not a ceiling.
func AllowCeilingLevel(s string) (Level, bool) {
	switch Level(s) {
	case LevelLow, LevelMedium, LevelHigh, LevelCritical:
		return Level(s), true
	default:
		return "", false
	}
}

// ceilingCovers reports whether a final level may be auto-approved at ceiling.
// Unclassified, empty, and any unknown name are refused before the rank
// compare. Critical is refused unless the ceiling is exactly critical.
// That equality is the whole check for a critical level: the rank compare
// below does not run for it, and only accepts low, medium, and high.
func ceilingCovers(level, ceiling Level) bool {
	if level == "" || level == LevelUnclassified {
		return false
	}
	if level == LevelCritical {
		return ceiling == LevelCritical
	}
	switch level {
	case LevelLow, LevelMedium, LevelHigh:
	default:
		return false
	}
	lr, lok := ceilingRank(level)
	cr, cok := ceilingRank(ceiling)
	if !lok || !cok {
		return false
	}
	return lr <= cr
}

// ceilingRank is the strict order for a ceiling compare.
// low is 1, medium is 2, high is 3, and critical is 4.
// Unclassified, empty, and any other name have no rank.
func ceilingRank(l Level) (int, bool) {
	switch l {
	case LevelLow:
		return 1, true
	case LevelMedium:
		return 2, true
	case LevelHigh:
		return 3, true
	case LevelCritical:
		return 4, true
	default:
		return 0, false
	}
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
