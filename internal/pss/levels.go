package pss

// Level represents a Pod Security Standard enforcement level.
type Level string

const (
	LevelPrivileged Level = "privileged"
	LevelBaseline   Level = "baseline"
	LevelRestricted Level = "restricted"
)

// ParseLevel returns the Level corresponding to the given string, and whether
// the string was a recognized level name.
func ParseLevel(s string) (Level, bool) {
	switch Level(s) {
	case LevelPrivileged, LevelBaseline, LevelRestricted:
		return Level(s), true
	default:
		return "", false
	}
}

// Levels returns all known PSS levels ordered from least to most restrictive.
func Levels() []Level {
	return []Level{LevelPrivileged, LevelBaseline, LevelRestricted}
}
