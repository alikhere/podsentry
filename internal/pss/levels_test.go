package pss

import (
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input string
		want  Level
		ok    bool
	}{
		{"privileged", LevelPrivileged, true},
		{"baseline", LevelBaseline, true},
		{"restricted", LevelRestricted, true},
		{"unknown", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseLevel(c.input)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseLevel(%q) = (%q, %v), want (%q, %v)", c.input, got, ok, c.want, c.ok)
		}
	}
}

func TestLevels(t *testing.T) {
	levels := Levels()
	if len(levels) != 3 {
		t.Fatalf("expected 3 levels, got %d", len(levels))
	}
	if levels[0] != LevelPrivileged {
		t.Errorf("expected first level to be privileged")
	}
	if levels[2] != LevelRestricted {
		t.Errorf("expected last level to be restricted")
	}
}
