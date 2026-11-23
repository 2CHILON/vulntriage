package model

import "testing"

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"critical", 4},
		{"HIGH", 3},
		{" medium ", 2},
		{"low", 1},
		{"note", 0},
		{"", 0},
		{"bogus", 0},
	}
	for _, tt := range tests {
		if got := SeverityRank(tt.in); got != tt.want {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
	if !(SeverityRank("critical") > SeverityRank("high") &&
		SeverityRank("high") > SeverityRank("medium") &&
		SeverityRank("medium") > SeverityRank("low") &&
		SeverityRank("low") > SeverityRank("note")) {
		t.Error("severity ranking is not strictly ordered")
	}
}

func TestIsValidSeverityName(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if !IsValidSeverityName(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range []string{"note", "", "urgent"} {
		if IsValidSeverityName(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}
