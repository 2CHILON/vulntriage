package model

import "strings"

// SeverityRank orders normalized severities: higher means more severe.
// Unknown values and "note" rank lowest. This is the single severity ranking
// used by the orchestrator.
func SeverityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// IsValidSeverityName reports whether s is one of critical, high, medium, low.
func IsValidSeverityName(s string) bool {
	return SeverityRank(s) > 0
}
