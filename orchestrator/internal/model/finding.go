package model

import (
	"time"
)

// Finding represents a unified vulnerability finding from any scanner.
type Finding struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scan_id"`
	Source      string    `json:"source"`   // "trivy", "semgrep", "zap", "depcheck"
	Severity    string    `json:"severity"` // "critical", "high", "medium", "low", "note"
	File        string    `json:"file"`
	Line        int       `json:"line"`
	CWE         string    `json:"cwe,omitempty"`
	CVE         string    `json:"cve,omitempty"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}
