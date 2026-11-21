package model

import (
	"time"
)

// Finding represents a unified vulnerability finding from any scanner.
type Finding struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	Source        string    `json:"source"`   // "trivy", "semgrep", "zap", "depcheck"
	Severity      string    `json:"severity"` // "critical", "high", "medium", "low", "note"
	File          string    `json:"file"`
	Line          int       `json:"line"`
	CWE           string    `json:"cwe,omitempty"`
	CVE           string    `json:"cve,omitempty"`
	Description   string    `json:"description"`
	DedupeGroupID string    `json:"dedupe_group_id,omitempty"`
	IsCanonical   bool      `json:"is_canonical"`
	DedupeReason  string    `json:"dedupe_reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
