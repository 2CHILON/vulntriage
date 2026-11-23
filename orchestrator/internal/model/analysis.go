package model

import "time"

// Analysis statuses stored in the analyses table.
const (
	AnalysisStatusOK      = "ok"
	AnalysisStatusFailed  = "analysis_failed"
	AnalysisStatusSkipped = "skipped"
)

// Analysis is the single current LLM analysis of one canonical finding.
// Pointer fields are NULL in the database when the analysis did not succeed.
type Analysis struct {
	FindingID     string    `json:"finding_id"`
	ScanID        string    `json:"-"`
	Status        string    `json:"status"`
	Exploitable   *bool     `json:"exploitable"`
	Confidence    *float64  `json:"confidence"`
	Priority      *string   `json:"priority"`
	Reasoning     string    `json:"reasoning"`
	SuggestedFix  string    `json:"suggested_fix"`
	Provider      string    `json:"provider"`
	PromptVersion string    `json:"prompt_version"`
	Error         string    `json:"error"`
	UpdatedAt     time.Time `json:"updated_at"`
}
