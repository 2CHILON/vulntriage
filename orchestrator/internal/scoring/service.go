package scoring

import (
	"context"
	"fmt"
	"strings"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// FindingSource provides access to findings.
type FindingSource interface {
	ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error)
}

// AnalysisSource provides access to analyses.
type AnalysisSource interface {
	GetAnalysis(ctx context.Context, findingID string) (*analysis.Analysis, error)
}

// ReachabilityProvider classifies a finding's reachability.
type ReachabilityProvider interface {
	ReachabilityFor(f model.Finding) (kind string, status string)
}

// ScoreStore stores and retrieves scores.
type ScoreStore interface {
	ReplaceScores(ctx context.Context, scanID string, scores []StoredScore) error
	ListScoresByScan(ctx context.Context, scanID string) ([]ScoredFinding, error)
}

// StoredScore is a single score to persist.
type StoredScore struct {
	FindingID string
	ScanID    string
	Score     int
	Priority  string
	Breakdown interface{}
}

// ScoredFinding is a finding with its score from the database.
type ScoredFinding struct {
	FindingID  string
	ScanID     string
	Score      int
	Priority   string
	Severity   string
	Source     string
	File       string
	Line       int
	CVE        string
	CWE        string
	Breakdown  interface{}
	ComputedAt string
}

// Summary holds statistics from a ScoreScan operation.
type Summary struct {
	ScanID          string         `json:"scan_id"`
	Scored          int            `json:"scored"`
	WithoutAnalysis int            `json:"without_analysis"`
	ByPriority      map[string]int `json:"by_priority"`
	Top             []TopItem      `json:"top"`
}

// TopItem is a top-scored finding summary.
type TopItem struct {
	FindingID string `json:"finding_id"`
	Score     int    `json:"score"`
	Priority  string `json:"priority"`
}

// SeverityRanking returns the numeric rank of a severity level (higher = more severe).
func SeverityRanking(severity string) int {
	switch strings.ToLower(severity) {
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

// Service orchestrates scoring of findings for a scan.
type Service struct {
	findingSource      FindingSource
	analysisSource     AnalysisSource
	reachabilitySource ReachabilityProvider
	scoreStore         ScoreStore
	weights            Weights
	exposureConfig     ExposureConfig
}

// NewService creates a new scoring service.
func NewService(
	findingSource FindingSource,
	analysisSource AnalysisSource,
	reachabilitySource ReachabilityProvider,
	scoreStore ScoreStore,
	weights Weights,
	exposureConfig ExposureConfig,
) *Service {
	return &Service{
		findingSource:      findingSource,
		analysisSource:     analysisSource,
		reachabilitySource: reachabilitySource,
		scoreStore:         scoreStore,
		weights:            weights,
		exposureConfig:     exposureConfig,
	}
}

// NotFoundError indicates a scan or other entity was not found.
type NotFoundError struct {
	Message string
}

func (e NotFoundError) Error() string {
	return e.Message
}

// ListScores retrieves all scores for a scan.
func (s *Service) ListScores(ctx context.Context, scanID string) ([]ScoredFinding, error) {
	return s.scoreStore.ListScoresByScan(ctx, scanID)
}
func (s *Service) ScoreScan(ctx context.Context, scanID string) (*Summary, error) {
	summary := &Summary{
		ScanID:     scanID,
		ByPriority: make(map[string]int),
		Top:        []TopItem{},
	}

	// Get canonical findings
	findings, err := s.findingSource.ListCanonicalFindings(ctx, scanID)
	if err != nil {
		return summary, fmt.Errorf("failed to list canonical findings: %w", err)
	}

	// If no canonical findings, return summary with what we found
	if len(findings) == 0 {
		return summary, nil
	}

	// Score each finding
	var scoredResults []ScoredResult

	for _, f := range findings {
		// Get analysis for this finding
		analysis, err := s.analysisSource.GetAnalysis(ctx, f.ID)
		if err != nil {
			analysis = nil
		}

		// Get reachability classification
		kind, status := s.reachabilitySource.ReachabilityFor(f)

		// Build input
		input := Input{
			Severity:           f.Severity,
			ReachabilityStatus: status,
			Kind:               kind,
			File:               f.File,
		}

		// Add analysis if available
		if analysis != nil && analysis.Status == "ok" {
			input.Analysis = &AnalysisInput{
				Status:      analysis.Status,
				Exploitable: analysis.Exploitable,
				Confidence:  analysis.Confidence,
			}
		}

		// Score the finding
		result := Score(input, s.weights, s.exposureConfig)

		scoredResults = append(scoredResults, ScoredResult{
			Finding: f,
			Result:  result,
		})

		// Update summary counts
		summary.Scored++
		if input.Analysis == nil || input.Analysis.Status != "ok" {
			summary.WithoutAnalysis++
		}

		// Count by priority
		summary.ByPriority[result.Priority]++
	}

	// Sort by rank: score desc, severity desc, ID asc
	sortByRank(scoredResults)

	// Collect top 5
	for i := 0; i < 5 && i < len(scoredResults); i++ {
		summary.Top = append(summary.Top, TopItem{
			FindingID: scoredResults[i].Finding.ID,
			Score:     scoredResults[i].Result.Score,
			Priority:  scoredResults[i].Result.Priority,
		})
	}

	// Convert to StoredScore for persistence
	var stored []StoredScore
	for _, sr := range scoredResults {
		stored = append(stored, StoredScore{
			FindingID: sr.Finding.ID,
			ScanID:    scanID,
			Score:     sr.Result.Score,
			Priority:  sr.Result.Priority,
			Breakdown: sr.Result.Breakdown,
		})
	}

	// Store scores in one transaction
	if err := s.scoreStore.ReplaceScores(ctx, scanID, stored); err != nil {
		return summary, fmt.Errorf("failed to store scores: %w", err)
	}

	return summary, nil
}

// ScoredResult combines a finding with its score.
type ScoredResult struct {
	Finding model.Finding
	Result  Result
}

// sortByRank sorts results by: score desc, severity desc, ID asc.
func sortByRank(results []ScoredResult) {
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if shouldSwap(results[i], results[j]) {
				results[i], results[j] = results[j], results[i]
			}
		}
	}
}

// shouldSwap returns true if results[i] should come after results[j] in rank order.
func shouldSwap(a, b ScoredResult) bool {
	// Score descending
	if a.Result.Score != b.Result.Score {
		return a.Result.Score < b.Result.Score
	}

	// Severity descending
	aRank := SeverityRanking(a.Finding.Severity)
	bRank := SeverityRanking(b.Finding.Severity)
	if aRank != bRank {
		return aRank < bRank
	}

	// ID ascending
	return a.Finding.ID > b.Finding.ID
}
