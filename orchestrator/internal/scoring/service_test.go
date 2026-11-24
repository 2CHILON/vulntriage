package scoring

import (
	"context"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// MockFindingSource is a test implementation.
type MockFindingSource struct {
	findings map[string][]model.Finding
}

func (m *MockFindingSource) ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	return m.findings[scanID], nil
}

// MockAnalysisSource is a test implementation.
type MockAnalysisSource struct {
	analyses map[string]*analysis.Analysis
}

func (m *MockAnalysisSource) GetAnalysis(ctx context.Context, findingID string) (*analysis.Analysis, error) {
	return m.analyses[findingID], nil
}

// MockReachability is a test implementation.
type MockReachability struct {
	results map[string][2]string // findingID -> [kind, status]
}

func (m *MockReachability) ReachabilityFor(f model.Finding) (kind string, status string) {
	if result, ok := m.results[f.ID]; ok {
		return result[0], result[1]
	}
	return "unknown", "unknown"
}

// MockScoreStore is a test implementation.
type MockScoreStore struct {
	storedScores  map[string][]StoredScore
	scoredResults map[string][]ScoredFinding
}

func (m *MockScoreStore) ReplaceScores(ctx context.Context, scanID string, scores []StoredScore) error {
	m.storedScores[scanID] = scores
	return nil
}

func (m *MockScoreStore) ListScoresByScan(ctx context.Context, scanID string) ([]ScoredFinding, error) {
	return m.scoredResults[scanID], nil
}

// TestScoreScanWithoutAnalysis tests scoring findings without analysis.
func TestScoreScanWithoutAnalysis(t *testing.T) {
	findings := []model.Finding{
		{
			ID:       "find1",
			ScanID:   "scan1",
			Severity: "high",
			File:     "app.js",
			Source:   "trivy",
		},
	}

	findingSource := &MockFindingSource{
		findings: map[string][]model.Finding{
			"scan1": findings,
		},
	}
	analysisSource := &MockAnalysisSource{
		analyses: make(map[string]*analysis.Analysis),
	}
	reachability := &MockReachability{
		results: map[string][2]string{
			"find1": {"code", "unknown"},
		},
	}
	scoreStore := &MockScoreStore{
		storedScores:  make(map[string][]StoredScore),
		scoredResults: make(map[string][]ScoredFinding),
	}

	service := NewService(
		findingSource,
		analysisSource,
		reachability,
		scoreStore,
		DefaultWeights(),
		ExposureConfig{},
	)

	summary, err := service.ScoreScan(context.Background(), "scan1")
	if err != nil {
		t.Fatalf("ScoreScan failed: %v", err)
	}

	if summary.Scored != 1 {
		t.Errorf("Scored = %d, want 1", summary.Scored)
	}
	if summary.WithoutAnalysis != 1 {
		t.Errorf("WithoutAnalysis = %d, want 1", summary.WithoutAnalysis)
	}
}

// TestScoreScanRanking tests that findings are ranked correctly.
func TestScoreScanRanking(t *testing.T) {
	findings := []model.Finding{
		{ID: "low", Severity: "low", File: "app.js", Source: "trivy"},
		{ID: "high", Severity: "high", File: "app.js", Source: "trivy"},
		{ID: "medium", Severity: "medium", File: "app.js", Source: "trivy"},
	}

	findingSource := &MockFindingSource{findings: map[string][]model.Finding{"scan1": findings}}
	analysisSource := &MockAnalysisSource{analyses: make(map[string]*analysis.Analysis)}
	reachability := &MockReachability{
		results: map[string][2]string{
			"low":    {"code", "unknown"},
			"high":   {"code", "unknown"},
			"medium": {"code", "unknown"},
		},
	}
	scoreStore := &MockScoreStore{
		storedScores:  make(map[string][]StoredScore),
		scoredResults: make(map[string][]ScoredFinding),
	}

	service := NewService(
		findingSource,
		analysisSource,
		reachability,
		scoreStore,
		DefaultWeights(),
		ExposureConfig{},
	)

	summary, err := service.ScoreScan(context.Background(), "scan1")
	if err != nil {
		t.Fatalf("ScoreScan failed: %v", err)
	}

	// Top item should be "high" severity
	if len(summary.Top) > 0 && summary.Top[0].FindingID != "high" {
		t.Errorf("first item = %s, want high", summary.Top[0].FindingID)
	}
}

// TestScoreScanNoCanonical tests behavior with no canonical findings.
func TestScoreScanNoCanonical(t *testing.T) {
	findingSource := &MockFindingSource{
		findings: map[string][]model.Finding{
			"scan1": {},
		},
	}
	analysisSource := &MockAnalysisSource{analyses: make(map[string]*analysis.Analysis)}
	reachability := &MockReachability{results: make(map[string][2]string)}
	scoreStore := &MockScoreStore{
		storedScores:  make(map[string][]StoredScore),
		scoredResults: make(map[string][]ScoredFinding),
	}

	service := NewService(
		findingSource,
		analysisSource,
		reachability,
		scoreStore,
		DefaultWeights(),
		ExposureConfig{},
	)

	summary, err := service.ScoreScan(context.Background(), "scan1")
	if err != nil {
		t.Fatalf("ScoreScan failed: %v", err)
	}

	if summary.Scored != 0 {
		t.Errorf("Scored = %d, want 0", summary.Scored)
	}
}
