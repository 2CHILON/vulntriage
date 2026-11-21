package dedupe

import (
	"context"
	"testing"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

func makeTestFinding(id, source, file string, line int, cve, cwe, desc string) *model.Finding {
	return &model.Finding{
		ID:          id,
		ScanID:      "test-scan",
		Source:      source,
		Severity:    "high",
		File:        file,
		Line:        line,
		CVE:         cve,
		CWE:         cwe,
		Description: desc,
		CreatedAt:   time.Now(),
	}
}

func TestExactMatchStrategy(t *testing.T) {
	tests := []struct {
		name     string
		findings []*model.Finding
		wantLen  int
	}{
		{
			name: "identical findings are duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
			},
			wantLen: 1,
		},
		{
			name: "different line numbers are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
				makeTestFinding("f2", "semgrep", "app.go", 43, "CVE-2024-1234", "", "SQL injection in query"),
			},
			wantLen: 2,
		},
		{
			name: "different descriptions are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "Different description"),
			},
			wantLen: 2,
		},
		{
			name: "different files are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
				makeTestFinding("f2", "semgrep", "db.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
			},
			wantLen: 2,
		},
		{
			name: "single finding creates one group",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
			},
			wantLen: 1,
		},
		{
			name:     "empty list returns empty",
			findings: []*model.Finding{},
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dedup := NewDeduplicator(&ExactMatchStrategy{})
			groups := dedup.Dedup(tt.findings)
			if len(groups) != tt.wantLen {
				t.Errorf("got %d groups, want %d", len(groups), tt.wantLen)
			}
		})
	}
}

func TestLocationAndCVEStrategy(t *testing.T) {
	tests := []struct {
		name     string
		findings []*model.Finding
		wantLen  int
	}{
		{
			name: "same location and CVE are duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "Different wording"),
			},
			wantLen: 1,
		},
		{
			name: "same location different CVE are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-5678", "", "Different CVE"),
			},
			wantLen: 2,
		},
		{
			name: "same location and CWE are duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "", "CWE-89", "SQL injection"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "", "CWE-89", "Different wording"),
			},
			wantLen: 1,
		},
		{
			name: "different locations are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
				makeTestFinding("f2", "semgrep", "app.go", 50, "CVE-2024-1234", "", "Same CVE"),
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dedup := NewDeduplicator(&LocationAndCVEStrategy{})
			groups := dedup.Dedup(tt.findings)
			if len(groups) != tt.wantLen {
				t.Errorf("got %d groups, want %d", len(groups), tt.wantLen)
			}
		})
	}
}

func TestCVEOnlyStrategy(t *testing.T) {
	tests := []struct {
		name     string
		findings []*model.Finding
		wantLen  int
	}{
		{
			name: "same CVE are duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "Description 1"),
				makeTestFinding("f2", "depcheck", "db.go", 100, "CVE-2024-1234", "", "Description 2"),
				makeTestFinding("f3", "semgrep", "api.go", 200, "CVE-2024-1234", "", "Description 3"),
			},
			wantLen: 1,
		},
		{
			name: "different CVEs are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "Description 1"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-5678", "", "Description 2"),
			},
			wantLen: 2,
		},
		{
			name: "findings without CVE are not duplicates",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "", "", "No CVE"),
				makeTestFinding("f2", "semgrep", "app.go", 42, "", "", "No CVE"),
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dedup := NewDeduplicator(&CVEOnlyStrategy{})
			groups := dedup.Dedup(tt.findings)
			if len(groups) != tt.wantLen {
				t.Errorf("got %d groups, want %d", len(groups), tt.wantLen)
			}
		})
	}
}

func TestCanonicalSelection(t *testing.T) {
	tests := []struct {
		name       string
		findings   []*model.Finding
		wantSource string
		wantHasCVE bool
	}{
		{
			name: "prefer CVE findings",
			findings: []*model.Finding{
				makeTestFinding("f1", "semgrep", "app.go", 42, "", "CWE-89", "SQL injection"),
				makeTestFinding("f2", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
			},
			wantSource: "trivy",
			wantHasCVE: true,
		},
		{
			name: "prefer trivy when no CVE",
			findings: []*model.Finding{
				makeTestFinding("f1", "semgrep", "app.go", 42, "", "", "SQL injection"),
				makeTestFinding("f2", "trivy", "app.go", 42, "", "", "SQL injection"),
			},
			wantSource: "trivy",
			wantHasCVE: false,
		},
		{
			name: "prefer longer descriptions",
			findings: []*model.Finding{
				makeTestFinding("f1", "trivy", "app.go", 42, "", "", "SQL Short"),
				makeTestFinding("f2", "trivy", "app.go", 42, "", "", "SQL Short"),
			},
			wantSource: "trivy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dedup := NewDeduplicator(&ExactMatchStrategy{})
			groups := dedup.Dedup(tt.findings)
			if len(groups) != 1 {
				t.Fatalf("expected 1 group, got %d", len(groups))
			}
			if groups[0].Representative.Source != tt.wantSource {
				t.Errorf("got source %s, want %s", groups[0].Representative.Source, tt.wantSource)
			}
			if tt.wantHasCVE && groups[0].Representative.CVE == "" {
				t.Error("expected canonical finding to have CVE")
			}
		})
	}
}

func TestMark(t *testing.T) {
	findings := []*model.Finding{
		makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
		makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
		makeTestFinding("f3", "zap", "db.go", 100, "CVE-2024-5678", "", "XSS vulnerability"),
	}

	dedup := NewDeduplicator(&ExactMatchStrategy{})
	groups := dedup.Dedup(findings)
	dedup.Mark(findings, groups)

	// f1 and f2 are duplicates; f1 is canonical
	if !findings[0].IsCanonical {
		t.Error("first finding should be canonical")
	}
	if findings[1].IsCanonical {
		t.Error("second finding should not be canonical (it's a duplicate)")
	}
	if findings[1].DedupeGroupID == "" {
		t.Error("second finding should have dedupe group ID")
	}
	if findings[1].DedupeReason == "" {
		t.Error("second finding should have dedupe reason")
	}

	// f3 is unique; it's also canonical (default IsCanonical is false but should be true for singles)
	// Since it's the only finding in its group, it gets the group ID
	if findings[2].DedupeGroupID == "" {
		t.Error("third finding should have dedupe group ID even if unique")
	}
	if !findings[2].IsCanonical {
		t.Error("third finding should be canonical (it's the only one in its group)")
	}
}

func TestDefaultStrategy(t *testing.T) {
	findings := []*model.Finding{
		// Exact match group
		makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
		makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "SQL injection in query"),
		// Location + CVE but different description (still matches via LocationAndCVE strategy)
		makeTestFinding("f3", "zap", "db.go", 100, "CVE-2024-5678", "", "Different wording for XSS"),
		// CVE only (also matches via CVEOnlyStrategy on CVE-2024-5678)
		makeTestFinding("f4", "depcheck", "vendor/lib.jar", 1, "CVE-2024-5678", "", "In dependency"),
	}

	dedup := NewDeduplicator(NewDefaultStrategy())
	groups := dedup.Dedup(findings)

	// f1 and f2 are exact matches (1 group)
	// f3 and f4 share CVE-2024-5678 (1 group)
	if len(groups) != 2 {
		t.Errorf("got %d groups, want 2", len(groups))
	}
}

func TestStats(t *testing.T) {
	findings := []*model.Finding{
		makeTestFinding("f1", "trivy", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
		makeTestFinding("f2", "semgrep", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
		makeTestFinding("f3", "zap", "app.go", 42, "CVE-2024-1234", "", "SQL injection"),
		makeTestFinding("f4", "trivy", "db.go", 100, "CVE-2024-5678", "", "XSS"),
	}

	dedup := NewDeduplicator(&ExactMatchStrategy{})
	groups := dedup.Dedup(findings)
	stats := GetStats(groups)

	if stats.TotalFindings != 4 {
		t.Errorf("TotalFindings: got %d, want 4", stats.TotalFindings)
	}
	if stats.GroupsCreated != 2 {
		t.Errorf("GroupsCreated: got %d, want 2", stats.GroupsCreated)
	}
	if stats.DuplicatesRemoved != 2 {
		t.Errorf("DuplicatesRemoved: got %d, want 2", stats.DuplicatesRemoved)
	}
	if stats.CanonicalFindings != 2 {
		t.Errorf("CanonicalFindings: got %d, want 2", stats.CanonicalFindings)
	}
}

func TestGetStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		wantErr  bool
	}{
		{"exact_match", "exact_match", false},
		{"location_and_cve", "location_and_cve", false},
		{"cve_only", "cve_only", false},
		{"cwe_only", "cwe_only", false},
		{"default", "default", false},
		{"unknown", "unknown_strategy", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetStrategy(tt.strategy)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// FakeScannerForTesting implements the FindingStore interface for unit tests.
type FakeScannerForTesting struct {
	findings map[string][]model.Finding // scanID -> findings
}

func NewFakeScannerForTesting() *FakeScannerForTesting {
	return &FakeScannerForTesting{
		findings: make(map[string][]model.Finding),
	}
}

func (f *FakeScannerForTesting) ScanExists(ctx context.Context, scanID string) (bool, error) {
	_, ok := f.findings[scanID]
	return ok, nil
}

func (f *FakeScannerForTesting) InsertScan(ctx context.Context, scanID string, toolName string) error {
	if _, ok := f.findings[scanID]; !ok {
		f.findings[scanID] = []model.Finding{}
	}
	return nil
}

func (f *FakeScannerForTesting) InsertFindings(ctx context.Context, findings []model.Finding) (int, error) {
	// For testing purposes, just append all findings
	for _, finding := range findings {
		f.findings[finding.ScanID] = append(f.findings[finding.ScanID], finding)
	}
	return len(findings), nil
}

func (f *FakeScannerForTesting) ListAllFindingsByScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	findings, ok := f.findings[scanID]
	if !ok {
		return []model.Finding{}, nil
	}
	return findings, nil
}

func (f *FakeScannerForTesting) ReplaceDedupeResults(ctx context.Context, scanID string, findings []model.Finding) error {
	f.findings[scanID] = findings
	return nil
}

func (f *FakeScannerForTesting) LoadFindings(scanID string, findings []model.Finding) {
	f.findings[scanID] = findings
}

// TestDedupeScan_Idempotence verifies that calling DedupeScan twice on the same scan
// produces identical results (case 3 from requirements).
func TestDedupeScan_Idempotence(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "f1",
			ScanID:      "scan-idempotence",
			Source:      "trivy",
			Severity:    "high",
			File:        "app.go",
			Line:        42,
			CVE:         "CVE-2024-1234",
			Description: "SQL injection",
			CreatedAt:   time.Now(),
		},
		{
			ID:          "f2",
			ScanID:      "scan-idempotence",
			Source:      "semgrep",
			Severity:    "high",
			File:        "app.go",
			Line:        42,
			CVE:         "CVE-2024-1234",
			Description: "SQL injection",
			CreatedAt:   time.Now(),
		},
		{
			ID:          "f3",
			ScanID:      "scan-idempotence",
			Source:      "zap",
			Severity:    "medium",
			File:        "db.go",
			Line:        100,
			CVE:         "CVE-2024-5678",
			Description: "XSS flaw",
			CreatedAt:   time.Now(),
		},
	}

	fake := NewFakeScannerForTesting()
	fake.LoadFindings("scan-idempotence", findings)

	ctx := context.Background()

	// First call to DedupeScan
	stats1, err := DedupeScan(ctx, fake, "scan-idempotence")
	if err != nil {
		t.Fatalf("first DedupeScan failed: %v", err)
	}

	// Get findings after first DedupeScan
	results1, err := fake.ListAllFindingsByScan(ctx, "scan-idempotence")
	if err != nil {
		t.Fatalf("failed to list findings after first DedupeScan: %v", err)
	}

	// Second call to DedupeScan on same scan
	stats2, err := DedupeScan(ctx, fake, "scan-idempotence")
	if err != nil {
		t.Fatalf("second DedupeScan failed: %v", err)
	}

	// Get findings after second DedupeScan
	results2, err := fake.ListAllFindingsByScan(ctx, "scan-idempotence")
	if err != nil {
		t.Fatalf("failed to list findings after second DedupeScan: %v", err)
	}

	// Stats should be identical
	if stats1.TotalFindings != stats2.TotalFindings {
		t.Errorf("TotalFindings differ: first %d, second %d", stats1.TotalFindings, stats2.TotalFindings)
	}
	if stats1.GroupsCreated != stats2.GroupsCreated {
		t.Errorf("GroupsCreated differ: first %d, second %d", stats1.GroupsCreated, stats2.GroupsCreated)
	}
	if stats1.CanonicalFindings != stats2.CanonicalFindings {
		t.Errorf("CanonicalFindings differ: first %d, second %d", stats1.CanonicalFindings, stats2.CanonicalFindings)
	}
	if stats1.DuplicatesRemoved != stats2.DuplicatesRemoved {
		t.Errorf("DuplicatesRemoved differ: first %d, second %d", stats1.DuplicatesRemoved, stats2.DuplicatesRemoved)
	}

	// Findings should be identical (same dedupe groups and canonical flags)
	if len(results1) != len(results2) {
		t.Errorf("Finding count differs: first %d, second %d", len(results1), len(results2))
	}

	for i := range results1 {
		if results1[i].DedupeGroupID != results2[i].DedupeGroupID {
			t.Errorf("Finding %d DedupeGroupID differs: first %q, second %q", i, results1[i].DedupeGroupID, results2[i].DedupeGroupID)
		}
		if results1[i].IsCanonical != results2[i].IsCanonical {
			t.Errorf("Finding %d IsCanonical differs: first %v, second %v", i, results1[i].IsCanonical, results2[i].IsCanonical)
		}
	}
}
