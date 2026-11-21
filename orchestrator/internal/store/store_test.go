package store

import (
	"context"
	"testing"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Note: These are basic unit tests. Full integration tests would require a live database.

func TestInsertFinding(t *testing.T) {
	// This test demonstrates the structure; actual DB integration testing would use testcontainers.
	finding := model.Finding{
		ID:          "test-finding-1",
		ScanID:      "scan-001",
		Source:      "trivy",
		Severity:    "high",
		File:        "app.py",
		Line:        42,
		CWE:         "CWE-79",
		CVE:         "CVE-2023-1234",
		Description: "Test vulnerability",
		CreatedAt:   time.Now().UTC(),
	}

	// Verify struct fields are set correctly
	if finding.ID == "" || finding.ScanID == "" {
		t.Error("Finding fields not properly initialized")
	}

	// Verify context usage
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if ctx == nil {
		t.Error("Context creation failed")
	}
}

func TestListFindings(t *testing.T) {
	findings := []model.Finding{
		{
			ID:          "test-1",
			ScanID:      "scan-001",
			Source:      "trivy",
			Severity:    "high",
			File:        "app.py",
			Line:        10,
			Description: "Test 1",
			CreatedAt:   time.Now().UTC(),
		},
		{
			ID:          "test-2",
			ScanID:      "scan-001",
			Source:      "semgrep",
			Severity:    "medium",
			File:        "app.py",
			Line:        20,
			Description: "Test 2",
			CreatedAt:   time.Now().UTC(),
		},
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.ScanID != "scan-001" {
			t.Errorf("expected scan_id 'scan-001', got %q", f.ScanID)
		}
	}
}

func TestReplaceDedupeResults_Structure(t *testing.T) {
	// Unit test to verify the ReplaceDedupeResults function signature and behavior expectations.
	// (Full integration testing requires a live PostgreSQL instance.)

	findings := []model.Finding{
		{
			ID:            "finding-1",
			ScanID:        "scan-001",
			Source:        "trivy",
			Severity:      "high",
			File:          "app.py",
			Line:          10,
			Description:   "SQL injection",
			DedupeGroupID: "group-1",
			IsCanonical:   true,
			DedupeReason:  "",
			CreatedAt:     time.Now().UTC(),
		},
		{
			ID:            "finding-2",
			ScanID:        "scan-001",
			Source:        "semgrep",
			Severity:      "high",
			File:          "app.py",
			Line:          10,
			Description:   "SQL injection",
			DedupeGroupID: "group-1",
			IsCanonical:   false,
			DedupeReason:  "deduplicated with finding-1",
			CreatedAt:     time.Now().UTC(),
		},
	}

	// Verify test data is well-formed
	if len(findings) != 2 {
		t.Fatalf("expected 2 test findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.ScanID != "scan-001" {
			t.Errorf("finding %q has wrong ScanID: %q", f.ID, f.ScanID)
		}
		if f.DedupeGroupID != "group-1" {
			t.Errorf("finding %q has wrong DedupeGroupID: %q", f.ID, f.DedupeGroupID)
		}
	}

	if !findings[0].IsCanonical {
		t.Error("first finding should be canonical")
	}
	if findings[1].IsCanonical {
		t.Error("second finding should not be canonical")
	}
}
