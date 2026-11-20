package parsers

import (
	"os"
	"testing"
)

func TestParseSARIF_Trivy(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/sarif/trivy.sarif")
	if err != nil {
		t.Fatalf("failed to read trivy.sarif: %v", err)
	}

	findings, err := ParseSARIF(data, "scan-trivy-001")
	if err != nil {
		t.Fatalf("ParseSARIF failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Check first finding has required fields
	f := findings[0]
	if f.ID == "" {
		t.Error("finding ID is empty")
	}
	if f.ScanID != "scan-trivy-001" {
		t.Errorf("expected scan_id 'scan-trivy-001', got %q", f.ScanID)
	}
	if f.Source == "" {
		t.Error("finding Source is empty")
	}
	if f.Severity == "" {
		t.Error("finding Severity is empty")
	}
	if f.Description == "" {
		t.Error("finding Description is empty")
	}
	if f.CreatedAt.IsZero() {
		t.Error("finding CreatedAt is zero")
	}
}

func TestParseSARIF_Semgrep(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/sarif/semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to read semgrep.sarif: %v", err)
	}

	findings, err := ParseSARIF(data, "scan-semgrep-001")
	if err != nil {
		t.Fatalf("ParseSARIF failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected findings, got none")
	}

	// Check first finding
	f := findings[0]
	if f.ScanID != "scan-semgrep-001" {
		t.Errorf("expected scan_id 'scan-semgrep-001', got %q", f.ScanID)
	}
	if f.File == "" {
		t.Error("finding File is empty")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"CRITICAL", "critical"},
		{"high", "high"},
		{"HIGH", "high"},
		{"4", "high"},
		{"medium", "medium"},
		{"warning", "medium"},
		{"low", "low"},
		{"LOW", "low"},
		{"note", "note"},
		{"none", "note"},
		{"unknown", "medium"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeSeverity(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
