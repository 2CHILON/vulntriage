package parsers

import (
	"os"
	"strings"
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

// TestStableIDWithDifferentSources verifies that the same CVE/file/line from two
// different sources produces different IDs (case 1 from requirements).
func TestStableIDWithDifferentSources(t *testing.T) {
	// Create SARIF with the same finding from two different sources
	trivy := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "trivy",
					"rules": [{
						"id": "CVE-2024-1234",
						"defaultConfiguration": {"level": "high"}
					}]
				}
			},
			"results": [{
				"ruleId": "CVE-2024-1234",
				"message": {"text": "SQL injection"},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "app.go"},
						"region": {"startLine": 42, "startColumn": 5}
					}
				}]
			}]
		}]
	}`)

	semgrep := []byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {
				"driver": {
					"name": "semgrep",
					"rules": [{
						"id": "CVE-2024-1234",
						"defaultConfiguration": {"level": "high"}
					}]
				}
			},
			"results": [{
				"ruleId": "CVE-2024-1234",
				"message": {"text": "SQL injection"},
				"locations": [{
					"physicalLocation": {
						"artifactLocation": {"uri": "app.go"},
						"region": {"startLine": 42, "startColumn": 5}
					}
				}]
			}]
		}]
	}`)

	trivyFindings, err := ParseSARIF(trivy, "scan-123")
	if err != nil {
		t.Fatalf("failed to parse trivy SARIF: %v", err)
	}
	if len(trivyFindings) != 1 {
		t.Fatalf("expected 1 trivy finding, got %d", len(trivyFindings))
	}

	semgrepFindings, err := ParseSARIF(semgrep, "scan-123")
	if err != nil {
		t.Fatalf("failed to parse semgrep SARIF: %v", err)
	}
	if len(semgrepFindings) != 1 {
		t.Fatalf("expected 1 semgrep finding, got %d", len(semgrepFindings))
	}

	// Different sources must produce different IDs even with identical CVE/file/line/message
	if trivyFindings[0].ID == semgrepFindings[0].ID {
		t.Errorf("trivy and semgrep findings have same ID %q, should differ", trivyFindings[0].ID)
	}

	// But all other fields should match for deduplication to work
	if trivyFindings[0].CVE != semgrepFindings[0].CVE {
		t.Errorf("CVE mismatch: trivy %q vs semgrep %q", trivyFindings[0].CVE, semgrepFindings[0].CVE)
	}
	if trivyFindings[0].File != semgrepFindings[0].File {
		t.Errorf("File mismatch: trivy %q vs semgrep %q", trivyFindings[0].File, semgrepFindings[0].File)
	}
	if trivyFindings[0].Line != semgrepFindings[0].Line {
		t.Errorf("Line mismatch: trivy %d vs semgrep %d", trivyFindings[0].Line, semgrepFindings[0].Line)
	}
}

// TestIDCollisionOrdinalSuffix verifies that two findings with identical hash within
// the same upload get deterministic ordinal suffixes (case 6 from requirements).
func TestIDCollisionOrdinalSuffix(t *testing.T) {
	// Two results identical in rule, file, line, column and message.
	result := `{"ruleId":"rule1","message":{"text":"same issue"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.go"},"region":{"startLine":42,"startColumn":5}}}]}`
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"trivy","rules":[{"id":"rule1","defaultConfiguration":{"level":"high"}}]}},"results":[` + result + `,` + result + `]}]}`)

	first, err := ParseSARIF(sarif, "scan-1")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("expected 2 findings (none dropped), got %d", len(first))
	}
	if first[0].ID == first[1].ID {
		t.Fatalf("identical results must get different IDs, both got %q", first[0].ID)
	}
	if !strings.HasPrefix(first[1].ID, first[0].ID+"-") {
		t.Errorf("second ID %q should be the first ID plus an ordinal suffix", first[1].ID)
	}

	second, err := ParseSARIF(sarif, "scan-1")
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}
	for i := range first {
		if first[i].ID != second[i].ID {
			t.Errorf("IDs not deterministic at %d: %q vs %q", i, first[i].ID, second[i].ID)
		}
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
