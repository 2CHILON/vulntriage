package parsers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// SARIFResult represents a result in SARIF format.
type SARIFResult struct {
	RuleID  string `json:"ruleId"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				EndLine     int `json:"endLine"`
				StartColumn int `json:"startColumn"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRule represents a rule definition in SARIF.
type SARIFRule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	HelpURI   string `json:"helpUri"`
	ShortDesc struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDesc struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	DefaultConfig struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFRun represents a run in SARIF.
type SARIFRun struct {
	Tool struct {
		Driver struct {
			Name  string      `json:"name"`
			Rules []SARIFRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFReport represents the SARIF report structure.
type SARIFReport struct {
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// ParseSARIF parses a SARIF JSON byte array and returns Finding structs.
// Findings within this upload are assigned IDs using a stable hash scheme to detect
// and handle collisions within the same upload (e.g., same ruleId from different sources).
func ParseSARIF(data []byte, scanID string) ([]model.Finding, error) {
	var report SARIFReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SARIF: %w", err)
	}

	var findings []model.Finding
	now := time.Now().UTC()
	idOrdinals := make(map[string]int) // Track collisions within this upload

	for _, run := range report.Runs {
		// Build rule map for quick lookup
		ruleMap := make(map[string]SARIFRule)
		for _, rule := range run.Tool.Driver.Rules {
			ruleMap[rule.ID] = rule
		}

		for _, result := range run.Results {
			rule, exists := ruleMap[result.RuleID]
			if !exists {
				continue
			}

			file := ""
			line := 0
			column := 0
			if len(result.Locations) > 0 {
				file = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
				line = result.Locations[0].PhysicalLocation.Region.StartLine
				column = result.Locations[0].PhysicalLocation.Region.StartColumn
			}

			severity := extractSeverity(rule, result)
			cve := extractCVE(rule.ID)
			cwe := extractCWE(rule.Properties)
			msg := result.Message.Text

			// Generate stable ID; handle collisions with ordinal suffix
			baseID := generateStableID(scanID, run.Tool.Driver.Name, result.RuleID, file, line, column, msg, 0)
			id := baseID
			ordinal := 1
			for idOrdinals[id] > 0 {
				id = generateStableID(scanID, run.Tool.Driver.Name, result.RuleID, file, line, column, msg, ordinal)
				ordinal++
			}
			idOrdinals[id]++

			finding := model.Finding{
				ID:          id,
				ScanID:      scanID,
				Source:      run.Tool.Driver.Name,
				Severity:    severity,
				File:        file,
				Line:        line,
				CWE:         cwe,
				CVE:         cve,
				Description: msg,
				CreatedAt:   now,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// generateStableID creates a stable hash-based ID from scan_id, source, ruleId, file, line, column, message.
// If ordinal > 0, appends it to the ID to handle collisions within the same upload.
func generateStableID(scanID, source, ruleID, file string, line, column int, message string, ordinal int) string {
	// Create stable hash input from all distinguishing fields
	input := fmt.Sprintf("%s|%s|%s|%s|%d|%d|%s", scanID, source, ruleID, file, line, column, message)
	hash := sha256.Sum256([]byte(input))
	hashStr := hex.EncodeToString(hash[:])

	if ordinal == 0 {
		return hashStr
	}
	return fmt.Sprintf("%s-%d", hashStr, ordinal)
}

// extractSeverity returns the severity level from rule or result properties.
func extractSeverity(rule SARIFRule, result SARIFResult) string {
	// First try result properties
	if severity, ok := result.Properties["security-severity"].(string); ok && severity != "" {
		return normalizeSeverity(severity)
	}

	// Then rule properties
	if severity, ok := rule.Properties["security-severity"].(string); ok && severity != "" {
		return normalizeSeverity(severity)
	}

	// Fall back to default rule configuration level
	level := rule.DefaultConfig.Level
	if level != "" {
		return normalizeSeverity(level)
	}

	return "medium"
}

// normalizeSeverity converts various severity formats to our standard set.
func normalizeSeverity(sev string) string {
	lower := strings.ToLower(sev)
	switch {
	case lower == "critical" || lower == "5":
		return "critical"
	case lower == "high" || lower == "4":
		return "high"
	case lower == "medium" || lower == "warning" || lower == "3":
		return "medium"
	case lower == "low" || lower == "2":
		return "low"
	case lower == "note" || lower == "none" || lower == "1" || lower == "0":
		return "note"
	default:
		return "medium"
	}
}

// extractCVE returns the CVE ID if present in the rule.
func extractCVE(ruleID string) string {
	if strings.HasPrefix(ruleID, "CVE-") {
		return ruleID
	}
	return ""
}

// extractCWE returns the CWE ID from properties if present.
func extractCWE(properties map[string]interface{}) string {
	if properties == nil {
		return ""
	}
	if cwe, ok := properties["cwe"].(string); ok {
		return cwe
	}
	return ""
}
