package scoring

import (
	"math"
	"strings"
)

// Score computes a risk score and priority for a finding.
// Pure function: no logging, no I/O, no randomness, no clock.
func Score(input Input, weights Weights, exposureCfg ExposureConfig) Result {
	// Compute each component
	severityComp := severityComponent(input.Severity)
	llmComp := llmComponent(input.Analysis)
	reachabilityComp := reachabilityComponent(input.ReachabilityStatus, input.Kind)
	exposureComp := exposureComponent(input.File, exposureCfg)

	// Weighted sum
	score := weights.Severity*severityComp +
		weights.LLM*llmComp +
		weights.Reachability*reachabilityComp +
		weights.Exposure*exposureComp

	// Clamp to [0, 1]
	if score < 0 {
		score = 0
	} else if score > 1 {
		score = 1
	}

	// Convert to 0-100 and round
	scoreInt := int(math.Round(score * 100))
	if scoreInt > 100 {
		scoreInt = 100
	}
	if scoreInt < 0 {
		scoreInt = 0
	}

	// Determine priority
	priority := determinePriority(scoreInt)

	// Build breakdown with contributions
	components := []Component{
		{
			Name:         "severity",
			Value:        severityComp,
			Weight:       weights.Severity,
			Contribution: weights.Severity * severityComp,
		},
		{
			Name:         "llm",
			Value:        llmComp,
			Weight:       weights.LLM,
			Contribution: weights.LLM * llmComp,
			Note:         llmNote(input.Analysis),
		},
		{
			Name:         "reachability",
			Value:        reachabilityComp,
			Weight:       weights.Reachability,
			Contribution: weights.Reachability * reachabilityComp,
		},
		{
			Name:         "exposure",
			Value:        exposureComp,
			Weight:       weights.Exposure,
			Contribution: weights.Exposure * exposureComp,
		},
	}

	breakdown := Breakdown{
		Components:  components,
		FinalScore:  scoreInt,
		WeightsUsed: weights,
	}

	return Result{
		Score:     scoreInt,
		Priority:  priority,
		Breakdown: breakdown,
	}
}

// severityComponent maps severity strings to component values.
func severityComponent(severity string) float64 {
	switch strings.ToLower(severity) {
	case "critical":
		return 1.00
	case "high":
		return 0.75
	case "medium":
		return 0.50
	case "low":
		return 0.25
	case "note":
		return 0.10
	default:
		return 0.10
	}
}

// llmComponent computes the LLM analysis component.
func llmComponent(analysis *AnalysisInput) float64 {
	if analysis == nil {
		return 0.5
	}

	switch analysis.Status {
	case "ok":
		if analysis.Exploitable == nil || analysis.Confidence == nil {
			return 0.5
		}
		if *analysis.Exploitable {
			// 0.5 + 0.5*confidence
			return 0.5 + 0.5*(*analysis.Confidence)
		}
		// Not exploitable: 0.5 - 0.5*confidence
		return 0.5 - 0.5*(*analysis.Confidence)

	case "analysis_failed", "skipped":
		return 0.5

	default:
		// No analysis
		return 0.5
	}
}

// llmNote returns a note if applicable for the LLM component.
func llmNote(analysis *AnalysisInput) string {
	if analysis == nil || analysis.Status != "ok" {
		return "LLM verdict unavailable"
	}
	return ""
}

// reachabilityComponent computes the reachability component.
func reachabilityComponent(status string, kind string) float64 {
	if kind == "code" {
		return 1.0
	}

	if kind == "dependency" {
		switch strings.ToLower(status) {
		case "imported":
			return 1.0
		case "not_imported":
			return 0.3
		default:
			return 0.5
		}
	}

	// kind == "none" or unknown
	return 0.5
}

// exposureComponent computes the exposure component based on file path.
func exposureComponent(file string, cfg ExposureConfig) float64 {
	normalized := normalizePath(file)

	// Check critical paths first (highest priority)
	for _, prefix := range cfg.CriticalPaths {
		if strings.HasPrefix(normalized, prefix) {
			return 1.0
		}
	}

	// Check low paths
	for _, prefix := range cfg.LowPaths {
		if strings.HasPrefix(normalized, prefix) {
			return 0.2
		}
	}

	// Default exposure
	return 0.5
}

// normalizePath normalizes a file path for prefix matching.
// Reuses the same normalization as dedupe package.
func normalizePath(file string) string {
	if file == "" {
		return ""
	}
	// Convert backslashes to forward slashes
	normalized := strings.ReplaceAll(file, "\\", "/")
	// Remove leading slashes
	normalized = strings.TrimLeft(normalized, "/")
	return normalized
}

// determinePriority maps score to priority level.
func determinePriority(score int) string {
	if score >= 80 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 40 {
		return "medium"
	}
	return "low"
}
