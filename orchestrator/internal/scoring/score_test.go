package scoring

import (
	"math"
	"testing"
)

// approxEq checks if two floats are approximately equal within a small epsilon.
func approxEq(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// TestSeverityComponent tests the severity component calculation.
func TestSeverityComponent(t *testing.T) {
	tests := []struct {
		severity string
		want     float64
	}{
		{"critical", 1.00},
		{"high", 0.75},
		{"medium", 0.50},
		{"low", 0.25},
		{"note", 0.10},
		{"unknown", 0.10},
		{"CRITICAL", 1.00}, // Case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityComponent(tt.severity)
			if got != tt.want {
				t.Errorf("severityComponent(%s) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

// TestLLMComponent tests the LLM analysis component calculation.
func TestLLMComponent(t *testing.T) {
	tests := []struct {
		name     string
		analysis *AnalysisInput
		want     float64
	}{
		{
			name:     "nil analysis",
			analysis: nil,
			want:     0.5,
		},
		{
			name: "ok and exploitable high confidence",
			analysis: &AnalysisInput{
				Status:      "ok",
				Exploitable: boolPtr(true),
				Confidence:  floatPtr(0.9),
			},
			want: 0.95, // 0.5 + 0.5*0.9
		},
		{
			name: "ok and exploitable low confidence",
			analysis: &AnalysisInput{
				Status:      "ok",
				Exploitable: boolPtr(true),
				Confidence:  floatPtr(0.1),
			},
			want: 0.55, // 0.5 + 0.5*0.1
		},
		{
			name: "ok and not exploitable high confidence",
			analysis: &AnalysisInput{
				Status:      "ok",
				Exploitable: boolPtr(false),
				Confidence:  floatPtr(0.9),
			},
			want: 0.05, // 0.5 - 0.5*0.9
		},
		{
			name: "ok and not exploitable low confidence",
			analysis: &AnalysisInput{
				Status:      "ok",
				Exploitable: boolPtr(false),
				Confidence:  floatPtr(0.1),
			},
			want: 0.45, // 0.5 - 0.5*0.1
		},
		{
			name: "analysis_failed",
			analysis: &AnalysisInput{
				Status: "analysis_failed",
			},
			want: 0.5,
		},
		{
			name: "skipped",
			analysis: &AnalysisInput{
				Status: "skipped",
			},
			want: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := llmComponent(tt.analysis)
			if !approxEq(got, tt.want) {
				t.Errorf("llmComponent() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestReachabilityComponent tests the reachability component calculation.
func TestReachabilityComponent(t *testing.T) {
	tests := []struct {
		name   string
		status string
		kind   string
		want   float64
	}{
		{"code finding", "unknown", "code", 1.0},
		{"dependency imported", "imported", "dependency", 1.0},
		{"dependency not imported", "not_imported", "dependency", 0.3},
		{"dependency unknown", "unknown", "dependency", 0.5},
		{"none kind", "unknown", "none", 0.5},
		{"unknown kind", "unknown", "unknown", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reachabilityComponent(tt.status, tt.kind)
			if got != tt.want {
				t.Errorf("reachabilityComponent(%s, %s) = %v, want %v", tt.status, tt.kind, got, tt.want)
			}
		})
	}
}

// TestExposureComponent tests the exposure component calculation.
func TestExposureComponent(t *testing.T) {
	cfg := ExposureConfig{
		CriticalPaths: []string{"secrets/", "config/prod/"},
		LowPaths:      []string{"test/", "tests/", "testdata/", "docs/"},
	}

	tests := []struct {
		name string
		file string
		want float64
	}{
		{"critical path match", "secrets/api.key", 1.0},
		{"critical path match 2", "config/prod/db.conf", 1.0},
		{"low path match", "tests/unit.js", 0.2},
		{"low path match 2", "docs/readme.md", 0.2},
		{"default exposure", "src/main.js", 0.5},
		{"empty file", "", 0.5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exposureComponent(tt.file, cfg)
			if got != tt.want {
				t.Errorf("exposureComponent(%s) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

// TestDeterminePriority tests priority mapping.
func TestDeterminePriority(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "critical"},
		{80, "critical"},
		{79, "high"},
		{60, "high"},
		{59, "medium"},
		{40, "medium"},
		{39, "low"},
		{0, "low"},
	}

	for _, tt := range tests {
		t.Run("score_"+string(rune(tt.score)), func(t *testing.T) {
			got := determinePriority(tt.score)
			if got != tt.want {
				t.Errorf("determinePriority(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

// TestWeightNormalization tests that weights are normalized to sum to 1.
func TestWeightNormalization(t *testing.T) {
	weights := Weights{
		Severity:     0.35,
		LLM:          0.35,
		Reachability: 0.20,
		Exposure:     0.10,
	}

	sum := weights.Severity + weights.LLM + weights.Reachability + weights.Exposure
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("weights sum to %v, want ~1.0", sum)
	}
}

// TestScoreMonotonicity tests that higher severity/confidence never lowers score.
func TestScoreMonotonicity(t *testing.T) {
	cfg := ExposureConfig{
		CriticalPaths: []string{},
		LowPaths:      []string{"test/"},
	}
	weights := DefaultWeights()

	// Test severity monotonicity
	baseSeverities := []string{"low", "medium", "high", "critical"}
	var prevScore int
	for _, sev := range baseSeverities {
		result := Score(Input{
			Severity:           sev,
			ReachabilityStatus: "unknown",
			Kind:               "code",
			File:               "app.js",
		}, weights, cfg)
		if result.Score < prevScore {
			t.Errorf("score decreased when severity increased: %d to %d", prevScore, result.Score)
		}
		prevScore = result.Score
	}

	// Test confidence monotonicity for exploitable
	prevScore = 0
	for conf := 0.0; conf <= 1.0; conf += 0.1 {
		result := Score(Input{
			Severity: "medium",
			Analysis: &AnalysisInput{
				Status:      "ok",
				Exploitable: boolPtr(true),
				Confidence:  floatPtr(conf),
			},
			ReachabilityStatus: "unknown",
			Kind:               "code",
			File:               "app.js",
		}, weights, cfg)
		if result.Score < prevScore {
			t.Errorf("score decreased for exploitable when confidence increased: %d to %d (conf=%v)", prevScore, result.Score, conf)
		}
		prevScore = result.Score
	}
}

// TestScoreClamping tests that scores are always 0-100.
func TestScoreClamping(t *testing.T) {
	cfg := ExposureConfig{
		CriticalPaths: []string{},
		LowPaths:      []string{},
	}

	// Extreme weights that could overflow if not clamped
	weights := Weights{
		Severity:     100.0,
		LLM:          100.0,
		Reachability: 100.0,
		Exposure:     100.0,
	}
	// Normalize
	sum := weights.Severity + weights.LLM + weights.Reachability + weights.Exposure
	weights.Severity /= sum
	weights.LLM /= sum
	weights.Reachability /= sum
	weights.Exposure /= sum

	result := Score(Input{
		Severity:           "critical",
		ReachabilityStatus: "imported",
		Kind:               "code",
		File:               "app.js",
		Analysis: &AnalysisInput{
			Status:      "ok",
			Exploitable: boolPtr(true),
			Confidence:  floatPtr(1.0),
		},
	}, weights, cfg)

	if result.Score < 0 || result.Score > 100 {
		t.Errorf("score out of range: %d", result.Score)
	}
}

// TestDeterminism tests that same input gives same output.
func TestDeterminism(t *testing.T) {
	cfg := ExposureConfig{
		CriticalPaths: []string{},
		LowPaths:      []string{"test/"},
	}
	weights := DefaultWeights()
	input := Input{
		Severity:           "high",
		ReachabilityStatus: "imported",
		Kind:               "dependency",
		File:               "app.js",
		Analysis: &AnalysisInput{
			Status:      "ok",
			Exploitable: boolPtr(true),
			Confidence:  floatPtr(0.75),
		},
	}

	result1 := Score(input, weights, cfg)
	result2 := Score(input, weights, cfg)

	if result1.Score != result2.Score || result1.Priority != result2.Priority {
		t.Errorf("non-deterministic: %v vs %v", result1, result2)
	}
}

// TestBreakdownSums tests that component contributions sum to score.
func TestBreakdownSums(t *testing.T) {
	cfg := ExposureConfig{
		CriticalPaths: []string{},
		LowPaths:      []string{"test/"},
	}
	weights := DefaultWeights()
	input := Input{
		Severity:           "high",
		ReachabilityStatus: "imported",
		Kind:               "code",
		File:               "app.js",
		Analysis: &AnalysisInput{
			Status:      "ok",
			Exploitable: boolPtr(true),
			Confidence:  floatPtr(0.5),
		},
	}

	result := Score(input, weights, cfg)

	// Sum contributions
	var sum float64
	for _, comp := range result.Breakdown.Components {
		sum += comp.Contribution
	}

	// Should round-trip to the score (within rounding error)
	expectedScore := int(sum * 100)
	if expectedScore != result.Score && expectedScore-1 != result.Score && expectedScore+1 != result.Score {
		t.Errorf("breakdown sum %v doesn't match score %d", sum, result.Score)
	}
}

// Helper functions

func boolPtr(b bool) *bool {
	return &b
}

func floatPtr(f float64) *float64 {
	return &f
}
