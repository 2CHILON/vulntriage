package scoring

import (
	"log"
	"strconv"
	"strings"
)

// Weights holds the normalized scoring weights.
type Weights struct {
	Severity     float64 `json:"severity"`
	LLM          float64 `json:"llm"`
	Reachability float64 `json:"reachability"`
	Exposure     float64 `json:"exposure"`
}

// DefaultWeights returns the default weights.
func DefaultWeights() Weights {
	return Weights{
		Severity:     0.35,
		LLM:          0.35,
		Reachability: 0.20,
		Exposure:     0.10,
	}
}

// LoadWeights loads weights from environment variables.
// If any value is invalid, uses defaults and logs a warning.
// Normalizes so that the sum equals 1.0.
func LoadWeights(getenv func(string) string) Weights {
	defaults := DefaultWeights()

	// Parse each weight, using defaults if parsing fails
	severityStr := getenv("SCORE_WEIGHT_SEVERITY")
	if severityStr == "" {
		severityStr = "0.35"
	}

	llmStr := getenv("SCORE_WEIGHT_LLM")
	if llmStr == "" {
		llmStr = "0.35"
	}

	reachabilityStr := getenv("SCORE_WEIGHT_REACHABILITY")
	if reachabilityStr == "" {
		reachabilityStr = "0.20"
	}

	exposureStr := getenv("SCORE_WEIGHT_EXPOSURE")
	if exposureStr == "" {
		exposureStr = "0.10"
	}

	w := Weights{}
	var parseErr error

	w.Severity, parseErr = strconv.ParseFloat(severityStr, 64)
	if parseErr != nil || w.Severity < 0 {
		w.Severity = defaults.Severity
		log.Printf("warning: invalid SCORE_WEIGHT_SEVERITY, using default %.2f", defaults.Severity)
	}

	w.LLM, parseErr = strconv.ParseFloat(llmStr, 64)
	if parseErr != nil || w.LLM < 0 {
		w.LLM = defaults.LLM
		log.Printf("warning: invalid SCORE_WEIGHT_LLM, using default %.2f", defaults.LLM)
	}

	w.Reachability, parseErr = strconv.ParseFloat(reachabilityStr, 64)
	if parseErr != nil || w.Reachability < 0 {
		w.Reachability = defaults.Reachability
		log.Printf("warning: invalid SCORE_WEIGHT_REACHABILITY, using default %.2f", defaults.Reachability)
	}

	w.Exposure, parseErr = strconv.ParseFloat(exposureStr, 64)
	if parseErr != nil || w.Exposure < 0 {
		w.Exposure = defaults.Exposure
		log.Printf("warning: invalid SCORE_WEIGHT_EXPOSURE, using default %.2f", defaults.Exposure)
	}

	// Check sum > 0
	sum := w.Severity + w.LLM + w.Reachability + w.Exposure
	if sum <= 0 {
		log.Printf("warning: weight sum is zero or negative, using defaults")
		w = defaults
		sum = w.Severity + w.LLM + w.Reachability + w.Exposure
	}

	// Normalize so sum = 1.0
	w.Severity /= sum
	w.LLM /= sum
	w.Reachability /= sum
	w.Exposure /= sum

	return w
}

// ExposureConfig holds exposure path configurations.
type ExposureConfig struct {
	CriticalPaths []string
	LowPaths      []string
}

// LoadExposureConfig loads exposure configuration from env.
func LoadExposureConfig(getenv func(string) string) ExposureConfig {
	criticalStr := getenv("EXPOSURE_CRITICAL_PATHS")
	lowStr := getenv("EXPOSURE_LOW_PATHS")
	if lowStr == "" {
		lowStr = "test/,tests/,testdata/,spec/,docs/,examples/"
	}

	var critical, low []string

	if criticalStr != "" {
		for _, p := range strings.Split(criticalStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				critical = append(critical, p)
			}
		}
	}

	if lowStr != "" {
		for _, p := range strings.Split(lowStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				low = append(low, p)
			}
		}
	}

	return ExposureConfig{
		CriticalPaths: critical,
		LowPaths:      low,
	}
}
