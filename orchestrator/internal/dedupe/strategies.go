package dedupe

import (
	"fmt"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Strategy defines how findings should be matched for deduplication.
type Strategy interface {
	// Name returns the strategy name.
	Name() string
	// Match returns true if two findings should be considered duplicates.
	Match(a, b *model.Finding) bool
	// Priority ranks findings for canonical selection (higher is better).
	Priority(f *model.Finding) int
}

// ExactMatchStrategy requires identical file, line, and description.
type ExactMatchStrategy struct{}

func (s *ExactMatchStrategy) Name() string {
	return "exact_match"
}

func (s *ExactMatchStrategy) Match(a, b *model.Finding) bool {
	return a.File == b.File &&
		a.Line == b.Line &&
		a.Description == b.Description
}

func (s *ExactMatchStrategy) Priority(f *model.Finding) int {
	// Prefer CVE findings, then CWE, then source priority
	score := 0
	if f.CVE != "" {
		score += 100
	}
	if f.CWE != "" {
		score += 50
	}
	// Prefer trivy > semgrep > zap > depcheck
	switch f.Source {
	case "trivy":
		score += 30
	case "semgrep":
		score += 20
	case "zap":
		score += 10
	}
	return score
}

// LocationAndCVEStrategy matches by file+line and shared CVE/CWE.
type LocationAndCVEStrategy struct{}

func (s *LocationAndCVEStrategy) Name() string {
	return "location_and_cve"
}

func (s *LocationAndCVEStrategy) Match(a, b *model.Finding) bool {
	// Must be same location
	if a.File != b.File || a.Line != b.Line {
		return false
	}
	// If both have CVE, must match
	if a.CVE != "" && b.CVE != "" {
		return a.CVE == b.CVE
	}
	// If both have CWE, must match
	if a.CWE != "" && b.CWE != "" {
		return a.CWE == b.CWE
	}
	// If only one has CVE/CWE, they can still match (conservative)
	return true
}

func (s *LocationAndCVEStrategy) Priority(f *model.Finding) int {
	score := 0
	if f.CVE != "" {
		score += 100
	}
	if f.CWE != "" {
		score += 50
	}
	switch f.Source {
	case "trivy":
		score += 30
	case "semgrep":
		score += 20
	case "zap":
		score += 10
	}
	return score
}

// CVEOnlyStrategy matches findings that share the same CVE identifier.
type CVEOnlyStrategy struct{}

func (s *CVEOnlyStrategy) Name() string {
	return "cve_only"
}

func (s *CVEOnlyStrategy) Match(a, b *model.Finding) bool {
	return a.CVE != "" && a.CVE == b.CVE
}

func (s *CVEOnlyStrategy) Priority(f *model.Finding) int {
	// Prefer trivy > semgrep > zap > depcheck for CVE findings
	switch f.Source {
	case "trivy":
		return 100
	case "depcheck":
		return 90
	case "semgrep":
		return 70
	case "zap":
		return 60
	default:
		return 50
	}
}

// CWEOnlyStrategy matches findings that share the same CWE and location.
type CWEOnlyStrategy struct{}

func (s *CWEOnlyStrategy) Name() string {
	return "cwe_only"
}

func (s *CWEOnlyStrategy) Match(a, b *model.Finding) bool {
	if a.CWE == "" || a.CWE != b.CWE {
		return false
	}
	// Same location is required for CWE matches
	return a.File == b.File && a.Line == b.Line
}

func (s *CWEOnlyStrategy) Priority(f *model.Finding) int {
	switch f.Source {
	case "semgrep":
		return 100
	case "zap":
		return 90
	case "trivy":
		return 70
	default:
		return 50
	}
}

// DefaultStrategy combines multiple approaches in a sensible order.
// Tries exact match first, then location+cve, then cve-only.
type DefaultStrategy struct {
	strategies []Strategy
}

func NewDefaultStrategy() *DefaultStrategy {
	return &DefaultStrategy{
		strategies: []Strategy{
			&ExactMatchStrategy{},
			&LocationAndCVEStrategy{},
			&CVEOnlyStrategy{},
		},
	}
}

func (s *DefaultStrategy) Name() string {
	return "default"
}

func (s *DefaultStrategy) Match(a, b *model.Finding) bool {
	for _, strat := range s.strategies {
		if strat.Match(a, b) {
			return true
		}
	}
	return false
}

func (s *DefaultStrategy) Priority(f *model.Finding) int {
	// Use exact match priority as the base
	return (&ExactMatchStrategy{}).Priority(f)
}

// GetStrategy returns a deduplication strategy by name.
func GetStrategy(name string) (Strategy, error) {
	switch name {
	case "exact_match":
		return &ExactMatchStrategy{}, nil
	case "location_and_cve":
		return &LocationAndCVEStrategy{}, nil
	case "cve_only":
		return &CVEOnlyStrategy{}, nil
	case "cwe_only":
		return &CWEOnlyStrategy{}, nil
	case "default":
		return NewDefaultStrategy(), nil
	default:
		return nil, fmt.Errorf("unknown strategy: %s", name)
	}
}
