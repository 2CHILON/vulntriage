package scoring

import "encoding/json"

// Input represents a finding's attributes for scoring.
type Input struct {
	Severity           string
	Analysis           *AnalysisInput
	ReachabilityStatus string
	Kind               string
	File               string
}

// AnalysisInput contains LLM analysis fields for scoring.
type AnalysisInput struct {
	Status      string
	Exploitable *bool
	Confidence  *float64
}

// Component holds a single scoring component's breakdown.
type Component struct {
	Name         string  `json:"name"`
	Value        float64 `json:"value"`
	Weight       float64 `json:"weight"`
	Contribution float64 `json:"contribution"`
	Note         string  `json:"note,omitempty"`
}

// Breakdown details the composition of a final score.
type Breakdown struct {
	Components  []Component `json:"components"`
	FinalScore  int         `json:"final_score"`
	WeightsUsed Weights     `json:"weights_used"`
}

// Result is the output of the Score function.
type Result struct {
	Score     int       `json:"score"`
	Priority  string    `json:"priority"`
	Breakdown Breakdown `json:"breakdown"`
}

// MarshalJSON ensures the Result marshals cleanly.
func (r Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	return json.Marshal(struct {
		*Alias
	}{
		Alias: (*Alias)(&r),
	})
}

// UnmarshalJSON ensures the Result unmarshals cleanly.
func (r *Result) UnmarshalJSON(data []byte) error {
	type Alias Result
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	return json.Unmarshal(data, &aux)
}
