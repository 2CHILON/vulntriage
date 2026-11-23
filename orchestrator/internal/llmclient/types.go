// Package llmclient is the HTTP client for the Python LLM service.
// JSON keys mirror llm-service/llm_service/app/schemas.py exactly; the service
// forbids extra keys, so every field here is required to match.
package llmclient

// Finding mirrors schemas.Finding. Optional fields are sent as JSON null when empty.
type Finding struct {
	ID          string  `json:"id"`
	Source      string  `json:"source"`
	Severity    *string `json:"severity"`
	File        *string `json:"file"`
	Line        *int    `json:"line"`
	CWE         *string `json:"cwe"`
	CVE         *string `json:"cve"`
	Description *string `json:"description"`
}

// Context mirrors schemas.ContextInput.
type Context struct {
	CodeSnippet     *string `json:"code_snippet"`
	DependencyUsage *string `json:"dependency_usage"`
}

// Request mirrors schemas.AnalyzeRequest.
type Request struct {
	Finding Finding  `json:"finding"`
	Context *Context `json:"context"`
}

// Result mirrors schemas.AnalysisResult.
type Result struct {
	Exploitable  bool    `json:"exploitable"`
	Confidence   float64 `json:"confidence"`
	Reasoning    string  `json:"reasoning"`
	SuggestedFix string  `json:"suggested_fix"`
	Priority     string  `json:"priority"`
}

// Response mirrors schemas.AnalyzeResponse.
type Response struct {
	FindingID     string  `json:"finding_id"`
	Status        string  `json:"status"`
	Result        *Result `json:"result"`
	Error         *string `json:"error"`
	Provider      string  `json:"provider"`
	PromptVersion string  `json:"prompt_version"`
}

// Response status values accepted from the service.
const (
	StatusOK             = "ok"
	StatusAnalysisFailed = "analysis_failed"
)

// StringPtr returns nil for an empty string, otherwise a pointer to s.
func StringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// LinePtr returns nil for a non-positive line number.
func LinePtr(line int) *int {
	if line <= 0 {
		return nil
	}
	return &line
}
