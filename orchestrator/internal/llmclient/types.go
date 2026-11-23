package llmclient

// Finding represents a vulnerability finding sent to the LLM service.
type Finding struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Severity    *string `json:"severity,omitempty"`
	File        *string `json:"file,omitempty"`
	Line        *int `json:"line,omitempty"`
	CWE         *string `json:"cwe,omitempty"`
	CVE         *string `json:"cve,omitempty"`
	Description *string `json:"description,omitempty"`
}

// ContextInput represents optional code context.
type ContextInput struct {
	CodeSnippet     *string `json:"code_snippet,omitempty"`
	DependencyUsage *string `json:"dependency_usage,omitempty"`
}

// AnalyzeRequest is the request to the LLM service.
type AnalyzeRequest struct {
	Finding Finding       `json:"finding"`
	Context *ContextInput `json:"context,omitempty"`
}

// AnalysisResult represents the LLM analysis result.
type AnalysisResult struct {
	Exploitable bool   `json:"exploitable"`
	Confidence  float64 `json:"confidence"`
	Reasoning   string  `json:"reasoning"`
	SuggestedFix string `json:"suggested_fix"`
	Priority    string  `json:"priority"`
}

// AnalyzeResponse is the response from the LLM service.
type AnalyzeResponse struct {
	FindingID     string          `json:"finding_id"`
	Status        string          `json:"status"`
	Result        *AnalysisResult `json:"result,omitempty"`
	Error         *string         `json:"error,omitempty"`
	Provider      string          `json:"provider"`
	PromptVersion string          `json:"prompt_version"`
}
