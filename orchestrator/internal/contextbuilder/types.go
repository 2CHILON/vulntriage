package contextbuilder

// Config holds configuration for the context builder.
type Config struct {
	SourceRoot      string // Repository root path (e.g., /repo); if empty, return Kind "none"
	ContextLines    int    // Number of lines before and after the flagged line (default 20)
	MaxContextChars int    // Max length of snippet after redaction (default 8000)
	MaxFileBytes    int    // Max file size to read (default 1048576 = 1MB)
	MaxFilesScanned int    // Max files to scan for imports (default 5000)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		SourceRoot:      "",
		ContextLines:    20,
		MaxContextChars: 8000,
		MaxFileBytes:    1048576,
		MaxFilesScanned: 5000,
	}
}

// Reachability describes how a dependency is used in the codebase.
type Reachability struct {
	Package      string   `json:"package"`       // Package name (e.g., "lodash", "yaml")
	Status       string   `json:"status"`        // "imported", "not_imported", or "unknown"
	Evidence     []string `json:"evidence"`      // Up to 5 proof lines (e.g., "app.js:5: import lodash from 'lodash'")
	FilesScanned int      `json:"files_scanned"` // Number of files scanned
}

// Context represents the safe context to send to the LLM service.
type Context struct {
	FindingID        string        `json:"finding_id"`
	Kind             string        `json:"kind"` // "code", "dependency", or "none"
	CodeSnippet      string        `json:"code_snippet,omitempty"`
	SnippetStartLine int           `json:"snippet_start_line,omitempty"`
	SnippetEndLine   int           `json:"snippet_end_line,omitempty"`
	DependencyUsage  string        `json:"dependency_usage,omitempty"`
	Reachability     *Reachability `json:"reachability,omitempty"`
	RedactionCount   int           `json:"redaction_count"`           // Number of secrets redacted
	WithheldReason   string        `json:"withheld_reason,omitempty"` // Why context was not provided
}

// ToLLMContext returns the two strings the Python LLM service expects.
func (c *Context) ToLLMContext() (codeSnippet, dependencyUsage string) {
	return c.CodeSnippet, c.DependencyUsage
}
