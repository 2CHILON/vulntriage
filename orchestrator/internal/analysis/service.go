package analysis

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// AnalysisStore defines methods needed to store analysis results.
type AnalysisStore interface {
	ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error)
	UpsertAnalysis(ctx context.Context, analysis *Analysis) error
	GetAnalysis(ctx context.Context, findingID string) (*Analysis, error)
}

// ContextBuilder defines the interface for building context.
type ContextBuilder interface {
	Build(f model.Finding) contextbuilder.Context
}

// LLMClient defines the interface for LLM analysis.
type LLMClient interface {
	Analyze(ctx context.Context, req *llmclient.AnalyzeRequest) (*llmclient.AnalyzeResponse, error)
	Health(ctx context.Context) error
}

// Analysis represents a stored analysis result.
type Analysis struct {
	FindingID     string
	ScanID        string
	Status        string // ok | analysis_failed | skipped
	Exploitable   *bool
	Confidence    *float64
	Priority      *string
	Reasoning     string
	SuggestedFix  string
	Provider      string
	PromptVersion string
	Error         string
	UpdatedAt     time.Time
}

// Summary holds statistics from an AnalyzeScan operation.
type Summary struct {
	ScanID            string
	Considered        int
	AnalyzedOK        int
	AnalysisFailed    int
	SkippedExisting   int
	SkippedLowSeverity int
	NotAttempted      int
	Provider          string
}

// Options for AnalyzeScan.
type Options struct {
	Force bool
}

// SeverityRanking returns the numeric rank of a severity level (higher = more severe).
func SeverityRanking(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// Service orchestrates the analysis of findings for a scan.
type Service struct {
	store               AnalysisStore
	builder             ContextBuilder
	client              LLMClient
	concurrency         int
	maxFindings         int
	minSeverityRanking  int
	overallTimeout      time.Duration
}

// NewService creates a new analysis service.
func NewService(
	store AnalysisStore,
	builder ContextBuilder,
	client LLMClient,
	concurrency int,
	maxFindings int,
	minSeverity string,
	overallTimeout time.Duration,
) *Service {
	return &Service{
		store:              store,
		builder:            builder,
		client:             client,
		concurrency:        concurrency,
		maxFindings:        maxFindings,
		minSeverityRanking: SeverityRanking(minSeverity),
		overallTimeout:     overallTimeout,
	}
}

// AnalyzeScan processes canonical findings for a scan and stores analysis results.
func (s *Service) AnalyzeScan(ctx context.Context, scanID string, opts Options) (*Summary, error) {
	summary := &Summary{
		ScanID:   scanID,
		Provider: "unknown",
	}

	// Apply overall timeout
	analyzeCtx, cancel := context.WithTimeout(ctx, s.overallTimeout)
	defer cancel()

	// Get canonical findings
	findings, err := s.store.ListCanonicalFindings(analyzeCtx, scanID)
	if err != nil {
		return summary, err
	}

	summary.Considered = len(findings)

	// Filter findings for analysis
	var toAnalyze []model.Finding
	for _, f := range findings {
		findingRanking := SeverityRanking(f.Severity)
		if findingRanking < s.minSeverityRanking {
			// Store as skipped
			analysis := &Analysis{
				FindingID:  f.ID,
				ScanID:     scanID,
				Status:     "skipped",
				Error:      "below minimum severity",
				UpdatedAt:  time.Now(),
				Provider:   "none",
				PromptVersion: "v1",
			}
			if err := s.store.UpsertAnalysis(analyzeCtx, analysis); err != nil {
				log.Printf("failed to store skipped analysis for %s: %v", f.ID, err)
			}
			summary.SkippedLowSeverity++
			continue
		}

		// Check if already analyzed with status ok
		if !opts.Force {
			existing, err := s.store.GetAnalysis(analyzeCtx, f.ID)
			if err != nil {
				log.Printf("failed to check existing analysis for %s: %v", f.ID, err)
				continue
			}
			if existing != nil && existing.Status == "ok" {
				summary.SkippedExisting++
				continue
			}
		}

		toAnalyze = append(toAnalyze, f)
	}

	// Cap at ANALYSIS_MAX_FINDINGS
	if len(toAnalyze) > s.maxFindings {
		summary.NotAttempted = len(toAnalyze) - s.maxFindings
		toAnalyze = toAnalyze[:s.maxFindings]
	}

	// Bounded concurrency channel
	semaphore := make(chan struct{}, s.concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, finding := range toAnalyze {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire slot

		go func(f model.Finding) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release slot

			// Check context deadline
			select {
			case <-analyzeCtx.Done():
				summary.NotAttempted++
				return
			default:
			}

			// Build context
			ctxResult := s.builder.Build(f)
			codeSnippet, depUsage := ctxResult.ToLLMContext()

			// Create request
			severity := f.Severity
			file := f.File
			line := f.Line
			cwe := f.CWE
			cve := f.CVE
			desc := f.Description

			req := &llmclient.AnalyzeRequest{
				Finding: llmclient.Finding{
					ID:          f.ID,
					Source:      f.Source,
					Severity:    &severity,
					File:        &file,
					Line:        &line,
					CWE:         &cwe,
					CVE:         &cve,
					Description: &desc,
				},
			}

			if codeSnippet != "" || depUsage != "" {
				req.Context = &llmclient.ContextInput{}
				if codeSnippet != "" {
					req.Context.CodeSnippet = &codeSnippet
				}
				if depUsage != "" {
					req.Context.DependencyUsage = &depUsage
				}
			}

			// Call LLM service
			resp, err := s.client.Analyze(analyzeCtx, req)
			if err != nil {
				analysis := &Analysis{
					FindingID:     f.ID,
					ScanID:        scanID,
					Status:        "analysis_failed",
					Error:         "analysis request failed",
					UpdatedAt:     time.Now(),
					Provider:      "unknown",
					PromptVersion: "v1",
				}
				if storeErr := s.store.UpsertAnalysis(analyzeCtx, analysis); storeErr != nil {
					log.Printf("failed to store failed analysis for %s: %v", f.ID, storeErr)
				}
				mu.Lock()
				summary.AnalysisFailed++
				mu.Unlock()
				return
			}

			log.Printf("analysis: finding=%s status=%s provider=%s", f.ID, resp.Status, resp.Provider)

			// Redact reasoning and suggested_fix
			reasoning := ""
			suggestedFix := ""
			if resp.Result != nil {
				reasoning, _ = contextbuilder.Redact(resp.Result.Reasoning)
				suggestedFix, _ = contextbuilder.Redact(resp.Result.SuggestedFix)
			}

			// Store result
			analysis := &Analysis{
				FindingID:     f.ID,
				ScanID:        scanID,
				Status:        resp.Status,
				Reasoning:     reasoning,
				SuggestedFix:  suggestedFix,
				Provider:      resp.Provider,
				PromptVersion: resp.PromptVersion,
				UpdatedAt:     time.Now(),
			}

			if resp.Status == "ok" && resp.Result != nil {
				analysis.Exploitable = &resp.Result.Exploitable
				analysis.Confidence = &resp.Result.Confidence
				analysis.Priority = &resp.Result.Priority
			}

			if resp.Error != nil {
				analysis.Error = *resp.Error
			}

			if err := s.store.UpsertAnalysis(analyzeCtx, analysis); err != nil {
				log.Printf("failed to store analysis for %s: %v", f.ID, err)
				mu.Lock()
				summary.AnalysisFailed++
				mu.Unlock()
				return
			}

			mu.Lock()
			if resp.Status == "ok" {
				summary.AnalyzedOK++
				summary.Provider = resp.Provider
			} else {
				summary.AnalysisFailed++
			}
			mu.Unlock()
		}(finding)
	}

	// Wait for all goroutines
	wg.Wait()

	// Count any remaining not_attempted from timeout
	select {
	case <-analyzeCtx.Done():
		// Context expired; some findings may not have been attempted
		break
	default:
	}

	return summary, nil
}
