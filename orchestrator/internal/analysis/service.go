// Package analysis sends canonical findings of a scan to the LLM service and
// stores one current analysis per finding.
package analysis

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// Defaults for Config fields left at their zero value.
const (
	DefaultConcurrency = 4
	DefaultMinSeverity = "medium"
	DefaultMaxFindings = 100
	DefaultTimeout     = 300 * time.Second

	belowMinSeverityError = "below minimum severity"
	maxErrorChars         = 500
	storeTimeout          = 5 * time.Second
)

// FindingSource lists the canonical findings of a scan.
type FindingSource interface {
	ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error)
}

// AnalysisStore reads and upserts the current analysis of a finding.
// GetAnalysis returns (nil, nil) when no analysis exists.
type AnalysisStore interface {
	GetAnalysis(ctx context.Context, findingID string) (*model.Analysis, error)
	UpsertAnalysis(ctx context.Context, a model.Analysis) error
}

// Store is everything AnalyzeScan needs from persistence.
type Store interface {
	FindingSource
	AnalysisStore
}

// ContextBuilder builds the redacted code or dependency context of a finding.
type ContextBuilder interface {
	Build(f model.Finding) contextbuilder.Context
}

// LLMClient sends one analysis request.
type LLMClient interface {
	Analyze(ctx context.Context, req llmclient.Request) (llmclient.Response, error)
}

// Config holds the cost and safety guards.
type Config struct {
	Concurrency int           // ANALYSIS_CONCURRENCY
	MinSeverity string        // ANALYSIS_MIN_SEVERITY
	MaxFindings int           // ANALYSIS_MAX_FINDINGS
	Timeout     time.Duration // ANALYSIS_TIMEOUT_SECONDS
}

// Options are per-run switches.
type Options struct {
	Force bool // re-analyze findings that already have status "ok"
}

// Summary reports what one run did. Every considered finding is counted in
// exactly one of the other counters.
type Summary struct {
	ScanID             string `json:"scan_id"`
	Considered         int    `json:"considered"`
	AnalyzedOK         int    `json:"analyzed_ok"`
	AnalysisFailed     int    `json:"analysis_failed"`
	SkippedExisting    int    `json:"skipped_existing"`
	SkippedLowSeverity int    `json:"skipped_low_severity"`
	NotAttempted       int    `json:"not_attempted"`
	Provider           string `json:"provider"`
}

// Service runs analyses.
type Service struct {
	cfg     Config
	store   Store
	builder ContextBuilder
	client  LLMClient
}

// NewService applies defaults to cfg and validates it.
func NewService(cfg Config, store Store, builder ContextBuilder, client LLMClient) (*Service, error) {
	if store == nil || builder == nil || client == nil {
		return nil, errors.New("analysis: store, builder and client are required")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = DefaultConcurrency
	}
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = DefaultMinSeverity
	}
	cfg.MinSeverity = strings.ToLower(strings.TrimSpace(cfg.MinSeverity))
	if !model.IsValidSeverityName(cfg.MinSeverity) {
		return nil, fmt.Errorf("analysis: invalid minimum severity %q", cfg.MinSeverity)
	}
	if cfg.MaxFindings <= 0 {
		cfg.MaxFindings = DefaultMaxFindings
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	return &Service{cfg: cfg, store: store, builder: builder, client: client}, nil
}

// Config returns the effective configuration (after defaults).
func (s *Service) Config() Config { return s.cfg }

// AnalyzeScan analyzes the canonical findings of scanID. Individual finding
// failures are recorded and never abort the run; an error is returned only when
// the findings or existing analyses cannot be read.
func (s *Service) AnalyzeScan(ctx context.Context, scanID string, opts Options) (Summary, error) {
	sum := Summary{ScanID: scanID}

	all, err := s.store.ListCanonicalFindings(ctx, scanID)
	if err != nil {
		return sum, fmt.Errorf("list canonical findings: %w", err)
	}
	// Defensive: never send a non-canonical finding, whatever the store returns.
	findings := make([]model.Finding, 0, len(all))
	for _, f := range all {
		if f.IsCanonical {
			findings = append(findings, f)
		}
	}
	// Most severe first so the MaxFindings cap keeps the important ones.
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := model.SeverityRank(findings[i].Severity), model.SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].ID < findings[j].ID
	})
	sum.Considered = len(findings)

	minRank := model.SeverityRank(s.cfg.MinSeverity)
	var toSend []model.Finding
	for _, f := range findings {
		existing, err := s.store.GetAnalysis(ctx, f.ID)
		if err != nil {
			return sum, fmt.Errorf("get analysis: %w", err)
		}
		switch {
		case existing != nil && existing.Status == model.AnalysisStatusOK && !opts.Force:
			sum.SkippedExisting++
		case model.SeverityRank(f.Severity) < minRank:
			s.save(ctx, model.Analysis{
				FindingID: f.ID, ScanID: scanID,
				Status: model.AnalysisStatusSkipped, Error: belowMinSeverityError,
			})
			sum.SkippedLowSeverity++
		default:
			toSend = append(toSend, f)
		}
	}
	if len(toSend) > s.cfg.MaxFindings {
		sum.NotAttempted += len(toSend) - s.cfg.MaxFindings
		toSend = toSend[:s.cfg.MaxFindings]
	}

	s.runWorkers(ctx, scanID, toSend, &sum)

	log.Printf("analysis: scan=%s considered=%d ok=%d failed=%d skipped_existing=%d skipped_low=%d not_attempted=%d",
		scanID, sum.Considered, sum.AnalyzedOK, sum.AnalysisFailed, sum.SkippedExisting, sum.SkippedLowSeverity, sum.NotAttempted)
	return sum, nil
}

type outcome int

const (
	outcomeOK outcome = iota
	outcomeFailed
	outcomeNotAttempted
)

// runWorkers analyzes toSend with bounded concurrency under the overall deadline.
func (s *Service) runWorkers(ctx context.Context, scanID string, toSend []model.Finding, sum *Summary) {
	if len(toSend) == 0 {
		return
	}
	runCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	var mu sync.Mutex
	record := func(o outcome, provider string) {
		mu.Lock()
		defer mu.Unlock()
		switch o {
		case outcomeOK:
			sum.AnalyzedOK++
		case outcomeFailed:
			sum.AnalysisFailed++
		case outcomeNotAttempted:
			sum.NotAttempted++
		}
		if provider != "" {
			sum.Provider = provider
		}
	}

	jobs := make(chan model.Finding)
	workers := s.cfg.Concurrency
	if workers > len(toSend) {
		workers = len(toSend)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				if runCtx.Err() != nil {
					record(outcomeNotAttempted, "")
					continue
				}
				record(s.analyzeOne(ctx, runCtx, scanID, f))
			}
		}()
	}

feed:
	for i, f := range toSend {
		select {
		case jobs <- f:
		case <-runCtx.Done():
			for range toSend[i:] {
				record(outcomeNotAttempted, "")
			}
			break feed
		}
	}
	close(jobs)
	wg.Wait()
}

// analyzeOne sends one finding and stores the outcome. baseCtx is used for the
// store write so finished results survive the overall deadline.
func (s *Service) analyzeOne(baseCtx, runCtx context.Context, scanID string, f model.Finding) (outcome, string) {
	built := s.builder.Build(f)
	code, dep := built.ToLLMContext()
	desc, _ := contextbuilder.Redact(f.Description)

	req := llmclient.Request{
		Finding: llmclient.Finding{
			ID:          f.ID,
			Source:      f.Source,
			Severity:    llmclient.StringPtr(f.Severity),
			File:        llmclient.StringPtr(f.File),
			Line:        llmclient.LinePtr(f.Line),
			CWE:         llmclient.StringPtr(f.CWE),
			CVE:         llmclient.StringPtr(f.CVE),
			Description: llmclient.StringPtr(desc),
		},
		Context: &llmclient.Context{
			CodeSnippet:     llmclient.StringPtr(code),
			DependencyUsage: llmclient.StringPtr(dep),
		},
	}

	resp, err := s.client.Analyze(runCtx, req)
	if err != nil {
		if runCtx.Err() != nil {
			// Overall deadline hit mid-request: leave it for the next run.
			log.Printf("analysis: finding=%s status=not_attempted", f.ID)
			return outcomeNotAttempted, ""
		}
		return s.saveFailed(baseCtx, scanID, f.ID, "", "", err.Error())
	}

	if resp.Status != llmclient.StatusOK || resp.Result == nil {
		msg := "analysis failed"
		if resp.Error != nil && *resp.Error != "" {
			msg = *resp.Error
		}
		return s.saveFailed(baseCtx, scanID, f.ID, resp.Provider, resp.PromptVersion, msg)
	}

	r := resp.Result
	reasoning, _ := contextbuilder.Redact(r.Reasoning)
	fix, _ := contextbuilder.Redact(r.SuggestedFix)
	exploitable, confidence, priority := r.Exploitable, r.Confidence, r.Priority
	a := model.Analysis{
		FindingID: f.ID, ScanID: scanID, Status: model.AnalysisStatusOK,
		Exploitable: &exploitable, Confidence: &confidence, Priority: &priority,
		Reasoning: reasoning, SuggestedFix: fix,
		Provider: resp.Provider, PromptVersion: resp.PromptVersion,
	}
	if !s.save(baseCtx, a) {
		return outcomeFailed, resp.Provider
	}
	log.Printf("analysis: finding=%s status=ok", f.ID)
	return outcomeOK, resp.Provider
}

func (s *Service) saveFailed(baseCtx context.Context, scanID, findingID, provider, promptVersion, msg string) (outcome, string) {
	s.save(baseCtx, model.Analysis{
		FindingID: findingID, ScanID: scanID, Status: model.AnalysisStatusFailed,
		Provider: provider, PromptVersion: promptVersion, Error: safeError(msg),
	})
	log.Printf("analysis: finding=%s status=analysis_failed", findingID)
	return outcomeFailed, provider
}

// save upserts with its own short timeout, detached from request cancellation.
func (s *Service) save(baseCtx context.Context, a model.Analysis) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), storeTimeout)
	defer cancel()
	if err := s.store.UpsertAnalysis(ctx, a); err != nil {
		log.Printf("analysis: finding=%s store_error", a.FindingID)
		return false
	}
	return true
}

// safeError redacts secret-like text and caps the length of an error message.
func safeError(msg string) string {
	msg, _ = contextbuilder.Redact(msg)
	if r := []rune(msg); len(r) > maxErrorChars {
		msg = string(r[:maxErrorChars]) + "…"
	}
	return msg
}
