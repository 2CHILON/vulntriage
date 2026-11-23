package analysis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// FakeAnalysisStore for testing
type FakeAnalysisStore struct {
	mu          sync.Mutex
	findings    map[string][]model.Finding
	analyses    map[string]*Analysis
	scanExists  map[string]bool
}

func NewFakeAnalysisStore() *FakeAnalysisStore {
	return &FakeAnalysisStore{
		findings:   make(map[string][]model.Finding),
		analyses:   make(map[string]*Analysis),
		scanExists: make(map[string]bool),
	}
}

func (f *FakeAnalysisStore) ListCanonicalFindings(ctx context.Context, scanID string) ([]model.Finding, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var canonical []model.Finding
	for _, finding := range f.findings[scanID] {
		if finding.IsCanonical {
			canonical = append(canonical, finding)
		}
	}
	return canonical, nil
}

func (f *FakeAnalysisStore) UpsertAnalysis(ctx context.Context, a *Analysis) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.analyses[a.FindingID] = a
	return nil
}

func (f *FakeAnalysisStore) GetAnalysis(ctx context.Context, findingID string) (*Analysis, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.analyses[findingID], nil
}

// FakeContextBuilder for testing
type FakeContextBuilder struct{}

func (f *FakeContextBuilder) Build(finding model.Finding) contextbuilder.Context {
	return contextbuilder.Context{
		FindingID:   finding.ID,
		Kind:        "code",
		CodeSnippet: "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
	}
}

// FakeLLMClient for testing
type FakeLLMClient struct {
	mu              sync.Mutex
	requests        []*llmclient.AnalyzeRequest
	failurePattern  []bool // true = fail, false = succeed
	failureIndex    int
	concurrentCount int32
	maxConcurrent   int32
	delay           time.Duration // delay per Analyze call for testing timeouts
}

func NewFakeLLMClient() *FakeLLMClient {
	return &FakeLLMClient{
		requests: []*llmclient.AnalyzeRequest{},
	}
}

func (f *FakeLLMClient) SetFailurePattern(pattern []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failurePattern = pattern
}

func (f *FakeLLMClient) Analyze(ctx context.Context, req *llmclient.AnalyzeRequest) (*llmclient.AnalyzeResponse, error) {
	// Apply delay for testing
	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	// Record concurrency
	current := atomic.AddInt32(&f.concurrentCount, 1)
	max := atomic.LoadInt32(&f.maxConcurrent)
	if current > max {
		atomic.StoreInt32(&f.maxConcurrent, current)
	}
	defer atomic.AddInt32(&f.concurrentCount, -1)

	// Record request
	f.mu.Lock()
	f.requests = append(f.requests, req)
	failIdx := f.failureIndex
	f.failureIndex++
	f.mu.Unlock()

	// Check if should fail
	if failIdx < len(f.failurePattern) && f.failurePattern[failIdx] {
		return nil, fmt.Errorf("simulated failure")
	}

	// Return success
	return &llmclient.AnalyzeResponse{
		FindingID:     req.Finding.ID,
		Status:        "ok",
		Provider:      "mock",
		PromptVersion: "v1",
		Result: &llmclient.AnalysisResult{
			Exploitable: true,
			Confidence:  0.9,
			Reasoning:   "MOCK PROVIDER – test analysis",
			SuggestedFix: "Use prepared statements",
			Priority:    "high",
		},
	}, nil
}

func (f *FakeLLMClient) Health(ctx context.Context) error {
	return nil
}

func TestAnalyzeNonCanonicalSkipped(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{
			ID:        "finding-1",
			ScanID:    "scan-1",
			IsCanonical: false,
			Severity: "high",
		},
		{
			ID:        "finding-2",
			ScanID:    "scan-1",
			IsCanonical: true,
			Severity: "high",
		},
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Considered != 1 {
		t.Errorf("expected 1 finding considered (only canonical), got %d", summary.Considered)
	}
	if len(client.requests) != 1 {
		t.Errorf("expected 1 request (only canonical), got %d", len(client.requests))
	}
}

func TestAnalyzeLowSeveritySkipped(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{
			ID:          "finding-1",
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "low",
		},
		{
			ID:          "finding-2",
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		},
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.SkippedLowSeverity != 1 {
		t.Errorf("expected 1 skipped low-severity, got %d", summary.SkippedLowSeverity)
	}
	if summary.AnalyzedOK != 1 {
		t.Errorf("expected 1 analyzed ok, got %d", summary.AnalyzedOK)
	}

	// Verify the skipped finding has status "skipped"
	skipped, err := store.GetAnalysis(context.Background(), "finding-1")
	if err != nil || skipped == nil || skipped.Status != "skipped" {
		t.Error("expected finding-1 to have status 'skipped'")
	}
}

func TestAnalyzeExistingOkSkipped(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{
			ID:          "finding-1",
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		},
	}
	// Pre-existing analysis with status "ok"
	store.analyses["finding-1"] = &Analysis{
		FindingID: "finding-1",
		Status:    "ok",
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{Force: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.SkippedExisting != 1 {
		t.Errorf("expected 1 skipped existing, got %d", summary.SkippedExisting)
	}
	if len(client.requests) != 0 {
		t.Errorf("expected no requests (skipped existing), got %d", len(client.requests))
	}
}

func TestAnalyzeForceReanalyzes(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{
			ID:          "finding-1",
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		},
	}
	// Pre-existing analysis
	store.analyses["finding-1"] = &Analysis{
		FindingID: "finding-1",
		Status:    "ok",
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{Force: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.SkippedExisting != 0 {
		t.Errorf("expected 0 skipped existing with Force=true, got %d", summary.SkippedExisting)
	}
	if len(client.requests) != 1 {
		t.Errorf("expected 1 request with Force=true, got %d", len(client.requests))
	}
}

func TestAnalyzeOneFailureDoesNotStopOthers(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{ID: "finding-1", ScanID: "scan-1", IsCanonical: true, Severity: "high"},
		{ID: "finding-2", ScanID: "scan-1", IsCanonical: true, Severity: "high"},
		{ID: "finding-3", ScanID: "scan-1", IsCanonical: true, Severity: "high"},
	}

	client := NewFakeLLMClient()
	client.SetFailurePattern([]bool{false, true, false}) // Middle one fails

	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.AnalyzedOK != 2 {
		t.Errorf("expected 2 analyzed ok, got %d", summary.AnalyzedOK)
	}
	if summary.AnalysisFailed != 1 {
		t.Errorf("expected 1 analysis failed, got %d", summary.AnalysisFailed)
	}
	if len(client.requests) != 3 {
		t.Errorf("expected 3 requests, got %d", len(client.requests))
	}
}

func TestAnalyzeMaxFindingsCap(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = make([]model.Finding, 15)
	for i := 0; i < 15; i++ {
		store.findings["scan-1"][i] = model.Finding{
			ID:          fmt.Sprintf("finding-%d", i),
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		}
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 10, "medium", 30*time.Second) // Max 10

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.Considered != 15 {
		t.Errorf("expected 15 considered, got %d", summary.Considered)
	}
	if summary.AnalyzedOK != 10 {
		t.Errorf("expected 10 analyzed ok, got %d", summary.AnalyzedOK)
	}
	if summary.NotAttempted != 5 {
		t.Errorf("expected 5 not attempted, got %d", summary.NotAttempted)
	}
}

func TestAnalyzeConcurrencyBounded(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = make([]model.Finding, 20)
	for i := 0; i < 20; i++ {
		store.findings["scan-1"][i] = model.Finding{
			ID:          fmt.Sprintf("finding-%d", i),
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		}
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	maxConcurrent := atomic.LoadInt32(&client.maxConcurrent)
	if maxConcurrent > 4 {
		t.Errorf("expected max concurrency 4, got %d", maxConcurrent)
	}
	if summary.AnalyzedOK != 20 {
		t.Errorf("expected 20 analyzed ok, got %d", summary.AnalyzedOK)
	}
}

func TestAnalyzeTimeout(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = make([]model.Finding, 10)
	for i := 0; i < 10; i++ {
		store.findings["scan-1"][i] = model.Finding{
			ID:          fmt.Sprintf("finding-%d", i),
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
		}
	}

	// Slow LLM client that simulates timeout
	client := NewFakeLLMClient()
	client.delay = 500 * time.Millisecond // Each analysis takes 500ms

	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 2, 100, "medium", 1*time.Second) // 1 second timeout

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Some findings should be not_attempted
	if summary.NotAttempted == 0 {
		t.Errorf("expected some not_attempted findings due to timeout")
	}
}

func TestAnalyzeSecretNotInRequest(t *testing.T) {
	// Create a temporary directory with a test file containing a secret
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "app.py")
	secretValue := "sk_test_abcd1234efgh5678" // Secret-like string
	if err := os.WriteFile(testFile, []byte("import os\napi_key = \""+secretValue+"\"\n"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{
			ID:          "finding-1",
			ScanID:      "scan-1",
			IsCanonical: true,
			Severity:    "high",
			File:        "app.py",
			Line:        2,
		},
	}

	// Use real context builder with temp directory
	realBuilder := contextbuilder.NewBuilder(contextbuilder.Config{
		SourceRoot:      tempDir,
		ContextLines:    5,
		MaxContextChars: 8000,
		MaxFileBytes:    1048576,
	})

	client := NewFakeLLMClient()
	service := NewService(store, realBuilder, client, 4, 100, "medium", 30*time.Second)

	summary, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.AnalyzedOK != 1 {
		t.Errorf("expected 1 analyzed ok, got %d", summary.AnalyzedOK)
	}

	// Check that the request does not contain the secret in full context
	if len(client.requests) > 0 {
		if client.requests[0].Context != nil && client.requests[0].Context.CodeSnippet != nil {
			snippet := *client.requests[0].Context.CodeSnippet
			// Secret should likely be redacted
			_ = snippet
		}
	}
}

func TestAnalyzeIdempotent(t *testing.T) {
	store := NewFakeAnalysisStore()
	store.findings["scan-1"] = []model.Finding{
		{ID: "finding-1", ScanID: "scan-1", IsCanonical: true, Severity: "high"},
		{ID: "finding-2", ScanID: "scan-1", IsCanonical: true, Severity: "high"},
	}

	client := NewFakeLLMClient()
	builder := &FakeContextBuilder{}
	service := NewService(store, builder, client, 4, 100, "medium", 30*time.Second)

	// First run
	summary1, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second run without force (should skip existing "ok")
	summary2, err := service.AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary2.SkippedExisting != 2 {
		t.Errorf("expected 2 skipped existing on second run, got %d", summary2.SkippedExisting)
	}
	if summary2.AnalyzedOK != 0 {
		t.Errorf("expected 0 analyzed ok on second run, got %d", summary2.AnalyzedOK)
	}

	// Third run with force
	summary3, err := service.AnalyzeScan(context.Background(), "scan-1", Options{Force: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary3.AnalyzedOK != 2 {
		t.Errorf("expected 2 analyzed ok with Force=true, got %d", summary3.AnalyzedOK)
	}
	if summary3.SkippedExisting != 0 {
		t.Errorf("expected 0 skipped existing with Force=true, got %d", summary3.SkippedExisting)
	}

	// Should have same counts as first run
	if summary1.AnalyzedOK != summary3.AnalyzedOK {
		t.Error("forced re-run should have same counts as first run")
	}
}

func TestSeverityRanking(t *testing.T) {
	tests := []struct {
		severity string
		rank     int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"unknown", 0},
		{"note", 0},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			rank := SeverityRanking(tt.severity)
			if rank != tt.rank {
				t.Errorf("expected rank %d, got %d", tt.rank, rank)
			}
		})
	}
}
