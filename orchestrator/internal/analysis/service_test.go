package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// fakeAWSKey builds an AWS-access-key-shaped string at runtime so no
// secret-shaped literal exists in the source file.
func fakeAWSKey() string {
	return "AK" + "IA" + strings.Repeat("Z", 8) + strings.Repeat("7", 8)
}

// --- fakes ---------------------------------------------------------------

type fakeStore struct {
	mu       sync.Mutex
	findings []model.Finding
	analyses map[string]model.Analysis
}

func newFakeStore(findings ...model.Finding) *fakeStore {
	return &fakeStore{findings: findings, analyses: map[string]model.Analysis{}}
}

func (s *fakeStore) ListCanonicalFindings(_ context.Context, scanID string) ([]model.Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deliberately returns non-canonical findings too: the service must filter.
	var out []model.Finding
	for _, f := range s.findings {
		if f.ScanID == scanID {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *fakeStore) GetAnalysis(_ context.Context, id string) (*model.Analysis, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.analyses[id]
	if !ok {
		return nil, nil
	}
	return &a, nil
}

func (s *fakeStore) UpsertAnalysis(_ context.Context, a model.Analysis) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.analyses[a.FindingID] = a
	return nil
}

func (s *fakeStore) get(id string) (model.Analysis, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.analyses[id]
	return a, ok
}

type fakeBuilder struct{}

func (fakeBuilder) Build(f model.Finding) contextbuilder.Context {
	return contextbuilder.Context{FindingID: f.ID, Kind: "code", CodeSnippet: "snippet for " + f.ID}
}

type fakeClient struct {
	mu          sync.Mutex
	requests    []llmclient.Request
	inFlight    int
	maxInFlight int
	// respond decides the answer; nil means a valid "ok" answer.
	respond func(ctx context.Context, req llmclient.Request, call int) (llmclient.Response, error)
}

func (c *fakeClient) Analyze(ctx context.Context, req llmclient.Request) (llmclient.Response, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req)
	call := len(c.requests)
	c.inFlight++
	if c.inFlight > c.maxInFlight {
		c.maxInFlight = c.inFlight
	}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	}()
	if c.respond != nil {
		return c.respond(ctx, req, call)
	}
	return okResponse(req.Finding.ID, "MOCK PROVIDER reasoning"), nil
}

func (c *fakeClient) sentIDs() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := map[string]int{}
	for _, r := range c.requests {
		ids[r.Finding.ID]++
	}
	return ids
}

func (c *fakeClient) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func okResponse(id, reasoning string) llmclient.Response {
	return llmclient.Response{
		FindingID: id, Status: llmclient.StatusOK, Provider: "mock", PromptVersion: "v1",
		Result: &llmclient.Result{Exploitable: true, Confidence: 0.7, Reasoning: reasoning, SuggestedFix: "fix", Priority: "high"},
	}
}

func finding(id, severity string, canonical bool) model.Finding {
	return model.Finding{
		ID: id, ScanID: "scan-1", Source: "semgrep", Severity: severity,
		File: "app.js", Line: 2, Description: "desc " + id, IsCanonical: canonical,
	}
}

func newSvc(t *testing.T, cfg Config, st Store, b ContextBuilder, c LLMClient) *Service {
	t.Helper()
	svc, err := NewService(cfg, st, b, c)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func checkInvariant(t *testing.T, s Summary) {
	t.Helper()
	sum := s.AnalyzedOK + s.AnalysisFailed + s.SkippedExisting + s.SkippedLowSeverity + s.NotAttempted
	if sum != s.Considered {
		t.Errorf("counters %+v add up to %d, want Considered=%d", s, sum, s.Considered)
	}
}

// --- tests ---------------------------------------------------------------

func TestAnalyzeScan_NonCanonicalNeverSent(t *testing.T) {
	st := newFakeStore(finding("c1", "high", true), finding("d1", "high", false), finding("d2", "critical", false))
	client := &fakeClient{}
	sum, err := newSvc(t, Config{}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	sent := client.sentIDs()
	if len(sent) != 1 || sent["c1"] != 1 {
		t.Errorf("sent = %v, want only c1", sent)
	}
	if _, ok := st.get("d1"); ok {
		t.Error("non-canonical finding d1 got an analysis row")
	}
	if sum.Considered != 1 || sum.AnalyzedOK != 1 {
		t.Errorf("summary = %+v", sum)
	}
	checkInvariant(t, sum)
}

func TestAnalyzeScan_SecretInSourceFileNeverSent(t *testing.T) {
	secret := fakeAWSKey()
	root := t.TempDir()
	src := "const a = 1;\nconst awsKey = \"" + secret + "\";\nconsole.log(a);\n"
	if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := contextbuilder.DefaultConfig()
	cfg.SourceRoot = root
	builder := contextbuilder.NewBuilder(cfg)

	f := finding("s1", "high", true)
	f.Description = "hardcoded credential " + secret
	st := newFakeStore(f)
	client := &fakeClient{}

	if _, err := newSvc(t, Config{}, st, builder, client).AnalyzeScan(context.Background(), "scan-1", Options{}); err != nil {
		t.Fatal(err)
	}
	if client.calls() != 1 {
		t.Fatalf("calls = %d, want 1", client.calls())
	}
	raw, _ := json.Marshal(client.requests)
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret from source file reached the LLM request")
	}
	if !strings.Contains(string(raw), "[REDACTED:") {
		t.Error("expected a redaction marker in the request (snippet was not built?)")
	}
}

func TestAnalyzeScan_OneFailureDoesNotStopBatch(t *testing.T) {
	st := newFakeStore(finding("a", "high", true), finding("b", "high", true), finding("c", "high", true))
	client := &fakeClient{respond: func(_ context.Context, req llmclient.Request, _ int) (llmclient.Response, error) {
		if req.Finding.ID == "b" {
			return llmclient.Response{}, fmt.Errorf("%w: status 500", llmclient.ErrUnavailable)
		}
		return okResponse(req.Finding.ID, "MOCK PROVIDER ok"), nil
	}}
	sum, err := newSvc(t, Config{Concurrency: 1}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if sum.AnalyzedOK != 2 || sum.AnalysisFailed != 1 {
		t.Errorf("summary = %+v, want ok=2 failed=1", sum)
	}
	b, _ := st.get("b")
	if b.Status != model.AnalysisStatusFailed || b.Error == "" || b.Exploitable != nil {
		t.Errorf("b stored as %+v", b)
	}
	checkInvariant(t, sum)
}

func TestAnalyzeScan_ServiceAnalysisFailedIsStoredAndRetried(t *testing.T) {
	secret := fakeAWSKey()
	st := newFakeStore(finding("a", "high", true))
	errText := "provider echoed " + secret
	client := &fakeClient{respond: func(_ context.Context, req llmclient.Request, call int) (llmclient.Response, error) {
		if call == 1 {
			return llmclient.Response{FindingID: req.Finding.ID, Status: llmclient.StatusAnalysisFailed, Error: &errText, Provider: "mock", PromptVersion: "v1"}, nil
		}
		return okResponse(req.Finding.ID, "MOCK PROVIDER ok"), nil
	}}
	svc := newSvc(t, Config{}, st, fakeBuilder{}, client)

	first, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{})
	a, _ := st.get("a")
	if first.AnalysisFailed != 1 || a.Status != model.AnalysisStatusFailed {
		t.Fatalf("first run %+v stored %+v", first, a)
	}
	if strings.Contains(a.Error, secret) {
		t.Error("secret in service error text was stored unredacted")
	}

	second, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{})
	if second.AnalyzedOK != 1 || client.calls() != 2 {
		t.Errorf("analysis_failed was not retried: %+v calls=%d", second, client.calls())
	}
}

func TestAnalyzeScan_ExistingOKSkippedUnlessForce(t *testing.T) {
	st := newFakeStore(finding("a", "high", true), finding("b", "critical", true))
	client := &fakeClient{}
	svc := newSvc(t, Config{}, st, fakeBuilder{}, client)

	if _, err := svc.AnalyzeScan(context.Background(), "scan-1", Options{}); err != nil {
		t.Fatal(err)
	}
	second, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{})
	if second.SkippedExisting != 2 || second.AnalyzedOK != 0 || client.calls() != 2 {
		t.Errorf("second run %+v calls=%d, want all skipped and no new calls", second, client.calls())
	}
	forced, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{Force: true})
	if forced.AnalyzedOK != 2 || forced.SkippedExisting != 0 || client.calls() != 4 {
		t.Errorf("forced run %+v calls=%d, want re-analysis", forced, client.calls())
	}
	checkInvariant(t, second)
	checkInvariant(t, forced)
}

func TestAnalyzeScan_BelowMinSeverityStoredAsSkipped(t *testing.T) {
	st := newFakeStore(finding("hi", "high", true), finding("lo", "low", true), finding("nt", "note", true))
	client := &fakeClient{}
	sum, _ := newSvc(t, Config{MinSeverity: "medium"}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{})

	if sum.SkippedLowSeverity != 2 || sum.AnalyzedOK != 1 {
		t.Errorf("summary = %+v", sum)
	}
	for _, id := range []string{"lo", "nt"} {
		a, ok := st.get(id)
		if !ok || a.Status != model.AnalysisStatusSkipped || a.Error != "below minimum severity" {
			t.Errorf("%s stored as %+v (present=%v)", id, a, ok)
		}
		if client.sentIDs()[id] != 0 {
			t.Errorf("%s was sent to the LLM", id)
		}
	}
	checkInvariant(t, sum)
}

func TestAnalyzeScan_MaxFindingsCap(t *testing.T) {
	st := newFakeStore(
		finding("m1", "medium", true), finding("c1", "critical", true),
		finding("h1", "high", true), finding("m2", "medium", true),
	)
	client := &fakeClient{}
	sum, _ := newSvc(t, Config{MaxFindings: 2}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{})

	if sum.AnalyzedOK != 2 || sum.NotAttempted != 2 {
		t.Errorf("summary = %+v, want ok=2 not_attempted=2", sum)
	}
	sent := client.sentIDs()
	if sent["c1"] != 1 || sent["h1"] != 1 {
		t.Errorf("sent = %v, want the two most severe (c1, h1)", sent)
	}
	if _, ok := st.get("m1"); ok {
		t.Error("capped finding got an analysis row")
	}
	checkInvariant(t, sum)
}

func TestAnalyzeScan_ConcurrencyLimit(t *testing.T) {
	var findings []model.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, finding(fmt.Sprintf("f%02d", i), "high", true))
	}
	st := newFakeStore(findings...)
	client := &fakeClient{respond: func(_ context.Context, req llmclient.Request, _ int) (llmclient.Response, error) {
		time.Sleep(15 * time.Millisecond)
		return okResponse(req.Finding.ID, "MOCK PROVIDER ok"), nil
	}}
	const limit = 3
	sum, _ := newSvc(t, Config{Concurrency: limit}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{})

	if client.maxInFlight > limit {
		t.Errorf("max in flight = %d, limit %d", client.maxInFlight, limit)
	}
	if client.maxInFlight < 2 {
		t.Errorf("max in flight = %d, expected parallel work", client.maxInFlight)
	}
	if sum.AnalyzedOK != 20 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestAnalyzeScan_OverallTimeoutKeepsFinishedResults(t *testing.T) {
	st := newFakeStore(finding("a", "critical", true), finding("b", "high", true), finding("c", "high", true), finding("d", "medium", true))
	client := &fakeClient{respond: func(ctx context.Context, req llmclient.Request, call int) (llmclient.Response, error) {
		if call == 1 {
			return okResponse(req.Finding.ID, "MOCK PROVIDER ok"), nil
		}
		<-ctx.Done() // hang until the overall deadline
		return llmclient.Response{}, fmt.Errorf("llm request cancelled: %w", ctx.Err())
	}}
	start := time.Now()
	sum, err := newSvc(t, Config{Concurrency: 1, Timeout: 100 * time.Millisecond}, st, fakeBuilder{}, client).
		AnalyzeScan(context.Background(), "scan-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("overall timeout not enforced")
	}
	if sum.AnalyzedOK != 1 || sum.NotAttempted != 3 || sum.AnalysisFailed != 0 {
		t.Errorf("summary = %+v, want ok=1 not_attempted=3", sum)
	}
	if a, ok := st.get("a"); !ok || a.Status != model.AnalysisStatusOK {
		t.Error("finished result was not kept")
	}
	for _, id := range []string{"b", "c", "d"} {
		if _, ok := st.get(id); ok {
			t.Errorf("%s should have no row after the deadline", id)
		}
	}
	checkInvariant(t, sum)
}

func TestAnalyzeScan_ReasoningIsRedactedBeforeStore(t *testing.T) {
	secret := fakeAWSKey()
	st := newFakeStore(finding("a", "high", true))
	client := &fakeClient{respond: func(_ context.Context, req llmclient.Request, _ int) (llmclient.Response, error) {
		r := okResponse(req.Finding.ID, "MOCK PROVIDER the key "+secret+" is exposed")
		r.Result.SuggestedFix = "rotate " + secret
		return r, nil
	}}
	if _, err := newSvc(t, Config{}, st, fakeBuilder{}, client).AnalyzeScan(context.Background(), "scan-1", Options{}); err != nil {
		t.Fatal(err)
	}
	a, _ := st.get("a")
	if strings.Contains(a.Reasoning, secret) || strings.Contains(a.SuggestedFix, secret) {
		t.Fatal("secret from LLM answer was stored unredacted")
	}
	if !strings.Contains(a.Reasoning, "[REDACTED:") {
		t.Errorf("reasoning = %q, want redaction marker", a.Reasoning)
	}
}

func TestAnalyzeScan_RerunIsIdempotent(t *testing.T) {
	st := newFakeStore(finding("a", "high", true), finding("b", "low", true), finding("c", "critical", true), finding("x", "high", false))
	client := &fakeClient{}
	svc := newSvc(t, Config{}, st, fakeBuilder{}, client)

	first, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{Force: true})
	rowsAfterFirst := len(st.analyses)
	second, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{Force: true})
	if first != second {
		t.Errorf("forced reruns differ: %+v vs %+v", first, second)
	}
	if len(st.analyses) != rowsAfterFirst {
		t.Errorf("row count changed %d -> %d (expected upsert, one row per finding)", rowsAfterFirst, len(st.analyses))
	}

	third, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{})
	fourth, _ := svc.AnalyzeScan(context.Background(), "scan-1", Options{})
	if third != fourth {
		t.Errorf("plain reruns differ: %+v vs %+v", third, fourth)
	}
	if third.SkippedExisting != first.AnalyzedOK || third.Considered != first.Considered {
		t.Errorf("plain rerun %+v inconsistent with %+v", third, first)
	}
}

func TestAnalyzeScan_ListError(t *testing.T) {
	svc := newSvc(t, Config{}, &errStore{}, fakeBuilder{}, &fakeClient{})
	if _, err := svc.AnalyzeScan(context.Background(), "scan-1", Options{}); err == nil {
		t.Error("expected error when findings cannot be listed")
	}
}

type errStore struct{ fakeStore }

func (*errStore) ListCanonicalFindings(context.Context, string) ([]model.Finding, error) {
	return nil, errors.New("db down")
}

func TestNewService_Validation(t *testing.T) {
	if _, err := NewService(Config{MinSeverity: "urgent"}, newFakeStore(), fakeBuilder{}, &fakeClient{}); err == nil {
		t.Error("invalid min severity accepted")
	}
	svc, err := NewService(Config{}, newFakeStore(), fakeBuilder{}, &fakeClient{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := svc.Config()
	if cfg.Concurrency != 4 || cfg.MinSeverity != "medium" || cfg.MaxFindings != 100 || cfg.Timeout != 300*time.Second {
		t.Errorf("defaults = %+v", cfg)
	}
}
