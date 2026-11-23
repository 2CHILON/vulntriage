package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

type fakeLLM struct {
	mu        sync.Mutex
	calls     int
	healthErr error
}

func (f *fakeLLM) Health(context.Context) error { return f.healthErr }

func (f *fakeLLM) Analyze(_ context.Context, req llmclient.Request) (llmclient.Response, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return llmclient.Response{
		FindingID: req.Finding.ID, Status: llmclient.StatusOK, Provider: "mock", PromptVersion: "v1",
		Result: &llmclient.Result{Exploitable: true, Confidence: 0.9, Reasoning: "MOCK PROVIDER test", SuggestedFix: "fix", Priority: "high"},
	}, nil
}

type stubBuilder struct{}

func (stubBuilder) Build(f model.Finding) contextbuilder.Context {
	return contextbuilder.Context{FindingID: f.ID, Kind: "none"}
}

// newAnalysisTestHandler seeds scan-a with: c1 (high, canonical), c2 (low, canonical), d1 (high, duplicate).
func newAnalysisTestHandler(t *testing.T, llm *fakeLLM) (*Handler, *FakeStore) {
	t.Helper()
	st := NewFakeStore()
	ctx := context.Background()
	_ = st.InsertScan(ctx, "scan-a", "semgrep")
	_, _ = st.InsertFindings(ctx, []model.Finding{
		{ID: "c1", ScanID: "scan-a", Source: "semgrep", Severity: "high", File: "a.js", Line: 1, Description: "x", IsCanonical: true},
		{ID: "c2", ScanID: "scan-a", Source: "semgrep", Severity: "low", File: "b.js", Line: 1, Description: "y", IsCanonical: true},
		{ID: "d1", ScanID: "scan-a", Source: "trivy", Severity: "high", File: "a.js", Line: 1, Description: "x", IsCanonical: false},
	})
	svc, err := analysis.NewService(analysis.Config{}, st, stubBuilder{}, llm)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(st).WithAnalysis(AnalysisDeps{Analyzer: svc, Health: llm, Reader: st})
	return h, st
}

func doRequest(h *Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.HandleScansRouter(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestAnalysisEndpoints_UnknownScan404(t *testing.T) {
	h, _ := newAnalysisTestHandler(t, &fakeLLM{})
	tests := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/scans/nope/analyze"},
		{http.MethodGet, "/api/v1/scans/nope/analyses"},
		{http.MethodGet, "/api/v1/scans/nope/findings/c1/analysis"},
	}
	for _, tt := range tests {
		if rec := doRequest(h, tt.method, tt.path); rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tt.method, tt.path, rec.Code)
		}
	}
}

func TestAnalyze_HealthFails503NothingStored(t *testing.T) {
	llm := &fakeLLM{healthErr: errors.New("down")}
	h, st := newAnalysisTestHandler(t, llm)

	rec := doRequest(h, http.MethodPost, "/api/v1/scans/scan-a/analyze")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if llm.calls != 0 {
		t.Errorf("LLM was called %d times", llm.calls)
	}
	if list, _ := st.ListAnalysesByScan(context.Background(), "scan-a"); len(list) != 0 {
		t.Errorf("stored %d analyses, want 0", len(list))
	}
}

func TestAnalyze_InvalidForce400(t *testing.T) {
	h, _ := newAnalysisTestHandler(t, &fakeLLM{})
	if rec := doRequest(h, http.MethodPost, "/api/v1/scans/scan-a/analyze?force=maybe"); rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAnalyze_SummaryNumbers(t *testing.T) {
	llm := &fakeLLM{}
	h, _ := newAnalysisTestHandler(t, llm)

	tests := []struct {
		name string
		path string
		want analysis.Summary
	}{
		{"first run", "/api/v1/scans/scan-a/analyze",
			analysis.Summary{ScanID: "scan-a", Considered: 2, AnalyzedOK: 1, SkippedLowSeverity: 1, Provider: "mock"}},
		{"second run skips existing", "/api/v1/scans/scan-a/analyze",
			analysis.Summary{ScanID: "scan-a", Considered: 2, SkippedExisting: 1, SkippedLowSeverity: 1}},
		{"force re-analyzes", "/api/v1/scans/scan-a/analyze?force=true",
			analysis.Summary{ScanID: "scan-a", Considered: 2, AnalyzedOK: 1, SkippedLowSeverity: 1, Provider: "mock"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(h, http.MethodPost, tt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			var got analysis.Summary
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("summary = %+v, want %+v", got, tt.want)
			}
		})
	}
	if llm.calls != 2 {
		t.Errorf("LLM calls = %d, want 2 (first + force)", llm.calls)
	}
}

func TestAnalysisGetEndpoints(t *testing.T) {
	h, _ := newAnalysisTestHandler(t, &fakeLLM{})
	if rec := doRequest(h, http.MethodPost, "/api/v1/scans/scan-a/analyze"); rec.Code != http.StatusOK {
		t.Fatalf("analyze status = %d", rec.Code)
	}

	rec := doRequest(h, http.MethodGet, "/api/v1/scans/scan-a/analyses")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var list []map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0]["finding_id"] != "c1" || list[1]["finding_id"] != "c2" {
		t.Fatalf("list = %v, want c1 and c2 only", list)
	}
	wantKeys := []string{"finding_id", "status", "exploitable", "confidence", "priority", "reasoning",
		"suggested_fix", "provider", "prompt_version", "error", "updated_at"}
	for _, k := range wantKeys {
		if _, ok := list[0][k]; !ok {
			t.Errorf("list item missing key %q", k)
		}
	}
	if len(list[0]) != len(wantKeys) {
		t.Errorf("list item has %d keys, want %d: %v", len(list[0]), len(wantKeys), list[0])
	}
	if list[0]["status"] != "ok" || list[1]["status"] != "skipped" || list[1]["exploitable"] != nil {
		t.Errorf("unexpected statuses: %v", list)
	}

	tests := []struct {
		name, path string
		wantCode   int
		wantStatus string
	}{
		{"ok analysis", "/api/v1/scans/scan-a/findings/c1/analysis", 200, "ok"},
		{"skipped analysis", "/api/v1/scans/scan-a/findings/c2/analysis", 200, "skipped"},
		{"duplicate has none", "/api/v1/scans/scan-a/findings/d1/analysis", 404, ""},
		{"unknown finding", "/api/v1/scans/scan-a/findings/zzz/analysis", 404, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(h, http.MethodGet, tt.path)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if tt.wantStatus == "" {
				return
			}
			var a map[string]interface{}
			_ = json.Unmarshal(rec.Body.Bytes(), &a)
			if a["status"] != tt.wantStatus {
				t.Errorf("status field = %v, want %s", a["status"], tt.wantStatus)
			}
		})
	}
}

func TestAnalysisFinding_OtherScan404(t *testing.T) {
	h, st := newAnalysisTestHandler(t, &fakeLLM{})
	_ = st.InsertScan(context.Background(), "scan-b", "trivy")
	if rec := doRequest(h, http.MethodGet, "/api/v1/scans/scan-b/findings/c1/analysis"); rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 for a finding of another scan", rec.Code)
	}
}
