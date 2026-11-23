package llmclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func okBody(findingID string) string {
	return `{"finding_id":"` + findingID + `","status":"ok","result":{"exploitable":true,"confidence":0.8,` +
		`"reasoning":"MOCK PROVIDER reasoning","suggested_fix":"fix it","priority":"high"},` +
		`"error":null,"provider":"mock","prompt_version":"v1"}`
}

func testRequest(id string) Request {
	return Request{
		Finding: Finding{ID: id, Source: "semgrep", Severity: StringPtr("high"), File: StringPtr("app.js"), Line: LinePtr(3)},
		Context: &Context{CodeSnippet: StringPtr("x = 1")},
	}
}

func newTestClient(t *testing.T, url string, timeout time.Duration) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: url, Timeout: timeout, RetryBackoff: time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestAnalyze_Responses(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantErr   error
		wantCalls int32
	}{
		{"success", 200, okBody("f1"), nil, 1},
		{"analysis_failed from service is accepted", 200,
			`{"finding_id":"f1","status":"analysis_failed","result":null,"error":"provider error","provider":"mock","prompt_version":"v1"}`, nil, 1},
		{"invalid JSON", 200, `{"finding_id":`, ErrInvalidResponse, 1},
		{"unknown field", 200, strings.Replace(okBody("f1"), `"error":null`, `"error":null,"extra":1`, 1), ErrInvalidResponse, 1},
		{"invalid status", 200, strings.Replace(okBody("f1"), `"status":"ok"`, `"status":"maybe"`, 1), ErrInvalidResponse, 1},
		{"confidence above 1", 200, strings.Replace(okBody("f1"), `0.8`, `1.5`, 1), ErrInvalidResponse, 1},
		{"confidence below 0", 200, strings.Replace(okBody("f1"), `0.8`, `-0.1`, 1), ErrInvalidResponse, 1},
		{"invalid priority", 200, strings.Replace(okBody("f1"), `"priority":"high"`, `"priority":"urgent"`, 1), ErrInvalidResponse, 1},
		{"empty reasoning with status ok", 200, strings.Replace(okBody("f1"), `"MOCK PROVIDER reasoning"`, `"   "`, 1), ErrInvalidResponse, 1},
		{"status ok without result", 200,
			`{"finding_id":"f1","status":"ok","result":null,"error":null,"provider":"mock","prompt_version":"v1"}`, ErrInvalidResponse, 1},
		{"mismatched finding_id", 200, okBody("other"), ErrInvalidResponse, 1},
		{"oversized body", 200, `{"pad":"` + strings.Repeat("a", MaxResponseBytes) + `"}`, ErrInvalidResponse, 1},
		{"422 is not retried", 422, `{"detail":"bad"}`, ErrRejected, 1},
		{"redirect is not followed", 302, ``, ErrRejected, 1},
		{"500 twice gives error after one retry", 500, `{"error":"Internal server error"}`, ErrUnavailable, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&calls, 1)
				if r.URL.Path != "/analyze" || r.Method != http.MethodPost {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if tt.status == 302 {
					w.Header().Set("Location", "/elsewhere")
				}
				w.WriteHeader(tt.status)
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()

			c := newTestClient(t, srv.URL, 5*time.Second)
			resp, err := c.Analyze(context.Background(), testRequest("f1"))
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if resp.FindingID != "f1" {
					t.Errorf("finding_id = %q", resp.FindingID)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), "127.0.0.1") {
					t.Errorf("error leaks URL: %v", err)
				}
				if strings.Contains(err.Error(), "MOCK PROVIDER") || strings.Contains(err.Error(), "detail") {
					t.Errorf("error leaks response body: %v", err)
				}
			}
			if got := atomic.LoadInt32(&calls); got != tt.wantCalls {
				t.Errorf("calls = %d, want %d", got, tt.wantCalls)
			}
		})
	}
}

func TestAnalyze_500ThenSuccessOnRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, okBody("f1"))
	}))
	defer srv.Close()

	resp, err := newTestClient(t, srv.URL, 5*time.Second).Analyze(context.Background(), testRequest("f1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != StatusOK || calls != 2 {
		t.Errorf("status=%q calls=%d, want ok and 2", resp.Status, calls)
	}
}

func TestAnalyze_NetworkErrorIsRetriedOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listens any more

	_, err := newTestClient(t, url, time.Second).Analyze(context.Background(), testRequest("f1"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v, want ErrUnavailable", err)
	}
	if strings.Contains(err.Error(), url) {
		t.Errorf("error leaks URL: %v", err)
	}
}

func TestAnalyze_SlowServerBeyondTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	_, err := newTestClient(t, srv.URL, 50*time.Millisecond).Analyze(context.Background(), testRequest("f1"))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("error = %v, want timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v, timeout not enforced", elapsed)
	}
}

func TestAnalyze_CancelledContext(t *testing.T) {
	var calls int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release) // runs before srv.Close so the handler can return

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()

	_, err := newTestClient(t, srv.URL, 5*time.Second).Analyze(ctx, testRequest("f1"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("calls = %d, cancelled request must not be retried", got)
	}
}

func TestAnalyze_RequestContainsOnlyAllowedKeys(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, okBody("f1"))
	}))
	defer srv.Close()

	if _, err := newTestClient(t, srv.URL, 5*time.Second).Analyze(context.Background(), testRequest("f1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(captured, &top); err != nil {
		t.Fatalf("request is not JSON: %v", err)
	}
	assertKeys(t, "top", top, []string{"context", "finding"})

	var finding, ctxObj map[string]json.RawMessage
	_ = json.Unmarshal(top["finding"], &finding)
	_ = json.Unmarshal(top["context"], &ctxObj)
	assertKeys(t, "finding", finding, []string{"cve", "cwe", "description", "file", "id", "line", "severity", "source"})
	assertKeys(t, "context", ctxObj, []string{"code_snippet", "dependency_usage"})
}

func assertKeys(t *testing.T, label string, m map[string]json.RawMessage, want []string) {
	t.Helper()
	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s keys = %v, want %v", label, got, want)
	}
}

func TestHealth(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{"healthy", 200, false},
		{"unhealthy", 503, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Errorf("path = %s", r.URL.Path)
				}
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()
			err := newTestClient(t, srv.URL, time.Second).Health(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_RejectsBadURL(t *testing.T) {
	for _, u := range []string{"", "localhost:8000", "ftp://x", "http://"} {
		if _, err := New(Config{BaseURL: u}); err == nil {
			t.Errorf("New(%q) should fail", u)
		}
	}
}
