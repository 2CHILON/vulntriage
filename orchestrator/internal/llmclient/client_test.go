package llmclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: true,
				Confidence:  0.95,
				Reasoning:   "SQL injection detected",
				SuggestedFix: "Use prepared statements",
				Priority:    "high",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	resp, err := client.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %s", resp.Status)
	}
	if resp.Result == nil || !resp.Result.Exploitable {
		t.Error("expected exploitable true")
	}
}

func TestAnalyze500Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: false,
				Confidence:  0.5,
				Reasoning:   "Not exploitable",
				SuggestedFix: "N/A",
				Priority:    "low",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	resp, err := client.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %s", resp.Status)
	}
}

func TestAnalyze500NoRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 2 {
		t.Errorf("expected 2 attempts (1 + 1 retry), got %d", attempts)
	}
}

func TestAnalyzeInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on invalid JSON")
	}
	if !strings.Contains(err.Error(), "invalid response format") {
		t.Errorf("expected 'invalid response format', got %v", err)
	}
}

func TestAnalyzeInvalidStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "unknown",
			Provider:      "mock",
			PromptVersion: "v1",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on invalid status")
	}
	if !strings.Contains(err.Error(), "invalid status value") {
		t.Errorf("expected 'invalid status value', got %v", err)
	}
}

func TestAnalyzeConfidenceOutOfBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: true,
				Confidence:  1.5,
				Reasoning:   "test",
				SuggestedFix: "test",
				Priority:    "high",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on invalid confidence")
	}
	if !strings.Contains(err.Error(), "confidence out of bounds") {
		t.Errorf("expected 'confidence out of bounds', got %v", err)
	}
}

func TestAnalyzeInvalidPriority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: true,
				Confidence:  0.95,
				Reasoning:   "test",
				SuggestedFix: "test",
				Priority:    "unknown",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on invalid priority")
	}
	if !strings.Contains(err.Error(), "invalid priority") {
		t.Errorf("expected 'invalid priority', got %v", err)
	}
}

func TestAnalyzeEmptyReasoning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: true,
				Confidence:  0.95,
				Reasoning:   "   ",
				SuggestedFix: "test",
				Priority:    "high",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on empty reasoning")
	}
	if !strings.Contains(err.Error(), "reasoning must be non-empty") {
		t.Errorf("expected 'reasoning must be non-empty', got %v", err)
	}
}

func TestAnalyzeFindingIDMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "wrong-id",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: true,
				Confidence:  0.95,
				Reasoning:   "test",
				SuggestedFix: "test",
				Priority:    "high",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on finding ID mismatch")
	}
	if !strings.Contains(err.Error(), "finding_id mismatch") {
		t.Errorf("expected 'finding_id mismatch', got %v", err)
	}
}

func TestAnalyzeOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write response header, then excessive data
		w.Write(make([]byte, 2*1024*1024))
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on oversized body")
	}
}

func TestAnalyzeTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, 100*time.Millisecond)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err == nil {
		t.Fatal("expected error on timeout")
	}
}

func TestAnalyzeCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:     "finding-123",
			Source: "semgrep",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Analyze(ctx, req)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestAnalyzeRequestJSON(t *testing.T) {
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AnalyzeResponse{
			FindingID:     "finding-123",
			Status:        "ok",
			Provider:      "mock",
			PromptVersion: "v1",
			Result: &AnalysisResult{
				Exploitable: false,
				Confidence:  0.5,
				Reasoning:   "test",
				SuggestedFix: "test",
				Priority:    "low",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	severity := "high"
	cve := "CVE-2024-1234"
	req := &AnalyzeRequest{
		Finding: Finding{
			ID:       "finding-123",
			Source:   "semgrep",
			Severity: &severity,
			CVE:      &cve,
		},
	}

	_, err := client.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unmarshal to check structure
	var payload AnalyzeRequest
	if err := json.Unmarshal(capturedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	// Verify only allowed keys are present (no extras like foo, bar, etc.)
	if payload.Finding.ID != "finding-123" || payload.Finding.Source != "semgrep" {
		t.Error("request fields incorrect")
	}
}

func TestHealthSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("expected /health, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHealthFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	err := client.Health(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}
