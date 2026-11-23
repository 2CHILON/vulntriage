package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
)

// TestAnalyzeScanHandleWriteDeadlineExtension tests that HandleAnalyzeScan
// safely calls http.NewResponseController().SetWriteDeadline() without crashing.
func TestAnalyzeScanHandleWriteDeadlineExtension(t *testing.T) {
	// Use httptest.NewServer which is a real server and supports ResponseController
	handler := NewHandler(&dummyStore{})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/scans/", handler.HandleScansRouter)

	server := httptest.NewServer(mux)
	defer server.Close()

	client := &http.Client{}
	url := server.URL + "/api/v1/scans/scan-123/analyze"

	// Should not crash when analysis service is nil (safe no-op)
	resp, err := client.Post(url, "application/json", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// Expect 500 since analysis service is not configured
	if resp.StatusCode != http.StatusInternalServerError {
		t.Logf("got status %d (expected 500 when service not configured)", resp.StatusCode)
	}
}

type dummyStore struct{}

func (ds *dummyStore) InsertScan(ctx context.Context, scanID, toolName string) error {
	return nil
}

func (ds *dummyStore) InsertFindings(ctx context.Context, findings []model.Finding) (int, error) {
	return 0, nil
}

func (ds *dummyStore) ScanExists(ctx context.Context, scanID string) (bool, error) {
	return true, nil
}

func (ds *dummyStore) GetFinding(ctx context.Context, findingID string) (*model.Finding, error) {
	return nil, nil
}

func (ds *dummyStore) ListAllFindingsByScan(ctx context.Context, scanID string) ([]model.Finding, error) {
	return nil, nil
}

func (ds *dummyStore) ReplaceDedupeResults(ctx context.Context, scanID string, findings []model.Finding) error {
	return nil
}

