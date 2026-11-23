package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHandleScanUpload_Trivy54Findings(t *testing.T) {
	// Load trivy.sarif fixture (should contain 54 findings)
	trivyData, err := os.ReadFile("../../../testdata/sarif/trivy.sarif")
	if err != nil {
		t.Fatalf("failed to read trivy.sarif: %v", err)
	}

	var trivySARIF interface{}
	if err := json.Unmarshal(trivyData, &trivySARIF); err != nil {
		t.Fatalf("failed to unmarshal trivy.sarif: %v", err)
	}

	store := NewFakeStore()
	handler := NewHandler(store)

	req := ScanUploadRequest{
		ScanID:    "scan-trivy-test",
		ToolName:  "trivy",
		SARIFData: trivySARIF,
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.HandleScanUpload(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["findings_stored"] != float64(54) {
		t.Errorf("expected findings_stored=54, got %v", resp["findings_stored"])
	}
	if resp["skipped_existing"] != float64(0) {
		t.Errorf("expected skipped_existing=0, got %v", resp["skipped_existing"])
	}
	if resp["total_findings"] != float64(54) {
		t.Errorf("expected total_findings=54, got %v", resp["total_findings"])
	}
}

func TestHandleScanUpload_Semgrep25Findings(t *testing.T) {
	// Load semgrep.sarif fixture (should contain 25 findings)
	semgrepData, err := os.ReadFile("../../../testdata/sarif/semgrep.sarif")
	if err != nil {
		t.Fatalf("failed to read semgrep.sarif: %v", err)
	}

	var semgrepSARIF interface{}
	if err := json.Unmarshal(semgrepData, &semgrepSARIF); err != nil {
		t.Fatalf("failed to unmarshal semgrep.sarif: %v", err)
	}

	store := NewFakeStore()
	handler := NewHandler(store)

	req := ScanUploadRequest{
		ScanID:    "scan-semgrep-test",
		ToolName:  "semgrep",
		SARIFData: semgrepSARIF,
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.HandleScanUpload(w, r)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["findings_stored"] != float64(25) {
		t.Errorf("expected findings_stored=25, got %v", resp["findings_stored"])
	}
	if resp["total_findings"] != float64(25) {
		t.Errorf("expected total_findings=25, got %v", resp["total_findings"])
	}
}

func TestHandleScanUpload_CrossUploadDedupe(t *testing.T) {
	// Load both fixtures
	trivyData, _ := os.ReadFile("../../../testdata/sarif/trivy-with-duplicates.sarif")
	semgrepData, _ := os.ReadFile("../../../testdata/sarif/semgrep-with-duplicates.sarif")

	var trivySARIF, semgrepSARIF interface{}
	json.Unmarshal(trivyData, &trivySARIF)
	json.Unmarshal(semgrepData, &semgrepSARIF)

	store := NewFakeStore()
	handler := NewHandler(store)

	// Upload trivy to same scan_id
	req1 := ScanUploadRequest{
		ScanID:    "scan-cross",
		ToolName:  "trivy",
		SARIFData: trivySARIF,
	}
	body1, _ := json.Marshal(req1)
	r1 := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	handler.HandleScanUpload(w1, r1)

	// Upload semgrep to SAME scan_id
	req2 := ScanUploadRequest{
		ScanID:    "scan-cross",
		ToolName:  "semgrep",
		SARIFData: semgrepSARIF,
	}
	body2, _ := json.Marshal(req2)
	r2 := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handler.HandleScanUpload(w2, r2)

	var resp2 map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp2)

	// Should have 4 total findings (2 from trivy + 2 from semgrep)
	if resp2["total_findings"] != float64(4) {
		t.Errorf("expected total_findings=4, got %v", resp2["total_findings"])
	}
	// Should have 2 groups (trivy findings form 1 group, semgrep findings form another)
	if resp2["dedupe_groups"] != float64(2) {
		t.Errorf("expected dedupe_groups=2, got %v", resp2["dedupe_groups"])
	}
	// Should have 2 canonical findings (one per group)
	if resp2["canonical_findings"] != float64(2) {
		t.Errorf("expected canonical_findings=2, got %v", resp2["canonical_findings"])
	}
}

func TestHandleScanUpload_SkippedExisting(t *testing.T) {
	// Load trivy-with-duplicates fixture (2 findings)
	trivyData, _ := os.ReadFile("../../../testdata/sarif/trivy-with-duplicates.sarif")

	var trivySARIF interface{}
	json.Unmarshal(trivyData, &trivySARIF)

	store := NewFakeStore()
	handler := NewHandler(store)

	// First upload with scan_id=A
	req1 := ScanUploadRequest{
		ScanID:    "scan-dup-a",
		ToolName:  "trivy",
		SARIFData: trivySARIF,
	}
	body1, _ := json.Marshal(req1)
	r1 := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	handler.HandleScanUpload(w1, r1)

	var resp1 map[string]interface{}
	json.NewDecoder(w1.Body).Decode(&resp1)
	firstUploadCount := int(resp1["findings_stored"].(float64))

	// Second upload SAME content but different scan_id=B
	// (Different scan_id means different IDs generated, so no ON CONFLICT)
	req2 := ScanUploadRequest{
		ScanID:    "scan-dup-b",
		ToolName:  "trivy",
		SARIFData: trivySARIF,
	}
	body2, _ := json.Marshal(req2)
	r2 := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handler.HandleScanUpload(w2, r2)

	var resp2 map[string]interface{}
	json.NewDecoder(w2.Body).Decode(&resp2)
	secondUploadInserted := int(resp2["findings_stored"].(float64))
	secondUploadSkipped := int(resp2["skipped_existing"].(float64))

	// Different scan_ids produce different hashes, so both inserts succeed
	if secondUploadInserted != firstUploadCount {
		t.Errorf("expected secondUploadInserted=%d (same as first), got %d", firstUploadCount, secondUploadInserted)
	}
	if secondUploadSkipped != 0 {
		t.Errorf("expected skipped_existing=0 (different scan_id), got %d", secondUploadSkipped)
	}

	// Now test actual skipped_existing: upload SAME scan_id again
	req3 := ScanUploadRequest{
		ScanID:    "scan-dup-a", // SAME as first upload
		ToolName:  "trivy",
		SARIFData: trivySARIF,
	}
	body3, _ := json.Marshal(req3)
	r3 := httptest.NewRequest("POST", "/api/v1/scans", bytes.NewReader(body3))
	w3 := httptest.NewRecorder()
	handler.HandleScanUpload(w3, r3)

	var resp3 map[string]interface{}
	json.NewDecoder(w3.Body).Decode(&resp3)
	thirdUploadInserted := int(resp3["findings_stored"].(float64))
	thirdUploadSkipped := int(resp3["skipped_existing"].(float64))

	// Same scan_id = same IDs = ON CONFLICT DO NOTHING = skipped
	if thirdUploadInserted != 0 {
		t.Errorf("expected findings_stored=0 (all skipped), got %d", thirdUploadInserted)
	}
	if thirdUploadSkipped != firstUploadCount {
		t.Errorf("expected skipped_existing=%d, got %d", firstUploadCount, thirdUploadSkipped)
	}
}

func TestHandleScanDedupe_Unknown404(t *testing.T) {
	store := NewFakeStore()
	handler := NewHandler(store)

	r := httptest.NewRequest("POST", "/api/v1/scans/unknown-scan-xyz/dedupe", nil)
	w := httptest.NewRecorder()

	handler.HandleScanDedupe(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}

	body, _ := io.ReadAll(w.Body)
	if !bytes.Contains(body, []byte("scan not found")) {
		t.Errorf("expected 'scan not found' in response, got %s", string(body))
	}
}

