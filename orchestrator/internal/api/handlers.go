package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/dedupe"
	"github.com/2CHILON/vulntriage/orchestrator/internal/parsers"
)

// Handler holds the store dependency and context builder for all HTTP handlers.
type Handler struct {
	store   dedupe.FindingStore
	builder *contextbuilder.Builder
}

// NewHandler creates a new Handler with the given FindingStore.
func NewHandler(store dedupe.FindingStore) *Handler {
	return &Handler{store: store}
}

// NewHandlerWithBuilder creates a Handler with a FindingStore and ContextBuilder.
func NewHandlerWithBuilder(store dedupe.FindingStore, builder *contextbuilder.Builder) *Handler {
	return &Handler{store: store, builder: builder}
}

// ScanUploadRequest represents the JSON payload for uploading a SARIF scan.
type ScanUploadRequest struct {
	ScanID    string      `json:"scan_id"`
	ToolName  string      `json:"tool_name"`
	SARIFData interface{} `json:"sarif_data"` // Raw SARIF JSON
}

// HandleScanUpload handles POST /api/v1/scans uploads.
func (h *Handler) HandleScanUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req ScanUploadRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if req.ScanID == "" {
		http.Error(w, "scan_id is required", http.StatusBadRequest)
		return
	}

	// Convert sarif_data back to JSON bytes
	sarifBytes, err := json.Marshal(req.SARIFData)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid sarif_data: %v", err), http.StatusBadRequest)
		return
	}

	// Parse SARIF into findings
	findings, err := parsers.ParseSARIF(sarifBytes, req.ScanID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse SARIF: %v", err), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Store scan record
	toolName := req.ToolName
	if toolName == "" {
		toolName = "unknown"
	}
	if err := h.store.InsertScan(ctx, req.ScanID, toolName); err != nil {
		log.Printf("failed to insert scan record: %v", err)
		http.Error(w, "failed to store scan", http.StatusInternalServerError)
		return
	}

	// Store findings from this upload (with ordinal-suffixed IDs for within-upload collisions)
	inserted, err := h.store.InsertFindings(ctx, findings)
	if err != nil {
		log.Printf("failed to insert findings: %v", err)
		http.Error(w, "failed to store findings", http.StatusInternalServerError)
		return
	}
	skippedExisting := len(findings) - inserted

	// Re-deduplicate the entire scan (including findings from previous uploads)
	dedupeStats, err := dedupe.DedupeScan(ctx, h.store, req.ScanID)
	if err != nil {
		log.Printf("failed to deduplicate scan: %v", err)
		http.Error(w, "failed to deduplicate scan", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":            req.ScanID,
		"findings_stored":    inserted,
		"skipped_existing":   skippedExisting,
		"total_findings":     dedupeStats.TotalFindings,
		"dedupe_groups":      dedupeStats.GroupsCreated,
		"duplicates_removed": dedupeStats.DuplicatesRemoved,
		"canonical_findings": dedupeStats.CanonicalFindings,
	})
}

// HandleScanDedupe handles POST /api/v1/scans/{id}/dedupe explicit dedupe requests.
func (h *Handler) HandleScanDedupe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract scan_id from path: /api/v1/scans/{id}/dedupe
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/scans/"), "/")
	if len(parts) < 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	scanID := parts[0]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if scan exists
	exists, err := h.store.ScanExists(ctx, scanID)
	if err != nil {
		log.Printf("failed to check scan existence: %v", err)
		http.Error(w, "failed to check scan", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	// Re-deduplicate the entire scan
	stats, err := dedupe.DedupeScan(ctx, h.store, scanID)
	if err != nil {
		log.Printf("failed to deduplicate scan: %v", err)
		http.Error(w, "failed to deduplicate scan", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":            scanID,
		"total_findings":     stats.TotalFindings,
		"dedupe_groups":      stats.GroupsCreated,
		"duplicates_removed": stats.DuplicatesRemoved,
		"canonical_findings": stats.CanonicalFindings,
	})
}

// HandleFindingContext handles GET /api/v1/scans/{scanID}/findings/{findingID}/context
func (h *Handler) HandleFindingContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract scanID and findingID from path
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/scans/"), "/")
	if len(parts) < 4 || parts[1] != "findings" || parts[3] != "context" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	scanID := parts[0]
	findingID := parts[2]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if scan exists
	exists, err := h.store.ScanExists(ctx, scanID)
	if err != nil {
		log.Printf("failed to check scan existence: %v", err)
		http.Error(w, "failed to check scan", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return
	}

	// Get finding by ID
	finding, err := h.store.GetFinding(ctx, findingID)
	if err != nil {
		log.Printf("failed to get finding: %v", err)
		http.Error(w, "failed to get finding", http.StatusInternalServerError)
		return
	}
	if finding == nil {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	// Verify the finding belongs to this scan
	if finding.ScanID != scanID {
		http.Error(w, "finding not found in this scan", http.StatusNotFound)
		return
	}

	// Build context
	var context contextbuilder.Context
	if h.builder != nil {
		context = h.builder.Build(*finding)
	} else {
		// No builder configured, return Kind "none"
		context = contextbuilder.Context{
			FindingID:      finding.ID,
			Kind:           "none",
			WithheldReason: "context builder not configured",
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(context)
}

// HandleScansRouter routes /api/v1/scans* requests to the appropriate handler.
func (h *Handler) HandleScansRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/api/v1/scans" || path == "/api/v1/scans/" {
		h.HandleScanUpload(w, r)
		return
	}

	// Check if it's a context request: /api/v1/scans/{id}/findings/{id}/context
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/scans/"), "/")
	if len(parts) >= 4 && parts[1] == "findings" && parts[3] == "context" {
		h.HandleFindingContext(w, r)
		return
	}

	// Check if it's a dedupe request: /api/v1/scans/{id}/dedupe
	if len(parts) >= 2 && parts[len(parts)-1] == "dedupe" {
		h.HandleScanDedupe(w, r)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}
