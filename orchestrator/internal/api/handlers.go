package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/dedupe"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
	"github.com/2CHILON/vulntriage/orchestrator/internal/parsers"
)

// Handler holds the store dependency and context builder for all HTTP handlers.
type Handler struct {
	store    dedupe.FindingStore
	builder  *contextbuilder.Builder
	analysis *AnalysisDeps
}

// Analyzer runs an analysis of one scan.
type Analyzer interface {
	AnalyzeScan(ctx context.Context, scanID string, opts analysis.Options) (analysis.Summary, error)
}

// HealthChecker reports whether the LLM service is reachable.
type HealthChecker interface {
	Health(ctx context.Context) error
}

// AnalysisReader reads stored analyses.
type AnalysisReader interface {
	GetAnalysis(ctx context.Context, findingID string) (*model.Analysis, error)
	ListAnalysesByScan(ctx context.Context, scanID string) ([]model.Analysis, error)
}

// AnalysisDeps are the dependencies of the analysis endpoints.
type AnalysisDeps struct {
	Analyzer Analyzer
	Health   HealthChecker
	Reader   AnalysisReader
}

// WithAnalysis enables the analysis endpoints and returns h.
func (h *Handler) WithAnalysis(deps AnalysisDeps) *Handler {
	h.analysis = &deps
	return h
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

	// /api/v1/scans/{id}/findings/{findingID}/analysis
	if len(parts) == 4 && parts[1] == "findings" && parts[3] == "analysis" {
		h.HandleFindingAnalysis(w, r)
		return
	}

	// /api/v1/scans/{id}/analyze and /api/v1/scans/{id}/analyses
	if len(parts) == 2 && parts[1] == "analyze" {
		h.HandleScanAnalyze(w, r)
		return
	}
	if len(parts) == 2 && parts[1] == "analyses" {
		h.HandleScanAnalyses(w, r)
		return
	}

	// Check if it's a dedupe request: /api/v1/scans/{id}/dedupe
	if len(parts) >= 2 && parts[len(parts)-1] == "dedupe" {
		h.HandleScanDedupe(w, r)
		return
	}

	http.Error(w, "not found", http.StatusNotFound)
}

// scanPathParts splits /api/v1/scans/{...} into its segments.
func scanPathParts(r *http.Request) []string {
	return strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/scans/"), "/")
}

// requireScan writes 404/500 and returns false when the scan cannot be confirmed.
func (h *Handler) requireScan(w http.ResponseWriter, r *http.Request, scanID string) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	exists, err := h.store.ScanExists(ctx, scanID)
	if err != nil {
		log.Printf("failed to check scan existence: %v", err)
		http.Error(w, "failed to check scan", http.StatusInternalServerError)
		return false
	}
	if scanID == "" || !exists {
		http.Error(w, "scan not found", http.StatusNotFound)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// HandleScanAnalyze handles POST /api/v1/scans/{id}/analyze[?force=true].
func (h *Handler) HandleScanAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := scanPathParts(r)[0]

	force := false
	if v := r.URL.Query().Get("force"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			http.Error(w, "force must be true or false", http.StatusBadRequest)
			return
		}
		force = b
	}

	if !h.requireScan(w, r, scanID) {
		return
	}
	if h.analysis == nil || h.analysis.Analyzer == nil || h.analysis.Health == nil {
		http.Error(w, "analysis not configured", http.StatusServiceUnavailable)
		return
	}

	// Fail fast before any work or storage when the LLM service is down.
	if err := h.analysis.Health.Health(r.Context()); err != nil {
		log.Printf("analysis: scan=%s llm service health check failed", scanID)
		http.Error(w, "llm service unavailable", http.StatusServiceUnavailable)
		return
	}

	summary, err := h.analysis.Analyzer.AnalyzeScan(r.Context(), scanID, analysis.Options{Force: force})
	if err != nil {
		log.Printf("analysis: scan=%s failed: %v", scanID, err)
		http.Error(w, "analysis failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// HandleScanAnalyses handles GET /api/v1/scans/{id}/analyses.
func (h *Handler) HandleScanAnalyses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	scanID := scanPathParts(r)[0]
	if !h.requireScan(w, r, scanID) {
		return
	}
	if h.analysis == nil || h.analysis.Reader == nil {
		http.Error(w, "analysis not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	analyses, err := h.analysis.Reader.ListAnalysesByScan(ctx, scanID)
	if err != nil {
		log.Printf("failed to list analyses: %v", err)
		http.Error(w, "failed to list analyses", http.StatusInternalServerError)
		return
	}
	if analyses == nil {
		analyses = []model.Analysis{}
	}
	writeJSON(w, http.StatusOK, analyses)
}

// HandleFindingAnalysis handles GET /api/v1/scans/{id}/findings/{findingID}/analysis.
func (h *Handler) HandleFindingAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := scanPathParts(r)
	if len(parts) != 4 || parts[1] != "findings" || parts[3] != "analysis" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	scanID, findingID := parts[0], parts[2]
	if !h.requireScan(w, r, scanID) {
		return
	}
	if h.analysis == nil || h.analysis.Reader == nil {
		http.Error(w, "analysis not configured", http.StatusServiceUnavailable)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	finding, err := h.store.GetFinding(ctx, findingID)
	if err != nil {
		log.Printf("failed to get finding: %v", err)
		http.Error(w, "failed to get finding", http.StatusInternalServerError)
		return
	}
	if finding == nil || finding.ScanID != scanID {
		http.Error(w, "finding not found", http.StatusNotFound)
		return
	}

	a, err := h.analysis.Reader.GetAnalysis(ctx, findingID)
	if err != nil {
		log.Printf("failed to get analysis: %v", err)
		http.Error(w, "failed to get analysis", http.StatusInternalServerError)
		return
	}
	// Only canonical findings are analyzed; a stale row left from an earlier
	// dedupe run is hidden, consistent with the list endpoint.
	if a == nil || a.ScanID != scanID || !finding.IsCanonical {
		http.Error(w, "analysis not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, a)
}
