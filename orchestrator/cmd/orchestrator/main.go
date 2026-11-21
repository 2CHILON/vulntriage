package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/2CHILON/vulntriage/orchestrator/internal/dedupe"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
	"github.com/2CHILON/vulntriage/orchestrator/internal/parsers"
	"github.com/2CHILON/vulntriage/orchestrator/internal/store"
)

var storeInstance *store.Store

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://postgres:postgres@localhost:5432/vulntriage"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	// Verify connection
	if err := pool.Ping(context.Background()); err != nil {
		log.Fatalf("failed to ping database: %v", err)
	}

	log.Println("Connected to database")

	storeInstance = store.NewStore(pool)

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/api/v1/scans", handleScanUpload)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      http.DefaultServeMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Starting server on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ScanUploadRequest represents the JSON payload for uploading a SARIF scan.
type ScanUploadRequest struct {
	ScanID    string      `json:"scan_id"`
	ToolName  string      `json:"tool_name"`
	SARIFData interface{} `json:"sarif_data"` // Raw SARIF JSON
}

func handleScanUpload(w http.ResponseWriter, r *http.Request) {
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

	// Deduplicate findings
	deduplicator := dedupe.NewDefaultDeduplicator()
	findingPtrs := make([]*model.Finding, len(findings))
	for i := range findings {
		findingPtrs[i] = &findings[i]
	}
	groups := deduplicator.Dedup(findingPtrs)
	deduplicator.Mark(findingPtrs, groups)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Store scan record
	toolName := req.ToolName
	if toolName == "" {
		toolName = "unknown"
	}
	if err := storeInstance.InsertScan(ctx, req.ScanID, toolName); err != nil {
		log.Printf("failed to insert scan record: %v", err)
		http.Error(w, "failed to store scan", http.StatusInternalServerError)
		return
	}

	// Store findings (now with dedupe data)
	if err := storeInstance.InsertFindings(ctx, findings); err != nil {
		log.Printf("failed to insert findings: %v", err)
		http.Error(w, "failed to store findings", http.StatusInternalServerError)
		return
	}

	stats := dedupe.GetStats(groups)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":           req.ScanID,
		"findings_stored":   len(findings),
		"total_findings":    stats.TotalFindings,
		"dedupe_groups":     stats.GroupsCreated,
		"duplicates_removed": stats.DuplicatesRemoved,
		"canonical_findings": stats.CanonicalFindings,
	})
}
