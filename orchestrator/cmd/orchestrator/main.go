package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/api"
	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
	"github.com/2CHILON/vulntriage/orchestrator/internal/model"
	"github.com/2CHILON/vulntriage/orchestrator/internal/scoring"
	"github.com/2CHILON/vulntriage/orchestrator/internal/store"
)

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

	storeInstance := store.NewStore(pool)

	// Build context builder from environment
	sourceRoot := os.Getenv("SOURCE_ROOT")
	contextLines := 20
	if cl, err := strconv.Atoi(os.Getenv("CONTEXT_LINES")); err == nil && cl > 0 {
		contextLines = cl
	}

	cfg := contextbuilder.Config{
		SourceRoot:      sourceRoot,
		ContextLines:    contextLines,
		MaxContextChars: 8000,
		MaxFileBytes:    1048576,
		MaxFilesScanned: 5000,
	}

	builder := contextbuilder.NewBuilder(cfg)

	// Set up LLM client
	llmServiceURL := os.Getenv("LLM_SERVICE_URL")
	if llmServiceURL == "" {
		llmServiceURL = "http://localhost:8000"
	}

	llmClientTimeout := 30 * time.Second
	if timeoutStr := os.Getenv("LLM_CLIENT_TIMEOUT_SECONDS"); timeoutStr != "" {
		if secs, err := strconv.Atoi(timeoutStr); err == nil && secs > 0 {
			llmClientTimeout = time.Duration(secs) * time.Second
		}
	}

	llmClient := llmclient.NewClient(llmServiceURL, llmClientTimeout)

	// Set up analysis service
	concurrency := 4
	if c, err := strconv.Atoi(os.Getenv("ANALYSIS_CONCURRENCY")); err == nil && c > 0 {
		concurrency = c
	}

	maxFindings := 100
	if m, err := strconv.Atoi(os.Getenv("ANALYSIS_MAX_FINDINGS")); err == nil && m > 0 {
		maxFindings = m
	}

	minSeverity := "medium"
	if s := os.Getenv("ANALYSIS_MIN_SEVERITY"); s != "" {
		minSeverity = strings.ToLower(s)
	}

	analysisTimeoutSecs := 300
	if t, err := strconv.Atoi(os.Getenv("ANALYSIS_TIMEOUT_SECONDS")); err == nil && t > 0 {
		if t > 900 {
			log.Printf("warning: ANALYSIS_TIMEOUT_SECONDS %d exceeds max 900, using default 300", t)
		} else {
			analysisTimeoutSecs = t
		}
	}
	if analysisTimeoutSecs <= 0 || analysisTimeoutSecs > 900 {
		log.Printf("warning: invalid ANALYSIS_TIMEOUT_SECONDS, using default 300")
		analysisTimeoutSecs = 300
	}
	analysisTimeout := time.Duration(analysisTimeoutSecs) * time.Second

	analysisService := analysis.NewService(
		storeInstance,
		builder,
		llmClient,
		concurrency,
		maxFindings,
		minSeverity,
		analysisTimeout,
	)

	// Set up scoring service
	weights := scoring.LoadWeights(os.Getenv)
	exposureConfig := scoring.LoadExposureConfig(os.Getenv)

	// Create a reachability adapter that uses the builder
	reachabilityAdapter := &builderReachabilityAdapter{builder: builder}

	scoringService := scoring.NewService(
		storeInstance,
		storeInstance,
		reachabilityAdapter,
		storeInstance,
		weights,
		exposureConfig,
	)

	// Create handlers with full dependencies
	handlers := api.NewHandlerFull(storeInstance, builder, analysisService, scoringService, llmClient, analysisTimeout)

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/api/v1/scans", handlers.HandleScansRouter)
	http.HandleFunc("/api/v1/scans/", handlers.HandleScansRouter)

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
	w.Write([]byte(`{"status":"ok"}`))
}

// builderReachabilityAdapter adapts the Builder to the ReachabilityProvider interface.
type builderReachabilityAdapter struct {
	builder *contextbuilder.Builder
}

func (a *builderReachabilityAdapter) ReachabilityFor(f model.Finding) (kind string, status string) {
	return a.builder.ReachabilityFor(f)
}
