package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/2CHILON/vulntriage/orchestrator/internal/analysis"
	"github.com/2CHILON/vulntriage/orchestrator/internal/api"
	"github.com/2CHILON/vulntriage/orchestrator/internal/contextbuilder"
	"github.com/2CHILON/vulntriage/orchestrator/internal/llmclient"
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

	// LLM client and analysis service
	llmURL := os.Getenv("LLM_SERVICE_URL")
	if llmURL == "" {
		llmURL = "http://localhost:8000"
	}
	llm, err := llmclient.New(llmclient.Config{
		BaseURL: llmURL,
		Timeout: time.Duration(envPositiveInt("LLM_CLIENT_TIMEOUT_SECONDS", 30)) * time.Second,
	})
	if err != nil {
		log.Fatalf("invalid LLM_SERVICE_URL: %v", err)
	}
	analyzer, err := analysis.NewService(analysis.Config{
		Concurrency: envPositiveInt("ANALYSIS_CONCURRENCY", analysis.DefaultConcurrency),
		MinSeverity: os.Getenv("ANALYSIS_MIN_SEVERITY"),
		MaxFindings: envPositiveInt("ANALYSIS_MAX_FINDINGS", analysis.DefaultMaxFindings),
		Timeout:     time.Duration(envPositiveInt("ANALYSIS_TIMEOUT_SECONDS", 300)) * time.Second,
	}, storeInstance, builder, llm)
	if err != nil {
		log.Fatalf("invalid analysis configuration: %v", err)
	}
	analysisCfg := analyzer.Config()
	log.Printf("analysis: concurrency=%d min_severity=%s max_findings=%d timeout=%s",
		analysisCfg.Concurrency, analysisCfg.MinSeverity, analysisCfg.MaxFindings, analysisCfg.Timeout)

	// Create handlers with dependency injection
	handlers := api.NewHandlerWithBuilder(storeInstance, builder).WithAnalysis(api.AnalysisDeps{
		Analyzer: analyzer,
		Health:   llm,
		Reader:   storeInstance,
	})

	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/api/v1/scans", handlers.HandleScansRouter)
	http.HandleFunc("/api/v1/scans/", handlers.HandleScansRouter)

	server := &http.Server{
		Addr:        ":8080",
		Handler:     http.DefaultServeMux,
		ReadTimeout: 10 * time.Second,
		// The analyze endpoint is synchronous; leave room for the overall analysis deadline.
		WriteTimeout: analysisCfg.Timeout + 15*time.Second,
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

// envPositiveInt reads a positive integer from the environment, falling back to def.
func envPositiveInt(name string, def int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		log.Printf("ignoring invalid %s, using default %d", name, def)
		return def
	}
	return v
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}
