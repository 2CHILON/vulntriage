package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is an HTTP client for the LLM service.
type Client struct {
	baseURL        string
	httpClient     *http.Client
	requestTimeout time.Duration
}

// NewClient creates a new LLM service client.
func NewClient(baseURL string, requestTimeout time.Duration) *Client {
	return &Client{
		baseURL:        strings.TrimSuffix(baseURL, "/"),
		httpClient:     &http.Client{},
		requestTimeout: requestTimeout,
	}
}

// Health checks if the LLM service is healthy. Uses a 2-second timeout.
func (c *Client) Health(ctx context.Context) error {
	healthCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(healthCtx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: network error")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}

	return nil
}

// Analyze sends a finding to the LLM service for analysis. Implements retry logic.
func (c *Client) Analyze(ctx context.Context, req *AnalyzeRequest) (*AnalyzeResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}

	// Marshal request to validate it only contains allowed keys
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Try up to 2 times (1 retry)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		analyzeCtx, cancel := context.WithTimeout(ctx, c.requestTimeout)
		defer cancel()

		httpReq, err := http.NewRequestWithContext(analyzeCtx, http.MethodPost, c.baseURL+"/analyze", bytes.NewReader(reqBody))
		if err != nil {
			lastErr = fmt.Errorf("failed to create request: %w", err)
			continue
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			// Retry on network errors
			lastErr = fmt.Errorf("network error")
			if attempt < 1 {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		defer resp.Body.Close()

		// Retry on 5xx errors
		if resp.StatusCode >= 500 && resp.StatusCode < 600 && attempt < 1 {
			lastErr = fmt.Errorf("server error: status %d", resp.StatusCode)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Cap response body at 1 MiB
		limitedBody := io.LimitReader(resp.Body, 1024*1024)
		respBody, err := io.ReadAll(limitedBody)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		// Check if body was truncated
		if resp.ContentLength > 1024*1024 {
			return nil, fmt.Errorf("response body too large")
		}

		var analysisResp AnalyzeResponse
		if err := json.Unmarshal(respBody, &analysisResp); err != nil {
			lastErr = fmt.Errorf("invalid response format")
			continue
		}

		// Validate response
		if err := validateResponse(&analysisResp, req); err != nil {
			return nil, err
		}

		return &analysisResp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("analyze failed after retries")
}

// validateResponse checks the response for validity.
func validateResponse(resp *AnalyzeResponse, req *AnalyzeRequest) error {
	// Reject unknown status values
	if resp.Status != "ok" && resp.Status != "analysis_failed" {
		return fmt.Errorf("invalid status value: %s", resp.Status)
	}

	// Check finding_id matches
	if resp.FindingID != req.Finding.ID {
		return fmt.Errorf("response finding_id mismatch")
	}

	// If status is ok, result must be present and valid
	if resp.Status == "ok" {
		if resp.Result == nil {
			return fmt.Errorf("status ok requires result field")
		}

		// Validate confidence is in [0, 1]
		if resp.Result.Confidence < 0.0 || resp.Result.Confidence > 1.0 {
			return fmt.Errorf("confidence out of bounds: %f", resp.Result.Confidence)
		}

		// Validate priority
		if resp.Result.Priority != "critical" && resp.Result.Priority != "high" &&
			resp.Result.Priority != "medium" && resp.Result.Priority != "low" {
			return fmt.Errorf("invalid priority value: %s", resp.Result.Priority)
		}

		// Reasoning must be non-empty
		if strings.TrimSpace(resp.Result.Reasoning) == "" {
			return fmt.Errorf("reasoning must be non-empty when status is ok")
		}
	}

	return nil
}
