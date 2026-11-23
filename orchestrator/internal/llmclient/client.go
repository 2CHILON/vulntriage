package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// MaxResponseBytes caps how much of a response body is read.
	MaxResponseBytes = 1 << 20 // 1 MiB
	// DefaultTimeout is the per-request timeout when none is configured.
	DefaultTimeout = 30 * time.Second
	// HealthTimeout bounds GET /health.
	HealthTimeout = 2 * time.Second
	// DefaultRetryBackoff is the pause before the single retry.
	DefaultRetryBackoff = 250 * time.Millisecond
)

// Error categories. Messages never contain URLs, bodies or request contents.
var (
	// ErrUnavailable covers network errors, timeouts and 5xx answers.
	ErrUnavailable = errors.New("llm service unavailable")
	// ErrRejected covers non-retryable HTTP statuses (3xx, 4xx).
	ErrRejected = errors.New("llm service rejected request")
	// ErrInvalidResponse covers malformed, oversized or untrustworthy responses.
	ErrInvalidResponse = errors.New("invalid llm service response")
)

var validPriorities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// Config configures a Client.
type Config struct {
	BaseURL      string        // e.g. http://localhost:8000
	Timeout      time.Duration // per-request timeout; DefaultTimeout when <= 0
	RetryBackoff time.Duration // DefaultRetryBackoff when <= 0
}

// Client calls the Python LLM service.
type Client struct {
	baseURL      string
	timeout      time.Duration
	retryBackoff time.Duration
	http         *http.Client
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("llmclient: base URL must be an absolute http(s) URL")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	backoff := cfg.RetryBackoff
	if backoff <= 0 {
		backoff = DefaultRetryBackoff
	}
	return &Client{
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		timeout:      timeout,
		retryBackoff: backoff,
		http: &http.Client{
			// Never follow redirects: a 3xx is returned as-is and treated as an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Health calls GET /health with a 2 second timeout and returns nil on a 2xx answer.
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, HealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("%w: cannot build health request", ErrUnavailable)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: health check failed (%s)", ErrUnavailable, describeTransportError(ctx, err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxResponseBytes))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%w: health check returned status %d", ErrUnavailable, resp.StatusCode)
	}
	return nil
}

// Analyze sends one finding to POST /analyze and validates the answer.
// Network errors and 5xx answers are retried once after a short backoff.
func (c *Client) Analyze(ctx context.Context, req Request) (Response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, errors.New("llmclient: cannot encode request")
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Response{}, fmt.Errorf("llm request cancelled: %w", ctx.Err())
			case <-time.After(c.retryBackoff):
			}
		}
		raw, retryable, err := c.post(ctx, body)
		if err == nil {
			return decodeAndValidate(raw, req.Finding.ID)
		}
		if ctx.Err() != nil {
			return Response{}, fmt.Errorf("llm request cancelled: %w", ctx.Err())
		}
		lastErr = err
		if !retryable {
			break
		}
	}
	return Response{}, lastErr
}

// post performs a single attempt. retryable is true for network errors and 5xx.
func (c *Client) post(ctx context.Context, body []byte) (raw []byte, retryable bool, err error) {
	attemptCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, c.baseURL+"/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.New("llmclient: cannot build request")
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %s", ErrUnavailable, describeTransportError(attemptCtx, err))
	}
	defer resp.Body.Close()

	raw, err = io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("%w: %s", ErrUnavailable, describeTransportError(attemptCtx, err))
	}

	switch {
	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, false, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
	if len(raw) > MaxResponseBytes {
		return nil, false, fmt.Errorf("%w: body exceeds %d bytes", ErrInvalidResponse, MaxResponseBytes)
	}
	return raw, false, nil
}

// describeTransportError gives a short reason without the URL that *url.Error carries.
func describeTransportError(ctx context.Context, err error) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "cancelled"
	}
	return "connection error"
}

// decodeAndValidate parses the body strictly and rejects untrustworthy answers.
func decodeAndValidate(raw []byte, wantFindingID string) (Response, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("%w: malformed JSON", ErrInvalidResponse)
	}
	if dec.More() {
		return Response{}, fmt.Errorf("%w: trailing data", ErrInvalidResponse)
	}
	if err := validate(resp, wantFindingID); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func validate(resp Response, wantFindingID string) error {
	if resp.FindingID != wantFindingID {
		return fmt.Errorf("%w: finding_id mismatch", ErrInvalidResponse)
	}
	switch resp.Status {
	case StatusOK:
		r := resp.Result
		if r == nil {
			return fmt.Errorf("%w: status ok without result", ErrInvalidResponse)
		}
		if math.IsNaN(r.Confidence) || r.Confidence < 0 || r.Confidence > 1 {
			return fmt.Errorf("%w: confidence out of range", ErrInvalidResponse)
		}
		if !validPriorities[r.Priority] {
			return fmt.Errorf("%w: unknown priority", ErrInvalidResponse)
		}
		if strings.TrimSpace(r.Reasoning) == "" {
			return fmt.Errorf("%w: empty reasoning", ErrInvalidResponse)
		}
	case StatusAnalysisFailed:
		// result is ignored; error text is optional.
	default:
		return fmt.Errorf("%w: unknown status", ErrInvalidResponse)
	}
	return nil
}
