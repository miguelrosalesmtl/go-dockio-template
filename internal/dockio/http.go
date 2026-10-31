package dockio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ErrUnavailable means døckio could not be asked: a network failure, a timeout,
// or a 5xx. It is never a verdict about a person or a credential, and callers
// must not treat it as one -- an outage must not sign anybody out.
var ErrUnavailable = errors.New("dockio: station unavailable")

// APIError is a 4xx answer from døckio, with its OAuth-style error code.
type APIError struct {
	Status      int
	Code        string // "invalid_grant", "invalid_client", ...
	Description string
}

func (e *APIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("dockio: %d %s: %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("dockio: %d %s", e.Status, e.Code)
}

// maxBody caps every response read from døckio. Nothing it legitimately sends
// comes close; a station that streams forever must not exhaust our memory.
const maxBody = 1 << 20

// NewHTTPClient is the client every call in this package uses.
//
// It does NOT follow redirects. Nothing in the protocol answers with one, and
// following a redirect would let a compromised or misconfigured endpoint send a
// client secret or an application token to another host.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// call sends one request and decodes a 2xx JSON answer into out (when out is not
// nil). A 4xx becomes *APIError; a network failure or a 5xx becomes ErrUnavailable.
func call(hc *http.Client, req *http.Request, out any) (int, error) {
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%w: read: %w", ErrUnavailable, err)
	}

	switch {
	case resp.StatusCode >= 500:
		return resp.StatusCode, fmt.Errorf("%w: %s %s answered %d", ErrUnavailable, req.Method, req.URL.Path, resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return resp.StatusCode, fmt.Errorf("%w: %s %s answered with a redirect, which is never followed",
			ErrUnavailable, req.Method, req.URL.Path)
	case resp.StatusCode >= 400:
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, &APIError{Status: resp.StatusCode, Code: e.Error, Description: e.Description}
	}

	if out != nil && len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return resp.StatusCode, fmt.Errorf("dockio: decode %s %s: %w", req.Method, req.URL.Path, err)
		}
	}
	return resp.StatusCode, nil
}

func getJSON(ctx context.Context, hc *http.Client, rawURL string, out any) error {
	u, err := ASCIIURL(rawURL)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	_, err = call(hc, req, out)
	return err
}

func sendJSON(ctx context.Context, hc *http.Client, method, rawURL, bearer string, in, out any) (int, error) {
	u, err := ASCIIURL(rawURL)
	if err != nil {
		return 0, err
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return call(hc, req, out)
}
