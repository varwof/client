// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

func NewClient(baseURL string, tlsConfig *tls.Config) *Client {
	return NewClientWithToken(baseURL, tlsConfig, "")
}

func NewClientWithToken(baseURL string, tlsConfig *tls.Config, token string) *Client {
	tr := &http.Transport{}
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
			// CL2 fix: never follow a redirect to a different host. The mTLS
			// client certificate is configured for the whole Transport, so a
			// cross-host redirect would present the client certificate to an
			// arbitrary third party.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				if req.URL.Host != via[0].URL.Host {
					return fmt.Errorf("redirect to different host %q blocked (zero-trust)", req.URL.Host)
				}
				return nil
			},
		},
		token: token,
	}
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (c *Client) do(method, path string, reqBody, respBody any) error {
	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var ae apiError
		if json.NewDecoder(resp.Body).Decode(&ae) == nil {
			if ae.Detail != "" {
				return fmt.Errorf("%s (detail: %s)", ae.Message, ae.Detail)
			}
			return fmt.Errorf("%s", ae.Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// doRaw issues a request and returns the full HTTP response for binary
// bodies (e.g. CRL DER) or status-code-only checks.
func (c *Client) doRaw(method, path string, reqBody any) (*http.Response, error) {
	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	return resp, nil
}

// doForm issues an application/x-www-form-urlencoded POST (used by the
// OAuth token endpoint, e.g. RFC 8693 x509→AIC-JWT exchange).
func (c *Client) doForm(path string, form url.Values, respBody any) error {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var ae apiError
		if json.NewDecoder(resp.Body).Decode(&ae) == nil {
			if ae.Detail != "" {
				return fmt.Errorf("%s (detail: %s)", ae.Message, ae.Detail)
			}
			return fmt.Errorf("%s", ae.Message)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if respBody != nil {
		if err := json.NewDecoder(resp.Body).Decode(respBody); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func readAll(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return data, nil
}
