package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient("https://localhost:4433/", nil)
	if c.baseURL != "https://localhost:4433" {
		t.Fatalf("baseURL = %q", c.baseURL)
	}
	if c.httpClient == nil {
		t.Fatal("http client nil")
	}
	c2 := NewClientWithToken("https://x", nil, "tok123")
	if c2.token != "tok123" {
		t.Fatalf("token = %q", c2.token)
	}
}

type testResp struct {
	OK   bool   `json:"ok"`
	Name string `json:"name"`
}

func TestClientDoSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cas" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		var in map[string]any
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if in["k"] != "v" {
			t.Errorf("body = %v", in)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"name":"ca1"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	var resp testResp
	if err := c.do("POST", "/api/v1/cas", map[string]string{"k": "v"}, &resp); err != nil {
		t.Fatalf("do: %v", err)
	}
	if !resp.OK || resp.Name != "ca1" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestClientDoNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	if err := c.do("GET", "/api/v1/health", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
}

func TestClientDoBearerToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer abc" {
			t.Errorf("auth = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClientWithToken(srv.URL, nil, "abc")
	if err := c.do("GET", "/x", nil, nil); err != nil {
		t.Fatalf("do: %v", err)
	}
}

func TestClientDoAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":400,"message":"bad request","detail":"field x"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	err := c.do("GET", "/x", nil, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bad request") || !strings.Contains(err.Error(), "field x") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientDoAPIErrorNonJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	err := c.do("GET", "/x", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientDoHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// hijack and close
		hj := w.(http.Hijacker)
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	if err := c.do("GET", "/x", nil, nil); err == nil {
		t.Fatal("expected error on connection failure")
	}
}

func TestClientDoBadRespBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	var out testResp
	if err := c.do("GET", "/x", nil, &out); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestClientDoRaw(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte{0x01, 0x02, 0x03})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	resp, err := c.doRaw("GET", "/crl.der", nil)
	if err != nil {
		t.Fatalf("doRaw: %v", err)
	}
	defer resp.Body.Close()
	data, err := readAll(resp.Body)
	if err != nil {
		t.Fatalf("readAll: %v", err)
	}
	if len(data) != 3 || data[0] != 0x01 {
		t.Fatalf("data = %v", data)
	}
}

func TestClientDoCrossHostRedirectBlocked(t *testing.T) {
	// A redirect to a different host must be blocked (CL2: the mTLS client
	// cert is shared across the whole Transport, so it must never be presented
	// to a third-party host).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("cross-host redirect target must never be reached")
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	err := c.do("GET", "/api/v1/cas", nil, nil)
	if err == nil {
		t.Fatal("cross-host redirect should be blocked (CL2)")
	}
	if !strings.Contains(err.Error(), "redirect to different host") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientDoSameHostRedirectAllowed(t *testing.T) {
	// A redirect within the same host must still work.
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		if r.URL.Path == "/final" {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	var out testResp
	if err := c.do("GET", "/redirect", nil, &out); err != nil {
		t.Fatalf("same-host redirect should succeed: %v", err)
	}
	if !out.OK {
		t.Fatalf("resp = %+v", out)
	}
	if hits != 2 {
		t.Fatalf("expected 2 hits, got %d", hits)
	}
}

func TestReadAll(t *testing.T) {
	data, err := readAll(strings.NewReader("hello"))
	if err != nil || string(data) != "hello" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	_, err = readAll(errReader{})
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
