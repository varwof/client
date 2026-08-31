// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// writeAICConfig writes an HTTP-mode config pointing at the test server.
func writeAICJWTConfig(t *testing.T, srvURL, certPath string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := `{"server":"` + srvURL + `","token":"tok123","client_cert":"` + certPath + `"}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestCmdAICJWTExchange(t *testing.T) {
	// Build a fake AIC certificate.
	userCert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "aic.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}

	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type = %q", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		gotForm = r.Form
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"eyJhbGciOiJFUzI1NiJ9.payload.sig","token_type":"Bearer","expires_in":3600,"scope":"varwof/demo-mysql-v1:SELECT:*"}`))
	}))
	defer srv.Close()

	cfg, err := LoadConfig(writeAICJWTConfig(t, srv.URL, certPath))
	if err != nil {
		t.Fatal(err)
	}
	c := NewClientWithToken(cfg.Server, nil, cfg.Token)

	out := captureStdout(t, func() {
		cmdAICJWT(c, cfg, map[string]string{})
	})

	if gotForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type = %q", gotForm.Get("grant_type"))
	}
	if gotForm.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:x509-cert" {
		t.Errorf("subject_token_type = %q", gotForm.Get("subject_token_type"))
	}
	if !strings.Contains(gotForm.Get("subject_token"), "BEGIN CERTIFICATE") {
		t.Errorf("subject_token does not carry the PEM cert")
	}
	if !strings.Contains(out, "eyJhbGciOiJFUzI1NiJ9.payload.sig") {
		t.Fatalf("stdout = %q, want access token", out)
	}
}

func TestCmdAICJWTToFile(t *testing.T) {
	userCert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "aic.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-abc","token_type":"Bearer","expires_in":60}`))
	}))
	defer srv.Close()

	cfg, _ := LoadConfig(writeAICJWTConfig(t, srv.URL, certPath))
	c := NewClientWithToken(cfg.Server, nil, cfg.Token)
	tokenPath := filepath.Join(dir, "out.jwt")

	out := captureStdout(t, func() {
		cmdAICJWT(c, cfg, map[string]string{"--out": tokenPath})
	})
	if !strings.Contains(out, "AIC-JWT written") {
		t.Fatalf("stdout = %q", out)
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "tok-abc" {
		t.Fatalf("token file = %q, want tok-abc", data)
	}
}

func TestCmdAICJWTNoCert(t *testing.T) {
	if os.Getenv("AICJWT_EXIT_HELPER") == "1" {
		cmdAICJWT(nil, &Config{}, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdAICJWTNoCert")
	cmd.Env = append(os.Environ(), "AICJWT_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--cert is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICJWTBadCert(t *testing.T) {
	if os.Getenv("AICJWT_BAD_EXIT_HELPER") == "1" {
		cmdAICJWT(nil, &Config{}, map[string]string{"--cert": "/nonexistent/aic.pem"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdAICJWTBadCert")
	cmd.Env = append(os.Environ(), "AICJWT_BAD_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "read certificate") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICJWTJSON(t *testing.T) {
	userCert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "aic.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"tok-json","token_type":"Bearer","expires_in":120}`))
	}))
	defer srv.Close()

	cfg, _ := LoadConfig(writeAICJWTConfig(t, srv.URL, certPath))
	c := NewClientWithToken(cfg.Server, nil, cfg.Token)

	out := captureStdout(t, func() {
		cmdAICJWT(c, cfg, map[string]string{"--json": "true"})
	})
	if !strings.Contains(out, `"access_token": "tok-json"`) {
		t.Fatalf("stdout = %q", out)
	}
}
