// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestCmdListCertsTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/certs" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("status") != "V" {
			t.Errorf("query = %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"1","ca_name":"Root CA","status":"V","common_name":"a.com","not_after":"2027-01-01"}]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdListCerts(c, map[string]string{"--status": "V"})
	})
	if !strings.Contains(out, "a.com") || !strings.Contains(out, "Root CA") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdListCertsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"2","ca_name":"Root CA","status":"R","common_name":"b.com"}]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdListCerts(c, map[string]string{"--json": "true"})
	})
	var got []jsonCert
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid json: %v\n%s", err, out)
	}
	if len(got) != 1 || got[0].CommonName != "b.com" {
		t.Errorf("got = %+v", got)
	}
}

func TestCmdListCAs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cas" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"Root CA","subject":"CN=Root","key_algorithm":"ECDSA","not_after":"2030-01-01"}]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdListCAs(c, nil)
	})
	if !strings.Contains(out, "Root CA") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdListCAsJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"Root CA"}]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdListCAs(c, map[string]string{"--json": "true"})
	})
	var got []jsonCA
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Root CA" {
		t.Errorf("got = %+v", got)
	}
}

func TestCmdCAInfoText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ca/Root CA" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"Root CA","subject":"CN=Root","key_algorithm":"ECDSA","fingerprint":"abc","not_before":"2020-01-01","not_after":"2030-01-01"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdCAInfo(c, map[string]string{"--ca": "Root CA"})
	})
	if !strings.Contains(out, "ECDSA") || !strings.Contains(out, "abc") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdCAInfoPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"Root CA","cert_pem":"-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----\n"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdCAInfo(c, map[string]string{"--ca": "Root CA", "--pem": "true"})
	})
	if !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Errorf("output = %q", out)
	}
}

func TestShowCertificateNoExtensions(t *testing.T) {
	cert, _ := makeTestSigner(t, "ops")
	out := captureStdout(t, func() {
		showCertificate(cert)
	})
	if !strings.Contains(out, "No varwof extensions") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdCertShow(t *testing.T) {
	cert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	path := filepath.Join(dir, "c.pem")
	writeTestCertPEM(t, path)

	out := captureStdout(t, func() {
		cmdCertShow(map[string]string{"--cert": path})
	})
	if !strings.Contains(out, "Test CA") || !strings.Contains(out, "Admin") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "Subject:") {
		t.Errorf("output = %q", out)
	}
	_ = cert
}

func TestCmdRevoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cert/Root CA/abc/revoke" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"cascade_count":2}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdRevoke(c, map[string]string{"--ca": "Root CA", "--serial": "abc", "--reason": "superseded"})
	})
	if !strings.Contains(out, "Revoked: Root CA/abc") || !strings.Contains(out, "Cascade: 2") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdGenerateCRL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/crl/Root CA/generate" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ca":"Root CA","length":1234}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdGenerateCRL(c, "Root CA")
	})
	if !strings.Contains(out, "CRL regenerated: Root CA (1234 bytes)") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdRevokeAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user/revoke-all" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revoked_count":5}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdRevokeAll(c, nil)
	})
	if !strings.Contains(out, "Revoked all: 5") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdRevokeByPrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/certs/revoke-by-principal" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revoked_count":3}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdRevokeByPrincipal(c, map[string]string{"--principal-uid": "z:z:hash"})
	})
	if !strings.Contains(out, "Revoked 3 cert(s) for principal z:z:hash") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdRevokeSubCA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sub-ca/Sub CA/revoke-all" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revoked_count":7}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdRevokeSubCA(c, map[string]string{"--sub-ca": "Sub CA"})
	})
	if !strings.Contains(out, "Revoked 7 cert(s) under sub-CA Sub CA") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdFindByKeyHash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cert/by-key" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("hash"); got != "deadbeef" {
			t.Errorf("hash = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"abc","ca_name":"Root CA","common_name":"a.com","status":"V","not_after":"2027-01-01"}]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdFindByKey(c, map[string]string{"--hash": "deadbeef"})
	})
	if !strings.Contains(out, "a.com") || !strings.Contains(out, "Root CA") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdFindByKeyJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdFindByKey(c, map[string]string{"--hash": "deadbeef", "--json": "true"})
	})
	var got []jsonCert
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got = %+v", got)
	}
}

func TestCmdReSign(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cert/Root CA/abc/re-sign" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"new1","common_name":"a.com","ca":"Root CA","cert_pem":"CERTDATA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdReSign(c, map[string]string{"--ca": "Root CA", "--serial": "abc"})
	})
	if !strings.Contains(out, "new1") || !strings.Contains(out, "CERTDATA") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdIssueOutDir(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/certs" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s1","common_name":"a.com","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	out := captureStdout(t, func() {
		cmdIssue(c, map[string]string{"--cn": "a.com", "--out": outDir})
	})
	if !strings.Contains(out, "Issued: a.com") || !strings.Contains(out, "s1.pem") {
		t.Errorf("output = %q", out)
	}
	// files written
	if _, err := os.Stat(filepath.Join(outDir, "s1.pem")); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "s1-key.pem")); err != nil {
		t.Errorf("key file not written: %v", err)
	}
}

func TestCmdAICIssue(t *testing.T) {
	dir := t.TempDir()
	userCert, userKey := makeTestSigner(t, "varwof:agent")
	certPath := filepath.Join(dir, "user.pem")
	keyPath := filepath.Join(dir, "user-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, userKey)}), 0600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/certs" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var req aicIssueReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode req: %v", err)
		}
		if req.UserAuthSig == "" || req.UserAuthSigAlgo != "ECDSA-SHA256" {
			t.Errorf("missing DA evidence: sig=%q algo=%q", req.UserAuthSig, req.UserAuthSigAlgo)
		}
		if req.UserCertPEM == "" {
			t.Error("missing user_cert_pem (C3: CA needs the DA signer certificate to verify the signature)")
		}
		if req.AgentID != "agent-1" {
			t.Errorf("agent = %q", req.AgentID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s1","common_name":"cn","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	outDir := filepath.Join(dir, "out")
	out := captureStdout(t, func() {
		cmdAICIssue(c, map[string]string{
			"--user-cert": certPath, "--user-key": keyPath,
			"--agent": "agent-1", "--caps": "varwof/demo-mysql-v1:query",
			"--ou": "varwof:agent", "--out": outDir,
		})
	})
	if !strings.Contains(out, "Issued AIC: agent-1") {
		t.Errorf("output = %q", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "agent-1.pem")); err != nil {
		t.Errorf("aic cert not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "agent-1.key")); err != nil {
		t.Errorf("aic key not written: %v", err)
	}
}

func TestUsageOutput(t *testing.T) {
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	usage()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = old
	data, _ := io.ReadAll(r)
	out := string(data)
	if !strings.Contains(out, "Usage: varwof-cli") || !strings.Contains(out, "repl") {
		t.Errorf("output = %q", out)
	}
}

func TestReplHelp(t *testing.T) {
	out := captureStdout(t, func() {
		replHelp()
	})
	if !strings.Contains(out, "Commands:") || !strings.Contains(out, "selfcheck") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdAICList(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "batch.json")
	data := `{"users":[{"cn":"zhangsan","subject":"CN=zhangsan","agents":[
	  {"agent_id":"a1","capabilities":[{"scheme_id":"varwof/demo-mysql-v1","capability_id":"query"}]}]}]}`
	if err := os.WriteFile(cfgPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		cmdAICList(map[string]string{"--config": cfgPath})
	})
	if !strings.Contains(out, "zhangsan") || !strings.Contains(out, "varwof/demo-mysql-v1:query") {
		t.Errorf("output = %q", out)
	}
}

func TestCmdRenew(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cert/Root CA/abc/renew" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"new1","common_name":"a.com","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	out := captureStdout(t, func() {
		cmdRenew(c, map[string]string{"--ca": "Root CA", "--serial": "abc", "--out": outDir})
	})
	if !strings.Contains(out, "Renewed: a.com (new serial: new1)") {
		t.Errorf("output = %q", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "new1.pem")); err != nil {
		t.Errorf("renewed cert not written: %v", err)
	}
}

func TestCmdPolicySign(t *testing.T) {
	dir := t.TempDir()
	cert, key := makeTestSigner(t, "admin")
	certPath := filepath.Join(dir, "admin.pem")
	keyPath := filepath.Join(dir, "admin-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)}), 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(file, []byte(`{"version":"v2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	outSig := filepath.Join(dir, "authz.json.sig")

	captured := captureStdout(t, func() {
		cmdPolicySign(map[string]string{
			"--file": file, "--cert": certPath, "--key": keyPath, "--out": outSig,
		})
	})
	if !strings.Contains(captured, "policy signed:") {
		t.Errorf("output = %q", captured)
	}
	sigData, err := os.ReadFile(outSig)
	if err != nil {
		t.Fatalf("sig file: %v", err)
	}
	// self-verify the produced signature
	if _, err := verifyPolicySignature(sigData, []byte(`{"version":"v2"}`)); err != nil {
		t.Fatalf("verify policy signature: %v", err)
	}
}

func TestCmdPolicySignNonAdminOU(t *testing.T) {
	dir := t.TempDir()
	cert, key := makeTestSigner(t, "ops")
	certPath := filepath.Join(dir, "ops.pem")
	keyPath := filepath.Join(dir, "ops-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)}), 0600); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "authz.json")
	if err := os.WriteFile(file, []byte(`{"version":"v2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	// cmdPolicySign exits with status 1 on non-admin OU; run in a subprocess-safe
	// way is impractical here, so assert the guard helper directly.
	if policySignerHasAdminOU(cert) {
		t.Fatal("ops OU should not be admin")
	}
}
