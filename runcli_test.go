// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeHTTPConfig(t *testing.T, srvURL string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	cfg := `{"server":"` + srvURL + `","token":"tok123"}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestRunCLIList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"s1","common_name":"cn1","status":"V"}]`))
	}))
	defer srv.Close()

	cfgPath := writeHTTPConfig(t, srv.URL)
	out := captureStdout(t, func() {
		runCLI(cfgPath, "list", map[string]string{}, nil)
	})
	if !strings.Contains(out, "cn1") {
		t.Fatalf("runCLI list output = %q", out)
	}
}

func TestRunCLICas(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"name":"Root CA","subject":"CN=Root"}]`))
	}))
	defer srv.Close()

	cfgPath := writeHTTPConfig(t, srv.URL)
	out := captureStdout(t, func() {
		runCLI(cfgPath, "cas", map[string]string{}, nil)
	})
	if !strings.Contains(out, "Root CA") {
		t.Fatalf("runCLI cas output = %q", out)
	}
}

func TestRunCLIIssue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s9","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()

	cfgPath := writeHTTPConfig(t, srv.URL)
	out := captureStdout(t, func() {
		runCLI(cfgPath, "issue", map[string]string{"--cn": "test1", "--ca": "Root CA", "--out": t.TempDir()}, nil)
	})
	if !strings.Contains(out, "s9") {
		t.Fatalf("runCLI issue output = %q", out)
	}
}

func TestRunCLIUnknownCommand(t *testing.T) {
	if os.Getenv("RUNCLI_EXIT_HELPER") == "1" {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not reached", 500)
		}))
		cfgPath := writeHTTPConfig(t, srv.URL)
		runCLI(cfgPath, "bogus-cmd", map[string]string{}, nil)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestRunCLIUnknownCommand")
	cmd.Env = append(os.Environ(), "RUNCLI_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "Unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestVersionString(t *testing.T) {
	v := versionString()
	if !strings.Contains(v, "varwof-cli") || !strings.Contains(v, runtime.GOOS) {
		t.Fatalf("versionString = %q", v)
	}
}

func TestCmdReplListAndExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"s1","common_name":"cn1","status":"V"}]`))
	}))
	defer srv.Close()

	cfgPath := writeHTTPConfig(t, srv.URL)

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Write([]byte("list\nexit\n"))
	w.Close()
	defer func() { os.Stdin = oldStdin }()

	out := captureStdout(t, func() {
		cmdRepl(cfgPath)
	})
	os.Stdin = oldStdin
	if !strings.Contains(out, "cn1") {
		t.Fatalf("repl output = %q", out)
	}
	if !strings.Contains(out, "bye") {
		t.Fatalf("repl output = %q", out)
	}
}

func TestCmdCertShowNoPath(t *testing.T) {
	if os.Getenv("CERTSHOW_EXIT_HELPER") == "1" {
		cmdCertShow(map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdCertShowNoPath")
	cmd.Env = append(os.Environ(), "CERTSHOW_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--cert") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdCertShowBadPEM(t *testing.T) {
	if os.Getenv("CERTSHOW_BAD_EXIT_HELPER") == "1" {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.pem")
		os.WriteFile(path, []byte("not-pem"), 0644)
		cmdCertShow(map[string]string{"--cert": path})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdCertShowBadPEM")
	cmd.Env = append(os.Environ(), "CERTSHOW_BAD_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "not a PEM") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdCertShowFile(t *testing.T) {
	userCert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		cmdCertShow(map[string]string{"--cert": path})
	})
	if !strings.Contains(out, "No varwof extensions") {
		t.Fatalf("cmdCertShow output = %q", out)
	}
}

func TestCmdIssueWithPA(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req issueReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode: %v", err)
		}
		if req.PrincipalAuthorization == nil || len(req.PrincipalAuthorization.Grants) != 1 {
			t.Errorf("PA = %+v", req.PrincipalAuthorization)
		}
		if req.PrincipalAuthorization.Grants[0].SchemeID != "mysql" {
			t.Errorf("grant = %+v", req.PrincipalAuthorization.Grants[0])
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s1","common_name":"cn1","cert_pem":"C","key_pem":"K","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdIssue(c, map[string]string{"--cn": "cn1", "--ca": "Root CA", "--pa": "mysql:SELECT"})
	})
	if !strings.Contains(out, "Serial: s1") {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdIssueNoOutDir(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s1","common_name":"cn1","cert_pem":"C","key_pem":"K","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdIssue(c, map[string]string{"--cn": "cn1", "--ca": "Root CA"})
	})
	if !strings.Contains(out, "Cert:\nC") {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdIssueNoCN(t *testing.T) {
	if os.Getenv("ISSUE_CN_EXIT_HELPER") == "1" {
		cmdIssue(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdIssueNoCN")
	cmd.Env = append(os.Environ(), "ISSUE_CN_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--cn is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdIssueBadPA(t *testing.T) {
	if os.Getenv("ISSUE_PA_EXIT_HELPER") == "1" {
		cmdIssue(nil, map[string]string{"--cn": "cn1", "--pa": "no-colon"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdIssueBadPA")
	cmd.Env = append(os.Environ(), "ISSUE_PA_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "invalid PA grant") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdFindByKeyFromCertFile(t *testing.T) {
	userCert, _ := makeTestSigner(t, "ops")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("hash"); len(got) != 64 {
			t.Errorf("hash len = %d", len(got))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdFindByKey(c, map[string]string{"--cert": certPath})
	})
	if !strings.Contains(out, "No certificates found") {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdFindByKeyNoArgs(t *testing.T) {
	if os.Getenv("FIND_EXIT_HELPER") == "1" {
		cmdFindByKey(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdFindByKeyNoArgs")
	cmd.Env = append(os.Environ(), "FIND_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--hash, --cert, or --key") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdFindByKeyBadCertFile(t *testing.T) {
	if os.Getenv("FIND_BAD_EXIT_HELPER") == "1" {
		cmdFindByKey(nil, map[string]string{"--cert": "/nonexistent/c.pem"})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdFindByKeyBadCertFile")
	cmd.Env = append(os.Environ(), "FIND_BAD_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "Error extracting hash") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCheckPassAndFail(t *testing.T) {
	old := selfcheckFailures
	selfcheckFailures = 0
	out := captureStdout(t, func() {
		check(true, "db", "ok")
		check(false, "tsa", "missing")
	})
	if !strings.Contains(out, "[PASS] db: ok") || !strings.Contains(out, "[FAIL] tsa: missing") {
		t.Fatalf("check output = %q", out)
	}
	if selfcheckFailures != 1 {
		t.Fatalf("selfcheckFailures = %d", selfcheckFailures)
	}
	selfcheckFailures = old
}

func TestCmdRevokeByPrincipalNoUID(t *testing.T) {
	if os.Getenv("REVOKEP_EXIT_HELPER") == "1" {
		cmdRevokeByPrincipal(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdRevokeByPrincipalNoUID")
	cmd.Env = append(os.Environ(), "REVOKEP_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--principal-uid is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdGenerateCRLServerError(t *testing.T) {
	if os.Getenv("CRL_ERR_HELPER") == "1" {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			w.Write([]byte(`{"code":500,"message":"boom"}`))
		}))
		defer srv.Close()
		cmdGenerateCRL(NewClient(srv.URL, nil), "Root CA")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdGenerateCRLServerError")
	cmd.Env = append(os.Environ(), "CRL_ERR_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "Error regenerating CRL") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestDoRawEncodeError(t *testing.T) {
	c := NewClient("http://127.0.0.1:1", nil)
	if _, err := c.doRaw("POST", "/x", func() {}); err == nil {
		t.Fatal("expected encode error")
	}
}

func TestCmdRevokeSubCANoName(t *testing.T) {
	if os.Getenv("REVOKESUB_EXIT_HELPER") == "1" {
		cmdRevokeSubCA(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdRevokeSubCANoName")
	cmd.Env = append(os.Environ(), "REVOKESUB_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--sub-ca is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdCAInfoNoName(t *testing.T) {
	if os.Getenv("CAINFO_EXIT_HELPER") == "1" {
		cmdCAInfo(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdCAInfoNoName")
	cmd.Env = append(os.Environ(), "CAINFO_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--ca is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICIssueConstraintsAndJSON(t *testing.T) {
	dir := t.TempDir()
	userCert, userKey := makeTestSigner(t, "varwof:agent")
	certPath := filepath.Join(dir, "user.pem")
	keyPath := filepath.Join(dir, "user-key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, userKey)}), 0600)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req aicIssueReq
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.AuthorizationConstraints) != 1 {
			t.Errorf("constraints = %+v", req.AuthorizationConstraints)
		}
		if req.Subject != "/C=CN/O=custom/CN=cn" {
			t.Errorf("subject = %q", req.Subject)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"s1","cert_pem":"C","key_pem":"K","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	outDir := filepath.Join(dir, "out")
	out := captureStdout(t, func() {
		cmdAICIssue(c, map[string]string{
			"--user-cert": certPath, "--user-key": keyPath,
			"--agent": "agent-1", "--caps": "varwof/demo-mysql-v1:query",
			"--constraints": "varwof/demo-mysql-v1:query:{\"max_rows\":100}",
			"--subject":     "/C=CN/O=custom/CN=cn",
			"--ca":          "Root CA",
			"--out":         outDir, "--json": "true",
		})
	})
	if !strings.Contains(out, "Issued AIC: agent-1") || !strings.Contains(out, `"serial_number": "s1"`) {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdPolicySignMissingArgs(t *testing.T) {
	if os.Getenv("POLICYSIGN_EXIT_HELPER") == "1" {
		cmdPolicySign(map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdPolicySignMissingArgs")
	cmd.Env = append(os.Environ(), "POLICYSIGN_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--file, --cert and --key") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdReSignMissingArgs(t *testing.T) {
	if os.Getenv("RESIGN_EXIT_HELPER") == "1" {
		cmdReSign(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdReSignMissingArgs")
	cmd.Env = append(os.Environ(), "RESIGN_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--ca and --serial are required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdRevokeAllWithReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req revokeReq
		json.NewDecoder(r.Body).Decode(&req)
		if req.Reason != "keyCompromise" {
			t.Errorf("reason = %q", req.Reason)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"revoked_count":2}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdRevokeAll(c, map[string]string{"--reason": "keyCompromise"})
	})
	if !strings.Contains(out, "Revoked all: 2") {
		t.Fatalf("output = %q", out)
	}
}

func TestRunCLIDispatchCommands(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/certs":
			w.Write([]byte(`{"serial_number":"s1","cert_pem":"C","key_pem":"K","ca":"Root CA"}`))
		case "/api/v1/cert/abc/s1/revoke", "/api/v1/cert/Root CA/s1/revoke":
			w.Write([]byte(`{"status":"revoked"}`))
		case "/api/v1/cert/Root CA/s1":
			w.Write([]byte(`{"serial_number":"s1","cert_pem":"C","ca":"Root CA"}`))
		case "/api/v1/certs/by-key", "/api/v1/cert/by-key":
			w.Write([]byte(`[]`))
		case "/api/v1/cert/Root CA/s1/renew", "/api/v1/cert/Root CA/s1/re-sign":
			w.Write([]byte(`{"serial_number":"s2","cert_pem":"C","ca":"Root CA"}`))
		case "/api/v1/cert/abc/s1/renew":
			w.Write([]byte(`{"serial_number":"s2","cert_pem":"C","ca":"Root CA"}`))
		case "/api/v1/ca/Root CA":
			w.Write([]byte(`{"name":"Root CA","subject":"CN=Root"}`))
		case "/api/v1/certs/list":
			w.Write([]byte(`[]`))
		case "/api/v1/crl/Root CA/generate":
			w.Write([]byte(`{"ca":"Root CA","length":10}`))
		case "/api/v1/user/revoke-all":
			w.Write([]byte(`{"revoked_count":1}`))
		case "/api/v1/certs/revoke-by-principal":
			w.Write([]byte(`{"revoked_count":1}`))
		case "/api/v1/sub-ca/Sub/revoke-all":
			w.Write([]byte(`{"revoked_count":1}`))
		default:
			http.Error(w, "unexpected "+r.URL.Path, 500)
		}
	}))
	defer srv.Close()
	cfgPath := writeHTTPConfig(t, srv.URL)

	cases := []struct {
		cmd string
		arg map[string]string
		pos []string
	}{
		{"revoke", map[string]string{"--ca": "abc", "--serial": "s1"}, nil},
		{"renew", map[string]string{"--ca": "Root CA", "--serial": "s1"}, nil},
		{"re-sign", map[string]string{"--ca": "Root CA", "--serial": "s1"}, nil},
		{"revoke-all", map[string]string{}, nil},
		{"revoke-by-principal", map[string]string{"--principal-uid": "u"}, nil},
		{"revoke-subca", map[string]string{"--sub-ca": "Sub"}, nil},
		{"find-by-key", map[string]string{"--hash": "abc"}, nil},
	}
	for _, tc := range cases {
		out := captureStdout(t, func() {
			runCLI(cfgPath, tc.cmd, tc.arg, tc.pos)
		})
		if strings.Contains(out, "unexpected") {
			t.Fatalf("%s output = %q", tc.cmd, out)
		}
	}
}
