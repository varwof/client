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
	"strings"
	"testing"
)

func TestCmdBatchIssue(t *testing.T) {
	dir := t.TempDir()
	reqFile := filepath.Join(dir, "reqs.json")
	reqs := `[{"cn":"s1","profile":"tls-server","ca":"Root CA","validity":90}]`
	if err := os.WriteFile(reqFile, []byte(reqs), 0644); err != nil {
		t.Fatal(err)
	}

	var gotPath string
	var gotMethod string
	var gotBatch struct {
		Requests []struct {
			CN       string `json:"cn"`
			Profile  string `json:"profile,omitempty"`
			CA       string `json:"ca,omitempty"`
			Validity int    `json:"validity,omitempty"`
		} `json:"requests"`
		Fast bool `json:"fast"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		if err := json.NewDecoder(r.Body).Decode(&gotBatch); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"serial_number":"s1","common_name":"s1","status":"V"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdBatchIssue(c, map[string]string{"--requests": reqFile})
	})
	if gotPath != "/api/v1/certs/batch" || gotMethod != "POST" {
		t.Fatalf("got %s %s", gotMethod, gotPath)
	}
	if len(gotBatch.Requests) != 1 || gotBatch.Requests[0].CN != "s1" {
		t.Fatalf("batch = %+v", gotBatch)
	}
	if !strings.Contains(out, `"serial_number": "s1"`) {
		t.Fatalf("output = %q", out)
	}
}

func TestCmdBatchIssueCSVFlag(t *testing.T) {
	dir := t.TempDir()
	reqFile := filepath.Join(dir, "reqs.json")
	if err := os.WriteFile(reqFile, []byte(`[{"cn":"s1"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	captureStdout(t, func() {
		cmdBatchIssue(c, map[string]string{"--csv": reqFile})
	})
}

func TestCmdBatchIssueNoFile(t *testing.T) {
	if os.Getenv("BATCH_EXIT_HELPER") == "1" {
		cmdBatchIssue(nil, map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdBatchIssueNoFile")
	cmd.Env = append(os.Environ(), "BATCH_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--requests") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICBatchFull(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	cfgPath := filepath.Join(dir, "batch.json")
	cfg := `{"ca":"Root CA","out_dir":"` + outDir + `","users":[
	  {"cn":"zhangsan","subject":"O=Varwof","agents":[
	    {"agent_id":"zs-agent","realm":"varwof","hash_algo":"sha256","delegation_mode":0,
	     "capabilities":[{"scheme_id":"varwof/demo-mysql-v1","capability_id":"query"}]}
	  ]}]}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	userCert, userKey := makeTestSigner(t, "varwof:agent")
	userPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}))
	userKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, userKey)}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/certs" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"serial_number":"a1","cert_pem":` + marshalJSON(userPEM) + `,"key_pem":` + marshalJSON(userKeyPEM) + `,"ca":"Root CA"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		cmdAICBatch(c, map[string]string{"--config": cfgPath})
	})
	if !strings.Contains(out, "zs-agent") {
		t.Fatalf("batch output = %q", out)
	}
	if _, err := os.Stat(filepath.Join(outDir, "zs-agent.pem")); err != nil {
		t.Fatalf("aic cert not written: %v", err)
	}
}

func TestIssueUserAndAgents(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "out")
	os.MkdirAll(outDir, 0755)

	userCert, userKey := makeTestSigner(t, "varwof:agent")
	certPath := filepath.Join(outDir, "zhangsan.pem")
	keyPath := filepath.Join(outDir, "zhangsan.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: userCert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, userKey)}), 0600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"a1","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, nil)
	u := batchUser{CN: "zhangsan", Subject: "O=Varwof", Agents: []batchAgt{
		{AgentID: "zs-agent", Realm: "varwof", HashAlgo: "sha256",
			Capabilities: []aicCap{{SchemeID: "varwof/demo-mysql-v1", CapabilityID: "query"}}},
	}}
	out := captureStdout(t, func() {
		issueUserAndAgents(c, "Root CA", outDir, "", u)
	})
	if !strings.Contains(out, "zs-agent") {
		t.Fatalf("output = %q", out)
	}
}

func TestIssueUserAndAgentsEmptyAgentID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected", 500)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	out := captureStdout(t, func() {
		issueUserAndAgents(c, "Root CA", t.TempDir(), "", batchUser{
			CN: "x", Agents: []batchAgt{{AgentID: ""}},
		})
	})
	if !strings.Contains(out, "agent_id empty") {
		t.Fatalf("output = %q", out)
	}
}

func TestIssueBatchUserCert(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"serial_number":"u1","cert_pem":"CERT","key_pem":"KEY","ca":"Root CA"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)
	path, err := issueBatchUserCert(c, "Root CA", batchUser{CN: "zhangsan", Subject: "O=Varwof"}, dir)
	if err != nil {
		t.Fatalf("issueBatchUserCert: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cert not written: %v", err)
	}
	if _, err := os.Stat(strings.TrimSuffix(path, ".pem") + ".key"); err != nil {
		t.Fatalf("key not written: %v", err)
	}
}
