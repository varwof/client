// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeBatchConfig(t *testing.T, dir string, content string) string {
	t.Helper()
	path := filepath.Join(dir, "batch.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

const validBatchJSON = `{
  "api_base": "https://core:4433",
  "ca": "Varwof Issuing CA",
  "out_dir": "/tmp/out",
  "users": [
    {"cn": "alice", "subject": "O=Varwof",
     "agents": [
       {"agent_id": "alice-agent-01", "realm": "varwof", "hash_algo": "sha256", "delegation_mode": 0,
        "capabilities": [{"scheme_id": "mysql", "capability_id": "SELECT:*"}],
        "authorization_constraints": []}
     ]}
  ]
}`

func TestLoadBatchConfigEmptyUsers(t *testing.T) {
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, `{"api_base":"x","users":[]}`)
	if _, err := loadBatchConfig(path); err == nil {
		t.Fatal("expected error for empty users")
	}
}

func TestCmdAICListOutput(t *testing.T) {
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, validBatchJSON)
	out := captureStdout(t, func() {
		cmdAICList(map[string]string{"--config": path})
	})
	if !strings.Contains(out, "alice") || !strings.Contains(out, "mysql:SELECT:*") {
		t.Fatalf("cmdAICList output = %q", out)
	}
}

func TestCmdAICDispatchList(t *testing.T) {
	dir := t.TempDir()
	path := writeBatchConfig(t, dir, validBatchJSON)
	out := captureStdout(t, func() {
		cmdAIC(nil, nil, map[string]string{"--config": path}, "list")
	})
	if !strings.Contains(out, "alice") {
		t.Fatalf("dispatch list output = %q", out)
	}
}

func TestCmdAICUnknownSub(t *testing.T) {
	if os.Getenv("AIC_EXIT_HELPER") == "1" {
		cmdAIC(nil, nil, map[string]string{}, "bogus")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdAICUnknownSub")
	cmd.Env = append(os.Environ(), "AIC_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "unknown aic subcommand") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICListNoConfig(t *testing.T) {
	if os.Getenv("AIC_LIST_EXIT_HELPER") == "1" {
		cmdAICList(map[string]string{})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdAICListNoConfig")
	cmd.Env = append(os.Environ(), "AIC_LIST_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestCmdAICIssueSPUFFEDomainRequired(t *testing.T) {
	if os.Getenv("AIC_SPIFFE_EXIT_HELPER") == "1" {
		cmdAICIssue(nil, map[string]string{
			"--user-cert": "/nonexistent",
			"--user-key":  "/nonexistent",
			"--agent":     "test-agent",
			"--caps":      "mysql:SELECT:*",
			"--spiffe":    "true",
			"--ca":        "test-ca",
		})
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdAICIssueSPUFFEDomainRequired")
	cmd.Env = append(os.Environ(), "AIC_SPIFFE_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit error")
	}
	if !strings.Contains(stderr.String(), "--spiffe-domain") {
		t.Fatalf("stderr = %q, expected --spiffe-domain error", stderr.String())
	}
}
