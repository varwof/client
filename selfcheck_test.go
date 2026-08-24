// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func testCAAndCert(t *testing.T) (caPEM, certPEM string, serial string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ser := big.NewInt(12345)
	certTmpl := &x509.Certificate{
		SerialNumber: ser,
		Subject:      pkix.Name{CommonName: "selfcheck-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, caCert, &certKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return caPEM, certPEM, ser.Text(16)
}

func newSelfcheckServer(t *testing.T) (*httptest.Server, string, string) {
	t.Helper()
	caPEM, certPEM, serial := testCAAndCert(t)

	// Build a valid (empty) CRL DER so downloadAndParseCRL parses it.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCertDER, _ := pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(caCertDER.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now(),
		NextUpdate: time.Now().Add(time.Hour),
	}, caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/healthz":
			w.Write([]byte(`{"status":"ok","version":"1.0.0","db":"ok","tsa_signer":"ok","crl_status":"ok"}`))
		case r.URL.Path == "/api/v1/cas":
			w.Write([]byte(`[{"name":"Test Issuing CA","cert_pem":` + marshalJSON(caPEM) + `}]`))
		case r.URL.Path == "/api/v1/certs" && r.Method == http.MethodPost:
			w.Write([]byte(`{"serial_number":"` + serial + `","common_name":"selfcheck-test","cert_pem":` + marshalJSON(certPEM) + `,"ca":"Test Issuing CA"}`))
		case r.URL.Path == "/api/v1/cert/Test Issuing CA/"+serial+"/revoke" && r.Method == http.MethodPost:
			w.Write([]byte(`{"status":"revoked"}`))
		case r.URL.Path == "/api/v1/crl/Test Issuing CA/generate" && r.Method == http.MethodPost:
			w.Write([]byte(`{"ca":"Test Issuing CA","length":1024}`))
		case r.URL.Path == "/api/v1/crl/Test Issuing CA":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(crlDER)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	return srv, serial, certPEM
}

func marshalJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestCmdSelfcheckAllPass(t *testing.T) {
	srv, _, _ := newSelfcheckServer(t)
	defer srv.Close()

	client := NewClient(srv.URL, nil)
	selfcheckFailures = 0
	out := captureStdout(t, func() {
		cmdSelfcheck(client, map[string]string{"--ca": "Test Issuing CA"})
	})
	if strings.Contains(out, "[FAIL]") {
		t.Fatalf("selfcheck reported failures:\n%s", out)
	}
	if !strings.Contains(out, "ALL PASS") {
		t.Fatalf("expected ALL PASS, got:\n%s", out)
	}
}

func TestCmdSelfcheckRequiresCA(t *testing.T) {
	if os.Getenv("SC_EXIT_HELPER") == "1" {
		client := NewClient("http://127.0.0.1:1", nil)
		cmdSelfcheck(client, map[string]string{})
		return
	}
	out, err := runHelperProcess(t)
	if err == nil {
		t.Fatalf("expected exit error, got nil, out=%q", out)
	}
	if !strings.Contains(out, "--ca is required") {
		t.Fatalf("expected --ca is required message, got %q", out)
	}
}

func runHelperProcess(t *testing.T) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCmdSelfcheckRequiresCA")
	cmd.Env = append(os.Environ(), "SC_EXIT_HELPER=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

func TestFetchHealthz(t *testing.T) {
	srv, _, _ := newSelfcheckServer(t)
	defer srv.Close()
	client := NewClient(srv.URL, nil)
	hz, err := fetchHealthz(client)
	if err != nil {
		t.Fatalf("fetchHealthz: %v", err)
	}
	if hz.Status != "ok" || hz.DB != "ok" {
		t.Fatalf("unexpected healthz: %+v", hz)
	}
}

func TestRepairCRLs(t *testing.T) {
	srv, _, _ := newSelfcheckServer(t)
	defer srv.Close()
	client := NewClient(srv.URL, nil)
	selfcheckFailures = 0
	out := captureStdout(t, func() {
		repairCRLs(client)
	})
	if !strings.Contains(out, "regenerated CRLs for 1 CA") {
		t.Fatalf("repairCRLs output = %q", out)
	}
}

func TestVerifyIssuedCert(t *testing.T) {
	caPEM, certPEM, _ := testCAAndCert(t)
	cas := []jsonCA{{Name: "Test Issuing CA", CertPEM: caPEM}}
	issued := &issueResp{CertPEM: certPEM}
	if err := verifyIssuedCert(issued, "Test Issuing CA", &cas); err != nil {
		t.Fatalf("verifyIssuedCert: %v", err)
	}
}

func TestVerifyIssuedCertCAByNameNotFound(t *testing.T) {
	caPEM, certPEM, _ := testCAAndCert(t)
	cas := []jsonCA{{Name: "Other CA", CertPEM: caPEM}}
	issued := &issueResp{CertPEM: certPEM}
	if err := verifyIssuedCert(issued, "Missing CA", &cas); err == nil {
		t.Fatal("expected error for CA not found")
	}
}

func TestVerifyIssuedCertInvalidPEM(t *testing.T) {
	cas := []jsonCA{{Name: "Test Issuing CA"}}
	issued := &issueResp{CertPEM: "not-pem"}
	if err := verifyIssuedCert(issued, "Test Issuing CA", &cas); err == nil {
		t.Fatal("expected error for non-PEM cert")
	}
}

func TestDownloadAndParseCRL(t *testing.T) {
	srv, _, _ := newSelfcheckServer(t)
	defer srv.Close()
	client := NewClient(srv.URL, nil)
	if err := downloadAndParseCRL(client, "Test Issuing CA"); err != nil {
		t.Fatalf("downloadAndParseCRL: %v", err)
	}
}
