package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestKeypair writes a CA cert + client cert/key to dir and returns the
// CA path, cert path, key path and the client signer (so callers can derive
// matching materials, e.g. an encrypted copy of the same key).
func writeTestKeypair(t *testing.T, dir string) (caPath, certPath, keyPath string, clientSigner crypto.Signer) {
	t.Helper()
	caKey := genSigner(t, "ecdsa")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}

	clientKey := genSigner(t, "ecdsa")
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, clientKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}

	caPath = filepath.Join(dir, "ca.pem")
	certPath = filepath.Join(dir, "client.pem")
	keyPath = filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, clientKey)}), 0600); err != nil {
		t.Fatal(err)
	}
	return caPath, certPath, keyPath, clientKey
}

func writeConfig(t *testing.T, path string, cfg map[string]string) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadConfigValid(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key, _ := writeTestKeypair(t, dir)
	cfgPath := filepath.Join(dir, "cfg.json")
	writeConfig(t, cfgPath, map[string]string{
		"server":      "https://localhost:4433",
		"ca_cert":     ca,
		"client_cert": cert,
		"client_key":  key,
	})
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server != "https://localhost:4433" {
		t.Fatalf("server = %q", cfg.Server)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key, _ := writeTestKeypair(t, dir)

	// missing server
	cfgPath := filepath.Join(dir, "no-server.json")
	writeConfig(t, cfgPath, map[string]string{"ca_cert": ca, "client_cert": cert, "client_key": key})
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: server required")
	}

	// missing ca_cert
	cfgPath = filepath.Join(dir, "no-ca.json")
	writeConfig(t, cfgPath, map[string]string{"server": "https://x", "client_cert": cert, "client_key": key})
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: ca_cert required")
	}

	// missing client_cert
	cfgPath = filepath.Join(dir, "no-cert.json")
	writeConfig(t, cfgPath, map[string]string{"server": "https://x", "ca_cert": ca, "client_key": key})
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: client_cert required")
	}

	// missing client_key
	cfgPath = filepath.Join(dir, "no-key.json")
	writeConfig(t, cfgPath, map[string]string{"server": "https://x", "ca_cert": ca, "client_cert": cert})
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: client_key required")
	}

	// plain http with only token is fine
	cfgPath = filepath.Join(dir, "http.json")
	writeConfig(t, cfgPath, map[string]string{"server": "http://127.0.0.1:8445", "token": "abc"})
	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatalf("http+token should pass: %v", err)
	}

	// invalid JSON
	cfgPath = filepath.Join(dir, "bad.json")
	if err := os.WriteFile(cfgPath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: invalid JSON")
	}

	// nonexistent file
	if _, err := LoadConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error: missing file")
	}
}

// TestLoadConfigRejectsWorldReadable verifies the CL4 fix: a config carrying
// credentials must not be world-readable.
func TestLoadConfigRejectsWorldReadable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "world.json")
	if err := os.WriteFile(cfgPath, []byte(`{"server":"http://127.0.0.1:8445","token":"abc"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: world-readable config rejected")
	}
}

// TestLoadConfigPlainHTTPRequiresToken verifies the CL5 fix: plain-http servers
// must authenticate with a token.
func TestLoadConfigPlainHTTPRequiresToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "no-token.json")
	writeConfig(t, cfgPath, map[string]string{"server": "http://127.0.0.1:8445"})
	if _, err := LoadConfig(cfgPath); err == nil {
		t.Fatal("expected error: http:// requires a token")
	}
}

func TestConfigTLSConfigPlainHTTP(t *testing.T) {
	cfg := &Config{Server: "http://127.0.0.1:8445", Token: "abc"}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg != nil {
		t.Fatal("expected nil tls.Config for plain http")
	}
}

func TestConfigTLSConfigValid(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key, _ := writeTestKeypair(t, dir)
	cfg := &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: key}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certs", len(tlsCfg.Certificates))
	}
	if tlsCfg.MinVersion == 0 {
		t.Fatal("MinVersion not set")
	}
}

func TestConfigTLSConfigErrors(t *testing.T) {
	dir := t.TempDir()
	ca, cert, key, _ := writeTestKeypair(t, dir)

	// missing client key file
	cfg := &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: filepath.Join(dir, "nokey.pem")}
	if _, err := cfg.TLSConfig(); err == nil {
		t.Fatal("expected error: missing key file")
	}

	// CA file with no certs
	emptyCA := filepath.Join(dir, "empty-ca.pem")
	if err := os.WriteFile(emptyCA, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg = &Config{Server: "https://x", CACert: emptyCA, ClientCert: cert, ClientKey: key}
	if _, err := cfg.TLSConfig(); err == nil {
		t.Fatal("expected error: no CA cert")
	}

	// mismatched cert/key pair
	otherKey := genSigner(t, "ecdsa")
	otherKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, otherKey)})
	otherKeyPath := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(otherKeyPath, otherKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg = &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: otherKeyPath}
	if _, err := cfg.TLSConfig(); err == nil {
		t.Fatal("expected error: mismatched keypair")
	}
}

func TestConfigTLSConfigEncryptedKey(t *testing.T) {
	dir := t.TempDir()
	ca, cert, _, clientSigner := writeTestKeypair(t, dir)
	encPEM := makeEncryptedPEM(t, clientSigner, "hunter2")
	encKeyPath := filepath.Join(dir, "enc-key.pem")
	if err := os.WriteFile(encKeyPath, encPEM, 0600); err != nil {
		t.Fatal(err)
	}

	// wrong password -> error
	cfg := &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: encKeyPath, KeyPassword: "wrong"}
	if _, err := cfg.TLSConfig(); err == nil {
		t.Fatal("expected error: wrong password")
	}

	// correct password -> ok
	cfg = &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: encKeyPath, KeyPassword: "hunter2"}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig with password: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certs", len(tlsCfg.Certificates))
	}

	// password via env var
	t.Setenv("PKI_KEY_PASSWORD", "hunter2")
	cfg = &Config{Server: "https://x", CACert: ca, ClientCert: cert, ClientKey: encKeyPath}
	tlsCfg, err = cfg.TLSConfig()
	if err != nil {
		t.Fatalf("TLSConfig with env password: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certs", len(tlsCfg.Certificates))
	}
}
