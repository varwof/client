package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pki "github.com/varwof/types"
)

func TestParseArgs(t *testing.T) {
	m, pos := parseArgs([]string{"--ca", "Root CA", "extra", "--json"})
	if m["--ca"] != "Root CA" {
		t.Errorf("--ca = %q", m["--ca"])
	}
	if m["--json"] != "true" {
		t.Errorf("--json = %q", m["--json"])
	}
	if len(pos) != 1 || pos[0] != "extra" {
		t.Errorf("pos = %v", pos)
	}

	// flag followed by another flag -> value flags consume the next arg even
	// when it starts with "--" (fixes "--flag --value" ambiguity); boolean
	// flags stay "true".
	m, _ = parseArgs([]string{"--ca", "--json"})
	if m["--ca"] != "--json" || m["--json"] != "" {
		t.Errorf("m = %v", m)
	}
	m, _ = parseArgs([]string{"--subject", "--json", "--ca", "Root"})
	if m["--subject"] != "--json" || m["--ca"] != "Root" {
		t.Errorf("m = %v", m)
	}
	m, _ = parseArgs([]string{"--json", "--spiffe"})
	if m["--json"] != "true" || m["--spiffe"] != "true" {
		t.Errorf("m = %v", m)
	}

	// empty
	m, pos = parseArgs(nil)
	if len(m) != 0 || len(pos) != 0 {
		t.Errorf("m=%v pos=%v", m, pos)
	}
}

func TestBuildQuery(t *testing.T) {
	q := buildQuery(map[string]string{"status": "V", "ca": "Root CA"})
	if !strings.Contains(q, "ca=Root+CA") || !strings.Contains(q, "status=V") {
		t.Errorf("query = %q", q)
	}
	// empty values are skipped
	q = buildQuery(map[string]string{"cn": "", "status": "R"})
	if strings.Contains(q, "cn=") {
		t.Errorf("query should skip empty: %q", q)
	}
	if !strings.Contains(q, "status=R") {
		t.Errorf("query = %q", q)
	}
	if q2 := buildQuery(nil); q2 != "" {
		t.Errorf("empty map -> %q", q2)
	}
}

func TestParseInt(t *testing.T) {
	if got := parseInt("", 30); got != 30 {
		t.Errorf("empty -> %d", got)
	}
	if got := parseInt("365", 30); got != 365 {
		t.Errorf("365 -> %d", got)
	}
	if got := parseInt("abc", 30); got != 30 {
		t.Errorf("abc -> %d", got)
	}
	if got := parseInt("-5", 30); got != -5 {
		t.Errorf("-5 -> %d", got)
	}
}

func TestFirstPos(t *testing.T) {
	if got := firstPos(nil); got != "" {
		t.Errorf("nil -> %q", got)
	}
	if got := firstPos([]string{"a", "b"}); got != "a" {
		t.Errorf("-> %q", got)
	}
}

func TestGrantsFromCaps(t *testing.T) {
	caps := []aicCap{
		{SchemeID: "varwof/demo-mysql-v1", CapabilityID: "query"},
		{SchemeID: "varwof/demo-mysql-v1", CapabilityID: "insert"},
	}
	grants := grantsFromCaps(caps)
	if len(grants) != 2 {
		t.Fatalf("len = %d", len(grants))
	}
	if grants[0].SchemeID != "varwof/demo-mysql-v1" || grants[0].CapabilityID != "query" {
		t.Errorf("grants[0] = %+v", grants[0])
	}
	if got := grantsFromCaps(nil); len(got) != 0 {
		t.Errorf("nil -> %d", len(got))
	}
}

func TestLoadBatchConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "batch.json")
	data := `{"api_base":"https://x","ca":"Root CA","out_dir":"/tmp/out",
	  "users":[{"cn":"zhangsan","subject":"CN=zhangsan","agents":[
	    {"agent_id":"a1","realm":"defaults","hash_algo":"SHA256","delegation_mode":0,
	     "capabilities":[{"scheme_id":"varwof/demo-mysql-v1","capability_id":"query"}]}]}]}`
	if err := os.WriteFile(cfgPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	bc, err := loadBatchConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadBatchConfig: %v", err)
	}
	if bc.CA != "Root CA" || len(bc.Users) != 1 || len(bc.Users[0].Agents) != 1 {
		t.Fatalf("batch = %+v", bc)
	}
	if bc.Users[0].Agents[0].Capabilities[0].CapabilityID != "query" {
		t.Errorf("caps = %+v", bc.Users[0].Agents[0].Capabilities)
	}

	// invalid JSON
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBatchConfig(bad); err == nil {
		t.Fatal("expected error on invalid JSON")
	}

	// missing file
	if _, err := loadBatchConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("expected error on missing file")
	}
}

func writeTestCertPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	cert, _ := makeTestSigner(t, "admin")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSPKIHashFromCertFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	cert := writeTestCertPEM(t, certPath)

	hash, err := spkiHashFromCertFile(certPath)
	if err != nil {
		t.Fatalf("spkiHashFromCertFile: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("hash len = %d", len(hash))
	}
	pubBytes, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	want := sha256.Sum256(pubBytes)
	if hash != fmt.Sprintf("%x", want) {
		t.Fatalf("hash mismatch")
	}

	// missing file
	if _, err := spkiHashFromCertFile(filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("expected error on missing file")
	}
	// no PEM data
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := spkiHashFromCertFile(bad); err == nil {
		t.Fatal("expected error on non-PEM file")
	}
}

func TestSPKIHashFromKeyFile(t *testing.T) {
	dir := t.TempDir()
	key := genSigner(t, "ecdsa")

	// PKCS8
	keyPath := filepath.Join(dir, "k8.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)}), 0600); err != nil {
		t.Fatal(err)
	}
	h1, err := spkiHashFromKeyFile(keyPath)
	if err != nil {
		t.Fatalf("PKCS8: %v", err)
	}

	// EC SEC1
	ecKey := key.(*ecdsa.PrivateKey)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPath := filepath.Join(dir, "ec.pem")
	if err := os.WriteFile(ecPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}), 0600); err != nil {
		t.Fatal(err)
	}
	h2, err := spkiHashFromKeyFile(ecPath)
	if err != nil {
		t.Fatalf("EC: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("PKCS8/EC hash mismatch: %s vs %s", h1, h2)
	}

	// RSA PKCS1
	rsaKey := genSigner(t, "rsa").(*rsa.PrivateKey)
	r1Path := filepath.Join(dir, "r1.pem")
	if err := os.WriteFile(r1Path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := spkiHashFromKeyFile(r1Path); err != nil {
		t.Fatalf("PKCS1: %v", err)
	}

	// garbage
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := spkiHashFromKeyFile(bad); err == nil {
		t.Fatal("expected error on non-PEM key")
	}
}

func TestPrincipalUidFromCert(t *testing.T) {
	cert, _ := makeTestSigner(t, "admin")
	uid, err := principalUidFromCert("zhangsan", cert)
	if err != nil {
		t.Fatalf("principalUidFromCert: %v", err)
	}
	parts := strings.Split(uid, ":")
	if len(parts) != 3 {
		t.Fatalf("uid = %q", uid)
	}
	if parts[0] != "zhangsan" || parts[1] != "zhangsan" {
		t.Errorf("uid parts = %v", parts)
	}
	if len(parts[2]) == 0 {
		t.Error("empty key hash")
	}
}

func TestLoadCertWithCN(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	cert := writeTestCertPEM(t, certPath)
	got, cn, err := loadCertWithCN(certPath)
	if err != nil {
		t.Fatalf("loadCertWithCN: %v", err)
	}
	if cn != cert.Subject.CommonName {
		t.Errorf("cn = %q want %q", cn, cert.Subject.CommonName)
	}
	if !got.Equal(cert) {
		t.Error("cert mismatch")
	}

	// missing file
	if _, _, err := loadCertWithCN(filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("expected error on missing file")
	}
	// not PEM
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadCertWithCN(bad); err == nil {
		t.Fatal("expected error on non-PEM file")
	}
}

func makeTestTBS() *pki.DelegationAuthTBS {
	ts := time.Now().UTC().Truncate(time.Second)
	return &pki.DelegationAuthTBS{
		Version:           1,
		AgentId:           "agent-1",
		PrincipalUid:      pki.PrincipalUid{Realm: "defaults", Identifier: "zhangsan", KeyHash: []byte{1, 2, 3}},
		Reason:            pki.Reason{ReasonCode: "API_ISSUE", Description: "test"},
		Capabilities:      []pki.Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "query"}},
		RequestedLifetime: 3600,
		Timestamp:         ts,
		Nonce:             bytes.Repeat([]byte{0x42}, 32),
	}
}

func TestSignDelegationAuth(t *testing.T) {
	dir := t.TempDir()
	for _, typ := range []string{"ecdsa", "rsa", "ed25519"} {
		key := genSigner(t, typ)
		keyPath := filepath.Join(dir, typ+".pem")
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)}), 0600); err != nil {
			t.Fatal(err)
		}
		tbs := makeTestTBS()
		sig, algo, err := signDelegationAuth(keyPath, "", tbs)
		if err != nil {
			t.Fatalf("%s: sign: %v", typ, err)
		}
		der, err := asn1.Marshal(*tbs)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(der)
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			if algo != "ECDSA-SHA256" {
				t.Errorf("%s: algo = %q", typ, algo)
			}
			if !ecdsa.VerifyASN1(&k.PublicKey, digest[:], sig) {
				t.Errorf("%s: signature invalid", typ)
			}
		case *rsa.PrivateKey:
			if algo != "RSA-SHA256" {
				t.Errorf("%s: algo = %q", typ, algo)
			}
			if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
				t.Errorf("%s: signature invalid: %v", typ, err)
			}
		case ed25519.PrivateKey:
			if algo != "Ed25519" {
				t.Errorf("%s: algo = %q", typ, algo)
			}
			if !ed25519.Verify(k.Public().(ed25519.PublicKey), digest[:], sig) {
				t.Errorf("%s: signature invalid", typ)
			}
		}
	}

	// missing key file
	if _, _, err := signDelegationAuth(filepath.Join(dir, "nope.pem"), "", makeTestTBS()); err == nil {
		t.Fatal("expected error on missing key")
	}
	// non-PEM key file
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := signDelegationAuth(bad, "", makeTestTBS()); err == nil {
		t.Fatal("expected error on non-PEM key")
	}

	// encrypted key with correct password (CL7)
	encKey := genSigner(t, "ecdsa")
	encPath := filepath.Join(dir, "enc.pem")
	if err := os.WriteFile(encPath, makeEncryptedPEM(t, encKey, "s3cret"), 0600); err != nil {
		t.Fatal(err)
	}
	encTBS := makeTestTBS()
	sig, algo, err := signDelegationAuth(encPath, "s3cret", encTBS)
	if err != nil {
		t.Fatalf("encrypted key sign: %v", err)
	}
	if algo != "ECDSA-SHA256" {
		t.Errorf("encrypted key algo = %q", algo)
	}
	der, err := asn1.Marshal(*encTBS)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(der)
	ek := encKey.(*ecdsa.PrivateKey)
	if !ecdsa.VerifyASN1(&ek.PublicKey, digest[:], sig) {
		t.Error("encrypted key signature invalid")
	}

	// encrypted key with wrong password -> error
	if _, _, err := signDelegationAuth(encPath, "wrong", makeTestTBS()); err == nil {
		t.Fatal("expected error on wrong password")
	}
}

func TestFillDelegationAuthEvidence(t *testing.T) {
	dir := t.TempDir()
	key := genSigner(t, "ecdsa")
	keyPath := filepath.Join(dir, "user.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)}), 0600); err != nil {
		t.Fatal(err)
	}
	caps := []pki.Capability{{SchemeId: "varwof/demo-mysql-v1", CapabilityId: "query"}}
	pu := pki.PrincipalUid{Realm: "defaults", Identifier: "zhangsan", KeyHash: []byte{9, 8, 7}}
	req := &aicIssueReq{}
	if err := fillDelegationAuthEvidence(req, keyPath, "", pu, "agent-1", caps, nil, 0); err != nil {
		t.Fatalf("fillDelegationAuthEvidence: %v", err)
	}
	if req.UserAuthSig == "" || req.UserAuthSigAlgo != "ECDSA-SHA256" {
		t.Errorf("sig = %q algo = %q", req.UserAuthSig, req.UserAuthSigAlgo)
	}
	if req.UserAuthNonce == "" {
		t.Error("nonce empty")
	}
	if req.UserAuthLifetime != 3600 {
		t.Errorf("lifetime = %d", req.UserAuthLifetime)
	}
	if _, err := time.Parse(time.RFC3339, req.UserAuthTimestamp); err != nil {
		t.Errorf("bad timestamp %q: %v", req.UserAuthTimestamp, err)
	}
	if req.UserAuthReasonCode != "API_ISSUE" {
		t.Errorf("reason = %q", req.UserAuthReasonCode)
	}

	// missing key -> error
	if err := fillDelegationAuthEvidence(req, filepath.Join(dir, "nope.pem"), "", pu, "a", nil, nil, 0); err == nil {
		t.Fatal("expected error on missing key")
	}
}
