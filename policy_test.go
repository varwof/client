package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeTestSigner(t *testing.T, ou string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Admin", OrganizationalUnit: []string{ou}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &signerKey.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	return cert, signerKey
}

func TestPolicySignatureRoundTrip(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	data := []byte(`{"version":"v2","roles":{"superadmin":{"profiles":["m-superadmin"],"grants":["ca:*"]}}}`)
	sig, err := buildPolicySignature(data, cert, key)
	if err != nil {
		t.Fatalf("buildPolicySignature: %v", err)
	}
	got, err := verifyPolicySignature(sig, data)
	if err != nil {
		t.Fatalf("verifyPolicySignature: %v", err)
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("signer cert mismatch")
	}
}

func TestPolicySignatureTamperedData(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	data := []byte(`{"version":"v2","roles":{}}`)
	sig, err := buildPolicySignature(data, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, data...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := verifyPolicySignature(sig, tampered); err == nil {
		t.Fatal("tampered data should be rejected")
	}
}

func TestPolicySignerAdminOU(t *testing.T) {
	adminCert, _ := makeTestSigner(t, "admin")
	opsCert, _ := makeTestSigner(t, "ops")
	if !policySignerHasAdminOU(adminCert) {
		t.Fatal("admin OU should be detected")
	}
	if policySignerHasAdminOU(opsCert) {
		t.Fatal("ops OU should not be admin")
	}
}

// wrappingSigner implements crypto.Signer by delegating to an inner signer.
// The old policy.go code asserted signer.(*ecdsa.PrivateKey) directly after a
// switch on signer.Public().(type) — that panics on a wrapped signer whose
// Public() returns an ecdsa.PublicKey but whose concrete type is not
// *ecdsa.PrivateKey. buildPolicySignature must handle it gracefully.
type wrappingSigner struct{ inner crypto.Signer }

func (w wrappingSigner) Public() crypto.PublicKey { return w.inner.Public() }
func (w wrappingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return w.inner.Sign(rand, digest, opts)
}

func TestBuildPolicySignatureWrappedSigner(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	data := []byte(`{"version":"v2","roles":{}}`)
	sig, err := buildPolicySignature(data, cert, wrappingSigner{key})
	if err != nil {
		t.Fatalf("buildPolicySignature with wrapped signer: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}
	// The produced signature must verify against the inner key.
	got, err := verifyPolicySignature(sig, data)
	if err != nil {
		t.Fatalf("verifyPolicySignature: %v", err)
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("signer cert mismatch")
	}
}

func TestCmdPolicySignLocal(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "authz.json")
	data := []byte(`{"version":"v2","roles":{}}`)
	os.WriteFile(policyPath, data, 0600)

	certPath := filepath.Join(dir, "admin.pem")
	certPEM := pemEncodeCert(cert)
	os.WriteFile(certPath, certPEM, 0600)
	keyPath := filepath.Join(dir, "admin.key")
	keyPEM, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyPath, pemEncodePrivateKey(key), 0600)
	_ = keyPEM

	// Calling cmdPolicySign directly would os.Exit, which cannot be captured. Instead, call the core logic.
	sig, err := buildPolicySignature(data, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath+".sig", sig, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPolicySignature(sig, data); err != nil {
		t.Fatalf("round-trip verify: %v", err)
	}
}

func pemEncodeCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// buildMultiCertSig builds a PKCS#7 detached signature but replaces the embedded
// certificate set with attacker-controlled certs (simulating a forged signature
// embedding a self-signed cert sharing the signer's serial number).
func buildForgedSigWithCerts(t *testing.T, data []byte, victimSerial *big.Int, extraCerts ...*x509.Certificate) []byte {
	t.Helper()
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerSelfSigned := &x509.Certificate{
		SerialNumber:          victimSerial,
		Subject:               pkix.Name{CommonName: "Attacker"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	der, err := x509.CreateCertificate(rand.Reader, attackerSelfSigned, attackerSelfSigned, &attackerKey.PublicKey, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	attackerCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// Craft the SignedData manually with the attacker cert embedded and signed
	// with the attacker key.
	hash := sha256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	signedAttrs := []pkcs7Attribute{
		{
			Type: oidContentType,
			Values: []asn1.RawValue{
				{FullBytes: mustMarshal(pkcs7OIDData)},
			},
		},
		{
			Type: oidMessageDigest,
			Values: []asn1.RawValue{
				{Class: 0, Tag: asn1.TagOctetString, Bytes: digest},
			},
		},
	}
	attrDER, err := marshalSignedAttrs(signedAttrs)
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256(attrDER)
	sigASN1, err := ecdsa.SignASN1(rand.Reader, attackerKey, hashed[:])
	if err != nil {
		t.Fatal(err)
	}

	// Emulate the victim's issuer name for the IssuerAndSerial so a serial-only
	// matcher would accept the attacker cert. But because the embedded cert's
	// RawIssuer (attacker self) differs, the issuer+serial matcher must reject.
	// Use the real victim cert to build the signer info if provided.
	var issuerRaw asn1.RawValue
	var attackerCerts []asn1.RawValue
	if len(extraCerts) > 0 {
		issuerRaw = asn1.RawValue{FullBytes: extraCerts[0].RawIssuer}
		attackerCerts = []asn1.RawValue{{FullBytes: attackerCert.Raw}}
	} else {
		issuerRaw = asn1.RawValue{FullBytes: attackerCert.RawIssuer}
		attackerCerts = []asn1.RawValue{{FullBytes: attackerCert.Raw}}
	}

	sd := pkcs7SignedData{
		Version: 1,
		DigestAlgorithms: []pkcs7AlgorithmIdentifier{
			{Algorithm: oidSHA256, Parameters: asn1.RawValue{Tag: 5}},
		},
		EncapContentInfo: pkcs7EncapsulatedContentInfo{
			ContentType: pkcs7OIDData,
		},
		Certificates: attackerCerts,
		SignerInfos: []pkcs7SignerInfo{
			{
				Version: 1,
				IssuerAndSerial: pkcs7IssuerAndSerial{
					Issuer:       issuerRaw,
					SerialNumber: victimSerial,
				},
				DigestAlgorithm:    pkcs7AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.RawValue{Tag: 5}},
				SignedAttributes:   signedAttrs,
				SignatureAlgorithm: pkcs7AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256, Parameters: asn1.RawValue{Tag: 5}},
				Signature:          sigASN1,
			},
		},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := pkcs7ContentInfo{
		ContentType: pkcs7OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	b, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestVerifyPolicySignatureRejectsSelfSignedSigner verifies CL1: an embedded
// self-signed attacker cert must not pass as the policy signer even when it
// shares the victim cert's serial number.
func TestVerifyPolicySignatureRejectsSelfSignedSigner(t *testing.T) {
	cert, _ := makeTestSigner(t, "admin")
	data := []byte(`{"version":"v2","roles":{}}`)

	forged := buildForgedSigWithCerts(t, data, cert.SerialNumber)
	if _, err := verifyPolicySignature(forged, data); err == nil {
		t.Fatal("self-signed signer with victim serial must be rejected (CL1)")
	}
}

// TestVerifyPolicySignatureRootsFailClosed verifies CL1 chain verification:
// nil roots must fail-closed; roots without the CA must reject.
func TestVerifyPolicySignatureRootsFailClosed(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	data := []byte(`{"version":"v2","roles":{}}`)
	sig, err := buildPolicySignature(data, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyPolicySignatureWithRoots(sig, data, nil); err == nil {
		t.Fatal("nil roots must fail-closed (CL1)")
	}

	// Roots pool that does not contain the CA that issued the signer.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCA := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "Other CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	otherDER, _ := x509.CreateCertificate(rand.Reader, otherCA, otherCA, &otherKey.PublicKey, otherKey)
	otherCACert, _ := x509.ParseCertificate(otherDER)
	pool := x509.NewCertPool()
	pool.AddCert(otherCACert)
	if _, err := verifyPolicySignatureWithRoots(sig, data, pool); err == nil {
		t.Fatal("signer not chained to roots pool must be rejected (CL1)")
	}
}

// TestVerifyPolicySignatureExpectedCert verifies the self-verify path binds the
// embedded signer to the expected certificate (issuer+serial+SPKI).
func TestVerifyPolicySignatureExpectedCert(t *testing.T) {
	cert, key := makeTestSigner(t, "admin")
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	data := []byte(`{"version":"v2","roles":{}}`)
	sig, err := buildPolicySignature(data, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	// Expected cert with the same serial but a different key must be rejected.
	fake := *cert
	fake.PublicKey = &otherKey.PublicKey
	if _, err := verifyPolicySignatureWithTrust(sig, data, nil, &fake); err == nil {
		t.Fatal("expected-cert binding must reject key mismatch (CL1)")
	}
	// Correct expected cert passes.
	if _, err := verifyPolicySignatureWithTrust(sig, data, nil, cert); err != nil {
		t.Fatalf("expected-cert binding should pass: %v", err)
	}
}
