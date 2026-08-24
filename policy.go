package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	pkcs7OIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	pkcs7OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

type pkcs7AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs7IssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type pkcs7Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type pkcs7SignerInfo struct {
	Version            int
	IssuerAndSerial    pkcs7IssuerAndSerial
	DigestAlgorithm    pkcs7AlgorithmIdentifier
	SignedAttributes   []pkcs7Attribute `asn1:"optional,implicit,tag:0"`
	SignatureAlgorithm pkcs7AlgorithmIdentifier
	Signature          []byte
}

type pkcs7EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms []pkcs7AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo pkcs7EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,implicit,tag:0"`
	SignerInfos      []pkcs7SignerInfo `asn1:"set"`
}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// buildPolicySignature creates a PKCS#7 detached signature (eContentType=OIDData, SHA-256).
// The signer certificate is embedded in the signature (for the verifier to extract).
// SignedAttributes contain contentType + messageDigest.
func buildPolicySignature(data []byte, cert *x509.Certificate, signer crypto.Signer) ([]byte, error) {
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
		return nil, err
	}

	var signature []byte
	var sigAlg pkcs7AlgorithmIdentifier
	hashed := sha256.Sum256(attrDER)
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		// crypto.Signer.Sign on an ECDSA key returns an ASN.1 DER signature
		// (equivalent to ecdsa.SignASN1), which is what the PKCS#7 verifier
		// expects. Using the interface method keeps wrapped signers working.
		signature, err = signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		sigAlg = pkcs7AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256, Parameters: asn1.RawValue{Tag: 5}}
	case *rsa.PublicKey:
		signature, err = signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		sigAlg = pkcs7AlgorithmIdentifier{Algorithm: oidRSAWithSHA256, Parameters: asn1.RawValue{Tag: 5}}
	case ed25519.PublicKey:
		// Ed25519 ignores opts and signs the message directly (pure Ed25519).
		signature, err = signer.Sign(rand.Reader, attrDER, crypto.Hash(0))
		if err != nil {
			return nil, err
		}
		sigAlg = pkcs7AlgorithmIdentifier{Algorithm: oidEd25519}
	default:
		return nil, fmt.Errorf("unsupported signer public key type %T", signer.Public())
	}

	sd := pkcs7SignedData{
		Version: 1,
		DigestAlgorithms: []pkcs7AlgorithmIdentifier{
			{Algorithm: oidSHA256, Parameters: asn1.RawValue{Tag: 5}},
		},
		EncapContentInfo: pkcs7EncapsulatedContentInfo{
			ContentType: pkcs7OIDData,
		},
		Certificates: []asn1.RawValue{
			{FullBytes: cert.Raw},
		},
		SignerInfos: []pkcs7SignerInfo{
			{
				Version: 1,
				IssuerAndSerial: pkcs7IssuerAndSerial{
					Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
					SerialNumber: cert.SerialNumber,
				},
				DigestAlgorithm:    pkcs7AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.RawValue{Tag: 5}},
				SignedAttributes:   signedAttrs,
				SignatureAlgorithm: sigAlg,
				Signature:          signature,
			},
		},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}
	ci := pkcs7ContentInfo{
		ContentType: pkcs7OIDSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER},
	}
	return asn1.Marshal(ci)
}

// marshalSignedAttrs encodes SignedAttributes as the content bytes of [0] IMPLICIT SET
// (the signature input = DER after stripping the SET header).
func marshalSignedAttrs(attrs []pkcs7Attribute) ([]byte, error) {
	wrapped, err := asn1.Marshal(struct {
		Attrs []pkcs7Attribute `asn1:"set"`
	}{Attrs: attrs})
	if err != nil {
		return nil, err
	}
	skip := 2
	if len(wrapped) > 1 && wrapped[1]&0x80 != 0 {
		skip = 2 + int(wrapped[1]&0x7f)
	}
	return wrapped[skip:], nil
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// verifyPolicySignature verifies a PKCS#7 detached signature and returns the
// signer certificate. It is the local self-verify entry point: it selects the
// signer by Issuer+Serial, checks validity and rejects self-signed/CA signer
// certs, but does NOT establish a trust chain. Callers that verify a policy
// file fetched from an untrusted source MUST use verifyPolicySignatureWithRoots.
func verifyPolicySignature(sigDER, data []byte) (*x509.Certificate, error) {
	return verifyPolicySignatureWithTrust(sigDER, data, nil, nil)
}

// verifyPolicySignatureWithRoots verifies the policy signature AND establishes
// that the signer certificate chains to a trusted root pool. A nil pool is
// fail-closed (refuse to verify) — prevents an attacker's self-signed cert from
// passing as a policy signer (CL1).
func verifyPolicySignatureWithRoots(sigDER, data []byte, roots *x509.CertPool) (*x509.Certificate, error) {
	if roots == nil {
		return nil, fmt.Errorf("policy signer trust roots not configured — refusing to verify (fail-closed)")
	}
	return verifyPolicySignatureWithTrust(sigDER, data, roots, nil)
}

// verifyPolicySignatureWithTrust is the shared implementation. When roots is
// non-nil the signer must chain to roots. When expected is non-nil the embedded
// signer must also match expected (issuer, serial and SPKI) — used by the local
// self-verify path so the embedded cert cannot be swapped for an attacker cert
// with the same serial number.
func verifyPolicySignatureWithTrust(sigDER, data []byte, roots *x509.CertPool, expected *x509.Certificate) (*x509.Certificate, error) {
	var ci pkcs7ContentInfo
	if _, err := asn1.Unmarshal(sigDER, &ci); err != nil {
		return nil, fmt.Errorf("unmarshal ContentInfo: %w", err)
	}
	var sd pkcs7SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("unmarshal SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("no signer infos")
	}
	si := sd.SignerInfos[0]

	// Select the signer certificate by Issuer AND SerialNumber (CL1: matching by
	// serial only let an attacker's self-signed cert with the same serial win).
	var signerCert *x509.Certificate
	for _, cr := range sd.Certificates {
		cert, err := x509.ParseCertificate(cr.FullBytes)
		if err != nil {
			continue
		}
		if cert.SerialNumber.Cmp(si.IssuerAndSerial.SerialNumber) != 0 {
			continue
		}
		if !bytes.Equal(cert.RawIssuer, si.IssuerAndSerial.Issuer.FullBytes) {
			continue
		}
		signerCert = cert
		break
	}
	if signerCert == nil {
		return nil, fmt.Errorf("no signer certificate matching issuer and serial")
	}

	// Reject CA and self-signed signer certificates outright (CL1: an embedded
	// self-signed root must never be accepted as a policy signer).
	if signerCert.IsCA {
		return nil, fmt.Errorf("signer certificate is a CA (subject=%s)", signerCert.Subject.String())
	}
	if bytes.Equal(signerCert.RawIssuer, signerCert.RawSubject) {
		return nil, fmt.Errorf("signer certificate is self-signed (subject=%s)", signerCert.Subject.String())
	}

	// Validity window check.
	now := time.Now()
	if now.Before(signerCert.NotBefore) || now.After(signerCert.NotAfter) {
		return nil, fmt.Errorf("signer certificate expired or not yet valid (subject=%s, validity %s→%s)",
			signerCert.Subject.String(), signerCert.NotBefore.Format(time.RFC3339), signerCert.NotAfter.Format(time.RFC3339))
	}

	// Optionally bind to an expected certificate (self-verify path).
	if expected != nil {
		if expected.SerialNumber.Cmp(signerCert.SerialNumber) != 0 {
			return nil, fmt.Errorf("embedded signer serial does not match expected cert")
		}
		expPKI, err := x509.MarshalPKIXPublicKey(expected.PublicKey)
		if err != nil {
			return nil, err
		}
		sigPKI, err := x509.MarshalPKIXPublicKey(signerCert.PublicKey)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expPKI, sigPKI) {
			return nil, fmt.Errorf("embedded signer public key does not match expected cert")
		}
	}

	// Compute content digest
	hash := sha256.New()
	hash.Write(data)
	contentDigest := hash.Sum(nil)

	// Re-encode signedAttrs as DER (SET OF)
	attrDER, err := asn1.Marshal(struct {
		Attrs []pkcs7Attribute `asn1:"set"`
	}{Attrs: si.SignedAttributes})
	if err != nil {
		return nil, err
	}
	// Strip SET tag header (2 bytes) to get [0] IMPLICIT content
	skip := 2
	if len(attrDER) > 1 && attrDER[1]&0x80 != 0 {
		skip = 2 + int(attrDER[1]&0x7f)
	}
	signedAttrContent := attrDER[skip:]

	// Validate contentType attribute (CL1: previously never checked).
	contentTypeFound := false
	for _, a := range si.SignedAttributes {
		if a.Type.Equal(oidContentType) && len(a.Values) > 0 {
			var oid asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(a.Values[0].FullBytes, &oid); err == nil && len(rest) == 0 {
				if oid.Equal(pkcs7OIDData) {
					contentTypeFound = true
				}
			}
		}
	}
	if !contentTypeFound {
		return nil, fmt.Errorf("signed content type attribute missing or not data (OIDData)")
	}

	// Verify messageDigest attribute
	found := false
	for _, a := range si.SignedAttributes {
		if a.Type.Equal(oidMessageDigest) && len(a.Values) > 0 {
			if !bytes.Equal(a.Values[0].Bytes, contentDigest) {
				return nil, fmt.Errorf("content digest mismatch")
			}
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("no messageDigest attribute")
	}

	switch k := signerCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		hashed := sha256.Sum256(signedAttrContent)
		var sig struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(si.Signature, &sig); err != nil {
			return nil, err
		}
		if !ecdsa.Verify(k, hashed[:], sig.R, sig.S) {
			return nil, fmt.Errorf("ECDSA signature mismatch")
		}
	case *rsa.PublicKey:
		hashed := sha256.Sum256(signedAttrContent)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hashed[:], si.Signature); err != nil {
			return nil, fmt.Errorf("RSA signature mismatch: %w", err)
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, signedAttrContent, si.Signature) {
			return nil, fmt.Errorf("Ed25519 signature mismatch")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type %T", k)
	}

	// Chain verification against trusted roots (CL1).
	if roots != nil {
		if _, err := signerCert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("policy signer cert chain not trusted: %w", err)
		}
	}

	return signerCert, nil
}

// policySignerHasAdminOU checks if the certificate OU contains admin (compatible with admin and gateway:admin).
func policySignerHasAdminOU(cert *x509.Certificate) bool {
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "admin" || ou == "gateway:admin" {
			return true
		}
	}
	return false
}

// cmdPolicySign signs a policy file with an admin certificate using PKCS#7 detached signature.
func cmdPolicySign(args map[string]string) {
	file := args["--file"]
	certPath := args["--cert"]
	keyPath := args["--key"]
	if file == "" || certPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --file, --cert and --key are required")
		os.Exit(1)
	}

	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read %s: %v\n", file, err)
		os.Exit(1)
	}

	certPEM, err := os.ReadFile(filepath.Clean(certPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read cert: %v\n", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: %s: not a PEM certificate\n", certPath)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: parse cert: %v\n", err)
		os.Exit(1)
	}

	keyData, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read key: %v\n", err)
		os.Exit(1)
	}
	var signer crypto.Signer
	if isEncryptedPEM(keyData) {
		pw := os.Getenv("PKI_KEY_PASSWORD")
		signer, err = decryptPrivateKeyPEM(keyData, pw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: decrypt key: %v\n", err)
			os.Exit(1)
		}
	} else {
		signer, err = parsePrivateKeyPEM(keyData)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: parse key: %v\n", err)
			os.Exit(1)
		}
	}

	if !policySignerHasAdminOU(cert) {
		fmt.Fprintf(os.Stderr, "Error: signer cert must carry admin OU (got %s)\n", cert.Subject.String())
		os.Exit(1)
	}

	sig, err := buildPolicySignature(data, cert, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: build signature: %v\n", err)
		os.Exit(1)
	}

	out := args["--out"]
	if out == "" {
		out = file + ".sig"
	}
	if err := os.WriteFile(filepath.Clean(out), sig, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: write %s: %v\n", out, err)
		os.Exit(1)
	}

	if _, err := verifyPolicySignatureWithTrust(sig, data, nil, cert); err != nil {
		fmt.Fprintf(os.Stderr, "Error: self-verify failed (do not deploy): %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("policy signed: %s -> %s (signer=%s, serial=%s)\n",
		file, out, cert.Subject.String(), cert.SerialNumber.String())
}
