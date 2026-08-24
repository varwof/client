package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"testing"
)

func genSigner(t *testing.T, typ string) crypto.Signer {
	t.Helper()
	switch typ {
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return k
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	default:
		t.Fatalf("unknown key type %q", typ)
		return nil
	}
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// makeEncryptedPEM builds a PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC encrypted
// PKCS#8 private key PEM ("ENCRYPTED PRIVATE KEY"), matching what
// openssl pkcs8 -topk8 -v2 aes-256-cbc produces and what
// decryptPrivateKeyPEM / decryptKeyPKCS8 accept.
func makeEncryptedPEM(t *testing.T, key crypto.Signer, password string) []byte {
	t.Helper()
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x5a}, 16)
	iv := bytes.Repeat([]byte{0x3c}, 16)
	dk, err := pbkdf2.Key(sha256.New, password, salt, 4096, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(privDER, aes.BlockSize)
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(enc, padded)

	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: 4096,
		KeyLength:      32,
		PRF:            pbkdf2PRF{Algorithm: oidHMACSHA256, Parameters: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	encSchemeParams, err := asn1.Marshal(iv)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: kdfParams}},
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: encSchemeParams}},
	})
	if err != nil {
		t.Fatal(err)
	}
	epki, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: p2}},
		EncryptedData:       enc,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: epki})
}

// sameSigner compares two crypto.Signer by their public key material (avoids
// comparing ed25519.PrivateKey which is a slice and not comparable with ==).
func sameSigner(a, b crypto.Signer) bool {
	pa, err1 := x509.MarshalPKIXPublicKey(a.Public())
	pb, err2 := x509.MarshalPKIXPublicKey(b.Public())
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(pa, pb)
}

func TestIsEncryptedPEM(t *testing.T) {
	enc := makeEncryptedPEM(t, genSigner(t, "ecdsa"), "secret")
	if !isEncryptedPEM(enc) {
		t.Fatal("encrypted PEM not detected")
	}
	key := genSigner(t, "ecdsa")
	plain := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)})
	if isEncryptedPEM(plain) {
		t.Fatal("plain PEM falsely detected as encrypted")
	}
	if isEncryptedPEM([]byte("not pem")) {
		t.Fatal("garbage falsely detected as encrypted")
	}
	if isEncryptedPEM(nil) {
		t.Fatal("nil falsely detected as encrypted")
	}
}

func mustMarshalKey(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPEMEncodePrivateKey(t *testing.T) {
	for _, typ := range []string{"ecdsa", "rsa", "ed25519"} {
		key := genSigner(t, typ)
		out := pemEncodePrivateKey(key)
		if len(out) == 0 {
			t.Fatalf("%s: empty PEM", typ)
		}
		block, _ := pem.Decode(out)
		if block == nil || block.Type != "PRIVATE KEY" {
			t.Fatalf("%s: not a PRIVATE KEY block: %v", typ, block)
		}
		signer, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("%s: parse PKCS8: %v", typ, err)
		}
		if _, ok := signer.(crypto.Signer); !ok {
			t.Fatalf("%s: not a signer", typ)
		}
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	// PKCS#8
	key := genSigner(t, "ecdsa")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)})
	parsed, err := parsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("PKCS8 parse: %v", err)
	}
	if !sameSigner(parsed, key) {
		t.Fatal("parsed key mismatch")
	}

	// RSA PKCS#1
	rsaKey := genSigner(t, "rsa").(*rsa.PrivateKey)
	pemData = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})
	parsed, err = parsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("PKCS1 parse: %v", err)
	}
	if !sameSigner(parsed, rsaKey) {
		t.Fatal("parsed RSA key mismatch")
	}

	// EC SEC1
	ecKey := genSigner(t, "ecdsa").(*ecdsa.PrivateKey)
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pemData = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	parsed, err = parsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EC parse: %v", err)
	}
	if !sameSigner(parsed, ecKey) {
		t.Fatal("parsed EC key mismatch")
	}

	// Unknown block type is skipped, then PKCS8 found
	pemData = append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x01}}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)})...,
	)
	parsed, err = parsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("skip-unknown parse: %v", err)
	}
	if !sameSigner(parsed, key) {
		t.Fatal("parsed key mismatch after skip")
	}

	// No PEM block
	if _, err := parsePrivateKeyPEM([]byte("garbage")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestDecryptPrivateKeyPEMPlain(t *testing.T) {
	key := genSigner(t, "ecdsa")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)})
	parsed, err := decryptPrivateKeyPEM(pemData, "ignored")
	if err != nil {
		t.Fatalf("decrypt plain: %v", err)
	}
	if !sameSigner(parsed, key) {
		t.Fatal("plain key mismatch")
	}
}

func TestDecryptPrivateKeyPEMEncrypted(t *testing.T) {
	for _, typ := range []string{"ecdsa", "rsa", "ed25519"} {
		key := genSigner(t, typ)
		enc := makeEncryptedPEM(t, key, "hunter2")
		parsed, err := decryptPrivateKeyPEM(enc, "hunter2")
		if err != nil {
			t.Fatalf("%s: decrypt: %v", typ, err)
		}
		if !sameSigner(parsed, key) {
			t.Fatalf("%s: key mismatch", typ)
		}
	}
}

func TestDecryptPrivateKeyPEMErrors(t *testing.T) {
	key := genSigner(t, "ecdsa")
	enc := makeEncryptedPEM(t, key, "right")

	// wrong password
	if _, err := decryptPrivateKeyPEM(enc, "wrong"); err == nil {
		t.Fatal("expected error on wrong password")
	}

	// garbage input
	if _, err := decryptPrivateKeyPEM([]byte("garbage"), "x"); err == nil {
		t.Fatal("expected error on garbage input")
	}

	// unsupported encryption algorithm (PBES1-style -> not PBES2)
	privDER := mustMarshalKey(t, key)
	epki, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{Algorithm: oidHMACSHA256}, // not oidPBES2
		EncryptedData:       privDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptKeyPKCS8(epki, "x"); err == nil {
		t.Fatal("expected error on non-PBES2 algorithm")
	}

	// unsupported KDF inside PBES2: reuse valid params but swap the PBKDF2 OID
	block, _ := pem.Decode(makeEncryptedPEM(t, key, "x"))
	var e encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &e); err != nil {
		t.Fatal(err)
	}
	var p2 pbes2Params
	if _, err := asn1.Unmarshal(e.EncryptionAlgorithm.Parameters.FullBytes, &p2); err != nil {
		t.Fatal(err)
	}
	p2Bad, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: nil}},
		EncryptionScheme:  p2.EncryptionScheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	epkiBadKDF, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: p2Bad}},
		EncryptedData:       e.EncryptedData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptKeyPKCS8(epkiBadKDF, "x"); err == nil {
		t.Fatal("expected error on unsupported KDF")
	}

	// unsupported cipher inside PBES2: valid KDF but wrong cipher OID
	p2BadCipher, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: p2.KeyDerivationFunc,
		EncryptionScheme:  algorithmIdentifier{Algorithm: oidPBKDF2, Parameters: asn1.RawValue{FullBytes: nil}},
	})
	if err != nil {
		t.Fatal(err)
	}
	epkiBadCipher, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{Algorithm: oidPBES2, Parameters: asn1.RawValue{FullBytes: p2BadCipher}},
		EncryptedData:       e.EncryptedData,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptKeyPKCS8(epkiBadCipher, "x"); err == nil {
		t.Fatal("expected error on unsupported cipher")
	}

	// truncated / empty DER
	if _, err := decryptKeyPKCS8(epki[:10], "x"); err == nil {
		t.Fatal("expected error on truncated DER")
	}
	if _, err := decryptKeyPKCS8(nil, "x"); err == nil {
		t.Fatal("expected error on empty DER")
	}
}

// TestDecryptKeyPKCS8RejectsCorruptedPadding verifies the strict PKCS#7
// padding check: ciphertext that passes the length heuristic but has a wrong
// middle padding byte must be rejected (prevents accepting corrupted
// plaintext that would silently fail later at PKCS8 parse).
func TestDecryptKeyPKCS8RejectsCorruptedPadding(t *testing.T) {
	key := genSigner(t, "ecdsa")
	enc := makeEncryptedPEM(t, key, "right")
	block, _ := pem.Decode(enc)

	// Flip the first ciphertext block's last byte; decryption then yields a
	// wrong plaintext. With the old single-byte check a 0x01 padding byte
	// would pass if the corruption only touched the tail; the strict check
	// rejects any mismatch across the padding run.
	var e encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &e); err != nil {
		t.Fatal(err)
	}
	if len(e.EncryptedData) < 2*aes.BlockSize {
		t.Fatal("ciphertext too short")
	}
	corrupted := make([]byte, len(e.EncryptedData))
	copy(corrupted, e.EncryptedData)
	corrupted[aes.BlockSize-1] ^= 0xff // flip a byte in the first block

	epkiBad, err := asn1.Marshal(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: e.EncryptionAlgorithm,
		EncryptedData:       corrupted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptKeyPKCS8(epkiBad, "right"); err == nil {
		t.Fatal("expected error on corrupted ciphertext (strict padding check)")
	}
}

// TestDecryptPrivateKeyPEMPlainWarns ensures a plain key passed with a
// password still decrypts (warning only, no failure).
func TestDecryptPrivateKeyPEMPlainWarns(t *testing.T) {
	key := genSigner(t, "ecdsa")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(t, key)})
	parsed, err := decryptPrivateKeyPEM(pemData, "p4ssword")
	if err != nil {
		t.Fatalf("decrypt plain with password: %v", err)
	}
	if !sameSigner(parsed, key) {
		t.Fatal("key mismatch")
	}
}
