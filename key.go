// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"
)

var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	nullRaw       = asn1.RawValue{Class: 0, Tag: 5, Bytes: nil}
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedData       []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int       `asn1:"optional"`
	PRF            pbkdf2PRF `asn1:"optional"`
}

type pbkdf2PRF struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func isEncryptedPEM(data []byte) bool {
	block, _ := pem.Decode(data)
	return block != nil && block.Type == "ENCRYPTED PRIVATE KEY"
}

func decryptPrivateKeyPEM(pemData []byte, password string) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found")
		}
		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			return decryptKeyPKCS8(block.Bytes, password)
		case "PRIVATE KEY":
			if password != "" {
				fmt.Fprintln(os.Stderr, "warning: key is not encrypted; the provided password is ignored")
			}
			raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
			if s, ok := raw.(crypto.Signer); ok {
				return s, nil
			}
			return nil, fmt.Errorf("key is not a signer")
		}
		pemData = rest
	}
}

func decryptKeyPKCS8(der []byte, password string) (crypto.Signer, error) {
	var e encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &e); err != nil {
		return nil, fmt.Errorf("parse EncryptedPrivateKeyInfo: %w", err)
	}
	if !e.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported encryption algorithm: %v", e.EncryptionAlgorithm.Algorithm)
	}
	var p2 pbes2Params
	if _, err := asn1.Unmarshal(e.EncryptionAlgorithm.Parameters.FullBytes, &p2); err != nil {
		return nil, fmt.Errorf("parse PBES2-params: %w", err)
	}
	if !p2.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported KDF: %v", p2.KeyDerivationFunc.Algorithm)
	}
	var p2p pbkdf2Params
	if _, err := asn1.Unmarshal(p2.KeyDerivationFunc.Parameters.FullBytes, &p2p); err != nil {
		return nil, fmt.Errorf("parse PBKDF2-params: %w", err)
	}
	iterations := p2p.IterationCount
	if iterations == 0 {
		iterations = 600000
	}
	// M12 fix: cap the KDF cost and validate key length before deriving so a
	// malicious/corrupt key file cannot force a CPU DoS or an unexpected key.
	const (
		maxPBKDF2Iterations = 10_000_000
		minPBKDF2SaltLen    = 8
	)
	if iterations > maxPBKDF2Iterations {
		return nil, fmt.Errorf("pbkdf2 iterations %d exceeds cap %d", iterations, maxPBKDF2Iterations)
	}
	if iterations < 1000 {
		return nil, fmt.Errorf("pbkdf2 iterations %d too low", iterations)
	}
	if len(p2p.Salt) < minPBKDF2SaltLen {
		return nil, fmt.Errorf("pbkdf2 salt too short (%d bytes)", len(p2p.Salt))
	}
	keyLen := p2p.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}
	if keyLen != 32 {
		return nil, fmt.Errorf("unsupported key length %d (only 32 for AES-256-CBC)", keyLen)
	}
	key, err := pbkdf2.Key(sha256.New, password, p2p.Salt, iterations, keyLen)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2: %w", err)
	}
	if !p2.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, fmt.Errorf("unsupported cipher: %v", p2.EncryptionScheme.Algorithm)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(p2.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("parse IV: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	padded := make([]byte, len(e.EncryptedData))
	mode.CryptBlocks(padded, e.EncryptedData)
	if len(padded) == 0 {
		return nil, fmt.Errorf("empty decrypted data")
	}
	padLen := int(padded[len(padded)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(padded) {
		return nil, fmt.Errorf("invalid padding")
	}
	// Verify every padding byte (not just the last one) to reject corrupted
	// ciphertext that happens to pass the length heuristic.
	for _, b := range padded[len(padded)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	privDER := padded[:len(padded)-padLen]
	raw, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if s, ok := raw.(crypto.Signer); ok {
		return s, nil
	}
	return nil, fmt.Errorf("not a signer")
}

func pemEncodePrivateKey(key crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// parsePrivateKeyPEM parses a PEM private key (supports PKCS#8, legacy RSA/EC formats).
func parsePrivateKeyPEM(pemData []byte) (crypto.Signer, error) {
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("no PEM private key block found")
		}
		var raw any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			raw, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			raw, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			raw, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			pemData = rest
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", block.Type, err)
		}
		if s, ok := raw.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("key is not a signer")
	}
}
