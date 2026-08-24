# varwof-cli Reference Manual

## Architecture

```
varwof-cli
├── config.go     — Config loading + mTLS setup + encrypted private key decryption
├── client.go     — HTTP client (JSON request/response)
├── key.go        — PKCS#8 PBES2 decryption (pure Go)
├── repl.go       — REPL interaction + CLI command dispatch
├── cmd_issue.go  — issue / batch
├── cmd_revoke.go — revoke / revoke-all / revoke-by-principal / revoke-subca
├── cmd_renew.go  — renew
├── cmd_list.go   — list / cas
└── cmd_find.go   — find-by-key / re-sign
```

## Password Resolution Flow

```
Config.KeyPassword non-empty? ──→ use that password
        │ no
PKI_KEY_PASSWORD env var set? ──→ use that password
        │ no
Interactive terminal prompt (term.ReadPassword) ──→ use entered password
```

## Private Key Decryption Flow

```
PEM Block Type == "ENCRYPTED PRIVATE KEY"?
  ├── yes → decryptKeyPKCS8()
  │        ├── ASN.1 parse EncryptedPrivateKeyInfo
  │        ├── Verify OIDs: PBES2 + PBKDF2 + HMAC-SHA256 + AES-256-CBC
  │        ├── PBKDF2-SHA256 key derivation (600K iterations, 32B key)
  │        ├── AES-256-CBC decryption
  │        ├── PKCS#7 unpadding
  │        └── PKCS#8 parse → crypto.Signer
  └── no → direct PKCS#8 parse → crypto.Signer
```

## SPKI Hash Extraction

```
cert file → x509.ParseCertificate → cert.PublicKey → spki.Hash → SHA-256 hex
key file  → ParsePKCS8PrivateKey / ParseECPrivateKey / ParsePKCS1PrivateKey → pubKey → spki.Hash
```

## Supported Key Formats

| Input | Parsing Method |
|------|---------|
| PKCS#8 (`PRIVATE KEY`) | `x509.ParsePKCS8PrivateKey` |
| EC (`EC PRIVATE KEY`) | `x509.ParseECPrivateKey` |
| PKCS#1 (`RSA PRIVATE KEY`) | `x509.ParsePKCS1PrivateKey` |
| Encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) | PBES2 decryption → PKCS#8 |
