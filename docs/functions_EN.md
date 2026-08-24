# varwof-cli Features

## Exported Types

```go
type Config struct {
    Server     string `json:"server"`
    CACert     string `json:"ca_cert"`
    ClientCert string `json:"client_cert"`
    ClientKey  string `json:"client_key"`
    KeyPassword string `json:"key_password,omitempty"`
    Token      string `json:"token,omitempty"` // Bearer token; required when Server uses http:// (plaintext)
}

type Client struct { /* baseURL, httpClient */ }
```

When `Server` starts with `http://` (smoke/plaintext API mode), varwof-cli automatically skips mTLS verification
and uses `Authorization: Bearer <token>` authentication instead; in this case `ca_cert`/`client_cert`/`client_key` may be omitted.

## Exported Functions

```go
func LoadConfig(path string) (*Config, error)
func (c *Config) TLSConfig() (*tls.Config, error)
func NewClient(baseURL string, tlsConfig *tls.Config) *Client
func NewClientWithToken(baseURL, token string) *Client
```

## Internal Functions

### Encrypted Private Keys (key.go)

```go
func isEncryptedPEM(data []byte) bool
func decryptPrivateKeyPEM(pemData []byte, password string) (crypto.Signer, error)
func decryptKeyPKCS8(der []byte, password string) (crypto.Signer, error)
func pemEncodePrivateKey(key crypto.Signer) []byte
```

Supported algorithms: PBES2 + PBKDF2-SHA256 (600K iterations) + AES-256-CBC

### SPKI Hash Extraction (cmd_find.go)

```go
func spkiHashFromCertFile(path string) (string, error)
func spkiHashFromKeyFile(path string) (string, error)
```

Supported private key formats: PKCS#8, EC, PKCS#1

## Command → API Mapping

| Command | Method | API Endpoint | Request Body |
|------|------|----------|--------|
| `issue` | POST | `/api/v1/certs` | `{ca, cn, san, profile, key_type, validity, ca_scope}` |
| `batch` | POST | `/api/v1/certs/batch` | `[{cn, ca, profile, validity}, ...]` |
| `revoke` | POST | `/api/v1/cert/{ca}/{serial}/revoke` | `{reason}`; with `--crl`, additionally POST `/api/v1/crl/{ca}/generate` |
| `revoke-all` | POST | `/api/v1/user/revoke-all` | — |
| `revoke-by-principal` | POST | `/api/v1/certs/revoke-by-principal` | `{principal_uid, reason}` |
| `revoke-subca` | POST | `/api/v1/sub-ca/{name}/revoke-all` | `{reason}` |
| `renew` | POST | `/api/v1/cert/{ca}/{serial}/renew` | — |
| `list` | GET | `/api/v1/certs?ca=&status=&cn=` | — |
| `cas` | GET | `/api/v1/cas` or `/api/v1/ca/{name}` | — |
| `find-by-key` | GET | `/api/v1/cert/by-key?hash=&ca=&status=` | — |
| `re-sign` | POST | `/api/v1/cert/{ca}/{serial}/re-sign` | `{target_ca, profile, validity}` |
| `selfcheck` | GET+POST | `/healthz` → `/api/v1/cas` → `/api/v1/certs` → `/api/v1/cert/{ca}/{serial}/revoke` → `/api/v1/crl/{ca}/generate` | Health self-check + CRL auto-repair |
| `aic issue` | POST | `/api/v1/certs` | `{ca, cn, subject, profile:agent-proxy, agent_id, principal_uid, capabilities, ...}` |
| `aic batch` | POST | `/api/v1/certs` × N + `/api/v1/certs` (user) | Issues per user/agent sequentially |
| `cert show` | Local | None (pure local decoding) | Reads PEM files |
| `policy sign` | Local | None (pure local signing) | Creates a PKCS#7 detached signature of authz.json / routes.json using the admin certificate |

## Command Details

### selfcheck — Health Self-check + Auto-repair

`varwof-cli <cfg> selfcheck --ca "<CA name>"`

Full closed-loop verification:
1. `/healthz` (public): DB / TSA / CRL freshness / status
2. If `crl_status` is degraded → automatically call `/api/v1/crl/{ca}/generate` to rebuild CRLs for all CAs, then re-check healthz
3. CA hierarchy reachable (mTLS or token)
4. Issue a 1-day test certificate → chain verification → revoke → generate CRL → download and parse DER

Any failed step outputs `[FAIL]`; when all steps pass it outputs `=== selfcheck: ALL PASS ===`. A non-zero exit code indicates failure.

### aic issue — Derive an AIC from a User Certificate

`varwof-cli <cfg> aic issue --user-cert <user.pem> --user-key <user.key> --agent <agent-id> --caps 'scheme:cap:* ...' [--ca <name>] [--ou gateway:<role>] [--out <dir>]`

1. Read the user certificate (`--user-cert`) and compute the SPKI SHA-256 to obtain the `principal_uid`
2. Sign the `DelegationAuthTBS` with the user private key (`--user-key`, required since v1.7.1) (SHA-256 DER, ECDSA/RSA-PKCS1v15/Ed25519), and write it as user authorization evidence into the `user_auth_*` request fields
3. Assemble the agent-proxy request (`agent_id`/`principal_uid`/`hash_algo:sha256`/`delegation_mode:0`/`PrincipalAuthorization.Grants`/`capabilities`); also include `user_cert_pem` (the user certificate PEM) so core can verify the DA signature at issuance time (C3)
4. `POST /api/v1/certs`, writing artifacts to `<agent-id>.pem` / `<agent-id>.key` under `--out`

Note: the agent-proxy profile mandates an OU (`--ou gateway:<role>`); otherwise an error is reported. Missing `--user-key` or an unsupported user certificate key algorithm results in an immediate error.

### aic batch — Batch Issue User Certificates + AICs

`varwof-cli <cfg> aic batch --config <batch.json>`

Config file format (compatible with the merged pki-aic-tool `config.json`):
- `ca` (string or array): issuing CA
- `out_dir`: output directory
- `users[]`: `{name, ou?, caps?}` — issues a user certificate for each user automatically (skipped if already present under `--out`), computing `principal_uid` from SPKI
- `agents[]`: `{user, agent, caps?}` — issues an agent-proxy AIC for the specified user

### aic list — List Batch Config Entries

`varwof-cli <cfg> aic list --config <batch.json>`

Parses locally only and prints each user's principal_uid along with agent mappings; no network requests are made.

### cert show — Decode Certificate Extensions Locally

`varwof-cli <cfg> cert show --cert <file.pem>`

Prints Subject/Issuer/Serial/validity period/KeyUsage/SAN, and decodes varwof custom extensions using `types.ParseAIC` / `types.ParseUserPermissionExtension`
(AIC 1.3.6.1.4.1.66257.1.1, PrincipalAuthorization 1.3.6.1.4.1.66257.1.2).
Standard fields rely on openssl alone; this command only covers extensions that openssl `x509 -text` cannot parse.

### policy sign — Sign Policy Files Locally

`varwof-cli policy sign --file authz.json --cert admin.pem --key admin.key [--out authz.json.sig]`

Creates a **PKCS#7 detached signature** of the policy file (authz.json / routes.json) (SHA-256, content is the raw file). This command does not require a server connection; the `<cfg>` position serves as a placeholder.

- The signer certificate must carry the `admin` or `gateway:admin` OU (otherwise rejected)
- Supports PKCS#8 / traditional RSA/EC private keys; encrypted keys can be decrypted via the `PKI_KEY_PASSWORD` environment variable
- Produces `<file>.sig` (default); after signing, the signature is automatically self-verified (not written on failure)
- Verification side: core `policy_signing` config + three-gateway `policy_signing` config + the `pki policy verify` ecosystem
- Signatures produced by `core pki policy sign` **verify against these** (same format, interoperable)

### KeyHash / principal_uid Semantics

The canonical semantics of `principal_uid` = SPKI SHA-256 of the person certificate (`sha256(MarshalPKIXPublicKey(cert.PublicKey))`, RawURLEncoding),
consistent with `types.MakePrincipalUidFromCert`; `find-by-key --cert` queries using the same hash.

## Supported Key Types

`ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096`, `ed25519`

## Supported Profiles

`tls-server`, `tls-client`, `code-signing`, `smime`, `ocsp-signing`, `timestamping`, `sub-ca`, `agent-proxy`, `cmp`

## Supported Revocation Reasons

`unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`
