# varwof-cli Quick Start (Extended)

> Manage core via the mTLS API without touching the database directly  
> Use a different config file per identity; permissions are controlled by server-side RBAC

---

## 1. Build

```bash
cd varwof-cli
GOWORK=off go build -o /usr/local/bin/varwof-cli .
# Or use go.work (project root)
cd .. && go build -o /usr/local/bin/varwof-cli ./varwof-cli
```

Zero external dependencies, pure Go standard library.

---

## 2. Configuration Files

One JSON file per identity:

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/admin.pem",
  "client_key": "/etc/pki/keys/admin.key"
}
```

| Field | Description | Required |
|------|------|------|
| `server` | core HTTPS API address (mTLS port) | ✅ |
| `ca_cert` | Root CA certificate PEM path (verifies the server) | ✅ |
| `client_cert` | This identity's certificate PEM path | ✅ |
| `client_key` | This identity's private key PEM path | ✅ |
| `key_password` | Private key password (optional; if omitted, an interactive prompt appears or the `PKI_KEY_PASSWORD` env var is read) | ❌ |

**Multi-identity management example:**

```bash
varwof-cli admin.json      issue --cn web.example.com     # admin issues
varwof-cli operator.json   list --ca "Issuing CA"         # ops queries
varwof-cli revoker.json    revoke --ca X --serial Y       # revoker revokes
varwof-cli auditor.json    list --status revoked          # auditor reviews revocations
```

Identity permissions are controlled by core's RBAC + `authz.json`.

---

## 3. Command Cheat Sheet

### Issuance

```bash
# Basic issuance (unencrypted key)
varwof-cli admin.json issue --cn web.example.com \
  --san "DNS:web.example.com,IP:10.0.0.1" \
  --profile tls-server --key-type ecdsa-p256 --validity 365

# Issue with password-encrypted key (PKCS#8 PBES2, OpenSSL compatible)
varwof-cli admin.json issue --cn alice \
  --key-password "AliceStrongP@ss" \
  --out ~/alice
# Output: ~/alice/<SERIAL>.pem + ~/alice/<SERIAL>.key
# The key is an Encrypted Private Key, decryptable with OpenSSL:
#   openssl pkey -in ~/alice/<SERIAL>.key -passin pass:AliceStrongP@ss

# Specify CA and output directory
varwof-cli admin.json issue --ca "Issuing CA" \
  --cn api.example.com --profile tls-server \
  --out ./certs
# Output: ./certs/<SERIAL>.pem + ./certs/<SERIAL>-key.pem
```

### Batch Issuance

```bash
cat > requests.json <<'EOF'
[
  {"cn":"svc1.example.com","san":"DNS:svc1.example.com","profile":"tls-server","key_type":"ecdsa-p256"},
  {"cn":"svc2.example.com","san":"DNS:svc2.example.com","profile":"tls-server","key_type":"ecdsa-p256"}
]
EOF
varwof-cli admin.json batch --requests requests.json
```

### Revocation

```bash
# Revoke a single certificate
varwof-cli admin.json revoke --ca "Issuing CA" --serial <hex> --reason keyCompromise

# Revoke all AIC certificates of a person (SQL-level, <10ms)
varwof-cli admin.json revoke-by-principal \
  --principal-uid "varwof:alice@example.com" \
  --reason superseded

# Revoke all end-entity certificates under a sub CA
varwof-cli admin.json revoke-subca \
  --sub-ca "Compromised Sub CA" \
  --reason cessationOfOperation
```

Revocation reasons: `unspecified` `keyCompromise` `cACompromise` `affiliationChanged` `superseded` `cessationOfOperation`

### Renewal

```bash
varwof-cli admin.json renew --ca "Issuing CA" --serial <hex>
varwof-cli admin.json renew --ca "Issuing CA" --serial <hex> --out ./certs
```

### Querying

```bash
# List certificates
varwof-cli operator.json list
varwof-cli operator.json list --ca "Issuing CA"
varwof-cli operator.json list --status revoked --cn web.example.com
varwof-cli auditor.json list --json                       # JSON output

# List CAs
varwof-cli operator.json cas
varwof-cli operator.json cas --ca "Issuing CA"            # details
varwof-cli operator.json cas --ca "Root CA" --pem         # export certificate PEM
```

### Query by Public Key (change CA, keep key)

```bash
# Extract SPKI hash from a certificate file and query
varwof-cli admin.json find-by-key --cert ./old-cert.pem

# Query via a key file
varwof-cli admin.json find-by-key --key ./old-key.pem

# Pass the hash directly
varwof-cli admin.json find-by-key --hash <sha256-hex>
```

### Re-sign (original public key + new CA)

During CA key rotation, re-issue a new certificate with the original public key so services only need to swap certificates while keys stay unchanged:

```bash
varwof-cli admin.json re-sign \
  --ca "Old CA" --serial <hex> \
  --target-ca "New CA" --validity 365
```

---

## 4. Key Password Management

varwof-cli supports three ways to supply the password for encrypted keys (highest to lowest precedence):

### 1. `key_password` field in the config file

Suitable for CI/CD or scripts:

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/alice.pem",
  "client_key": "/etc/pki/keys/alice.key",
  "key_password": "P@ssw0rd"
}
```

### 2. `PKI_KEY_PASSWORD` environment variable

Suitable for injection from a secret management service:

```bash
export PKI_KEY_PASSWORD=$(vault read -field=key_password secret/pki/alice)
varwof-cli alice.json list
```

### 3. Interactive prompt

When no password is provided, varwof-cli automatically detects whether the key is encrypted and, if so, prompts for the password (no echo):

```bash
varwof-cli alice.json list
Enter password for /etc/pki/keys/alice.key: <enter password, not echoed>
```

### REPL Mode — One Password, Many Operations

Ideal for admins' daily work: enter the password once and share it across subsequent commands:

```bash
varwof-cli admin.json repl

varwof-cli> Connected to https://pki-core:4433
varwof-cli> issue --cn web.example.com
Issued: web.example.com (serial: ABC123...)
varwof-cli> issue --cn api.example.com
Issued: api.example.com (serial: DEF456...)
varwof-cli> list --status V
...
varwof-cli> exit
bye
```

REPL mode avoids entering a password for every command and also works with unencrypted keys.

---

## 5. Complete Workflow Examples

### Scenario: Employee Onboarding Issuance

```bash
# 1. Admin issues a client certificate
varwof-cli admin.json issue --cn alice \
  --san "email:alice@example.com" \
  --profile tls-client --out ./alice

# 2. Ops confirms successful issuance
varwof-cli operator.json list --cn alice

# 3. Sign an AIC certificate (for gateway authentication)
curl -sk --cert admin.pem --key admin.key \
  https://pki:4433/api/v1/aic/issue \
  -d '{"agent_id":"alice-agent","principal_uid":"varwof:alice@example.com",...}'
```

### Scenario: Employee Offboarding Revocation

```bash
# Revoke all of this person's AIC certificates in one command
varwof-cli admin.json revoke-by-principal \
  --principal-uid "varwof:alice@example.com" \
  --reason cessationOfOperation

# Optionally also revoke their personal certificate
varwof-cli admin.json revoke --ca "Issuing CA" --serial <alice-cert-serial>
```

### Scenario: CA Key Rotation

```bash
# 1. Preserve every entity's public key via re-sign
varwof-cli admin.json re-sign \
  --ca "Old Issuing CA" --serial <ser1> \
  --target-ca "New Issuing CA"

# 2. After confirmation, revoke the original certificates under the old CA
varwof-cli admin.json revoke --ca "Old Issuing CA" --serial <ser1> --reason superseded

# 3. Finally revoke the old CA itself
varwof-cli admin.json revoke-subca --sub-ca "Old Issuing CA" --reason superseded
```

### Scenario: Sub CA Compromise

```bash
# Revoke all certificates under the sub CA in one step (SQL batch, completes in seconds)
varwof-cli admin.json revoke-subca \
  --sub-ca "Old Issuing CA" \
  --reason keyCompromise

# Verify the revocation results
varwof-cli auditor.json list --ca "Old Issuing CA" --status revoked --json
```

---

## 6. Configuration File Templates

### admin.json (Admin — full permissions)

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/admin.pem",
  "client_key": "/etc/pki/keys/admin.key"
}
```

### operator.json (Ops Operator — issue/revoke/query)

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/operator.pem",
  "client_key": "/etc/pki/keys/operator.key"
}
```

### auditor.json (Auditor — read-only)

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/auditor.pem",
  "client_key": "/etc/pki/keys/auditor.key"
}
```

---

## 7. FAQ

**Q: Getting `forbidden`?**
A: The current identity lacks permission for that operation. Switch to the admin config, or check the role permission definitions in `authz.json`.

**Q: Getting `connection refused`?**
A: core is not running or the API port is wrong. Verify the address and port in the `server` URL.

**Q: Getting `x509: certificate signed by unknown authority`?**
A: The `ca_cert` path is wrong or it is not the root CA that issued the client certificate. Use the correct root CA from the chain.

**Q: `find-by-key` returns nothing?**
A: Confirm you are on core v21+; older versions lack the `spki_hash` column. Use `cas --ca <CA> --pem` to check the server version.

**Q: `revoke-by-principal` returns 0 rows?**
A: Confirm the `principal_uid` format is correct. For AIC certificates the format is `realm:identifier:keyHash`. Check the `principal_uid` field value from `list --json`.

**Q: How do I view my current identity's permissions?**
A: Call the API directly: `curl -sk --cert cert.pem --key key.pem https://pki:4433/api/v1/permissions/check`
