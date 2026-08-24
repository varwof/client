# varwof-cli Examples

## Example 1: Issue a Certificate and Save Files

```bash
varwof-cli admin.json issue \
  --cn "web.example.com" \
  --ca issuing \
  --san "web.example.com,10.0.0.1" \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out ./certs

# Output: ./certs/ABCD1234.pem + ./certs/ABCD1234-key.pem
```

## Example 2: Batch Issuance

Create `requests.json`:

```json
[
  {"cn": "web1.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365},
  {"cn": "web2.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365},
  {"cn": "web3.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365}
]
```

```bash
varwof-cli admin.json batch --requests requests.json --fast
```

## Example 3: Revocation + Cascading

```bash
# Revoke a single certificate
varwof-cli admin.json revoke --ca issuing --serial ABCD1234 --reason keyCompromise

# Revoke all AIC certificates by principal
varwof-cli admin.json revoke-by-principal --principal-uid "realm:agent:abc123"

# Revoke all certificates under a sub CA
varwof-cli admin.json revoke-subca --sub-ca "Issuing CA 2"
```

## Example 4: Find Certificates by Public Key

```bash
# Query via certificate file
varwof-cli admin.json find-by-key --cert server.pem --json

# Query via private key file
varwof-cli admin.json find-by-key --key server.key

# Query via SPKI hash
varwof-cli admin.json find-by-key --hash "30820122300d06092a864886f70d01010b05003082010f3082010a0282010100..."
```

## Example 5: Re-sign with a Different CA

```bash
varwof-cli admin.json re-sign \
  --ca old-issuing --serial ABCD1234 \
  --target-ca new-issuing \
  --profile tls-server \
  --validity 365
```

## Example 6: Daily REPL Operations

```bash
$ varwof-cli admin.json repl
Password: ********

pki> cas
Name              Subject                   NotBefore  NotAfter
issuing           CN=Issuing CA             2026-01-01 2036-01-01

pki> list --ca issuing --status active
Serial            CN                NotAfter     Profile
ABCD1234          web.example.com   2027-01-01   tls-server

pki> renew --ca issuing --serial ABCD1234 --out ./renewed
Certificate renewed: serial=EFGH5678

pki> exit
```

## Example 7: Encrypted Private Key Configuration

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin-encrypted.key",
  "key_password": "my-secret"
}
```

Or use an environment variable:

```bash
export PKI_KEY_PASSWORD="my-secret"
varwof-cli admin.json list
```

## Example 8: Identities with Different Permissions

```bash
# Admin — can issue/revoke
varwof-cli admin.json issue --cn "new-cert"

# Ops — can only renew/list
varwof-cli ops.json renew --ca issuing --serial ABCD1234
varwof-cli ops.json list

# Auditor — can only list
varwof-cli auditor.json list --status revoked
```
