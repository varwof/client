# varwof-cli Usage Guide

## Entry Format

```bash
varwof-cli <config.json> <command> [flags]
varwof-cli <config.json> repl          # REPL interactive mode
varwof-cli <config.json>              # defaults to REPL
```

## Command Overview

| Command | Mode | Description |
|------|------|------|
| `issue` | CLI + REPL | Issue a certificate |
| `batch` | CLI only | Batch issuance |
| `revoke` | CLI + REPL | Revoke a single certificate |
| `revoke-all` | CLI only | Revoke all certificates of the current user |
| `revoke-by-principal` | CLI + REPL | Bulk revoke by Principal UID |
| `revoke-subca` | CLI + REPL | Revoke all certificates under a sub CA |
| `renew` | CLI + REPL | Renew a certificate |
| `list` | CLI + REPL | List certificates |
| `cas` | CLI + REPL | List/view CAs |
| `find-by-key` | CLI + REPL | Query certificates by public key |
| `re-sign` | CLI + REPL | Re-sign with the original public key |
| `selfcheck` | CLI only | Health self-check + CRL auto-repair |
| `aic issue` | CLI only | Derive an AIC from a user certificate (agent-proxy) |
| `aic batch` | CLI only | Batch issue user certificates + AICs from a config file |
| `aic list` | CLI only | Parse batch config and list users/agents |
| `cert show` | CLI + REPL | Parse a certificate locally (including AIC/PA extensions) |

## issue — Issue a Certificate

```bash
varwof-cli config.json issue \
  --cn "server.example.com" \
  --ca issuing \
  --san "server.example.com,10.0.0.1" \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out ./certs
```

| flag | Required | Default | Description |
|------|------|--------|------|
| `--cn` | **Yes** | — | Common Name |
| `--ca` | No | — | Target CA |
| `--san` | No | — | SAN (comma-separated) |
| `--subject` | No | — | Subject field |
| `--profile` | No | — | Certificate profile |
| `--key-type` | No | — | Key type |
| `--validity` | No | 365 | Validity in days |
| `--ca-scope` | No | — | Management scope of a management certificate (m-admin/m-superadmin): specifies which sub CAs it may manage, written into SAN URI + OID extension. Only superadmin may specify arbitrarily; admins with a scope can only issue within their own scope |
| `--out` | No | — | Output directory |

```bash
# Issue an admin certificate that can only manage the "Client CA" sub CA (requires superadmin identity)
varwof-cli config.json issue \
  --cn "client-ca-admin@example.com" \
  --ca "Org Management CA" \
  --profile m-admin \
  --ca-scope "Client CA" \
  --out ./certs
```

## revoke — Revoke a Certificate

```bash
varwof-cli config.json revoke --ca issuing --serial ABCD1234 --reason keyCompromise
varwof-cli config.json revoke --ca issuing --serial ABCD1234 --crl   # also regenerate the CRL after revocation
```

| flag | Required | Description |
|------|------|------|
| `--ca` | **Yes** | CA name |
| `--serial` | **Yes** | Certificate serial number |
| `--reason` | No | Revocation reason |
| `--crl` | No | After successful revocation, call `POST /api/v1/crl/{ca}/generate` to regenerate that CA's CRL |

Revocation reasons: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`

## revoke-by-principal — Revoke by Person

```bash
varwof-cli config.json revoke-by-principal --principal-uid "realm:user123:abc123"
```

## renew — Renew

```bash
varwof-cli config.json renew --ca issuing --serial ABCD1234 --out ./renewed
```

## list — List Certificates

```bash
varwof-cli config.json list --ca issuing --status active --json
```

| flag | Description |
|------|------|
| `--ca` | Filter by CA |
| `--status` | Filter by status (active/revoked) |
| `--cn` | Filter by CN |
| `--json` | JSON output |

## cas — View CAs

```bash
# List all CAs
varwof-cli config.json cas

# View details of a single CA
varwof-cli config.json cas --ca issuing --json

# Output PEM
varwof-cli config.json cas --ca issuing --pem
```

## find-by-key — Query by Public Key

```bash
# Via SPKI hash
varwof-cli config.json find-by-key --hash "abc123..."

# Via certificate file
varwof-cli config.json find-by-key --cert server.pem

# Via private key file
varwof-cli config.json find-by-key --key server.key
```

## re-sign — Re-sign

```bash
varwof-cli config.json re-sign \
  --ca issuing --serial ABCD1234 \
  --target-ca issuing \
  --profile tls-server \
  --validity 365
```

## selfcheck — Health Self-check + CRL Auto-repair

```bash
varwof-cli config.json selfcheck --ca "Issuing CA"
```

Full closed loop: healthz (public) → if CRL is degraded, automatically rebuild CRLs for all CAs → CA hierarchy → issue test certificate → chain verification → revoke → generate/parse CRL. When everything passes it outputs `=== selfcheck: ALL PASS ===`.

## aic issue — Derive an AIC from a User Certificate

```bash
varwof-cli config.json aic issue \
  --user-cert alice.pem \
  --user-key alice-key.pem \
  --agent alice-agent-01 \
  --caps 'ca:issue:* ca:revoke:*' \
  --ca "Issuing CA" \
  --ou gateway:ops \
  --out ./certs
```

Computes principal_uid from the user certificate SPKI, signs DelegationAuthTBS with the user private key (`--user-key`, required since v1.7.1), then issues an agent-proxy certificate; the agent-proxy profile mandates `--ou gateway:<role>`.

## aic batch — Batch Issue User Certificates + AICs

```bash
varwof-cli config.json aic batch --config batch.json
```

Batch config format (compatible with the merged pki-aic-tool config):

```json
{
  "ca": "Issuing CA",
  "out_dir": "./certs",
  "users": [
    { "name": "zhangsan", "ou": "gateway:ops", "caps": ["mysql:SELECT:*", "mysql:INSERT:*"] }
  ],
  "agents": [
    { "user": "zhangsan", "agent": "agent-zs-001", "caps": ["mysql:SELECT:*", "mysql:INSERT:*"] }
  ]
}
```

For each user, a user certificate is issued automatically (skipped if a certificate with the same name already exists in the `--out` directory), principal_uid is computed from SPKI, then an agent-proxy AIC is issued for each agent. `caps` is a space-separated capability list (either string or array form).

## aic list — List Users/Agents in a Batch Config

```bash
varwof-cli config.json aic list --config batch.json
```

Parses the batch config and prints the principal_uid each user will receive along with the corresponding agent list; makes no changes on the server side.

## cert show — Parse a Certificate Locally

```bash
varwof-cli config.json cert show --cert alice-agent-01.pem
```

Outputs Subject/Issuer/Serial/validity period/KeyUsage/SAN, and decodes varwof custom extensions:

- **AIC** (OID 1.3.6.1.4.1.66257.1.1): agent_id, principal_uid, delegation mode, capabilities
- **PrincipalAuthorization** (OID 1.3.6.1.4.1.66257.1.2): version, grants, authorizationConstraints

Standard fields (those openssl can parse directly) are not decoded redundantly; this command only covers extensions invisible to openssl `x509 -text`.

## REPL Interactive Mode

```bash
varwof-cli config.json repl
# Enter password (if needed)
# Enter REPL

pki> issue --cn "test.example.com" --profile tls-server
pki> list --ca issuing
pki> cas
pki> help
pki> exit
```

The REPL asks for the password once, supports multiple operations, and automatically renews connections.
