# varwof-cli — Command Line Management Tool

Command line management client for the Varwof PKI core. Connects directly to the core API over mTLS, supporting certificate issuance, revocation, renewal, querying, and more.

```
Issuance request → varwof-cli ──mTLS──→ core API
```

## Features

- `issue` — Issue new certificates
- `revoke` — Revoke certificates
- `renew` — Renew certificates
- `list` — List certificates/CAs
- `cas` — View CA list
- `find-by-key` — Query certificates by public key
- `re-sign` — Re-sign a certificate with its original public key
- `revoke-by-principal` — Revoke by person (principal)
- `revoke-subca` — Revoke by sub CA
- `batch` — Batch issuance

## Project Structure

```
varwof-cli/
├── main.go                # CLI entry point
├── client.go              # mTLS HTTP client
├── config.go              # Config loading
├── key.go                 # Key parsing
├── repl.go                # REPL interactive mode
├── cmd_issue.go           # issue command
├── cmd_revoke.go          # revoke command
├── cmd_renew.go           # renew command
├── cmd_list.go            # list command
├── cmd_find.go            # find-by-key command
├── docs/                  # User documentation
├── README.md
└── go.mod
```
