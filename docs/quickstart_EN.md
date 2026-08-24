# varwof-cli Quick Start

> Pure Go CLI management tool | mTLS direct connection to core | 11 commands + REPL

## Installation

```bash
go build -o varwof-cli .
```

## Configuration File

Create `admin.json`:

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin.key"
}
```

Encrypted private key support (optional):

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin-encrypted.key",
  "key_password": "my-secret"
}
```

## Basic Usage

```bash
# Issue a certificate
varwof-cli admin.json issue --cn "server.example.com" --profile tls-server --out ./certs

# List certificates
varwof-cli admin.json list --ca issuing

# Revoke a certificate
varwof-cli admin.json revoke --ca issuing --serial ABCD1234

# REPL interactive mode
varwof-cli admin.json repl
```

## Password Precedence

1. `key_password` field in the config file
2. `PKI_KEY_PASSWORD` environment variable
3. Interactive terminal prompt

## Next Steps

- [Configuration Reference](config.md) — detailed config field descriptions
- [Usage Guide](usage.md) — all commands explained
- [Examples](examples.md) — real-world scenarios
