// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	configPath := os.Args[1]
	if strings.HasPrefix(configPath, "-") {
		usage()
		os.Exit(1)
	}

	if len(os.Args) < 3 || os.Args[2] == "repl" {
		cmdRepl(configPath)
		return
	}

	command := os.Args[2]
	// policy subcommand does not depend on server connection, runs locally.
	if command == "policy" {
		args, _ := parseArgs(os.Args[3:])
		cmdPolicySign(args)
		return
	}
	globalArgs, globalPos := parseArgs(os.Args[3:])
	runCLI(configPath, command, globalArgs, globalPos)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: varwof-cli <config.json> <command> [flags]
       varwof-cli <config.json> repl

Config file format:
  { "server": "https://varwof-core:4433",
    "ca_cert": "/path/to/root.pem",
    "client_cert": "/path/to/cert.pem",
    "client_key": "/path/to/key.pem",
    "key_password": "optional-password",
    "token": "optional-api-token" }

For the internal plain-HTTP API (varwof-core serve api api_addr), use
"server": "http://127.0.0.1:8445" with only a "token" — no TLS fields.

If key is encrypted and no password in config, varwof-cli prompts
interactively. Password can also be set via PKI_KEY_PASSWORD env var.

Commands:
  repl     Interactive REPL (prompts for password once)
  issue    --cn <cn> [--ca <ca>] [--san <san>] [--profile <profile>]
           [--key-type <type>] [--validity <days>] [--ca-scope <sub-ca>]
           [--pa 'scheme:cap ...'] [--out <dir>]
  batch    --requests <file.json> [--fast]
  revoke   --ca <ca> --serial <serial> [--reason <reason>] [--crl]
           (--crl also regenerates the CA's CRL after revoking)
  revoke-all [--reason <reason>]
  revoke-by-principal --principal-uid <uid> [--reason <reason>]
  revoke-subca --sub-ca <name> [--reason <reason>]
  renew    --ca <ca> --serial <serial> [--out <dir>]
  find-by-key --hash <hex>|--cert <file>|--key <file>
           [--ca <ca>] [--status <status>] [--json]
  re-sign  --ca <ca> --serial <serial>
           [--target-ca <ca>] [--profile <profile>] [--validity <days>]
  list     [--ca <ca>] [--status <status>] [--cn <cn>] [--json]
  cas      [--ca <name>] [--json] [--pem]
  selfcheck --ca <ca>   Smoke-test the PKI: healthz + CRL repair + issue/revoke/CRL
  aic issue --user-cert <file> --user-key <file> --agent <id> --caps 'scheme:cap ...' [--constraints 'scheme:cap[:jsonparams] ...']
           [--pa 'scheme:cap ...'] [--ca <ca>] [--ou <ou>] [--out <dir>] [--spiffe --spiffe-domain <domain>]
           Issue an AIC from an existing user cert
  aic batch --config <file.json> [--out <dir>]  Batch-issue AICs from a JSON user list
  aic list --config <file.json>   List users in the batch config file
  aic jwt [--cert <file.pem>] [--scope <s>] [--out <file>] [--json]
           Exchange an X.509 AIC certificate for a short-lived AIC-JWT
           (RFC 8693 via core /oauth/token). Default cert = config client_cert.
           Print the token, or write it with --out.
  cert show --cert <file.pem>     Decode a certificate's varwof extensions
           (AIC / PrincipalAuthorization) that openssl x509 -text cannot
  policy sign --file authz.json --cert admin.pem --key admin-key.pem
           [--out authz.json.sig]  Sign a policy file (authz.json / routes.json)
           with an admin certificate (PKCS#7 detached signature)

Revoke reasons: unspecified, keyCompromise, cACompromise,
  affiliationChanged, superseded, cessationOfOperation

Profiles: tls-server, tls-client, code-signing, smime, etc.
Key types: ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096, ed25519
`)
}

// booleanFlags are CLI flags that take no value. All other flags consume the
// next argument as their value even when it begins with "--" (e.g. a subject
// string), fixing the ambiguity where "--flag --value" used to parse as two
// flags.
var booleanFlags = map[string]bool{
	"--fast":   true,
	"--json":   true,
	"--spiffe": true,
	"--pem":    true,
	"--keep":   true,
	"--info":   true,
	"--crl":    true,
}

func parseArgs(args []string) (map[string]string, []string) {
	m := make(map[string]string)
	var pos []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") {
			key := args[i]
			if booleanFlags[key] {
				m[key] = "true"
				continue
			}
			// Value flag: consume the next argument unconditionally so a value
			// that legitimately starts with "--" is not misparsed as a flag.
			if i+1 < len(args) {
				m[key] = args[i+1]
				i++
			} else {
				m[key] = "true"
			}
		} else {
			pos = append(pos, args[i])
		}
	}
	return m, pos
}
