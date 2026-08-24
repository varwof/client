package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func cmdRepl(configPath string) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	// Handle key password if encrypted
	if cfg.ClientKey != "" {
		keyData, err := os.ReadFile(cfg.ClientKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read key error: %v\n", err)
			os.Exit(1)
		}
		if isEncryptedPEM(keyData) {
			if cfg.KeyPassword == "" {
				cfg.KeyPassword = os.Getenv("PKI_KEY_PASSWORD")
			}
			if cfg.KeyPassword == "" {
				fmt.Fprintf(os.Stderr, "Enter key password: ")
				pwBytes, err := term.ReadPassword(syscall.Stdin)
				fmt.Fprintln(os.Stderr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Read password error: %v\n", err)
					os.Exit(1)
				}
				cfg.KeyPassword = string(pwBytes)
			}
		}
	}

	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS error: %v\n", err)
		os.Exit(1)
	}

	client := NewClientWithToken(cfg.Server, tlsCfg, cfg.Token)
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("varwof-cli> Connected to %s\n", cfg.Server)
	fmt.Println("varwof-cli> Type 'help' for commands, 'exit' to quit")

	for {
		fmt.Print("varwof-cli> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		command := parts[0]
		args, _ := parseArgs(parts[1:])

		// Subcommand detection: `aic batch` / `aic list` / `cert show`.
		sub := ""
		if len(parts) > 1 && !strings.HasPrefix(parts[1], "--") {
			sub = parts[1]
		}

		switch command {
		case "exit", "quit", "q":
			fmt.Println("bye")
			return
		case "help", "?":
			replHelp()
		case "issue":
			cmdIssue(client, args)
		case "revoke":
			cmdRevoke(client, args)
		case "revoke-by-principal":
			cmdRevokeByPrincipal(client, args)
		case "revoke-subca":
			cmdRevokeSubCA(client, args)
		case "renew":
			cmdRenew(client, args)
		case "list":
			cmdListCerts(client, args)
		case "cas":
			if args["--info"] == "true" || args["--ca"] != "" {
				cmdCAInfo(client, args)
			} else {
				cmdListCAs(client, args)
			}
		case "find-by-key":
			cmdFindByKey(client, args)
		case "re-sign":
			cmdReSign(client, args)
		case "selfcheck":
			cmdSelfcheck(client, args)
		case "aic":
			cmdAIC(client, args, sub)
		case "cert":
			cmdCertShow(args)
		default:
			fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
			fmt.Println("Type 'help' for available commands")
		}
	}
}

func replHelp() {
	fmt.Println(`
Commands:
  issue     --cn <cn> [--ca <ca>] [--san <san>] [--profile <p>] [--key-type <t>] [--validity <d>] [--out <dir>]
  revoke    --ca <ca> --serial <serial> [--reason <r>]
  revoke-by-principal --principal-uid <uid> [--reason <r>]
  revoke-subca --sub-ca <name> [--reason <r>]
  renew     --ca <ca> --serial <serial> [--out <dir>]
  list      [--ca <ca>] [--status <s>] [--cn <cn>] [--json]
  cas       [--ca <name>] [--json] [--pem]
  find-by-key --hash <hex>|--cert <file>|--key <file>
  re-sign   --ca <ca> --serial <s> [--target-ca <ca>] [--profile <p>] [--validity <d>]
  selfcheck --ca <ca>              Smoke-test PKI: healthz + CRL repair + issue/revoke/CRL
  aic issue --user-cert <file> --user-key <file> --agent <id> --caps 'scheme:cap ...' [--constraints 'scheme:cap[:jsonparams] ...']
  aic batch --config <file.json>   Batch-issue AICs from a JSON user list
  aic list --config <file.json>    List users in the batch config file
  cert show --cert <file.pem>      Decode AIC / PrincipalAuthorization extensions
  exit / quit`)
}

func runCLI(configPath string, command string, args map[string]string, pos []string) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	// Handle key password if encrypted
	if cfg.ClientKey != "" {
		keyData, err := os.ReadFile(cfg.ClientKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read key error: %v\n", err)
			os.Exit(1)
		}
		if isEncryptedPEM(keyData) {
			if cfg.KeyPassword == "" {
				cfg.KeyPassword = os.Getenv("PKI_KEY_PASSWORD")
			}
			if cfg.KeyPassword == "" {
				fmt.Fprintf(os.Stderr, "Enter password for %s: ", cfg.ClientKey)
				pwBytes, err := term.ReadPassword(syscall.Stdin)
				fmt.Fprintln(os.Stderr)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Read password error: %v\n", err)
					os.Exit(1)
				}
				cfg.KeyPassword = string(pwBytes)
			}
		}
	}

	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS error: %v\n", err)
		os.Exit(1)
	}

	client := NewClientWithToken(cfg.Server, tlsCfg, cfg.Token)

	switch command {
	case "issue":
		cmdIssue(client, args)
	case "batch":
		cmdBatchIssue(client, args)
	case "revoke":
		cmdRevoke(client, args)
	case "revoke-all":
		cmdRevokeAll(client, args)
	case "revoke-by-principal":
		cmdRevokeByPrincipal(client, args)
	case "revoke-subca":
		cmdRevokeSubCA(client, args)
	case "renew":
		cmdRenew(client, args)
	case "list":
		cmdListCerts(client, args)
	case "cas":
		if args["--info"] == "true" || args["--ca"] != "" {
			cmdCAInfo(client, args)
		} else {
			cmdListCAs(client, args)
		}
	case "find-by-key":
		cmdFindByKey(client, args)
	case "re-sign":
		cmdReSign(client, args)
	case "selfcheck":
		cmdSelfcheck(client, args)
	case "aic":
		cmdAIC(client, args, firstPos(pos))
	case "cert":
		cmdCertShow(args)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		usage()
		os.Exit(1)
	}
}
