// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func cmdRenew(client *Client, args map[string]string) {
	caName := args["--ca"]
	serial := args["--serial"]
	if caName == "" || serial == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca and --serial are required")
		os.Exit(1)
	}
	var resp issueResp
	if err := client.do("POST", "/api/v1/cert/"+caName+"/"+serial+"/renew", nil, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	outDir := strings.TrimRight(args["--out"], "/")
	if outDir != "" {
		os.MkdirAll(outDir, 0755)
		certFile := outDir + "/" + resp.SerialNumber + ".pem"
		keyFile := outDir + "/" + resp.SerialNumber + "-key.pem"
		os.WriteFile(certFile, []byte(resp.CertPEM), 0644)
		os.WriteFile(keyFile, []byte(resp.KeyPEM), 0600)
		fmt.Printf("Renewed: %s (new serial: %s)\n  Cert:  %s\n  Key:   %s\n", resp.CommonName, resp.SerialNumber, certFile, keyFile)
	} else {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(resp)
	}
}
