// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type issueReq struct {
	CA                     string `json:"ca"`
	CN                     string `json:"cn"`
	SAN                    string `json:"san,omitempty"`
	Subject                string `json:"subject,omitempty"`
	Profile                string `json:"profile,omitempty"`
	KeyType                string `json:"key_type,omitempty"`
	Validity               int    `json:"validity,omitempty"`
	CAScope                string `json:"ca_scope,omitempty"`
	PrincipalAuthorization *aicPA `json:"principal_authorization,omitempty"`
}

type issueResp struct {
	SerialNumber string `json:"serial_number"`
	CommonName   string `json:"common_name"`
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	CA           string `json:"ca"`
	SPIFFEID     string `json:"spiffe_id,omitempty"`
}

func cmdIssue(client *Client, args map[string]string) {
	req := issueReq{
		CA:       args["--ca"],
		CN:       args["--cn"],
		SAN:      args["--san"],
		Subject:  args["--subject"],
		Profile:  args["--profile"],
		KeyType:  args["--key-type"],
		Validity: parseInt(args["--validity"], 365),
		CAScope:  args["--ca-scope"],
	}
	if req.CN == "" {
		fmt.Fprintln(os.Stderr, "Error: --cn is required")
		os.Exit(1)
	}
	if pa := args["--pa"]; pa != "" {
		var grants []aicGrant
		for _, g := range strings.Fields(pa) {
			parts := strings.SplitN(g, ":", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Error: invalid PA grant %q (expected scheme:capability)\n", g)
				os.Exit(1)
			}
			grants = append(grants, aicGrant{SchemeID: parts[0], CapabilityID: parts[1]})
		}
		req.PrincipalAuthorization = &aicPA{Grants: grants}
	}
	var resp issueResp
	if err := client.do("POST", "/api/v1/certs", &req, &resp); err != nil {
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
		fmt.Printf("Issued: %s\n  Serial: %s\n  Cert:  %s\n  Key:   %s\n", resp.CommonName, resp.SerialNumber, certFile, keyFile)
	} else {
		fmt.Printf("Issued: %s\n  Serial: %s\n  CA:    %s\n  Cert:\n%s\n  Key:\n%s\n",
			resp.CommonName, resp.SerialNumber, resp.CA, resp.CertPEM, resp.KeyPEM)
	}
}

func parseInt(s string, def int) int {
	if s == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return def
	}
	return n
}

func cmdBatchIssue(client *Client, args map[string]string) {
	requestsFile := args["--requests"]
	if requestsFile == "" {
		requestsFile = args["--csv"]
	}
	if requestsFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --requests or --csv is required")
		os.Exit(1)
	}
	data, err := os.ReadFile(requestsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading requests file: %v\n", err)
		os.Exit(1)
	}
	var reqs []issueReq
	if err := json.Unmarshal(data, &reqs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing requests JSON: %v\n", err)
		os.Exit(1)
	}
	type batchEntry struct {
		CN                     string `json:"cn"`
		SAN                    string `json:"san,omitempty"`
		Profile                string `json:"profile,omitempty"`
		CA                     string `json:"ca,omitempty"`
		KeyType                string `json:"key_type,omitempty"`
		Validity               int    `json:"validity,omitempty"`
		PrincipalAuthorization *aicPA `json:"principal_authorization,omitempty"`
	}
	type batchPayload struct {
		Requests []batchEntry `json:"requests"`
		Fast     bool         `json:"fast"`
	}
	batch := batchPayload{Fast: args["--fast"] == "true"}
	for _, r := range reqs {
		batch.Requests = append(batch.Requests, batchEntry{
			CN: r.CN, SAN: r.SAN, Profile: r.Profile,
			CA: r.CA, KeyType: r.KeyType, Validity: r.Validity,
			PrincipalAuthorization: r.PrincipalAuthorization,
		})
	}
	type batchResult struct {
		SerialNumber string `json:"serial_number"`
		CommonName   string `json:"common_name"`
		Status       string `json:"status"`
		Error        string `json:"error,omitempty"`
	}
	var results []batchResult
	if err := client.do("POST", "/api/v1/certs/batch", &batch, &results); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}
