// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

// oauthTokenResponse mirrors core's /oauth/token response.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// cmdAICJWT exchanges an X.509 AIC certificate for a short-lived AIC-JWT
// via core's /oauth/token (RFC 8693 token exchange). The subject certificate
// defaults to the config's client_cert (the operator's AIC), overridable
// with --cert. The result is a Bearer token accepted by gateway HTTP
// listeners configured with a matching jwt_ca_file trust root.
func cmdAICJWT(client *Client, cfg *Config, args map[string]string) {
	certPath := args["--cert"]
	if certPath == "" {
		certPath = cfg.ClientCert
	}
	if certPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --cert is required (or set client_cert in the config)")
		os.Exit(1)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read certificate %s: %v\n", certPath, err)
		os.Exit(1)
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", string(certPEM))
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:x509-cert")
	if scope := args["--scope"]; scope != "" {
		form.Set("scope", scope)
	}

	var resp oauthTokenResponse
	if err := client.doForm("/oauth/token", form, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: token exchange: %v\n", err)
		os.Exit(1)
	}
	if resp.AccessToken == "" {
		fmt.Fprintln(os.Stderr, "Error: token exchange returned no access_token")
		os.Exit(1)
	}

	out := args["--out"]
	if out != "" {
		if err := os.WriteFile(out, []byte(resp.AccessToken), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error: write token file %s: %v\n", out, err)
			os.Exit(1)
		}
		fmt.Printf("AIC-JWT written to %s (expires in %ds)\n", out, resp.ExpiresIn)
	}

	if args["--json"] == "true" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(resp)
		return
	}

	if out == "" {
		fmt.Println(resp.AccessToken)
	} else {
		fmt.Printf("token_type:  %s\n", resp.TokenType)
		if resp.Scope != "" {
			fmt.Printf("scope:       %s\n", resp.Scope)
		}
	}
}
