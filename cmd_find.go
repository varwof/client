// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"text/tabwriter"
)

func cmdFindByKey(client *Client, args map[string]string) {
	hash := args["--hash"]
	certFile := args["--cert"]
	keyFile := args["--key"]

	if hash == "" && certFile == "" && keyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: one of --hash, --cert, or --key is required")
		os.Exit(1)
	}
	if hash == "" {
		if certFile != "" {
			h, err := spkiHashFromCertFile(certFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error extracting hash from cert: %v\n", err)
				os.Exit(1)
			}
			hash = h
		} else if keyFile != "" {
			h, err := spkiHashFromKeyFile(keyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error extracting hash from key: %v\n", err)
				os.Exit(1)
			}
			hash = h
		}
	}

	q := buildQuery(map[string]string{
		"hash":   hash,
		"ca":     args["--ca"],
		"status": args["--status"],
	})
	path := "/api/v1/cert/by-key?" + q

	var certs []jsonCert
	if err := client.do("GET", path, nil, &certs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if args["--json"] == "true" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(certs)
		return
	}

	if len(certs) == 0 {
		fmt.Println("No certificates found for this public key")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tCA\tCN\tSTATUS\tNOT AFTER")
	for _, c := range certs {
		short := c.SerialNumber
		if len(short) > 16 {
			short = short[:16]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", short, c.CAName, c.CommonName, c.Status, c.NotAfter)
	}
	w.Flush()
}

func cmdReSign(client *Client, args map[string]string) {
	caName := args["--ca"]
	serial := args["--serial"]
	if caName == "" || serial == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca and --serial are required")
		os.Exit(1)
	}

	type reSignReq struct {
		TargetCA string `json:"target_ca,omitempty"`
		Profile  string `json:"profile,omitempty"`
		Validity int    `json:"validity,omitempty"`
	}
	req := reSignReq{
		TargetCA: args["--target-ca"],
		Profile:  args["--profile"],
		Validity: parseInt(args["--validity"], 365),
	}

	var resp issueResp
	if err := client.do("POST", "/api/v1/cert/"+caName+"/"+serial+"/re-sign", &req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Re-signed: %s (new serial: %s)\n  CA:     %s\n  Cert:\n%s\n",
		resp.CommonName, resp.SerialNumber, resp.CA, resp.CertPEM)
}

func spkiHashFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM data in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", h), nil
}

func spkiHashFromKeyFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM data in key file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParseECPrivateKey(block.Bytes)
		if err2 != nil {
			key3, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err3 != nil {
				return "", fmt.Errorf("parse private key: PKCS8=%v, EC=%v, PKCS1=%v", err, err2, err3)
			}
			key = key3
		} else {
			key = key2
		}
	}
	pub, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return "", fmt.Errorf("key does not expose public key")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub.Public())
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", h), nil
}
