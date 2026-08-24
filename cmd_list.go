package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
)

type jsonCert struct {
	SerialNumber string  `json:"serial_number"`
	CAName       string  `json:"ca_name"`
	Status       string  `json:"status"`
	Subject      string  `json:"subject"`
	CommonName   string  `json:"common_name"`
	NotBefore    string  `json:"not_before"`
	NotAfter     string  `json:"not_after"`
	RevokedAt    *string `json:"revoked_at,omitempty"`
	RevokeReason *int    `json:"revoke_reason,omitempty"`
	Fingerprint  string  `json:"fingerprint"`
}

type jsonCA struct {
	Name         string `json:"name"`
	Subject      string `json:"subject"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	KeyAlgorithm string `json:"key_algorithm"`
	Fingerprint  string `json:"fingerprint"`
	CertPEM      string `json:"cert_pem"`
}

func cmdListCerts(client *Client, args map[string]string) {
	path := "/api/v1/certs"
	q := buildQuery(map[string]string{
		"ca":     args["--ca"],
		"status": args["--status"],
		"cn":     args["--cn"],
	})
	if q != "" {
		path += "?" + q
	}
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
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tCN\tCA\tSTATUS\tNOT AFTER")
	for _, c := range certs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", c.SerialNumber, c.CommonName, c.CAName, c.Status, c.NotAfter)
	}
	w.Flush()
}

func cmdListCAs(client *Client, args map[string]string) {
	var cas []jsonCA
	if err := client.do("GET", "/api/v1/cas", nil, &cas); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if args["--json"] == "true" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(cas)
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "NAME\tSUBJECT\tKEY ALGO\tNOT AFTER")
	for _, c := range cas {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Name, c.Subject, c.KeyAlgorithm, c.NotAfter)
	}
	w.Flush()
}

func cmdCAInfo(client *Client, args map[string]string) {
	name := args["--ca"]
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca is required")
		os.Exit(1)
	}
	var ca jsonCA
	if err := client.do("GET", "/api/v1/ca/"+name, nil, &ca); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if args["--json"] == "true" || args["--pem"] == "true" {
		if args["--pem"] == "true" {
			fmt.Print(ca.CertPEM)
		} else {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			enc.Encode(ca)
		}
		return
	}
	fmt.Printf("Name:         %s\n", ca.Name)
	fmt.Printf("Subject:      %s\n", ca.Subject)
	fmt.Printf("Key Algo:     %s\n", ca.KeyAlgorithm)
	fmt.Printf("Fingerprint:  %s\n", ca.Fingerprint)
	fmt.Printf("Not Before:   %s\n", ca.NotBefore)
	fmt.Printf("Not After:    %s\n", ca.NotAfter)
}

func buildQuery(params map[string]string) string {
	v := url.Values{}
	for key, value := range params {
		if value != "" {
			v.Set(key, value)
		}
	}
	return v.Encode()
}
