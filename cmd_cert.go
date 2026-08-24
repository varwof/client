// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	pki "github.com/varwof/types"
)

// cmdCertShow decodes a certificate file and prints its standard fields plus
// the varwof-specific extensions (AIC, PrincipalAuthorization) that openssl
// x509 -text cannot decode.
func cmdCertShow(args map[string]string) {
	path := args["--cert"]
	if path == "" {
		fmt.Fprintln(os.Stderr, "Error: --cert <file.pem> is required")
		os.Exit(1)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: read %s: %v\n", path, err)
		os.Exit(1)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error: %s: not a PEM file\n", path)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: parse %s: %v\n", path, err)
		os.Exit(1)
	}
	showCertificate(cert)
}

// showCertificate prints cert fields and decoded varwof extensions.
func showCertificate(cert *x509.Certificate) {
	fmt.Printf("Subject:  %s\n", cert.Subject)
	fmt.Printf("Issuer:   %s\n", cert.Issuer)
	fmt.Printf("Serial:   %s\n", cert.SerialNumber)
	fmt.Printf("NotBefore: %s\n", cert.NotBefore)
	fmt.Printf("NotAfter:  %s\n", cert.NotAfter)
	fmt.Printf("KeyUsage: %d\n", cert.KeyUsage)
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS:      %v\n", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Printf("IP:       %v\n", cert.IPAddresses)
	}

	fmt.Println()
	var showAIC, showPA bool
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(pki.OIDAIC):
			showAIC = true
		case ext.Id.Equal(pki.OIDPrincipalAuthorization):
			showPA = true
		}
	}

	if showAIC {
		aic, err := pki.ParseAIC(cert)
		if err != nil {
			fmt.Printf("AIC Extension (%s): <parse error: %v>\n", pki.OIDAIC, err)
		} else if aic != nil {
			fmt.Printf("AIC Extension: version=%d agent_id=%s\n", aic.Version, aic.AgentId)
			fmt.Printf("  PrincipalUid: %s\n", aic.Principal())
			fmt.Printf("  DelegationMode: %d\n", aic.DelegationMode)
			if len(aic.Capabilities) > 0 {
				fmt.Println("  Capabilities:")
				for _, c := range aic.Capabilities {
					fmt.Printf("    %s:%s\n", c.SchemeId, c.CapabilityId)
				}
			}
			if len(aic.AuthorizationConstraints) > 0 {
				fmt.Println("  AuthorizationConstraints:")
				for _, c := range aic.AuthorizationConstraints {
					fmt.Printf("    %s:%s\n", c.SchemeId, c.CapabilityId)
				}
			}
			if aic.DelegationAuthorization.IsPresent() {
				da := aic.DelegationAuthorization
				fmt.Printf("  DelegationAuthorization: lifetime=%d ts=%s nonce=%x\n",
					da.RequestedLifetime, da.Timestamp, da.Nonce)
			}
		}
	}

	if showPA {
		pa, err := pki.ParseUserPermissionExtension(cert)
		if err != nil {
			fmt.Printf("PrincipalAuthorization (%s): <parse error: %v>\n", pki.OIDPrincipalAuthorization, err)
		} else if pa != nil {
			fmt.Printf("PrincipalAuthorization: version=%d\n", pa.Version)
			if len(pa.Grants) > 0 {
				fmt.Println("  Grants:")
				for _, g := range pa.Grants {
					fmt.Printf("    %s:%s\n", g.SchemeId, g.CapabilityId)
				}
			}
			if len(pa.AuthorizationConstraints) > 0 {
				fmt.Println("  AuthorizationConstraints:")
				for _, c := range pa.AuthorizationConstraints {
					fmt.Printf("    %s:%s\n", c.SchemeId, c.CapabilityId)
				}
			}
			if pa.DelegationPolicy.MaxAgents > 0 || pa.DelegationPolicy.MaxSessionHours > 0 {
				fmt.Printf("  DelegationPolicy: version=%d maxAgents=%d allowedMode=%d maxSessionHours=%d\n",
					pa.DelegationPolicy.Version, pa.DelegationPolicy.MaxAgents,
					pa.DelegationPolicy.AllowedMode, pa.DelegationPolicy.MaxSessionHours)
			}
		}
	}
	if !showAIC && !showPA {
		fmt.Println("No varwof extensions (AIC / PrincipalAuthorization) found.")
	}
}
