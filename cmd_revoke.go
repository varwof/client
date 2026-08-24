package main

import (
	"fmt"
	"os"
)

type revokeReq struct {
	Reason string `json:"reason,omitempty"`
}

func cmdRevoke(client *Client, args map[string]string) {
	caName := args["--ca"]
	serial := args["--serial"]
	if caName == "" || serial == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca and --serial are required")
		os.Exit(1)
	}
	reason := args["--reason"]
	var req *revokeReq
	if reason != "" {
		req = &revokeReq{Reason: reason}
	}
	var resp map[string]any
	if err := client.do("POST", "/api/v1/cert/"+caName+"/"+serial+"/revoke", req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked: %s/%s\n", caName, serial)
	if c, ok := resp["cascade_count"]; ok && c.(float64) > 0 {
		fmt.Printf("  Cascade: %v additional cert(s) revoked\n", c)
	}
	if args["--crl"] == "true" {
		cmdGenerateCRL(client, caName)
	}
}

func cmdGenerateCRL(client *Client, caName string) {
	var crlResp map[string]any
	if err := client.do("POST", "/api/v1/crl/"+caName+"/generate", nil, &crlResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error regenerating CRL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  CRL regenerated: %s (%v bytes)\n", crlResp["ca"], crlResp["length"])
}

func cmdRevokeAll(client *Client, args map[string]string) {
	reason := args["--reason"]
	var req *revokeReq
	if reason != "" {
		req = &revokeReq{Reason: reason}
	}
	var resp map[string]any
	if err := client.do("POST", "/api/v1/user/revoke-all", req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked all: %v\n", resp["revoked_count"])
}

func cmdRevokeByPrincipal(client *Client, args map[string]string) {
	uid := args["--principal-uid"]
	if uid == "" {
		fmt.Fprintln(os.Stderr, "Error: --principal-uid is required")
		os.Exit(1)
	}
	type revokeByPrincipalReq struct {
		PrincipalUid string `json:"principal_uid"`
		Reason       string `json:"reason,omitempty"`
	}
	req := revokeByPrincipalReq{PrincipalUid: uid, Reason: args["--reason"]}
	var resp map[string]any
	if err := client.do("POST", "/api/v1/certs/revoke-by-principal", &req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked %v cert(s) for principal %s\n", resp["revoked_count"], uid)
}

func cmdRevokeSubCA(client *Client, args map[string]string) {
	name := args["--sub-ca"]
	if name == "" {
		fmt.Fprintln(os.Stderr, "Error: --sub-ca is required")
		os.Exit(1)
	}
	type revokeSubCAReq struct {
		Reason string `json:"reason,omitempty"`
	}
	req := revokeSubCAReq{Reason: args["--reason"]}
	var resp map[string]any
	if err := client.do("POST", "/api/v1/sub-ca/"+name+"/revoke-all", &req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Revoked %v cert(s) under sub-CA %s\n", resp["revoked_count"], name)
}
