// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pki "github.com/varwof/types"
)

// batchConfig mirrors the legacy varwof-aic-tool config format (now merged into varwof-cli).
type batchConfig struct {
	APIBase     string      `json:"api_base"`
	CA          string      `json:"ca"`
	OutDir      string      `json:"out_dir"`
	KeyPassword string      `json:"key_password,omitempty"`
	Users       []batchUser `json:"users"`
}

type batchUser struct {
	CN      string     `json:"cn"`
	Subject string     `json:"subject"`
	Agents  []batchAgt `json:"agents"`
}

type batchAgt struct {
	AgentID                  string   `json:"agent_id"`
	Realm                    string   `json:"realm"`
	HashAlgo                 string   `json:"hash_algo"`
	DelegationMode           int      `json:"delegation_mode"`
	Capabilities             []aicCap `json:"capabilities"`
	AuthorizationConstraints []aicCap `json:"authorization_constraints"`
}

func loadBatchConfig(path string) (*batchConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg batchConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("%s: no users defined", path)
	}
	return &cfg, nil
}

func cmdAICList(args map[string]string) {
	configPath := args["--config"]
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --config <file.json> is required")
		os.Exit(1)
	}
	cfg, err := loadBatchConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	for _, u := range cfg.Users {
		var caps []string
		for _, a := range u.Agents {
			for _, c := range a.Capabilities {
				caps = append(caps, c.SchemeID+":"+c.CapabilityID)
			}
		}
		fmt.Printf("%-20s  subject=%-45s  agents=%d  caps=%s\n",
			u.CN, u.Subject, len(u.Agents), strings.Join(caps, ","))
	}
}

func cmdAICBatch(client *Client, args map[string]string) {
	configPath := args["--config"]
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --config <file.json> is required")
		os.Exit(1)
	}
	cfg, err := loadBatchConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	caName := cfg.CA
	if caName == "" {
		caName = args["--ca"]
	}
	if caName == "" {
		fmt.Fprintln(os.Stderr, "Error: no CA specified (set 'ca' in config or pass --ca)")
		os.Exit(1)
	}
	outDir := cfg.OutDir
	if override := strings.TrimRight(args["--out"], "/"); override != "" {
		outDir = override
	}
	if outDir == "" {
		outDir = "."
	}
	keyPassword := cfg.KeyPassword
	if override := args["--key-password"]; override != "" {
		keyPassword = override
	}
	os.MkdirAll(outDir, 0755)

	fmt.Println("=== AIC batch ===")
	fmt.Printf("CA:     %s\nOutput: %s\n\n", caName, outDir)

	for _, u := range cfg.Users {
		issueUserAndAgents(client, caName, outDir, keyPassword, u)
	}
	fmt.Println("=== Done ===")
}

func issueUserAndAgents(client *Client, caName, outDir, keyPassword string, u batchUser) {
	fmt.Printf("--- %s (%s) ---\n", u.CN, u.Subject)

	var userCertPath string
	for _, a := range u.Agents {
		if a.AgentID == "" {
			fmt.Printf("  [WARN] %s: agent_id empty, skipping\n", u.CN)
			continue
		}
		// principal_uid must come from a real user certificate. Look for an
		// existing <cn>.pem in the output dir, else issue one via the API.
		path := filepath.Join(outDir, u.CN+".pem")
		if userCertPath == "" {
			if _, err := os.Stat(path); err == nil {
				userCertPath = path
			} else {
				path, err = issueBatchUserCert(client, caName, u, outDir)
				if err != nil {
					fmt.Printf("  [FAIL] user cert %s: %v\n", u.CN, err)
					return
				}
				userCertPath = path
			}
			fmt.Printf("  [OK] user cert: %s\n", userCertPath)
		}

		cert, cn, err := loadCertWithCN(userCertPath)
		if err != nil {
			fmt.Printf("  [FAIL] load user cert: %v\n", err)
			return
		}
		puid, err := principalUidFromCert(cn, cert)
		if err != nil {
			fmt.Printf("  [FAIL] principal_uid: %v\n", err)
			return
		}
		fmt.Printf("  [OK] principal_uid: %s\n", puid)
		fmt.Printf("  -> %s (mode=%d, hash=%s, %d caps)\n",
			a.AgentID, a.DelegationMode, a.HashAlgo, len(a.Capabilities))

		req := aicIssueReq{
			CA:                       caName,
			CN:                       cn,
			Subject:                  u.Subject,
			Profile:                  "agent-proxy",
			KeyType:                  "ecdsa-p256",
			Validity:                 1,
			AgentID:                  a.AgentID,
			PrincipalUID:             puid,
			HashAlgo:                 a.HashAlgo,
			DelegationMode:           &a.DelegationMode,
			PrincipalAuthorization:   &aicPA{Grants: grantsFromCaps(a.Capabilities)},
			Capabilities:             a.Capabilities,
			AuthorizationConstraints: a.AuthorizationConstraints,
		}

		// C3: Carry the DA signer certificate PEM for varwof-core to verify DelegationAuthorization.
		if certPEM, err := readPEM(userCertPath); err == nil {
			req.UserCertPEM = certPEM
		}

		// v1.7.1: Need user private key to sign DelegationAuthTBS as authorization evidence.
		userKeyPath := strings.TrimSuffix(userCertPath, ".pem") + ".key"
		pu, err := pki.ParsePrincipalUid(puid)
		if err != nil {
			fmt.Printf("  [FAIL] parse principal_uid: %v\n", err)
			return
		}
		var tbsCaps []pki.Capability
		for _, c := range a.Capabilities {
			tbsCaps = append(tbsCaps, pki.Capability{SchemeId: c.SchemeID, CapabilityId: c.CapabilityID})
		}
		var tbsConstraints []pki.Capability
		for _, c := range a.AuthorizationConstraints {
			tbsConstraints = append(tbsConstraints, pki.Capability{SchemeId: c.SchemeID, CapabilityId: c.CapabilityID, Parameters: c.Parameters})
		}
		if err := fillDelegationAuthEvidence(&req, userKeyPath, keyPassword, pu, a.AgentID, tbsCaps, tbsConstraints, a.DelegationMode); err != nil {
			fmt.Printf("  [FAIL] sign delegation authorization: %v\n", err)
			return
		}

		var resp issueResp
		if err := client.do("POST", "/api/v1/certs", &req, &resp); err != nil {
			fmt.Printf("  [FAIL] AIC %s: %v\n", a.AgentID, err)
			continue
		}
		certFile := filepath.Join(outDir, a.AgentID+".pem")
		keyFile := filepath.Join(outDir, a.AgentID+".key")
		os.WriteFile(certFile, []byte(resp.CertPEM), 0600)
		os.WriteFile(keyFile, []byte(resp.KeyPEM), 0600)
		fmt.Printf("  [OK] AIC: %s (serial: %s)\n", certFile, resp.SerialNumber)
	}
}

// issueBatchUserCert issues a throwaway tls-client user certificate via the API.
func issueBatchUserCert(client *Client, caName string, u batchUser, outDir string) (string, error) {
	path := filepath.Join(outDir, u.CN+".pem")
	keyPath := filepath.Join(outDir, u.CN+".key")
	var issued issueResp
	err := client.do("POST", "/api/v1/certs", &issueReq{
		CA:       caName,
		CN:       u.CN,
		Subject:  u.Subject,
		Profile:  "tls-client",
		KeyType:  "ecdsa-p256",
		Validity: 365,
	}, &issued)
	if err != nil {
		return "", err
	}
	os.WriteFile(path, []byte(issued.CertPEM), 0600)
	os.WriteFile(keyPath, []byte(issued.KeyPEM), 0600)
	return path, nil
}

func grantsFromCaps(caps []aicCap) []aicGrant {
	grants := make([]aicGrant, len(caps))
	for i, c := range caps {
		grants[i] = aicGrant{SchemeID: c.SchemeID, CapabilityID: c.CapabilityID}
	}
	return grants
}
