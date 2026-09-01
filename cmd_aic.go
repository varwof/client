// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	pki "github.com/varwof/types"
)

// aicCap mirrors the AIC capabilities payload on POST /api/v1/certs.
type aicCap struct {
	SchemeID     string `json:"scheme_id"`
	CapabilityID string `json:"capability_id"`
	Parameters   []byte `json:"parameters,omitempty"`
}

// aicGrant mirrors PrincipalAuthorization.Grants payload.
type aicGrant struct {
	SchemeID     string `json:"scheme_id"`
	CapabilityID string `json:"capability_id"`
	Parameters   []byte `json:"parameters,omitempty"`
}

type aicPA struct {
	Grants []aicGrant `json:"grants"`
}

type aicIssueReq struct {
	CA                     string   `json:"ca"`
	CN                     string   `json:"cn"`
	Subject                string   `json:"subject,omitempty"`
	Profile                string   `json:"profile"`
	KeyType                string   `json:"key_type"`
	Validity               int      `json:"validity"`
	AgentID                string   `json:"agent_id"`
	PrincipalUID           string   `json:"principal_uid"`
	HashAlgo               string   `json:"hash_algo,omitempty"`
	DelegationMode         *int     `json:"delegation_mode,omitempty"`
	PrincipalAuthorization *aicPA   `json:"principal_authorization,omitempty"`
	Capabilities           []aicCap `json:"capabilities,omitempty"`
	// v1.7.1 DelegationAuthorization evidence (user-authorized AIC issuance).
	UserAuthSig        string `json:"user_auth_signature,omitempty"`
	UserAuthSigAlgo    string `json:"user_auth_signature_algo,omitempty"`
	UserAuthNonce      string `json:"user_auth_nonce,omitempty"`
	UserAuthLifetime   int    `json:"user_auth_lifetime,omitempty"`
	UserAuthTimestamp  string `json:"user_auth_timestamp,omitempty"`
	UserAuthReasonCode string `json:"user_auth_reason_code,omitempty"`
	UserAuthReasonDesc string `json:"user_auth_reason_description,omitempty"`
	// ClaimsDigest is the SHA-256 of the validated capability claims file
	// (P1-3). It is embedded in the signed DelegationAuthorization reason so
	// the authorization evidence is anchored to the AI-generated claims.
	ClaimsDigest string `json:"capability_claims_digest,omitempty"`
	// UserCertPEM is the DA signer (user) certificate PEM. varwof-core uses it to verify
	// the DelegationAuthorization signature (C3: CA must verify the subject's signature).
	UserCertPEM string `json:"user_cert_pem,omitempty"`
	// AuthorizationConstraints are session-level constraints (allowed-cidr / time-window / max-concurrent).
	// Written to AIC extension field 7, enforced offline by gateways.
	AuthorizationConstraints []aicCap `json:"authorization_constraints,omitempty"`
	// IsSPIFFE enables SPIFFE identity integration. When true, agent_id is transformed
	// to "spiffe://{spiffe_trust_domain}/agent/{agent_id}" and embedded in SAN URIs.
	IsSPIFFE *bool `json:"is_spiffe,omitempty"`
	// SPIFFEDomain is the SPIFFE trust domain (e.g. "varwof.com").
	// Required when is_spiffe=true.
	SPIFFEDomain string `json:"spiffe_trust_domain,omitempty"`
}

func cmdAICIssue(client *Client, args map[string]string) {
	// --from-claims: consume the validated capability claims file directly
	// (gen-capability minimal set). Must run before --caps/--pa are read.
	// Derives --caps (and --pa when unset) with JSON parameters and anchors
	// the file digest into the signed DA reason, so the operator never
	// hand-copies inline JSON (P0-2 ergonomics).
	if fromClaims := args["--from-claims"]; fromClaims != "" {
		data, err := os.ReadFile(fromClaims)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: read claims file: %v\n", err)
			os.Exit(1)
		}
		tokens, digest, err := claimsToCapTokens(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		args["--caps"] = strings.Join(tokens, " ")
		if args["--pa"] == "" {
			// Least-privilege default: the principal authorizes exactly the
			// claims that were generated and validated.
			args["--pa"] = args["--caps"]
		}
		if args["--claims-digest"] == "" {
			args["--claims-digest"] = digest
		}
	}

	userCertPath := args["--user-cert"]
	userKeyPath := args["--user-key"]
	agentID := args["--agent"]
	capsStr := args["--caps"]
	caName := args["--ca"]
	spiffeDomain := args["--spiffe-domain"]
	isSPIFFE := args["--spiffe"] == "true"
	claimsDigest := args["--claims-digest"]

	if userCertPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --user-cert is required")
		os.Exit(1)
	}
	if userKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --user-key is required (v1.7.1: AIC issuance requires the user's delegation authorization signature)")
		os.Exit(1)
	}
	if agentID == "" || capsStr == "" {
		fmt.Fprintln(os.Stderr, "Error: --agent and --caps are required")
		os.Exit(1)
	}
	if isSPIFFE && spiffeDomain == "" {
		fmt.Fprintln(os.Stderr, "Error: --spiffe-domain is required when --spiffe is set")
		os.Exit(1)
	}

	userCert, cn, err := loadCertWithCN(userCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// C3: Carry the DA signer certificate PEM for varwof-core to verify DelegationAuthorization.
	userCertPEM, err := readPEM(userCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ou := args["--ou"]
	subject := args["--subject"]
	if subject == "" {
		if ou != "" {
			subject = fmt.Sprintf("/C=CN/O=varwof.com/OU=%s/CN=%s", ou, cn)
		} else {
			subject = fmt.Sprintf("/C=CN/O=varwof.com/CN=%s", cn)
		}
	}

	puid, err := principalUidFromCert(cn, userCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var caps []aicCap
	var tbsCaps []pki.Capability
	for _, c := range strings.Fields(capsStr) {
		scheme, capID, params, err := parseCapToken(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		caps = append(caps, aicCap{SchemeID: scheme, CapabilityID: capID, Parameters: params})
		tbsCaps = append(tbsCaps, pki.Capability{SchemeId: scheme, CapabilityId: capID, Parameters: params})
	}

	// PA grants: only from --pa flag, NOT from --caps.
	// When --pa is empty, PA will be auto-derived from authz.json policy.
	var grants []aicGrant
	if paStr := args["--pa"]; paStr != "" {
		for _, g := range strings.Fields(paStr) {
			scheme, capID, params, err := parseCapToken(g)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			grants = append(grants, aicGrant{SchemeID: scheme, CapabilityID: capID, Parameters: params})
		}
	}

	// v1.7.1: Sign DelegationAuthTBS with the user's private key as authorization evidence.
	pu, err := pki.ParsePrincipalUid(puid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: parse principal_uid: %v\n", err)
		os.Exit(1)
	}

	// --constraints 'scheme:cap[:jsonparams] ...' session-level constraints.
	var constraints []aicCap
	var tbsConstraints []pki.Capability
	if cs := args["--constraints"]; cs != "" {
		for _, c := range strings.Fields(cs) {
			parts := strings.SplitN(c, ":", 3)
			if len(parts) < 2 {
				fmt.Fprintf(os.Stderr, "Error: invalid constraint %q (expected scheme:capability[:jsonparams])\n", c)
				os.Exit(1)
			}
			params := []byte(nil)
			if len(parts) == 3 && parts[2] != "" {
				params = []byte(parts[2])
			}
			constraints = append(constraints, aicCap{SchemeID: parts[0], CapabilityID: parts[1], Parameters: params})
			tbsConstraints = append(tbsConstraints, pki.Capability{SchemeId: parts[0], CapabilityId: parts[1], Parameters: params})
		}
	}

	mode := 0
	var isSPIFFEPtr *bool
	if isSPIFFE {
		isSPIFFEPtr = &isSPIFFE
	}
	// Build SPIFFE ID for DA signing and output display.
	daAgentID := agentID
	if isSPIFFE {
		daAgentID = pki.BuildSPIFFEID(spiffeDomain, agentID)
	}
	req := aicIssueReq{
		CA:                       caName,
		CN:                       cn,
		Subject:                  subject,
		Profile:                  "agent-proxy",
		KeyType:                  "ecdsa-p256",
		Validity:                 1,
		AgentID:                  agentID,
		PrincipalUID:             puid,
		HashAlgo:                 "sha256",
		DelegationMode:           &mode,
		PrincipalAuthorization:   &aicPA{Grants: grants},
		Capabilities:             caps,
		AuthorizationConstraints: constraints,
		UserCertPEM:              userCertPEM,
		IsSPIFFE:                 isSPIFFEPtr,
		SPIFFEDomain:             spiffeDomain,
		ClaimsDigest:             claimsDigest,
	}
	userKeyPassword := args["--key-password"]
	if err := fillDelegationAuthEvidence(&req, userKeyPath, userKeyPassword, pu, daAgentID, tbsCaps, tbsConstraints, mode); err != nil {
		fmt.Fprintf(os.Stderr, "Error: sign delegation authorization: %v\n", err)
		os.Exit(1)
	}

	var resp issueResp
	if err := client.do("POST", "/api/v1/certs", &req, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	outDir := strings.TrimRight(args["--out"], "/")
	if outDir == "" {
		outDir = "."
	}
	// CL6 fix: surface mkdir/write failures — a silently dropped cert/key file
	// makes the operator believe the AIC was persisted when it was not.
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: create output dir: %v\n", err)
		os.Exit(1)
	}
	certFile := filepath.Join(outDir, agentID+".pem")
	keyFile := filepath.Join(outDir, agentID+".key")
	if err := os.WriteFile(certFile, []byte(resp.CertPEM), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: write cert file %s: %v\n", certFile, err)
		os.Exit(1)
	}
	if err := os.WriteFile(keyFile, []byte(resp.KeyPEM), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: write key file %s: %v\n", keyFile, err)
		os.Exit(1)
	}

	fmt.Printf("Issued AIC: %s\n", agentID)
	fmt.Printf("  PrincipalUID: %s\n", puid)
	fmt.Printf("  Subject:      %s\n", subject)
	fmt.Printf("  Serial:       %s\n", resp.SerialNumber)
	fmt.Printf("  Validity:     1 day\n")
	if resp.SPIFFEID != "" {
		fmt.Printf("  SPIFFE ID:    %s\n", resp.SPIFFEID)
	}
	fmt.Printf("  Cert:         %s\n  Key:          %s\n", certFile, keyFile)
	if args["--json"] == "true" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(resp)
	}
}

// signDelegationAuth signs the DelegationAuthTBS DER with the user's private key.
// The returned signature algorithm name matches what varwof-core serve accepts
// (ECDSA-SHA256 / RSA-SHA256 / Ed25519). Supports plain and PBES2-encrypted
// (ENCRYPTED PRIVATE KEY) key files (CL7).
func signDelegationAuth(userKeyPath, password string, tbs *pki.DelegationAuthTBS) (sig []byte, algo string, err error) {
	der, err := asn1.Marshal(*tbs)
	if err != nil {
		return nil, "", fmt.Errorf("marshal delegation TBS: %w", err)
	}
	digest := sha256.Sum256(der)

	keyPEM, err := os.ReadFile(userKeyPath)
	if err != nil {
		return nil, "", fmt.Errorf("read user key %s: %w", userKeyPath, err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, "", fmt.Errorf("%s: not a PEM file", userKeyPath)
	}

	var key crypto.Signer
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if password == "" {
			password = resolveKeyPassword("", userKeyPath)
		}
		key, err = decryptPrivateKeyPEM(keyPEM, password)
		if err != nil {
			return nil, "", fmt.Errorf("decrypt user key %s: %w", userKeyPath, err)
		}
	} else {
		key, err = parsePrivateKeyPEM(keyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("parse user key %s: %w", userKeyPath, err)
		}
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		s, err := ecdsa.SignASN1(rand.Reader, k, digest[:])
		return s, "ECDSA-SHA256", err
	case *rsa.PrivateKey:
		s, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
		return s, "RSA-SHA256", err
	case ed25519.PrivateKey:
		return ed25519.Sign(k, digest[:]), "Ed25519", nil
	default:
		return nil, "", fmt.Errorf("unsupported user key type %T", key)
	}
}

// fillDelegationAuthEvidence builds a v1.7.1 DelegationAuthTBS (using the same
// field order as varwof-core serve) and signs it with the user's private key,
// filling the user_auth_* request fields so varwof-core can verify the TBS.
// delegationMode must match the request's delegation_mode value, otherwise the
// CA-side verification (C3) rebuilds a different TBS and rejects the signature.
func fillDelegationAuthEvidence(req *aicIssueReq, userKeyPath, password string, pu pki.PrincipalUid, agentID string, caps []pki.Capability, constraints []pki.Capability, delegationMode int) error {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ts := time.Now().UTC().Truncate(time.Second)
	reasonCode := "API_ISSUE"
	reasonDesc := "user-authorized AIC issuance"
	if cd := req.ClaimsDigest; cd != "" {
		reasonDesc += "; capability-claims:sha256:" + cd
	}
	tbs := &pki.DelegationAuthTBS{
		Version:                  1,
		AgentId:                  agentID,
		PrincipalUid:             pu,
		Reason:                   pki.Reason{ReasonCode: reasonCode, Description: reasonDesc},
		Capabilities:             caps,
		DelegationMode:           pki.DelegationMode(delegationMode),
		AuthorizationConstraints: constraints,
		RequestedLifetime:        3600,
		Timestamp:                ts,
		Nonce:                    nonce,
	}
	sig, sigAlgo, err := signDelegationAuth(userKeyPath, password, tbs)
	if err != nil {
		return err
	}
	req.UserAuthSig = base64.StdEncoding.EncodeToString(sig)
	req.UserAuthSigAlgo = sigAlgo
	req.UserAuthNonce = base64.StdEncoding.EncodeToString(nonce)
	req.UserAuthLifetime = 3600
	req.UserAuthTimestamp = ts.Format(time.RFC3339)
	req.UserAuthReasonCode = reasonCode
	req.UserAuthReasonDesc = reasonDesc
	return nil
}

// cmdAIC routes the `aic` command to its subcommands. With no subcommand it
// defaults to `aic issue` (backward compatible).
func cmdAIC(client *Client, cfg *Config, args map[string]string, sub string) {
	switch sub {
	case "batch":
		cmdAICBatch(client, args)
	case "list":
		cmdAICList(args)
	case "jwt":
		cmdAICJWT(client, cfg, args)
	case "", "issue":
		cmdAICIssue(client, args)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown aic subcommand %q (expected issue|batch|list|jwt)\n", sub)
		os.Exit(1)
	}
}

// firstPos returns the first positional argument, or "".
func firstPos(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}

// loadCertWithCN reads a PEM certificate and returns it plus its CN.
func loadCertWithCN(path string) (*x509.Certificate, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", fmt.Errorf("%s: not a PEM file", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", path, err)
	}
	return cert, cert.Subject.CommonName, nil
}

// readPEM reads a PEM file and returns its raw PEM text.
func readPEM(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("%s: not a valid PEM file", path)
	}
	return string(data), nil
}

// principalUidFromCert builds a principal_uid whose KeyHash is the SPKI
// SHA-256 of the user certificate — delegated to the shared types
// implementation so format changes stay in sync (CL9).
func principalUidFromCert(cn string, cert *x509.Certificate) (string, error) {
	return pki.MakePrincipalUidFromCert(cn, cn, cert).String(), nil
}

// parseCapToken parses a capability token of the form
//
//	scheme:capability
//	scheme:capability:{json-params}
//	scheme:capability{json-params}
//
// The scheme segment is everything up to the first ':' of the base; the
// capability ID may itself contain ':' (e.g. "query:SELECT"). Parameters are
// the JSON object/array following the first '{' (P0-2).
func parseCapToken(token string) (scheme, capID string, params []byte, err error) {
	base := token
	if idx := strings.Index(token, "{"); idx >= 0 {
		base = strings.TrimSuffix(token[:idx], ":")
		raw := token[idx:]
		if len(raw) < 2 || (raw[0] != '{' && raw[0] != '[') || !json.Valid([]byte(raw)) {
			return "", "", nil, fmt.Errorf("invalid capability %q: parameters must be a JSON object/array", token)
		}
		params = []byte(raw)
	}
	parts := strings.SplitN(base, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", nil, fmt.Errorf("invalid capability %q (expected scheme:capability[:jsonparams])", token)
	}
	return parts[0], parts[1], params, nil
}

// claimsToCapTokens converts a validated capability claims file into
// capability tokens ("scheme:cap:{json}") plus the SHA-256 file digest used
// to anchor the claims into the signed DelegationAuthorization (P1-3).
func claimsToCapTokens(data []byte) ([]string, string, error) {
	var claims []struct {
		SchemeID   string         `json:"scheme_id"`
		Capability string         `json:"capability"`
		Parameters map[string]any `json:"parameters,omitempty"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, "", fmt.Errorf("parse claims file: %w", err)
	}
	if len(claims) == 0 {
		return nil, "", fmt.Errorf("claims file is empty")
	}
	tokens := make([]string, 0, len(claims))
	for i, c := range claims {
		if c.SchemeID == "" || c.Capability == "" {
			return nil, "", fmt.Errorf("claim[%d] missing scheme_id/capability", i)
		}
		tok := c.SchemeID + ":" + c.Capability
		if len(c.Parameters) > 0 {
			b, err := json.Marshal(c.Parameters)
			if err != nil {
				return nil, "", fmt.Errorf("claim[%d] parameters: %w", i, err)
			}
			tok += ":" + string(b)
		}
		tokens = append(tokens, tok)
	}
	sum := sha256.Sum256(data)
	return tokens, hex.EncodeToString(sum[:]), nil
}
