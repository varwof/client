package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

type healthzResp struct {
	Status    string `json:"status"`
	Version   string `json:"version"`
	DB        string `json:"db"`
	TSASigner string `json:"tsa_signer,omitempty"`
	CRLStatus string `json:"crl_status,omitempty"`
}

type crlGenerateResp struct {
	CA     string `json:"ca"`
	Length int    `json:"length"`
}

var selfcheckFailures int

func check(ok bool, name, detail string) {
	if ok {
		fmt.Printf("  [PASS] %s: %s\n", name, detail)
	} else {
		fmt.Printf("  [FAIL] %s: %s\n", name, detail)
		selfcheckFailures++
	}
}

func cmdSelfcheck(client *Client, args map[string]string) {
	caName := args["--ca"]
	if caName == "" {
		fmt.Fprintln(os.Stderr, "Error: --ca is required (issuing CA name for cert lifecycle test)")
		os.Exit(1)
	}
	keep := args["--keep"] == "true"

	fmt.Println("=== varwof-core selfcheck ===")
	fmt.Printf("Server: %s\n", client.baseURL)
	fmt.Println()

	// 1. healthz (public) — probe, then auto-repair CRL if degraded.
	hz, err := fetchHealthz(client)
	if err != nil {
		check(false, "healthz", err.Error())
	} else {
		check(hz.DB == "ok", "database", hz.DB)
		if hz.TSASigner != "" {
			check(hz.TSASigner == "ok", "tsa signer", hz.TSASigner)
		}
		if hz.CRLStatus == "ok" {
			check(true, "crl freshness", hz.CRLStatus)
		} else {
			// Auto-repairable: report the finding, then repair below.
			fmt.Printf("  [INFO] crl freshness: %s (auto-repair will attempt)\n", hz.CRLStatus)
		}
		if hz.Status == "ok" {
			check(true, "healthz status", fmt.Sprintf("%s (v%s)", hz.Status, hz.Version))
		} else if hz.CRLStatus != "ok" {
			fmt.Printf("  [INFO] healthz status: %s (degraded due to CRL; repairing below)\n", hz.Status)
		} else {
			check(false, "healthz status", hz.Status)
		}
	}

	if hz.Status == "degraded" && hz.CRLStatus != "ok" {
		fmt.Println()
		fmt.Println("  [INFO] degraded CRL status detected; regenerating CRLs for all CAs...")
		repairCRLs(client)
		fmt.Println()

		// Re-check healthz after repair and report the final state.
		hz2, err2 := fetchHealthz(client)
		if err2 != nil {
			check(false, "healthz after repair", err2.Error())
		} else {
			check(hz2.CRLStatus == "ok", "crl freshness after repair", hz2.CRLStatus)
			check(hz2.Status == "ok", "healthz after repair", hz2.Status)
		}
	}

	// 3. CA hierarchy reachable (mTLS).
	var cas []jsonCA
	if err := client.do("GET", "/api/v1/cas", nil, &cas); err != nil {
		check(false, "CA list (mTLS)", err.Error())
	} else {
		check(len(cas) > 0, "CA list (mTLS)", fmt.Sprintf("%d CAs", len(cas)))
	}

	// 4. Issue a throwaway test cert.
	testCN := "selfcheck-" + time.Now().Format("20060102-150405")
	var issued issueResp
	err = client.do("POST", "/api/v1/certs", &issueReq{
		CA:       caName,
		CN:       testCN,
		Profile:  "tls-client",
		KeyType:  "ecdsa-p256",
		Validity: 1,
	}, &issued)
	if err != nil {
		check(false, "issue test cert", err.Error())
		return
	}
	check(issued.SerialNumber != "", "issue test cert", fmt.Sprintf("%s serial=%s", testCN, issued.SerialNumber))

	// Verify issued cert parses and chain to the CA.
	if err := verifyIssuedCert(&issued, caName, &cas); err != nil {
		check(false, "verify issued cert", err.Error())
	} else {
		check(true, "verify issued cert", "parses and chains to CA")
	}

	// 5. Revoke it.
	reason := "superseded"
	if err := client.do("POST", "/api/v1/cert/"+caName+"/"+issued.SerialNumber+"/revoke",
		&revokeReq{Reason: reason}, &map[string]any{}); err != nil {
		check(false, "revoke test cert", err.Error())
	} else {
		check(true, "revoke test cert", issued.SerialNumber)
	}

	// 6. Regenerate CRL to include the revoked cert.
	var crl crlGenerateResp
	if err := client.do("POST", "/api/v1/crl/"+caName+"/generate", nil, &crl); err != nil {
		check(false, "generate CRL", err.Error())
	} else {
		check(crl.Length > 0, "generate CRL", fmt.Sprintf("ca=%s bytes=%d", crl.CA, crl.Length))
	}

	// 7. Download and parse the CRL.
	if err := downloadAndParseCRL(client, caName); err != nil {
		check(false, "download/parse CRL", err.Error())
	} else {
		check(true, "download/parse CRL", "DER parses as CRL")
	}

	if !keep {
		_ = os.Remove(issued.CertPEM)
	}

	fmt.Println()
	if selfcheckFailures > 0 {
		fmt.Printf("=== selfcheck: %d FAILURE(S) ===\n", selfcheckFailures)
		os.Exit(1)
	}
	fmt.Println("=== selfcheck: ALL PASS ===")
}

// fetchHealthz retrieves the /healthz payload (public endpoint).
func fetchHealthz(client *Client) (healthzResp, error) {
	var hz healthzResp
	err := client.do("GET", "/healthz", nil, &hz)
	return hz, err
}

// repairCRLs regenerates CRLs for every configured CA, fixing a degraded
// "crl_status: no CRL found" healthz state without touching varwof-core.
func repairCRLs(client *Client) {
	var cas []jsonCA
	if err := client.do("GET", "/api/v1/cas", nil, &cas); err != nil {
		check(false, "repair: list CAs", err.Error())
		return
	}
	repaired := 0
	for _, c := range cas {
		var crl crlGenerateResp
		if err := client.do("POST", "/api/v1/crl/"+c.Name+"/generate", nil, &crl); err != nil {
			fmt.Printf("  [WARN] repair CRL %s: %v\n", c.Name, err)
			continue
		}
		repaired++
	}
	if repaired > 0 {
		fmt.Printf("  [INFO] regenerated CRLs for %d CA(s)\n", repaired)
	}
}

func verifyIssuedCert(issued *issueResp, caName string, cas *[]jsonCA) error {
	block, _ := pem.Decode([]byte(issued.CertPEM))
	if block == nil {
		return fmt.Errorf("issued cert is not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse issued cert: %w", err)
	}
	for _, ca := range *cas {
		if ca.Name != caName {
			continue
		}
		pool := x509.NewCertPool()
		caBlock, _ := pem.Decode([]byte(ca.CertPEM))
		if caBlock == nil {
			continue
		}
		caCert, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(caCert)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("verify chain: %w", err)
		}
		return nil
	}
	return fmt.Errorf("CA %q not found in CA list", caName)
}

func downloadAndParseCRL(client *Client, caName string) error {
	resp, err := client.doRaw("GET", "/api/v1/crl/"+caName, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	der, err := readAll(resp.Body)
	if err != nil {
		return err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("parse CRL DER: %w", err)
	}
	_ = crl
	return nil
}
