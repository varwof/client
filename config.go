// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"
)

// Config is the varwof-cli configuration file structure.
// Specified via --config <path> or VARWOF_CLI_CONFIG, fields are file paths
// or string literals. Supports mTLS or Token authentication.
//
// Example:
//
//	{
//	  "server": "https://127.0.0.1:4433",
//	  "ca_cert": "/etc/varwof/core/keys/ca.pem",
//	  "client_cert": "/etc/varwof/core/keys/agent.pem",
//	  "client_key": "/etc/varwof/core/keys/agent.key",
//	  "token": ""
//	}
type Config struct {
	Server      string `json:"server"`
	CACert      string `json:"ca_cert"`
	ClientCert  string `json:"client_cert"`
	ClientKey   string `json:"client_key"`
	KeyPassword string `json:"key_password,omitempty"`
	Token       string `json:"token,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	// CL4 fix: the config may carry a plaintext token/key_password. Refuse to
	// use a world-readable config so credentials are not readable by other
	// users. Warn (but keep working) when the config is group-readable.
	if fi, statErr := os.Stat(path); statErr == nil {
		if fi.Mode().Perm()&0o004 != 0 {
			return nil, fmt.Errorf("config %s is world-readable (0%o); chmod 600 to protect credentials", path, fi.Mode().Perm())
		}
		if fi.Mode().Perm()&0o040 != 0 {
			fmt.Fprintf(os.Stderr, "warning: config %s is group-readable (0%o); consider chmod 600\n", path, fi.Mode().Perm())
		}
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Server == "" {
		return nil, errors.New("server is required")
	}
	// mTLS is required unless the server is a plain-HTTP internal API
	// endpoint (e.g. serve api's api_addr) with token authentication.
	if !strings.HasPrefix(cfg.Server, "http://") {
		if cfg.CACert == "" {
			return nil, errors.New("ca_cert is required (or use http:// for internal API)")
		}
		if cfg.ClientCert == "" {
			return nil, errors.New("client_cert is required")
		}
		if cfg.ClientKey == "" {
			return nil, errors.New("client_key is required")
		}
	}
	// CL4 fix: warn when credentials are stored in plaintext on disk so the
	// operator is aware that the config file itself is a secrets store.
	if cfg.Token != "" {
		fmt.Fprintf(os.Stderr, "warning: token stored in plaintext in %s; prefer PKI_KEY_PASSWORD-style env or remove it\n", path)
	}
	if cfg.KeyPassword != "" {
		fmt.Fprintf(os.Stderr, "warning: key_password stored in plaintext in %s; prefer PKI_KEY_PASSWORD env or interactive prompt\n", path)
	}
	// CL5 fix: a plain-http server means the token travels unencrypted. Warn
	// loudly when the target is not a loopback address so the operator cannot
	// silently leak credentials over the network.
	if strings.HasPrefix(cfg.Server, "http://") {
		if cfg.Token == "" {
			return nil, errors.New("http:// server requires a token for authentication")
		}
		if !isLoopbackServer(cfg.Server) {
			fmt.Fprintf(os.Stderr, "WARNING: server %s is plain HTTP and not a loopback address — "+
				"the API token will be sent in cleartext over the network\n", cfg.Server)
		}
	}
	return &cfg, nil
}

// resolveKeyPassword returns the private-key password from (in order) the
// explicit value, the PKI_KEY_PASSWORD env var, or an interactive prompt.
// Returns "" when the operator declines (caller will surface a decrypt error).
func resolveKeyPassword(explicit, keyPath string) string {
	if explicit != "" {
		return explicit
	}
	if p := os.Getenv("PKI_KEY_PASSWORD"); p != "" {
		return p
	}
	fmt.Fprintf(os.Stderr, "Enter password for %s: ", keyPath)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return ""
	}
	return string(pw)
}

// isLoopbackServer reports whether the (http://) server URL resolves to a
// loopback host (127.0.0.1, ::1, or localhost).
func isLoopbackServer(server string) bool {
	u, err := url.Parse(server)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || h == "" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (c *Config) TLSConfig() (*tls.Config, error) {
	// Plain-HTTP internal API: no client certificate required.
	if strings.HasPrefix(c.Server, "http://") {
		return nil, nil
	}
	keyData, err := os.ReadFile(c.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}

	var tlsCert tls.Certificate
	if isEncryptedPEM(keyData) {
		password := c.KeyPassword
		if password == "" {
			password = os.Getenv("PKI_KEY_PASSWORD")
		}
		if password == "" {
			fmt.Fprintf(os.Stderr, "Enter password for %s: ", c.ClientKey)
			pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return nil, fmt.Errorf("read password: %w", err)
			}
			password = string(pwBytes)
		}
		signer, err := decryptPrivateKeyPEM(keyData, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt key: %w", err)
		}
		certData, err := os.ReadFile(c.ClientCert)
		if err != nil {
			return nil, fmt.Errorf("read client cert: %w", err)
		}
		tlsCert, err = tls.X509KeyPair(certData, pemEncodePrivateKey(signer))
		if err != nil {
			return nil, fmt.Errorf("build tls cert: %w", err)
		}
	} else {
		var err error
		tlsCert, err = tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load cert pair: %w", err)
		}
	}
	caData, err := os.ReadFile(c.CACert)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, errors.New("no CA cert found in ca_cert file")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
