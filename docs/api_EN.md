# varwof-cli API Reference

> This document describes varwof-cli's internal API (exported types/functions), as well as the core REST API it calls.

## Exported Types

### Config

```go
type Config struct {
    Server      string `json:"server"`
    CACert      string `json:"ca_cert"`
    ClientCert  string `json:"client_cert"`
    ClientKey   string `json:"client_key"`
    KeyPassword string `json:"key_password,omitempty"`
}
```

### Client

```go
type Client struct { /* baseURL, httpClient */ }
```

## Exported Functions

```go
func LoadConfig(path string) (*Config, error)
func (c *Config) TLSConfig() (*tls.Config, error)
func NewClient(baseURL string, tlsConfig *tls.Config) *Client
```

## core REST API Endpoints

See [core API documentation](../core/docs/API.md) for details.
