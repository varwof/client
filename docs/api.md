# varwof-cli API 参考

> 本文档描述 varwof-cli 的内部 API（导出类型/函数），以及它调用的 core REST API。

## 导出类型

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

## 导出函数

```go
func LoadConfig(path string) (*Config, error)
func (c *Config) TLSConfig() (*tls.Config, error)
func NewClient(baseURL string, tlsConfig *tls.Config) *Client
```

## core REST API 端点

详见 [core API 文档](../core/docs/API.md)。
