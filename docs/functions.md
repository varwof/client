# varwof-cli 功能特性

## 导出类型

```go
type Config struct {
    Server     string `json:"server"`
    CACert     string `json:"ca_cert"`
    ClientCert string `json:"client_cert"`
    ClientKey  string `json:"client_key"`
    KeyPassword string `json:"key_password,omitempty"`
    Token      string `json:"token,omitempty"` // Bearer token; required when Server uses http:// (plaintext)
}

type Client struct { /* baseURL, httpClient */ }
```

当 `Server` 以 `http://` 开头时（冒烟/明文 API 模式），varwof-cli 自动跳过 mTLS 校验，
改用 `Authorization: Bearer <token>` 认证；此时 `ca_cert`/`client_cert`/`client_key` 可省略。

## 导出函数

```go
func LoadConfig(path string) (*Config, error)
func (c *Config) TLSConfig() (*tls.Config, error)
func NewClient(baseURL string, tlsConfig *tls.Config) *Client
func NewClientWithToken(baseURL, token string) *Client
```

## 内部函数

### 加密私钥 (key.go)

```go
func isEncryptedPEM(data []byte) bool
func decryptPrivateKeyPEM(pemData []byte, password string) (crypto.Signer, error)
func decryptKeyPKCS8(der []byte, password string) (crypto.Signer, error)
func pemEncodePrivateKey(key crypto.Signer) []byte
```

支持算法：PBES2 + PBKDF2-SHA256 (600K iterations) + AES-256-CBC

### SPKI 哈希提取 (cmd_find.go)

```go
func spkiHashFromCertFile(path string) (string, error)
func spkiHashFromKeyFile(path string) (string, error)
```

支持私钥格式：PKCS#8、EC、PKCS#1

## 命令 → API 映射

| 命令 | 方法 | API 端点 | 请求体 |
|------|------|----------|--------|
| `issue` | POST | `/api/v1/certs` | `{ca, cn, san, profile, key_type, validity, ca_scope}` |
| `batch` | POST | `/api/v1/certs/batch` | `[{cn, ca, profile, validity}, ...]` |
| `revoke` | POST | `/api/v1/cert/{ca}/{serial}/revoke` | `{reason}`；`--crl` 时追加 POST `/api/v1/crl/{ca}/generate` |
| `revoke-all` | POST | `/api/v1/user/revoke-all` | — |
| `revoke-by-principal` | POST | `/api/v1/certs/revoke-by-principal` | `{principal_uid, reason}` |
| `revoke-subca` | POST | `/api/v1/sub-ca/{name}/revoke-all` | `{reason}` |
| `renew` | POST | `/api/v1/cert/{ca}/{serial}/renew` | — |
| `list` | GET | `/api/v1/certs?ca=&status=&cn=` | — |
| `cas` | GET | `/api/v1/cas` 或 `/api/v1/ca/{name}` | — |
| `find-by-key` | GET | `/api/v1/cert/by-key?hash=&ca=&status=` | — |
| `re-sign` | POST | `/api/v1/cert/{ca}/{serial}/re-sign` | `{target_ca, profile, validity}` |
| `selfcheck` | GET+POST | `/healthz` → `/api/v1/cas` → `/api/v1/certs` → `/api/v1/cert/{ca}/{serial}/revoke` → `/api/v1/crl/{ca}/generate` | 健康自检 + CRL 自动修复 |
| `aic issue` | POST | `/api/v1/certs` | `{ca, cn, subject, profile:agent-proxy, agent_id, principal_uid, capabilities, ...}` |
| `aic batch` | POST | `/api/v1/certs` × N + `/api/v1/certs` (user) | 逐个用户/agent 签发 |
| `cert show` | 本地 | 无（纯本地解码） | 读取 PEM 文件 |
| `policy sign` | 本地 | 无（纯本地签名） | 用管理员证书对 authz.json / routes.json 做 PKCS#7 分离签名 |

## 命令详情

### selfcheck — 健康自检 + 自动修复

`varwof-cli <cfg> selfcheck --ca "<CA name>"`

完整闭环验证：
1. `/healthz`（公开）：DB / TSA / CRL freshness / status
2. 若 `crl_status` degraded → 自动调 `/api/v1/crl/{ca}/generate` 为所有 CA 重建 CRL，随后复检 healthz
3. CA 层次可达（mTLS 或 token）
4. 签发 1 天期测试证书 → 链验证 → 吊销 → 生成 CRL → 下载并解析 DER

任一环节失败输出 `[FAIL]`，全部通过输出 `=== selfcheck: ALL PASS ===`，退出码非零表示失败。

### aic issue — 从用户证书派生 AIC

`varwof-cli <cfg> aic issue --user-cert <user.pem> --user-key <user.key> --agent <agent-id> --caps 'scheme:cap:* ...' [--ca <name>] [--ou gateway:<role>] [--out <dir>]`

1. 读取用户证书（`--user-cert`），计算 SPKI SHA-256 得到 `principal_uid`
2. 用用户私钥（`--user-key`，v1.7.1 必填）对 `DelegationAuthTBS` 签名（SHA-256 DER，ECDSA/RSA-PKCS1v15/Ed25519），作为用户授权证据写入 `user_auth_*` 请求字段
3. 组装 agent-proxy 请求（`agent_id`/`principal_uid`/`hash_algo:sha256`/`delegation_mode:0`/`PrincipalAuthorization.Grants`/`capabilities`）；同时携带 `user_cert_pem`（用户证书 PEM），供 core 在签发时验签 DA（C3）
4. `POST /api/v1/certs`，产物写到 `--out` 下 `<agent-id>.pem` / `<agent-id>.key`

注意：agent-proxy profile 强制要求 OU（`--ou gateway:<role>`），否则报错提示；缺 `--user-key` 或用户证书私钥算法不支持时直接报错。

### aic batch — 批量签发用户证书 + AIC

`varwof-cli <cfg> aic batch --config <batch.json>`

配置文件格式（兼容已合并的 pki-aic-tool `config.json`）：
- `ca`（字符串或数组）：签发 CA
- `out_dir`：产物目录
- `users[]`：`{name, ou?, caps?}` — 每个 user 自动签发用户证书（`--out` 下已存在则跳过），按 SPKI 算 `principal_uid`
- `agents[]`：`{user, agent, caps?}` — 为指定 user 签发 agent-proxy AIC

### aic list — 列出批量配置

`varwof-cli <cfg> aic list --config <batch.json>`

仅本地解析并打印每个 user 的 principal_uid 及 agent 映射，不发网络请求。

### cert show — 本地解码证书扩展

`varwof-cli <cfg> cert show --cert <file.pem>`

打印 Subject/Issuer/Serial/有效期/KeyUsage/SAN，并用 `types.ParseAIC` / `types.ParseUserPermissionExtension`
解码 varwof 自定义扩展（AIC 1.3.6.1.4.1.66257.1.1、PrincipalAuthorization 1.3.6.1.4.1.66257.1.2）。
标准字段依赖 openssl 即可，本命令只覆盖 openssl `x509 -text` 无法解析的扩展。

### policy sign — 本地签名策略文件

`varwof-cli policy sign --file authz.json --cert admin.pem --key admin.key [--out authz.json.sig]`

对策略文件（authz.json / routes.json）做 **PKCS#7 分离签名**（SHA-256，内容为文件原文）。本命令不依赖 server 连接，`<cfg>` 位置可占位。

- 签名者证书必须携带 `admin` 或 `gateway:admin` OU（否则拒绝）
- 支持 PKCS#8 / 传统 RSA/EC 私钥；加密私钥可用 `PKI_KEY_PASSWORD` 环境变量解密
- 产出 `<file>.sig`（默认），签名后自动自验签（失败则不写入）
- 验签端：core `policy_signing` 配置 + 三网关 `policy_signing` 配置 + `pki policy verify` 生态
- 与 `core pki policy sign` 产生的签名**互相验证**（同格式互操作）

### KeyHash / principal_uid 语义

`principal_uid` 规范语义 = 人证书 SPKI SHA-256（`sha256(MarshalPKIXPublicKey(cert.PublicKey))`，RawURLEncoding），
与 `types.MakePrincipalUidFromCert` 一致；`find-by-key --cert` 用同一哈希查询。

## 支持的 Key Types

`ecdsa-p256`、`ecdsa-p384`、`rsa-2048`、`rsa-4096`、`ed25519`

## 支持的 Profiles

`tls-server`、`tls-client`、`code-signing`、`smime`、`ocsp-signing`、`timestamping`、`sub-ca`、`agent-proxy`、`cmp`

## 支持的 Revoke Reasons

`unspecified`、`keyCompromise`、`cACompromise`、`affiliationChanged`、`superseded`、`cessationOfOperation`
