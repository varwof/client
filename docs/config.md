# varwof-cli 配置参考

## Config 结构体

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin.key",
  "key_password": "optional-password",
  "token": "optional-bearer-token"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `server` | string | **是** | core 服务 URL |
| `ca_cert` | string | mTLS 时**是** | CA 证书路径（用于验证服务端） |
| `client_cert` | string | mTLS 时**是** | 客户端证书路径（mTLS 身份） |
| `client_key` | string | mTLS 时**是** | 客户端私钥路径 |
| `key_password` | string | 否 | 私钥密码（明文或加密私钥均适用） |
| `token` | string | token 时**是** | Bearer token；`server` 为 `http://` 时自动使用，跳过 mTLS |

## 明文 + Token 模式（冒烟/开发环境）

当 `server` 以 `http://` 开头时，varwof-cli 跳过 mTLS 校验，改用 `Authorization: Bearer <token>`：

```json
{
  "server": "http://127.0.0.1:8445",
  "token": "f530f9ffd0c279f8d8fe139260c9b8ef...",
  "ca_cert": "",
  "client_cert": "",
  "client_key": ""
}
```

## 加密私钥

支持 PKCS#8 EncryptedPrivateKeyInfo 格式（PBES2 + PBKDF2-SHA256 + AES-256-CBC）。

兼容 `openssl pkey -aes-256-cbc -pass pass:xxx` 生成的加密私钥。

## 不同身份配置

不同权限用不同配置文件：

```bash
# 管理员操作
varwof-cli admin.json issue --cn "new-cert"

# 审计员操作
varwof-cli auditor.json list --status revoked

# 运维操作
varwof-cli ops.json renew --ca issuing --serial ABCD1234
```

## aic batch 配置文件（batch.json）

`aic batch` / `aic list` 使用的独立配置文件（与已合并的 pki-aic-tool `config.json` 兼容）：

```json
{
  "ca": "Issuing CA",
  "out_dir": "./certs",
  "users": [
    { "name": "zhangsan", "ou": "gateway:ops", "caps": ["mysql:SELECT:*", "mysql:INSERT:*"] }
  ],
  "agents": [
    { "user": "zhangsan", "agent": "agent-zs-001", "caps": ["mysql:SELECT:*", "mysql:INSERT:*"] }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `ca` | string \| [string] | 签发 CA（user 与 agent 共用） |
| `out_dir` | string | 产物目录（证书/私钥） |
| `users[].name` | string | 用户名，作为用户证书 CN |
| `users[].ou` | string | 可选 OU（agent-proxy 需要 `gateway:<role>`） |
| `users[].caps` | [string] \| string | 用户证书能力 |
| `agents[].user` | string | 关联的用户名 |
| `agents[].agent` | string | agent_id |
| `agents[].caps` | [string] \| string | AIC capabilities |

## 环境变量

| 变量 | 说明 |
|------|------|
| `PKI_KEY_PASSWORD` | 全局私钥密码（per-config `key_password` 优先） |
