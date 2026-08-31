# varwof-cli 使用指南

## 入口格式

```bash
varwof-cli <config.json> <command> [flags]
varwof-cli <config.json> repl          # REPL 交互模式
varwof-cli <config.json>              # 默认 REPL
```

## 命令一览

| 命令 | 模式 | 说明 |
|------|------|------|
| `issue` | CLI + REPL | 签发证书 |
| `batch` | CLI only | 批量签发 |
| `revoke` | CLI + REPL | 吊销单个证书 |
| `revoke-all` | CLI only | 吊销当前用户所有证书 |
| `revoke-by-principal` | CLI + REPL | 按 Principal UID 批量吊销 |
| `revoke-subca` | CLI + REPL | 吊销子 CA 下所有证书 |
| `renew` | CLI + REPL | 续签证书 |
| `list` | CLI + REPL | 列出证书 |
| `cas` | CLI + REPL | 列出/查看 CA |
| `find-by-key` | CLI + REPL | 按公钥查询证书 |
| `re-sign` | CLI + REPL | 原公钥重签 |
| `selfcheck` | CLI only | 健康自检 + CRL 自动修复 |
| `aic issue` | CLI only | 从用户证书派生 AIC（agent-proxy） |
| `aic batch` | CLI only | 按配置文件批量签发用户证书 + AIC |
| `aic list` | CLI only | 解析批量配置并列出用户/agent |
| `aic jwt` | CLI only | 将 X.509 AIC 证书兑换为短效 AIC-JWT（RFC 8693） |
| `cert show` | CLI + REPL | 本地解析证书（含 AIC/PA 扩展） |

## issue — 签发证书

```bash
varwof-cli config.json issue \
  --cn "server.example.com" \
  --ca issuing \
  --san "server.example.com,10.0.0.1" \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out ./certs
```

| flag | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--cn` | **是** | — | Common Name |
| `--ca` | 否 | — | 指定 CA |
| `--san` | 否 | — | SAN（逗号分隔） |
| `--subject` | 否 | — | Subject 字段 |
| `--profile` | 否 | — | 证书 profile |
| `--key-type` | 否 | — | 密钥类型 |
| `--validity` | 否 | 365 | 有效天数 |
| `--ca-scope` | 否 | — | 管理证书（m-admin/m-superadmin）的管理范围：指定其可管理的子 CA 名，写入 SAN URI + OID 扩展。仅 superadmin 可任意指定；带 scope 的管理员只能在其自身 scope 内签发 |
| `--out` | 否 | — | 输出目录 |

```bash
# 签发一个仅能管理 "Client CA" 子 CA 的管理员证书（需 superadmin 身份）
varwof-cli config.json issue \
  --cn "client-ca-admin@example.com" \
  --ca "Org Management CA" \
  --profile m-admin \
  --ca-scope "Client CA" \
  --out ./certs
```

## revoke — 吊销证书

```bash
varwof-cli config.json revoke --ca issuing --serial ABCD1234 --reason keyCompromise
varwof-cli config.json revoke --ca issuing --serial ABCD1234 --crl   # 吊销后同时重新生成 CRL
```

| flag | 必填 | 说明 |
|------|------|------|
| `--ca` | **是** | CA 名称 |
| `--serial` | **是** | 证书序列号 |
| `--reason` | 否 | 吊销原因 |
| `--crl` | 否 | 吊销成功后调用 `POST /api/v1/crl/{ca}/generate` 重新生成该 CA 的 CRL |

吊销原因：`unspecified`、`keyCompromise`、`cACompromise`、`affiliationChanged`、`superseded`、`cessationOfOperation`

## revoke-by-principal — 按人吊销

```bash
varwof-cli config.json revoke-by-principal --principal-uid "realm:user123:abc123"
```

## renew — 续签

```bash
varwof-cli config.json renew --ca issuing --serial ABCD1234 --out ./renewed
```

## list — 列出证书

```bash
varwof-cli config.json list --ca issuing --status active --json
```

| flag | 说明 |
|------|------|
| `--ca` | 过滤 CA |
| `--status` | 过滤状态（active/revoked） |
| `--cn` | 过滤 CN |
| `--json` | JSON 输出 |

## cas — 查看 CA

```bash
# 列出所有 CA
varwof-cli config.json cas

# 查看单个 CA 详情
varwof-cli config.json cas --ca issuing --json

# 输出 PEM
varwof-cli config.json cas --ca issuing --pem
```

## find-by-key — 按公钥查询

```bash
# 通过 SPKI 哈希
varwof-cli config.json find-by-key --hash "abc123..."

# 通过证书文件
varwof-cli config.json find-by-key --cert server.pem

# 通过私钥文件
varwof-cli config.json find-by-key --key server.key
```

## re-sign — 重签

```bash
varwof-cli config.json re-sign \
  --ca issuing --serial ABCD1234 \
  --target-ca issuing \
  --profile tls-server \
  --validity 365
```

## selfcheck — 健康自检 + CRL 自动修复

```bash
varwof-cli config.json selfcheck --ca "Issuing CA"
```

完整闭环：healthz（公开）→ 若 CRL degraded 自动为所有 CA 重建 CRL → CA 层次 → 签发测试证书 → 链验证 → 吊销 → 生成/解析 CRL。全部通过输出 `=== selfcheck: ALL PASS ===`。

## aic issue — 从用户证书派生 AIC

```bash
varwof-cli config.json aic issue \
  --user-cert alice.pem \
  --user-key alice-key.pem \
  --agent alice-agent-01 \
  --caps 'ca:issue:* ca:revoke:*' \
  --ca "Issuing CA" \
  --ou gateway:ops \
  --out ./certs
```

按用户证书 SPKI 计算 principal_uid，用用户私钥（`--user-key`，v1.7.1 必填）签名 DelegationAuthTBS 后签发 agent-proxy 证书；agent-proxy profile 强制要求 `--ou gateway:<role>`。

## aic batch — 批量签发用户证书 + AIC

```bash
varwof-cli config.json aic batch --config batch.json
```

批量配置格式（与已合并的 pki-aic-tool 配置兼容）：

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

对每个 user 自动签发用户证书（若 `--out` 目录中已存在同名证书则跳过），按 SPKI 计算 principal_uid，再为每个 agent 签发 agent-proxy AIC。`caps` 为空格分隔的能力列表（字符串或数组形式均可）。

## aic list — 列出批量配置的用户/agent

```bash
varwof-cli config.json aic list --config batch.json
```

解析批量配置，打印每个用户将获得的 principal_uid 及对应 agent 列表，不改动服务端。

## aic jwt — 将 AIC 证书兑换为 AIC-JWT

```bash
varwof-cli config.json aic jwt --out alice-agent-01.jwt
```

通过 core 的 `/oauth/token`（RFC 8693 token exchange）将 X.509 AIC 证书兑换为短效 AIC-JWT。默认使用配置中的 `client_cert`，可用 `--cert` 覆盖：

| flag | 必填 | 默认值 | 说明 |
|------|------|--------|------|
| `--cert` | 否 | config `client_cert` | 要兑换的 AIC 证书 PEM 路径 |
| `--scope` | 否 | — | 可选 scope 覆盖 |
| `--out` | 否 | 标准输出 | 将 token 写入文件（0600） |
| `--json` | 否 | — | 输出完整 JSON 响应 |

兑换凭证（mTLS 客户端证书或 DPoP）由 config 的 `client_cert`/`client_key` 提供。输出的 Bearer token 可用于 gateway HTTP 监听器（配置了匹配的 `jwt_ca_file` 信任根），例如：

```bash
export TOKEN=$(varwof-cli config.json aic jwt)
curl -H "Authorization: Bearer $TOKEN" https://gateway:8443/api/query
```

## cert show — 本地解析证书

```bash
varwof-cli config.json cert show --cert alice-agent-01.pem
```

输出 Subject/Issuer/Serial/有效期/KeyUsage/SAN，并解码 varwof 自定义扩展：

- **AIC**（OID 1.3.6.1.4.1.66257.1.1）：agent_id、principal_uid、delegation mode、capabilities
- **PrincipalAuthorization**（OID 1.3.6.1.4.1.66257.1.2）：版本、grants、authorizationConstraints

标准字段（openssl 可直接解析的）不做重复解码；本命令只覆盖 openssl `x509 -text` 看不到的扩展。

## REPL 交互模式

```bash
varwof-cli config.json repl
# 输入密码（如需要）
# 进入 REPL

pki> issue --cn "test.example.com" --profile tls-server
pki> list --ca issuing
pki> cas
pki> help
pki> exit
```

REPL 一次密码，多次操作，自动续期连接。
