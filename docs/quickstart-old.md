# varwof-cli 快速上手

> 通过 mTLS API 管理 core，无需直接操作数据库  
> 不同身份用不同配置文件，权限由服务端 RBAC 控制

---

## 一、构建

```bash
cd varwof-cli
GOWORK=off go build -o /usr/local/bin/varwof-cli .
# 或使用 go.work（项目根目录）
cd .. && go build -o /usr/local/bin/varwof-cli ./varwof-cli
```

零外部依赖，纯 Go 标准库。

---

## 二、配置文件

每个身份用一个独立的 JSON 文件：

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/admin.pem",
  "client_key": "/etc/pki/keys/admin.key"
}
```

| 字段 | 说明 | 必填 |
|------|------|------|
| `server` | core HTTPS API 地址（mTLS 端口） | ✅ |
| `ca_cert` | 根 CA 证书 PEM 路径（验证服务端） | ✅ |
| `client_cert` | 本身份证书 PEM 路径 | ✅ |
| `client_key` | 本身份私钥 PEM 路径 | ✅ |
| `key_password` | 私钥密码（可选，如不填则交互式提示或读 `PKI_KEY_PASSWORD` 环境变量） | ❌ |

**多身份管理示例：**

```bash
varwof-cli admin.json      issue --cn web.example.com     # 管理员签发
varwof-cli operator.json   list --ca "Issuing CA"         # 运维查询
varwof-cli revoker.json    revoke --ca X --serial Y       # 吊销员吊销
varwof-cli auditor.json    list --status revoked          # 审计员查吊销记录
```

身份权限由 core 的 RBAC + `authz.json` 控制。

---

## 三、命令速查

### 签发

```bash
# 基本签发（密钥不加密）
varwof-cli admin.json issue --cn web.example.com \
  --san "DNS:web.example.com,IP:10.0.0.1" \
  --profile tls-server --key-type ecdsa-p256 --validity 365

# 签发 + 密码加密密钥（PKCS#8 PBES2，OpenSSL 兼容）
varwof-cli admin.json issue --cn alice \
  --key-password "AliceStrongP@ss" \
  --out ~/alice
# 输出: ~/alice/<SERIAL>.pem + ~/alice/<SERIAL>.key
# 密钥是 Encrypted Private Key，可用 OpenSSL 解密：
#   openssl pkey -in ~/alice/<SERIAL>.key -passin pass:AliceStrongP@ss

# 指定 CA、输出到目录
varwof-cli admin.json issue --ca "Issuing CA" \
  --cn api.example.com --profile tls-server \
  --out ./certs
# 输出: ./certs/<SERIAL>.pem + ./certs/<SERIAL>-key.pem
```

### 批量签发

```bash
cat > requests.json <<'EOF'
[
  {"cn":"svc1.example.com","san":"DNS:svc1.example.com","profile":"tls-server","key_type":"ecdsa-p256"},
  {"cn":"svc2.example.com","san":"DNS:svc2.example.com","profile":"tls-server","key_type":"ecdsa-p256"}
]
EOF
varwof-cli admin.json batch --requests requests.json
```

### 吊销

```bash
# 吊销单张证书
varwof-cli admin.json revoke --ca "Issuing CA" --serial <hex> --reason keyCompromise

# 按人吊销所有 AIC 证书（SQL 级，<10ms）
varwof-cli admin.json revoke-by-principal \
  --principal-uid "varwof:alice@example.com" \
  --reason superseded

# 按子 CA 吊销其下所有实体证书
varwof-cli admin.json revoke-subca \
  --sub-ca "Compromised Sub CA" \
  --reason cessationOfOperation
```

吊销原因: `unspecified` `keyCompromise` `cACompromise` `affiliationChanged` `superseded` `cessationOfOperation`

### 续期

```bash
varwof-cli admin.json renew --ca "Issuing CA" --serial <hex>
varwof-cli admin.json renew --ca "Issuing CA" --serial <hex> --out ./certs
```

### 查询

```bash
# 列出证书
varwof-cli operator.json list
varwof-cli operator.json list --ca "Issuing CA"
varwof-cli operator.json list --status revoked --cn web.example.com
varwof-cli auditor.json list --json                       # JSON 输出

# 列出 CA
varwof-cli operator.json cas
varwof-cli operator.json cas --ca "Issuing CA"            # 详情
varwof-cli operator.json cas --ca "Root CA" --pem         # 导出证书 PEM
```

### 按公钥查询（换 CA 不换密钥）

```bash
# 从证书文件提取 SPKI 哈希并查询
varwof-cli admin.json find-by-key --cert ./old-cert.pem

# 从密钥文件查询
varwof-cli admin.json find-by-key --key ./old-key.pem

# 直接传哈希
varwof-cli admin.json find-by-key --hash <sha256-hex>
```

### 重签（原公钥 + 新 CA）

CA 密钥轮换时，用原公钥签发新证书，业务端只需换证书、密钥不变：

```bash
varwof-cli admin.json re-sign \
  --ca "Old CA" --serial <hex> \
  --target-ca "New CA" --validity 365
```

---

## 四、密钥密码管理

varwof-cli 支持三种方式提供加密密钥的密码（优先级从高到低）：

### 1. 配置文件 `key_password` 字段

适合 CI/CD 或脚本：

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/alice.pem",
  "client_key": "/etc/pki/keys/alice.key",
  "key_password": "P@ssw0rd"
}
```

### 2. 环境变量 `PKI_KEY_PASSWORD`

适合从密钥管理服务注入：

```bash
export PKI_KEY_PASSWORD=$(vault read -field=key_password secret/pki/alice)
varwof-cli alice.json list
```

### 3. 交互式提示

密码不填时，自动检测密钥是否加密，加密则弹出密码输入（不回显）：

```bash
varwof-cli alice.json list
Enter password for /etc/pki/keys/alice.key: <输入密码，不回显>
```

### REPL 模式 — 一次密码多次操作

适合管理员日常操作：只输一次密码，后续命令共用：

```bash
varwof-cli admin.json repl

varwof-cli> Connected to https://pki-core:4433
varwof-cli> issue --cn web.example.com
Issued: web.example.com (serial: ABC123...)
varwof-cli> issue --cn api.example.com
Issued: api.example.com (serial: DEF456...)
varwof-cli> list --status V
...
varwof-cli> exit
bye
```

REPL 模式避免每个命令都要输密码，也适合与非加密密钥配合使用。

---

## 五、完整工作流示例

### 场景：员工入职签发

```bash
# 1. 管理员签发客户端证书
varwof-cli admin.json issue --cn alice \
  --san "email:alice@example.com" \
  --profile tls-client --out ./alice

# 2. 运维确认签发成功
varwof-cli operator.json list --cn alice

# 3. 签 AIC 证书（用于网关认证）
curl -sk --cert admin.pem --key admin.key \
  https://pki:4433/api/v1/aic/issue \
  -d '{"agent_id":"alice-agent","principal_uid":"varwof:alice@example.com",...}'
```

### 场景：员工离职吊销

```bash
# 一条命令吊销此人所有 AIC 证书
varwof-cli admin.json revoke-by-principal \
  --principal-uid "varwof:alice@example.com" \
  --reason cessationOfOperation

# 也可吊销其个人证书
varwof-cli admin.json revoke --ca "Issuing CA" --serial <alice-cert-serial>
```

### 场景：CA 密钥轮换

```bash
# 1. 通过重签保留所有实体的公钥
varwof-cli admin.json re-sign \
  --ca "Old Issuing CA" --serial <ser1> \
  --target-ca "New Issuing CA"

# 2. 确认后吊销旧 CA 下的原证书
varwof-cli admin.json revoke --ca "Old Issuing CA" --serial <ser1> --reason superseded

# 3. 最后吊销旧 CA
varwof-cli admin.json revoke-subca --sub-ca "Old Issuing CA" --reason superseded
```

### 场景：子 CA 被攻破

```bash
# 一步吊销子 CA 下所有证书（SQL 批量，秒级完成）
varwof-cli admin.json revoke-subca \
  --sub-ca "Old Issuing CA" \
  --reason keyCompromise

# 检查吊销结果
varwof-cli auditor.json list --ca "Old Issuing CA" --status revoked --json
```

---

## 六、配置文件模板

### admin.json（管理员 — 全部权限）

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/admin.pem",
  "client_key": "/etc/pki/keys/admin.key"
}
```

### operator.json（运维操作员 — 签发/吊销/查询）

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/operator.pem",
  "client_key": "/etc/pki/keys/operator.key"
}
```

### auditor.json（审计员 — 只读）

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/root-ca.pem",
  "client_cert": "/etc/pki/keys/auditor.pem",
  "client_key": "/etc/pki/keys/auditor.key"
}
```

---

## 七、常见问题

**Q: 提示 `forbidden`？**
A: 当前身份没有该操作的权限。换 admin 配置，或检查 `authz.json` 的角色权限定义。

**Q: 提示 `connection refused`？**
A: core 未运行或 API 端口不对。确认 `server` URL 中的地址和端口。

**Q: 提示 `x509: certificate signed by unknown authority`？**
A: `ca_cert` 路径错误或不是签发该客户端证书的根 CA。使用链中正确的根 CA。

**Q: `find-by-key` 查不到？**
A: 确认是 v21+ 版本的 core，旧版本没有 `spki_hash` 列。使用 `cas --ca <CA> --pem` 检查服务端版本。

**Q: `revoke-by-principal` 返回 0 条？**
A: 确认 `principal_uid` 格式正确。AIC 证书的格式为 `realm:identifier:keyHash`。从 `list --json` 中查看 `principal_uid` 字段值。

**Q: 如何查看我当前身份的权限？**
A: 直接调 API：`curl -sk --cert cert.pem --key key.pem https://pki:4433/api/v1/permissions/check`
