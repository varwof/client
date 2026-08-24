# varwof-cli 示例

## 示例 1：签发证书并保存文件

```bash
varwof-cli admin.json issue \
  --cn "web.example.com" \
  --ca issuing \
  --san "web.example.com,10.0.0.1" \
  --profile tls-server \
  --key-type ecdsa-p256 \
  --validity 365 \
  --out ./certs

# 输出：./certs/ABCD1234.pem + ./certs/ABCD1234-key.pem
```

## 示例 2：批量签发

创建 `requests.json`：

```json
[
  {"cn": "web1.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365},
  {"cn": "web2.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365},
  {"cn": "web3.example.com", "ca": "issuing", "profile": "tls-server", "validity": 365}
]
```

```bash
varwof-cli admin.json batch --requests requests.json --fast
```

## 示例 3：吊销 + 级联

```bash
# 吊销单个证书
varwof-cli admin.json revoke --ca issuing --serial ABCD1234 --reason keyCompromise

# 按人吊销所有 AIC 证书
varwof-cli admin.json revoke-by-principal --principal-uid "realm:agent:abc123"

# 吊销子 CA 下所有证书
varwof-cli admin.json revoke-subca --sub-ca "Issuing CA 2"
```

## 示例 4：按公钥查证书链

```bash
# 通过证书文件查
varwof-cli admin.json find-by-key --cert server.pem --json

# 通过私钥文件查
varwof-cli admin.json find-by-key --key server.key

# 通过 SPKI 哈希查
varwof-cli admin.json find-by-key --hash "30820122300d06092a864886f70d01010b05003082010f3082010a0282010100..."
```

## 示例 5：重签换 CA

```bash
varwof-cli admin.json re-sign \
  --ca old-issuing --serial ABCD1234 \
  --target-ca new-issuing \
  --profile tls-server \
  --validity 365
```

## 示例 6：REPL 日常操作

```bash
$ varwof-cli admin.json repl
Password: ********

pki> cas
Name              Subject                   NotBefore  NotAfter
issuing           CN=Issuing CA             2026-01-01 2036-01-01

pki> list --ca issuing --status active
Serial            CN                NotAfter     Profile
ABCD1234          web.example.com   2027-01-01   tls-server

pki> renew --ca issuing --serial ABCD1234 --out ./renewed
Certificate renewed: serial=EFGH5678

pki> exit
```

## 示例 7：加密私钥配置

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin-encrypted.key",
  "key_password": "my-secret"
}
```

或使用环境变量：

```bash
export PKI_KEY_PASSWORD="my-secret"
varwof-cli admin.json list
```

## 示例 8：不同权限身份

```bash
# 管理员 — 可签发/吊销
varwof-cli admin.json issue --cn "new-cert"

# 运维 — 只能续签/列出
varwof-cli ops.json renew --ca issuing --serial ABCD1234
varwof-cli ops.json list

# 审计 — 只能列出
varwof-cli auditor.json list --status revoked
```
