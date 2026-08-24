# varwof-cli 参考手册

## 架构

```
varwof-cli
├── config.go     — 配置加载 + mTLS 构建 + 加密私钥解密
├── client.go     — HTTP 客户端（JSON 请求/响应）
├── key.go        — PKCS#8 PBES2 解密（纯 Go）
├── repl.go       — REPL 交互 + CLI 命令分发
├── cmd_issue.go  — issue / batch
├── cmd_revoke.go — revoke / revoke-all / revoke-by-principal / revoke-subca
├── cmd_renew.go  — renew
├── cmd_list.go   — list / cas
└── cmd_find.go   — find-by-key / re-sign
```

## 密码解析流程

```
Config.KeyPassword 非空? ──→ 使用该密码
        │ 否
PKI_KEY_PASSWORD 环境变量? ──→ 使用该密码
        │ 否
终端交互提示 (term.ReadPassword) ──→ 使用输入密码
```

## 私钥解密流程

```
PEM Block Type == "ENCRYPTED PRIVATE KEY"?
  ├── 是 → decryptKeyPKCS8()
  │        ├── ASN.1 解析 EncryptedPrivateKeyInfo
  │        ├── 验证 OID: PBES2 + PBKDF2 + HMAC-SHA256 + AES-256-CBC
  │        ├── PBKDF2-SHA256 密钥派生 (600K iterations, 32B key)
  │        ├── AES-256-CBC 解密
  │        ├── PKCS#7 去填充
  │        └── PKCS#8 解析 → crypto.Signer
  └── 否 → 直接 PKCS#8 解析 → crypto.Signer
```

## SPKI 哈希提取

```
cert 文件 → x509.ParseCertificate → cert.PublicKey → spki.Hash → SHA-256 hex
key 文件  → ParsePKCS8PrivateKey / ParseECPrivateKey / ParsePKCS1PrivateKey → pubKey → spki.Hash
```

## 支持的密钥格式

| 输入 | 解析方式 |
|------|---------|
| PKCS#8 (`PRIVATE KEY`) | `x509.ParsePKCS8PrivateKey` |
| EC (`EC PRIVATE KEY`) | `x509.ParseECPrivateKey` |
| PKCS#1 (`RSA PRIVATE KEY`) | `x509.ParsePKCS1PrivateKey` |
| 加密 PKCS#8 (`ENCRYPTED PRIVATE KEY`) | PBES2 解密 → PKCS#8 |
