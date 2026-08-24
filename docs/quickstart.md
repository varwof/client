# varwof-cli 快速开始

> 纯 Go CLI 管理工具 | mTLS 直连 core | 11 个命令 + REPL

## 安装

```bash
go build -o varwof-cli .
```

## 配置文件

创建 `admin.json`：

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin.key"
}
```

加密私钥支持（可选）：

```json
{
  "server": "https://pki-core:4433",
  "ca_cert": "/etc/pki/ca.pem",
  "client_cert": "/etc/pki/admin.pem",
  "client_key": "/etc/pki/admin-encrypted.key",
  "key_password": "my-secret"
}
```

## 基本使用

```bash
# 签发证书
varwof-cli admin.json issue --cn "server.example.com" --profile tls-server --out ./certs

# 列出证书
varwof-cli admin.json list --ca issuing

# 吊销证书
varwof-cli admin.json revoke --ca issuing --serial ABCD1234

# REPL 交互模式
varwof-cli admin.json repl
```

## 密码优先级

1. 配置文件 `key_password` 字段
2. `PKI_KEY_PASSWORD` 环境变量
3. 终端交互提示

## 下一步

- [配置参考](config.md) — 配置字段详解
- [使用指南](usage.md) — 全部命令详解
- [示例](examples.md) — 实际场景
