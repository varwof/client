# varwof-cli

> 命令行管理工具 —— 通过 mTLS 直连 core API，支持证书签发、吊销、续期、查询

[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/varwof/client)](https://pkg.go.dev/github.com/varwof/client)

[English](README.md)

## 什么是 varwof-cli？

Varwof PKI 核心的命令行管理客户端。通过 mTLS 直连 core API。

## 快速开始

```bash
go build -o varwof-cli .

cat > config.json <<EOF
{
  "server": "https://127.0.0.1:4433",
  "ca_cert": "/etc/varwof/core/root/ca.pem",
  "client_cert": "/etc/varwof/core/keys/superadmin.pem",
  "client_key": "/etc/varwof/core/keys/superadmin-key.pem"
}
EOF

varwof-cli --config config.json issue --cn server.example.com --profile tls-server
```

## 安装

```bash
go build -o varwof-cli .
```

## 命令

| 命令 | 说明 |
|------|------|
| `issue` | 签发新证书 |
| `revoke` | 吊销证书 |
| `renew` | 续期证书 |
| `list` | 列出证书/CA |
| `cas` | 查看 CA 列表 |
| `find-by-key` | 按公钥查询 |
| `re-sign` | 原公钥重签 |
| `revoke-by-principal` | 按人吊销 |
| `revoke-subca` | 按子 CA 吊销 |
| `batch` | 批量签发 |

client 是 varwof 生态的**管理客户端**。本项目是 [Open Invention Network](https://openinventionnetwork.com/) 成员。

## 链接

| | |
|---|---|
| 主页 | https://varwof.com |
| 社区 | https://varwof.org |
| IETF 草案 | [draft-wei-aic-identity-cert](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/) |
| 许可证 | Apache-2.0 |
| 成员 | [Open Invention Network](https://openinventionnetwork.com/) |
