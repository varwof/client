# varwof-cli — 命令行管理工具

Varwof PKI 核心的命令行管理客户端。通过 mTLS 直连 core API，支持证书签发、吊销、续期、查询等操作。

```
签发请求 → varwof-cli ──mTLS──→ core API
```

## 功能

- `issue` — 签发新证书
- `revoke` — 吊销证书
- `renew` — 续期证书
- `list` — 列出证书/CA
- `cas` — 查看 CA 列表
- `find-by-key` — 按公钥查询证书
- `re-sign` — 原公钥重签证书
- `revoke-by-principal` — 按人吊销
- `revoke-subca` — 按子 CA 吊销
- `batch` — 批量签发

## Project Structure

```
varwof-cli/
├── main.go                # CLI 入口
├── client.go              # mTLS HTTP 客户端
├── config.go              # 配置加载
├── key.go                 # 密钥解析
├── repl.go                # REPL 交互模式
├── cmd_issue.go           # issue 命令
├── cmd_revoke.go          # revoke 命令
├── cmd_renew.go           # renew 命令
├── cmd_list.go            # list 命令
├── cmd_find.go            # find-by-key 命令
├── docs/                  # 用户文档
├── README.md
└── go.mod
```
