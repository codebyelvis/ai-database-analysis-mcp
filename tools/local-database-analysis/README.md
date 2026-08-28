# Slice 1：本地数据库分析安全 fixture

本目录只包含无数据库依赖的 Python 3.11+ 标准库 fixture 与确定性测试（计划目标为 Python 3.12），验证：

- UTF-8 canonical JSON 与 compact `evidence.scope`；
- SOURCE_REGISTER 的 DBAR1 记录扫描；
- 注入假进程表上的 V1 同二进制身份匹配；
- `RESERVED`、`SPAWN_VERIFIED` 与 `REVOKE_PENDING_CLEANUP` 的最小状态转换；
- 完整响应不超过 32768 个 UTF-8 字节。
- revision 12 完整无库安全 fixture：capability/userPresence/nonce/replay、十项组件、七态单 run、双 permit/lease/cleanup、profile/preflight/权限反向校验、对象身份/ONLY/SQL/DLP、14 份 schema、分页预算与随机化发现。
- 无库 stdio MCP 适配层，可由本机 Codex CLI 调用上述 fixture 工具。

运行：

```sh
./tools/local-database-analysis/run_slice1.sh
```

本地 Codex 适配层启动入口为 `./tools/local-database-analysis/run_mcp_server.sh`。它只处理 stdin/stdout 上的 JSON-RPC，不读取文件、网络、真实进程表、钥匙串、环境凭据或数据库；未知工具和合同拒绝均以安全错误返回。

本切片不读取真实进程表、钥匙串或环境凭据，不建立网络连接，不执行数据库命令，也不启动外部数据库工具。`FakeProc` 和 `/bin/toolbox` 仅是测试数据，不代表真实运行时依赖。

`security_fixtures.py` 只实现可注入、可重复的安全边界模型；它不声称实现 root-owned/code-signed macOS 组件、Keychain、Toolbox 或真实 Kingbase 运行时。
