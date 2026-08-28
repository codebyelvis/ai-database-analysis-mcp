# Private Kingbase read-only MCP

本目录是 `add-real-kingbase-readonly-mcp-v1` 的本地私有 stdio server，归属
Task 7–8 executor。它不通过 MCP 注册暴露给其他消费者。

## Tools

只提供并固定以下两个工具，顺序不可变：

- `kingbase_readonly_preflight`
- `kingbase_catalog_query`

请求 Schema 来自本目录 `schemas/` 的五份绑定 runtime mirror；server 使用
严格 UTF-8、JSON、字节上限和只读响应合同。

## Offline prerequisites

- 绑定的 Python 3.14 与 Node 20 可执行文件必须保持 SHA-256 不变。
- Ajv 必须由已安装 lock 与 package metadata 共同确认是 8.20.0。
- 不得设置执行隔离 denylist 中的变量。
- Python 命令使用 `-I -S -B` 与固定 source-only prefix；runner 会检查 prefix
  和临时 staging 的精确清理。

离线验证命令：

```sh
./tools/kingbase-readonly-mcp/run_tests.sh
```

成功时最后一行是 `KINGBASE_READONLY_OFFLINE_OK`。独立 shell 语法检查分别为：

```sh
sh -n tools/kingbase-readonly-mcp/run_kingbase_readonly_mcp.sh
sh -n tools/kingbase-readonly-mcp/run_tests.sh
```

真实 smoke 失败时只会在 stderr 输出冻结的阶段标记
失败时输出 `TASK7_SMOKE_BLOCKED|phase=<phase>`；若 Adapter 返回固定白名单错误，追加
`|code=<error-code>`。不会输出 traceback、SQL、连接参数或凭据。

## Boundary

本 server 仅接受固定 request Schema 和固定五个目录查询 operation；不接受通用
SQL、分页、DML、DDL、重试或 fallback。notification 不调用 Adapter，也不产生
响应。生产 server 必须由 launcher 传入已验证的绝对 Node 路径，并在 Schema
bootstrap 成功后才开始协议循环。

Stage B 的真实链和 evidence 更新属于已批准 execution Brief 的一次性边界；本
README 不提供连接参数、秘密材料或外部服务操作说明。Task 8、注册变更、shared
consumer、Git 和状态转换均不在本目录授权内。
