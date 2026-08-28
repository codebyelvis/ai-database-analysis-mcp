# ai-database-analysis-mcp

本仓库提供本地数据库分析 MCP。产业选股链路采用两层只读架构：

```text
Codex
  -> industry-stock-selection-local
       -> entity_resolve / business_query
       -> private stdio child (never registered)
       -> fixed Kingbase catalog operations
```

## 产业选股 MCP

Codex 只注册公开服务 `industry-stock-selection-local`，公开工具精确为：

- `entity_resolve`
- `business_query`

公开桥位于 [`tools/industry-stock-selection-bridge`](tools/industry-stock-selection-bridge/README.md)，
私有数据库边界位于 [`tools/kingbase-readonly-mcp`](tools/kingbase-readonly-mcp/README.md)。私有服务
`kingbase-readonly-private` 不得注册或直接暴露给模型。

离线验证：

```sh
./tools/kingbase-readonly-mcp/run_tests.sh
./tools/industry-stock-selection-bridge/run_tests.sh
```

成功标记分别为 `KINGBASE_READONLY_OFFLINE_OK` 和
`INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`。运行时使用仓库内 `package-lock.json` 对应的 Node 20 / Ajv
8.20.0；安装依赖时在私有目录运行 `npm ci --ignore-scripts`，不要提交 `node_modules`。

## 安全边界

- 没有通用 SQL、DML/DDL、分页 fallback、重试或第二数据库链。
- 密码只从本机 Keychain 读取，不写入参数、配置、日志或仓库。
- 数据库账号仍可能具备写权限；只读性由固定 SQL、只读事务、metadata guard 和公开 relation 闭集共同强制。
- 真实能力只覆盖产业目录 `CHILDREN` 和产品/产业 `PARENT_PATH`；公司、排名、财务、供应链等请求明确不支持。

模型开发工作台快速恢复入口：
[`01-会话恢复.md`](/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台/01-会话恢复.md)。
