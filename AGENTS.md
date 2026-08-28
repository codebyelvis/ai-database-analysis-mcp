# ai-database-analysis-mcp

<!-- AI_APP_MODEL_WORKBENCH_FAST_RESUME_BEGIN version=1 -->
触发条件：用户请求恢复 ai-app 模型开发工作台，或明确进入只读 MCP Track。
工作台：`/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台`
启动入口：`/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台/01-会话恢复.md`
安全边界：入口只用于 route/profile 与两阶段只读判断；不授权数据库写入、SQL、MCP 注册、代码、Git、发布或部署。
<!-- AI_APP_MODEL_WORKBENCH_FAST_RESUME_END version=1 -->

<!-- KINGBASE_READONLY_MCP_CAPABILITY_BEGIN version=1 -->
数据源分析或数据源适配层方案开发需要产业目录事实时，先确认当前 Codex runtime 中 `industry-stock-selection-local` 为 `ready`，再只通过其公开 `entity_resolve`、`business_query` 工具读取；先解析实体，再把返回的 canonical ID 交给业务查询。`ai-database-analysis-local` 仅用于协议/fixture 诊断，不代替业务数据桥；私有 `kingbase_*` 工具、通用 SQL、DML/DDL、模型自行生成内部 ID、retry/fallback 均禁止。

能力、数据范围、失败语义和恢复入口：`/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台/memory/topics/local-database-analysis-mcp.md`。本段只声明已实现的只读能力及正确调用边界；任何具体会话仍须遵守工作台 Stage 2 授权，未落库的数据不得表述为可用。
<!-- KINGBASE_READONLY_MCP_CAPABILITY_END version=1 -->
