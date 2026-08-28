# Industry Stock Selection Local MCP

`industry-stock-selection-local` is the only Codex-visible server in the real
Kingbase catalog chain. It exposes exactly two read-only tools:

- `entity_resolve`
- `business_query`

The public process privately owns `kingbase-readonly-private`; that child is
never registered with Codex and never exposes generic SQL. The bridge supports
only catalog `CHILDREN` and product/industry `PARENT_PATH`. Company, ranking,
finance, upstream/downstream and other uncovered relations fail closed without
starting a database call.

Run the offline suite:

```sh
./tools/industry-stock-selection-bridge/run_tests.sh
```

Expected stdout is exactly:

```text
INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK
```

The production stdio command is:

```sh
./tools/industry-stock-selection-bridge/run_industry_selection_bridge.sh
```

Do not register `tools/kingbase-readonly-mcp/run_kingbase_readonly_mcp.sh`.
