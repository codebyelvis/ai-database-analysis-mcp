# Kingbase Read-only MCP End-to-End Closure Implementation Plan

> **For Codex:** Execute this plan in order with strict TDD. Do not expose or register `kingbase-readonly-private`; the only Codex-visible MCP is `industry-stock-selection-local` with exactly `entity_resolve` and `business_query`.

**Goal:** Turn the already implemented private Kingbase read-only adapter into a Codex-usable, two-tool industry-selection MCP, verify it offline and with one bounded test-database smoke, register only the public bridge, and publish the standalone MCP repository to its configured GitHub origin.

**Architecture:** Keep the existing private adapter as the only database boundary. Add a deterministic public bridge in this repository that owns the private stdio child, maps the frozen Skill relations to fixed private operations, and projects private responses into the formal Skill contracts. The Skill repository remains the source of the four public JSON Schemas and answer/planning rules; runtime copies in this repository must be byte-identical. No generic SQL, company/ranking/financial fallback, private MCP registration, retry, or second database chain is allowed.

**Tech Stack:** Python 3.14 stdlib, POSIX `sh`, JSON-RPC over stdio, existing Node 20 + Ajv 8.20.0 schema harness, `unittest`, OpenSpec CLI, Codex CLI MCP registration.

**Execution roots:**

- MCP repository: `/Users/elvis/file/develop/workspace/ai-database-analysis-mcp`
- Skill repository: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package`
- Governance/OpenSpec root: `/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台`

**Safety contract:**

- The private server remains unregistered and model-invisible.
- Database access occurs only after all offline tests pass and at most once for the final smoke batch.
- The smoke must use the existing Keychain profile and fixed operations; it must not send DML/DDL or generic SQL.
- Never print credentials, endpoints, user names, connection strings, SQL payloads, raw database rows outside the existing sanitized evidence shape, or child tracebacks.
- Preserve unrelated dirty changes in the Skill repository.
- The MCP repository has no commits yet, so a Git worktree cannot be created. Execute in the current user-authorized workspace with a strict path allowlist.
- Do not use `/usr/bin/python3`; use `/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14` for Python verification.

## Execution outcome

Completed on 2026-08-28:

- private runner: `KINGBASE_READONLY_OFFLINE_OK`;
- public bridge runner: `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`;
- Skill evaluation: 64/64 tests;
- final bounded database smoke: `KINGBASE_READONLY_SMOKE_OK`;
- Codex registration: only `industry-stock-selection-local` was added;
- combined implementation review: PASS.

The final smoke used one preflight and five fixed catalog operations. Its temporary
JSON output was deleted after the sanitized evidence update. No private MCP
registration, generic SQL, retry, fallback, DML, or DDL was introduced.

### 2026-08-29 repair outcome

An adversarial post-closeout review identified a deep-JSON classification defect
and missing runtime enforcement of the four public Schemas. The Direct Change plan
`2026-08-29-fix-mcp-contract-boundaries.md` repaired both with strict TDD while
preserving this plan's two-layer architecture, two-tool public surface, fixed
database operation set, and prior sanitized smoke evidence.

The repaired postimage passed both offline runners, both Slice regressions, a fresh
independent implementation rereview, a final independent Sol/ultra whole-change
review, and a fresh Codex-A app-server status probe.
The public MCP loads as version `1.0.0` with exactly `entity_resolve` and
`business_query`; the private MCP remains unregistered. No database rerun was
required for this protocol/schema-only repair.

The task sections below are the historical 2026-08-28 execution record; later
repository state and repair evidence are governed by the outcomes above and the
2026-08-29 Direct Change plan.

---

## Task 1: Freeze the baseline and repair the existing Skill fixture regression

**Files:**

- Modify only if the canonical fixture can be reconstructed deterministically:
  - `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/fixtures/industry-stock-selection-base.mock.json`
  - `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/test_codex_mcp_server.py`
  - `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/test_llm_bridge.py`
  - `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/test_llm_evaluation.py`
  - `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/test_mock_tools.py`

**Step 1: Record the observed baseline**

Run:

```bash
cd /Users/elvis/file/develop/workspace/ai-database-analysis-mcp
./tools/kingbase-readonly-mcp/run_tests.sh
```

Expected: exit `0`, stdout exactly `KINGBASE_READONLY_OFFLINE_OK`.

Run:

```bash
cd /Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package
/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -B -m unittest discover -s domains/stock-selection/docs/models/产业选股/evaluation -p 'test_*.py' -v
```

Observed baseline on 2026-08-28: four `setUpClass` errors caused only by the missing old path `domains/stock-selection/docs/models/产业选股Skill联调Mock数据.json`; 18 other tests pass.

**Step 2: Add a failing fixture-path regression test**

Change the four affected test modules to reference a repository-owned fixture below `evaluation/fixtures/` and add an assertion that the file exists and has a non-empty `cases` array.

Run the four affected modules before creating the fixture. Expected: RED because `industry-stock-selection-base.mock.json` is absent.

**Step 3: Create the minimal canonical base fixture**

Reconstruct only the cases required by the existing tests from their frozen expected requests/responses. Do not invent real database facts; every record must remain `mockData=true` and clearly mock-scoped.

Run the full evaluation suite. Expected: all existing evaluation tests pass with no network or database access.

---

## Task 2: Harden the private transport without changing its public private-tool contract

**Files:**

- Modify: `tools/kingbase-readonly-mcp/tests/test_mcp_server.py`
- Modify: `tools/kingbase-readonly-mcp/tests/test_schema_client.py`
- Modify: `tools/kingbase-readonly-mcp/kingbase_readonly_server.py`
- Modify: `tools/kingbase-readonly-mcp/schema_client.py`
- Modify if required by tests: `tools/kingbase-readonly-mcp/psql_runner.py`
- Modify if required by tests: `tools/kingbase-readonly-mcp/run_kingbase_readonly_mcp.sh`
- Modify if required by tests: `tools/kingbase-readonly-mcp/run_tests.sh`

**Step 1: RED — v1 rejects pagination input**

Add tests proving `tools/list` accepts only `{}` and rejects a non-empty `cursor`, because the OpenSpec v1 contract has no cursor or next-page token.

Run the focused test and observe RED under the current `_valid_list_params` behavior.

**Step 2: GREEN — close the cursor branch**

Change `_valid_list_params` to require exactly `{}`. Re-run the focused test.

**Step 3: RED — Schema worker write failures are fail-closed**

Add transport tests for `stdin.write()` returning `None`, returning a short byte count, raising `BrokenPipeError`, and `flush()` raising. Each must raise only `SchemaUnavailable("contract validation unavailable")`, terminate the child, and expose no raw diagnostic.

Run focused tests and observe RED for any uncovered branch.

**Step 4: GREEN — exact write and flush checks**

Implement exact byte-count checking and safe exception translation in `schema_client.py`. Re-run focused tests.

**Step 5: RED/GREEN — deterministic psql executable and environment**

Add tests that the production runner resolves `psql` once to an absolute regular executable and passes an allowlisted child environment containing only the required fixed PostgreSQL variables plus the ephemeral password. Prove caller `PGHOST`, `PGSERVICE`, `PGPASSFILE`, `PGOPTIONS`, and PATH replacement cannot redirect the connection or executable.

Implement the smallest compatible seam in `psql_runner.py` and launcher wiring. Do not change SQL templates, operation count, Keychain handling, or response schemas.

**Step 6: Run the private offline suite**

```bash
cd /Users/elvis/file/develop/workspace/ai-database-analysis-mcp
./tools/kingbase-readonly-mcp/run_tests.sh
```

Expected: `KINGBASE_READONLY_OFFLINE_OK` and no `.task7-*`, `__pycache__`, or `.pyc` residue.

---

## Task 3: Add formal public bridge contracts

**Files:**

- Create: `tools/industry-stock-selection-bridge/contracts/entity-resolve.request.schema.json`
- Create: `tools/industry-stock-selection-bridge/contracts/entity-resolve.response.schema.json`
- Create: `tools/industry-stock-selection-bridge/contracts/business-query.request.schema.json`
- Create: `tools/industry-stock-selection-bridge/contracts/business-query.response.schema.json`
- Create: `tools/industry-stock-selection-bridge/tests/test_contracts.py`
- Modify: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/business-query.response.schema.json`

**Step 1: RED — express real catalog path fields**

Add contract tests requiring real `PATH_RESULT` data to support:

- `sourceEntityId` for product-to-industry paths;
- `nodeLevel` in `ROOT|L1|L2|L3` for catalog nodes;
- step-level `dataAsOf` and data-level `truncated`;
- `mockData=false` on real envelopes/data/nodes;
- no `security_sort`, `product_sort`, ranking evidence, connection fields, or private MCP operation names in the real directory branch.

Validate fixtures with Ajv 2020 strict. Observe RED against the current Skill response schema.

**Step 2: GREEN — minimally extend the formal response schema**

Update only the approved fields from OpenSpec design section 5. Keep existing mock branches compatible. Copy all four formal schemas byte-for-byte into the bridge `contracts/` directory.

**Step 3: Add mirror and strict-compile tests**

The bridge test must compare its four runtime copies byte-for-byte with the Skill repository source and compile all four under the existing Ajv 8.20.0 strict runtime. No new dependency installation.

---

## Task 4: Implement the private MCP child client with strict lifecycle handling

**Files:**

- Create: `tools/industry-stock-selection-bridge/private_mcp_client.py`
- Create: `tools/industry-stock-selection-bridge/tests/test_private_mcp_client.py`

**Step 1: RED — lifecycle and protocol tests**

Test an injected fake process for:

- fixed absolute launcher path;
- empty/allowlisted child environment;
- eager `initialize` handshake;
- monotonically increasing JSON-RPC ids;
- exact response-id matching;
- bounded line length, strict UTF-8/JSON, response timeout, EOF, and child exit;
- `tools/call` result text parsed as exactly one JSON object;
- no retry and no raw stderr/traceback propagation;
- `close()` terminates, waits, and kills only if necessary.

Run and observe module-import RED.

**Step 2: GREEN — minimal synchronous client**

Implement a single-threaded synchronous stdio client. The production launcher path is repository-relative and not caller-overridable. The private child remains unregistered.

Run focused tests.

---

## Task 5: Implement deterministic `IndustrySelectionBridge`

**Files:**

- Create: `tools/industry-stock-selection-bridge/industry_selection_bridge.py`
- Create: `tools/industry-stock-selection-bridge/tests/test_bridge.py`
- Create: `tools/industry-stock-selection-bridge/tests/fixtures/private_responses.json`

**Step 1: RED — `entity_resolve` mapping**

Cover:

- one `RESOLVE_CATALOG` call per `CATALOG_NODE` mention using `searchText` when present, otherwise `text`, `expectedEntityType=ANY`, `limit=10`;
- zero rows → `NOT_FOUND`;
- one row → `RESOLVED` with unchanged canonical id/name and `mockData=false`;
- multiple rows → `AMBIGUOUS` preserving private order;
- private error → `ERROR`, no retry;
- any `COMPANY` mention → stable `RESOLUTION_UNAVAILABLE` and zero private calls for that mention;
- duplicate mention ids, invalid references, more than 8 mentions, or more than 20 steps fail closed before private calls;
- a resolved plan is emitted only when every referenced mention is resolved.

Run and observe import RED.

**Step 2: GREEN — implement entity resolution**

Implement only the approved mapping; do not generate, rewrite, or normalize entity ids.

**Step 3: RED — `business_query` mapping**

Cover exactly:

- `CHILDREN` for `INDUSTRY_ROOT/L1/L2` → `INDUSTRY_CHILDREN` → `NODE_SET`;
- `PARENT_PATH` for `PRODUCT` → `PRODUCT_INDUSTRIES` → `PATH_RESULT` with `sourceEntityId`;
- `PARENT_PATH` for `INDUSTRY_ROOT/L1/L2/L3` → `INDUSTRY_PARENT_PATH` → `PATH_RESULT`;
- ordered execution and `STEP_RESULT` consumption only from earlier successful bridge results;
- maximum 20 source entities, deterministic deduplication, preserved private ordering;
- unsupported relations and company sources return stable step errors with zero private calls;
- empty/error dependency produces the formal skipped state;
- real outputs use `mockData=false`, preserve `dataAsOf`/counts/truncation, and do not contain private operation/query/connection fields.

**Step 4: GREEN — implement business mapping**

Implement the smallest closed relation table. Do not implement upstream/downstream/company/ranking/metrics/evidence fallbacks.

Run the bridge tests and Ajv-validate every projected response.

---

## Task 6: Implement the public two-tool MCP stdio server and launcher

**Files:**

- Create: `tools/industry-stock-selection-bridge/industry_selection_bridge_server.py`
- Create: `tools/industry-stock-selection-bridge/run_industry_selection_bridge.sh`
- Create: `tools/industry-stock-selection-bridge/run_tests.sh`
- Create: `tools/industry-stock-selection-bridge/README.md`
- Create: `tools/industry-stock-selection-bridge/tests/test_server.py`
- Create: `tools/industry-stock-selection-bridge/tests/test_launcher.py`

**Step 1: RED — exact MCP surface**

Add tests for:

- protocol version `2024-11-05`;
- server name `industry-stock-selection-local`, version `1.0.0`;
- exact tool order `entity_resolve`, `business_query`;
- fresh input/output schema copies and read-only/non-destructive annotations;
- initialize, ping, tools/list, tools/call and exact JSON-RPC error envelopes;
- notifications produce zero bridge/private calls and zero output;
- 1,048,576-byte UTF-8 line cap, strict JSON constants, finite numbers, depth 64, drain-and-continue;
- canonical one-line JSON output and exact write/flush failure handling;
- startup/private-child failure exits nonzero with one frozen safe stderr line and no protocol success output.

Observe RED before server creation.

**Step 2: GREEN — implement the server**

Reuse the proven private-server parsing structure where semantics match, but do not import its private tool definitions. Public `tools/list` accepts only `{}`. Catch all startup/transport exceptions at the safe boundary.

**Step 3: RED/GREEN — launcher closure**

The launcher must resolve its own directory, use the bound Python 3.14 runtime, reject preload/debug variables, start only the public bridge, supervise its process group, forward HUP/INT/TERM, reap descendants, and emit no raw diagnostics. Add fake runtime/child tests before implementation.

**Step 4: Add the bridge offline runner**

The runner executes bridge contracts, client, mapper, server, launcher syntax, and an end-to-end in-process fake-private fixture. It must never access Keychain or psql and prints exactly `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK` on success.

---

## Task 7: Synchronize Skill planning and answer rules

**Files:**

- Modify: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/industry-stock-selection/SKILL.md`
- Modify: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/industry-stock-selection/references/query-planning.md`
- Modify: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/industry-stock-selection/references/answer-rules.md`
- Create: `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/industry-stock-selection/references/kingbase-readonly-data-domain.md`
- Modify: relevant tests under `/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/domains/stock-selection/docs/models/产业选股/evaluation/`

**Step 1: RED — supported/unsupported planning**

Add tests proving only catalog `CHILDREN` and product/industry `PARENT_PATH` are executable in the real data domain. Company, upstream/downstream/components/applications, ranking, finance, customer, supplier, metrics, evidence, and profile requests must remain `unsupportedItems` and must not enter tool arguments.

**Step 2: GREEN — update rules and data-domain reference**

Document the three `ai_dw` tables, keys, joins, hierarchy, derived root id, `BUS_DATE`, real supported relations, truncation, residual write-capable-account risk, and forbidden inference. Keep final answers textual; never expose private operation names, ids, SQL, connection data, or raw tool JSON.

**Step 3: Run the complete Skill evaluation suite**

Expected: no missing fixture, no network/database access, all tests green.

---

## Task 8: Offline integration gate

**Files:**

- Modify: `tools/industry-stock-selection-bridge/run_tests.sh` only if a test is missing from the manifest.

**Step 1: Run private MCP offline suite**

```bash
cd /Users/elvis/file/develop/workspace/ai-database-analysis-mcp
./tools/kingbase-readonly-mcp/run_tests.sh
```

Expected: `KINGBASE_READONLY_OFFLINE_OK`.

**Step 2: Run public bridge offline suite**

```bash
./tools/industry-stock-selection-bridge/run_tests.sh
```

Expected: `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`.

**Step 3: Run Skill tests and OpenSpec strict**

Run the complete industry evaluation suite and:

```bash
cd /Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台
openspec validate add-real-kingbase-readonly-mcp-v1 --strict
```

**Step 4: Static safety checks**

Run both target shell syntax checks independently; compare all public/runtime schema mirrors; scan changed files for secrets, generic SQL, DML/DDL, private registration, mock fallback, `security_sort`, `product_sort`, traceback output, cache and temp residue.

No database step may begin unless all four offline gates pass after the final code change.

---

## Task 9: One bounded real smoke through the complete bridge chain

**Files:**

- Modify only the existing sanitized evidence document after success:
  - `/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台/sources/verified/产业模型/2026-08-21-测试环境Kingbase只读MCP-v1-smoke.md`

**Step 1: Verify prerequisites without exposing secrets**

Check VPN reachability and Keychain item presence/status only. Do not print password, endpoint, account, connection string, or SQL.

**Step 2: Run exactly one private smoke batch**

Use the existing `smoke_test_environment.py` fixed chain: one preflight plus five catalog operations, no retry/fallback/second query chain. Preserve only the closed sanitized evidence shape.

**Step 3: Run one public bridge smoke projection**

Reuse the already obtained private results in memory or fixture projection where possible. If a public bridge call would cause an additional database chain, do not run it; the production mapping is proven offline and the private B3 smoke remains the sole database chain.

**Step 4: Update sanitized evidence**

Record pass/fail, counts/watermark/read-boundary shape, operation labels, and unsupported coverage only. Do not record rows or connection details.

---

## Task 10: Register only the public MCP in Codex and verify visibility

**Files:**

- External state: Codex MCP configuration only.

**Step 1: Inspect current CLI syntax and state**

Run `codex mcp --help`, `codex mcp add --help`, and `codex mcp list`. Use the installed CLI as the command authority and the official OpenAI Codex MCP documentation as supporting guidance.

**Step 2: Add `industry-stock-selection-local`**

Register the absolute public launcher command. Do not register `kingbase-readonly-private`. Do not place credentials in command arguments or configuration.

**Step 3: Verify**

`codex mcp list` must show the public name and no private name. Start a fresh Codex process/session and verify `tools/list` exposes exactly `entity_resolve` and `business_query`. Execute a harmless protocol/list probe first; do not perform another database smoke.

---

## Task 11: Evidence reconciliation and independent reviews

**Files:**

- Create a fresh successor evidence contract under the workbench only after code and registration are stable.
- Do not mutate or reactivate blocked original/v4/v5 Handoffs or revoked Leases.

**Step 1: Bind final postimages and evidence**

Bind all changed repository and Skill files, offline markers, the single sanitized smoke evidence SHA, Codex registration list evidence, and zero-residue scans.

**Step 2: Fresh Sol/high combined implementation review**

The reviewer is read-only and must not rerun database smoke. Any implementation finding returns to the relevant TDD task.

**Step 3: Fresh Sol/max final review**

Use only the bound Python 3.14 executable for any Python probe. No `/usr/bin/python3`, no raw diagnostic, no database rerun. Complete only if this final review passes.

---

## Task 12: GitHub publication

**Files:**

- Git state in `/Users/elvis/file/develop/workspace/ai-database-analysis-mcp` only.

**Step 1: Verify repository scope**

Confirm the remote remains `https://github.com/codebyelvis/ai-database-analysis-mcp.git`, no secrets/caches/temp files are tracked, and the final diff contains only intended MCP repository files.

**Step 2: Create the initial commit**

Because the repository currently has no commits, stage only the reviewed repository tree and create one initial commit after final verification. Do not stage or commit the separate Skill/workbench repositories.

**Step 3: Push**

Push the reviewed branch to the configured GitHub origin. Do not force push. Verify the remote branch head and report the commit id.

**Step 4: Final handoff**

Report the registered MCP name, two visible tools, verification commands and results, single-smoke evidence location, GitHub branch/commit, remaining database ACL risk, and any separate uncommitted Skill/workbench documentation changes.
