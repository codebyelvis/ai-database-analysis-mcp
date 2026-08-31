# MCP Contract-Boundary Repair Implementation Plan

> **For Codex:** Execute this Direct Change in order with strict TDD. It restores the already published MCP contracts; it does not add tools, Schema fields, database operations, dependencies, or registrations.

**Goal:** Make both stdio servers reject arbitrarily deep JSON deterministically without terminating, and make `industry-stock-selection-local` enforce its four advertised JSON Schemas before and after bridge dispatch.

**Architecture:** Replace recursive JSON inspection with one iterative depth/finite-value walk in each server. Reuse the existing fail-closed Python `SchemaClient` transport by parameterizing its worker path, contract allowlist, and startup probe. Give the public bridge its own Ajv harness/worker over the existing pinned Node 20/Ajv 8.20.0 installation. Validate request -> bridge -> response, with zero bridge/private calls for invalid requests and no invalid response publication.

**Tech Stack:** Python 3.14 stdlib, POSIX `sh`, JSON-RPC stdio, Node 20, existing Ajv 8.20.0, `unittest`, `node:test`.

**Execution root:** `/Users/elvis/file/develop/workspace/ai-database-analysis-mcp`

**Change classification:** Direct Change. The canonical OpenSpec already requires bounded strict JSON, declared input Schemas, stable errors, and a private-only database boundary. This repair changes no public Schema, tool name, tool description, database operation, or compatibility promise.

**Safety boundaries:**

- Do not access Keychain, Kingbase/psql, the network, or any real business operation.
- Do not register or expose `kingbase-readonly-private`; do not change Codex registration during implementation.
- Do not add dependencies or generic SQL; do not change the four public Schema files.
- Use `/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14`, never `/usr/bin/python3`.
- Preserve unrelated work. The baseline is clean `master` at `701ad0ed5324f6b7e213966c394a1214a1f832f8`.
- The user explicitly authorized implementation, local MCP update, Git commit, and push on the current workspace/branch.

## Task 1: Freeze RED tests for deep JSON

**Files:**

- Modify: `tools/kingbase-readonly-mcp/tests/test_mcp_server.py`
- Modify: `tools/industry-stock-selection-bridge/tests/test_server.py`

**Step 1: Add private-server RED**

Construct the 1,200-level request as raw bytes (do not use recursive `json.dumps`): a notification-shaped `tools/call` followed by a valid ping. Assert exact output is a null-id `-32700 parse_error` followed by the ping result, adapter call count remains zero, and serve returns `0`.

**Step 2: Add public-server RED**

Use the same raw-byte shape and expectations, additionally asserting zero bridge calls and deterministic close.

**Step 3: Observe RED**

Run the two focused files with the bound Python. The private test must show `-32603` instead of `-32700`; the public test must show premature termination/empty output. Do not edit production code before both failures are observed.

## Task 2: Freeze RED tests for public runtime Schema enforcement

**Files:**

- Modify: `tools/kingbase-readonly-mcp/tests/test_schema_client.py`
- Modify: `tools/industry-stock-selection-bridge/tests/test_server.py`
- Create: `tools/industry-stock-selection-bridge/tests/test_schema_client.py`
- Modify: `tools/industry-stock-selection-bridge/tests/public_contracts.test.mjs`
- Modify: `tools/industry-stock-selection-bridge/tests/test_launcher.py`

**Step 1: Parameterized transport RED**

Add tests requiring `SchemaClient` to support an explicit absolute worker, an instance contract allowlist, and an explicit `(contract, instance)` startup probe while preserving all private defaults. Reject relative/symlink/non-file workers and unknown contracts fail-closed.

The public server SHALL load the shared module without mutating `sys.path`: resolve the fixed sibling path `../kingbase-readonly-mcp/schema_client.py`, create a private module name with `importlib.util.spec_from_file_location()`, execute it once, and expose only `SchemaClient`/`SchemaUnavailable`. Add both a repo-root import test and the real-launcher initialize/list regression; neither may construct the private MCP.

**Step 2: Server boundary RED**

Inject a deterministic fake validator and assert:

- request Schema `false` -> `-32602 invalid_params`, zero bridge calls;
- validator unavailable/non-boolean -> `-32603 internal_error`, zero calls for request failures;
- bridge response Schema `false` or validator unavailable -> `-32603 internal_error`, invalid payload absent from stdout;
- notifications remain silent and invoke neither validator nor bridge.

The exact tool mapping is:

```text
entity_resolve -> entityResolveRequest -> entityResolveResponse
business_query -> businessQueryRequest -> businessQueryResponse
```

**Step 3: Real-worker RED**

Require a public Ajv worker round trip for all four contracts, each with a valid and invalid instance. Include the known missing `presentation.visibility` request regression. `public_contracts.test.mjs` must call all four real validators, not merely compile them.

**Step 4: Startup/launcher RED**

Freeze resource ownership as transfer-on-entry: every `bridge` and `schema_client` passed to `serve()` becomes owned by `serve()`. Add tests, before implementation, proving:

- schema validator is constructed before the bridge;
- schema success followed by bridge-construction failure closes schema exactly once and never calls bridge methods;
- every EOF, read failure, short/failed write, protocol error, and internal-error exit closes bridge first and schema second, each exactly once;
- schema startup failure constructs no bridge;
- every startup failure produces no protocol stdout and exactly `INDUSTRY_SELECTION_BRIDGE_FAILED\n`.

Freeze the launcher runtime values:

```text
Node=/opt/homebrew/Cellar/node@20/20.20.2/bin/node
Node SHA-256=d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4
Ajv version=8.20.0
Ajv metadata=package.json, package-lock.json, node_modules/.package-lock.json,
             node_modules/ajv/package.json
Ajv import=node_modules/ajv/dist/2020.js
```

Before GREEN, add executable launcher tests for a fake PATH Node, wrong fixed-Node SHA, each Ajv metadata mismatch, and Ajv import failure. Failure-path tests SHALL build only a private `TemporaryDirectory` mirror/copy of the launcher and the minimum sibling layout, with a marker-only dummy server; they SHALL never alter governed paths. Each branch must return `1`, emit empty stdout plus exactly one frozen stderr line, and leave the server/bridge/private marker absent. The real launcher initialize/list test is the positive branch.

## Task 3: Implement the minimal GREEN

**Files:**

- Modify: `tools/kingbase-readonly-mcp/kingbase_readonly_server.py`
- Modify: `tools/kingbase-readonly-mcp/schema_client.py`
- Modify: `tools/industry-stock-selection-bridge/industry_selection_bridge_server.py`
- Create: `tools/industry-stock-selection-bridge/schema_harness.mjs`
- Create: `tools/industry-stock-selection-bridge/schema_worker.mjs`
- Modify: `tools/industry-stock-selection-bridge/run_industry_selection_bridge.sh`
- Modify: `tools/industry-stock-selection-bridge/run_tests.sh`
- Modify: `tools/industry-stock-selection-bridge/README.md`

**Step 1: Iterative JSON safety**

Replace recursive finite/depth helpers with a single explicit stack. Container depth is checked before extending children; any depth above `64` raises `ValueError`. `_parse_request` translates `RecursionError`, `TypeError`, `ValueError`, and `JSONDecodeError` to frozen `parse_error`.

**Step 2: Parameterize `SchemaClient` without changing defaults**

Add optional `worker_path`, `contracts`, and `startup_probe`. `_ProcessTransport` must require an absolute regular non-symlink worker. The default remains the private sibling worker, the four private contracts, and `("preflightRequest", {})`. All failures remain `SchemaUnavailable("contract validation unavailable")` and terminate the worker.

The public production import uses only the frozen `importlib.util` sibling-file loader from Task 2; no `sys.path` insertion, PATH lookup, package installation, or second code copy is allowed.

**Step 3: Add the public Ajv runtime**

`schema_harness.mjs` loads the four existing public Schema files, adds all of them to one Ajv 2020 instance with `strict:true`, `strictRequired:false`, `strictTypes:false`, `allErrors:true`, then exposes the four frozen runtime contract names. `schema_worker.mjs` accepts only `{id,contract,instance}` and emits only `{id,valid}`. It imports the already installed pinned Ajv; no package operation is allowed.

**Step 4: Enforce both public boundaries**

Create the ready public `SchemaClient` before constructing the bridge. If bridge creation fails, close the ready validator immediately. Once both resources enter `serve()`, it owns them and closes bridge then validator exactly once on every exit path. In `_dispatch`, validate arguments before the bridge call and the returned value before `_tool_result`. Validation failure semantics are exactly those frozen in Task 2. Do not change `industry_selection_bridge.py` or any Schema.

**Step 5: Extend the public launcher/runner**

The launcher must verify the frozen physical Node executable/SHA and all four frozen Ajv metadata values plus the absolute Ajv import, before starting Python. It then passes only `INDUSTRY_SCHEMA_NODE_BINARY` into the sanitized child environment. Production must never resolve Node from `PATH`. The runner must include the new Python schema-client test and public worker tests while keeping exact success stdout `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`.

**Step 6: Focused GREEN**

Run all files changed in Tasks 1-2 plus independent `sh -n` checks. No test may access the database or instantiate the private MCP for an invalid public request.

## Task 4: Full offline verification and independent implementation review

Run, in order:

```sh
./tools/kingbase-readonly-mcp/run_tests.sh
./tools/industry-stock-selection-bridge/run_tests.sh
PYTHON_BIN=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14 ./tools/local-database-analysis/run_slice1.sh
PYTHON_BIN=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14 ./tools/local-database-analysis/run_slice2.sh
git diff --check
```

Expected markers: `KINGBASE_READONLY_OFFLINE_OK`, `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`, `SLICE1_OK`, `SLICE2_OK`.

Then request a fresh distinct read-only implementation review covering the diff, exact public/private protocol behavior, Schema execution, no-database evidence, and test completeness. Fix every actionable finding with RED -> GREEN before proceeding.

## Task 5: Correct closeout evidence and local workbench projection

**Repository files:**

- Modify: `docs/review/2026-08-28-kingbase-readonly-mcp-final-review.md`
- Modify: `docs/superpowers/plans/2026-08-28-kingbase-readonly-mcp-end-to-end-closure.md`

**Local workbench files (local synchronization only; not part of this repository push):**

- Modify the current closeout checkpoint/topic/index/workbench/session projections identified by the 2026-08-28 MCP closeout.
- Do not rewrite or complete historical blocked Handoff/Lease/status artifacts.

Record the discovered defect, the exact repair, fresh offline markers, review result, and the fact that no database rerun was required. Run workbench `openspec validate --all --strict --no-interactive` and its link/profile validation commands.

## Task 6: Final verification, Git push, and local MCP activation

After the final edit, rerun the full Task 4 matrix plus the relevant workbench validators. Verify no `__pycache__`, `.pyc`, `.bridge-source-only-pycache`, `.task7-source-only-pycache`, or `/tmp/task7-*` residue remains.

Start a fresh Codex app-server process against the existing account-A configuration and prove:

- `industry-stock-selection-local` reaches `ready`;
- its exact public tools are `entity_resolve,business_query`;
- `ai-database-analysis-local` remains the separate diagnostic MCP;
- no private tool is visible.

Commit only the scoped repository changes with a conventional commit, push `master` to `origin`, and verify `git ls-remote origin refs/heads/master` equals the local commit. The local Codex configuration already points directly at this repository, so no copy or re-registration is needed; a fresh Codex-a session/process must load the pushed local postimage.

## Execution outcome

Implemented on 2026-08-29 with strict RED -> observed RED -> minimal GREEN.

- Both private and public servers now classify a raw 1,200-level JSON request as
  `-32700 parse_error`, continue to the following ping, and perform zero business
  dispatch for the malformed input.
- The public server executes all four advertised request/response Schemas through
  the pinned Ajv worker. Invalid requests stop before bridge/private dispatch;
  invalid or unavailable response validation returns only the frozen internal
  error and never publishes the invalid payload.
- The shared `SchemaClient` accepts the public worker/contract/startup-probe seam
  while preserving its private defaults and fail-closed behavior. Worker startup,
  selector setup, signal exit, and bridge/schema ownership all close deterministically.
- Launcher and runner checks cover the physical Node identity, five Ajv metadata
  values, the absolute Ajv import, and negative fixtures that fail for the intended
  gate rather than an unrelated missing import.
- Offline verification produced `KINGBASE_READONLY_OFFLINE_OK`,
  `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`, `SLICE1_OK`, and `SLICE2_OK`.
- A fresh independent implementation rereview returned
  `IMPLEMENTATION_REREVIEW=PASS` with no actionable finding.
- The final independent Sol/ultra whole-change review returned
  `FINAL_WHOLE_CHANGE_REVIEW=PASS`; its one P2 test-coverage finding was closed
  by binding both tools to their exact request/response contract-name sequence
  and proving exception/non-boolean request validation performs zero bridge calls.
- A fresh Codex-A app-server probe loaded `industry-stock-selection-local` version
  `1.0.0` with exactly `entity_resolve` and `business_query`, retained the separate
  diagnostic `ai-database-analysis-local`, and exposed no private Kingbase MCP.

No Keychain, database, network, package-manager, registration, generic SQL,
DML/DDL, retry, fallback, or real-business operation was used for this repair.
The accepted 2026-08-28 sanitized smoke evidence remains authoritative; no
database rerun was required.
