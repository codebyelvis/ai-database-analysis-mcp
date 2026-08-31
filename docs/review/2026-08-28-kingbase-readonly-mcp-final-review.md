# Kingbase Read-only MCP Final Review

Date: 2026-08-28

## Verdict

`IMPLEMENTATION_REVIEW=PASS`

The two-layer design is appropriate for the required trust boundary:

- Codex sees only `industry-stock-selection-local`.
- The public surface contains exactly `entity_resolve` and `business_query`.
- `kingbase-readonly-private` is an owned stdio child and is never registered.
- The bridge maps only the frozen catalog relations and contains no generic SQL,
  retry, fallback, ranking, company, finance, or supply-chain expansion.

No P0, P1, or P2 implementation finding remains.

## Verification

- Private offline runner: `KINGBASE_READONLY_OFFLINE_OK`.
- Public bridge offline runner: `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`.
- Industry-selection Skill evaluation: 64 tests passed.
- Public/Skill Schema mirrors: 4/4 byte-identical.
- OpenSpec strict validation: PASS.
- Public launcher and private launcher/runner shell syntax: PASS.
- Codex registration: public MCP enabled at the absolute public launcher; private
  MCP absent from the registration list.
- Final test-database smoke: PASS with one preflight and five fixed catalog
  operations, no retry, fallback, second query chain, DML, or DDL.
- Smoke output and Python cache/temp residue: absent after exact cleanup.

## Security assessment

- Credentials remain in the local Keychain boundary and are never persisted in
  this repository, command arguments, evidence, or logs.
- Child processes use bounded I/O, safe diagnostics, fixed executable identities,
  and constrained environments.
- Notifications are discarded before bridge/private dispatch and produce no
  response.
- Responses are canonical one-line JSON with bounded input depth/size and strict
  non-finite-number rejection.
- The database account may retain write privileges. The observed runtime boundary
  is therefore `CLIENT_ENFORCED_READ_ONLY`; fixed SQL, read-only transaction
  settings, metadata guards, and the closed public relation set remain mandatory.

## Review model

This is the user-authorized combined Sol/xhigh architecture and implementation
closeout. Earlier independent Task 7/8 evidence remains historical support; this
review additionally covers the public bridge, Skill contract synchronization,
Codex registration, final offline gates, and the final bounded smoke.

## 2026-08-29 contract-boundary repair addendum

A later adversarial review found two implementation gaps without changing the
approved architecture or database contract:

- sufficiently deep JSON could escape deterministic protocol classification;
- the public MCP advertised four JSON Schemas but did not execute them at both the
  request and response boundaries.

The repair replaces recursive JSON inspection with a bounded iterative walk in
both servers, translates decoder recursion into the frozen parse error, and adds a
public Ajv worker through the existing pinned Node/Ajv runtime. The public server
now validates request -> bridge -> response, keeps notifications side-effect free,
and closes schema/bridge/worker resources on startup, stream, and catchable-signal
exit paths. Launcher tests also bind the actual package-lock Ajv entry and isolate
each negative branch from unrelated import failures.

Fresh repair evidence:

- private offline runner: `KINGBASE_READONLY_OFFLINE_OK`;
- public bridge runner: `INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK`;
- Slice regressions: `SLICE1_OK` and `SLICE2_OK`;
- fresh independent implementation rereview: `IMPLEMENTATION_REREVIEW=PASS`;
- final independent Sol/ultra review: `FINAL_WHOLE_CHANGE_REVIEW=PASS` after its
  contract-mapping test-coverage finding was fixed and re-reviewed;
- fresh Codex-A app-server status: public version `1.0.0`, exact public tool set
  `entity_resolve,business_query`, separate diagnostic MCP retained, private MCP
  absent.

The repair used no database, Keychain, network, package manager, MCP registration,
generic SQL, DML/DDL, retry, fallback, or second business chain. The prior bounded
and sanitized B3 smoke remains valid; no database rerun was needed.
