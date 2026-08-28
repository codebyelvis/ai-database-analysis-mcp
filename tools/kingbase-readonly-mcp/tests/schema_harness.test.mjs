import assert from "node:assert/strict";
import test from "node:test";

import {
  compileContracts,
  loadFixtures,
  runNegativeMatrix,
  schemaDirectory,
} from "../schema_harness.mjs";


test("Ajv 2020 strict compiles all five contracts", () => {
  const validators = compileContracts(schemaDirectory());
  assert.deepEqual(
    Object.keys(validators).sort(),
    [
      "catalogRequest",
      "catalogResponse",
      "fixtures",
      "preflightRequest",
      "preflightResponse",
    ],
  );
});

test("embedded AUTH_UNAVAILABLE empty-object response is accepted", () => {
  const validators = compileContracts(schemaDirectory());
  const example = validators.schemas.preflightResponse.examples[0];
  assert.equal(validators.preflightResponse(example), true);
});

test("negative matrix is exactly 19 schema and 18 semantic-ready cases", () => {
  const validators = compileContracts(schemaDirectory());
  const fixtures = loadFixtures(schemaDirectory());
  assert.equal(validators.fixtures(fixtures), true);
  const summary = runNegativeMatrix(validators, fixtures);
  assert.deepEqual(summary, {
    total: 37,
    uniqueCaseIds: true,
    schemaRejected: 19,
    semanticReady: 18,
    mustNotStartPsql: true,
  });
});

test("public response schemas reject private physical column properties", () => {
  const validators = compileContracts(schemaDirectory());
  const fixtures = loadFixtures(schemaDirectory());
  const preflight = {
    success: true,
    operation: "kingbase_readonly_preflight",
    profile: "ai_app_industry_test_ro",
    schema: "ai_dw",
    readBoundary: {
      transactionReadOnly: true,
      privilegeMode: "CLIENT_ENFORCED_READ_ONLY",
      databasePrivilegeRisk: "WRITE_CAPABLE_ACCOUNT",
    },
    objects: [
      { table: "T_EDW_VAR_PD_INFO_Q", rowCount: 1, uniqueKeyCount: 1, columns: ["PD_ID"] },
      { table: "T_EDW_VAR_PD_IDTY_RELA_Q", rowCount: 1, uniqueKeyCount: 1, columns: ["PD_ID", "TERT_IDTY_ID"] },
      { table: "T_EDW_VAR_HCZQ_IDTY_CLAS_Q", rowCount: 1, uniqueKeyCount: 1, columns: ["TERT_IDTY_ID"] },
    ],
    dataAsOf: "2026-08-11",
    queryId: "0123456789abcdef",
  };
  assert.equal(validators.preflightResponse(preflight), true);

  const operations = [
    "RESOLVE_CATALOG",
    "SEARCH_PRODUCTS",
    "PRODUCT_INDUSTRIES",
    "INDUSTRY_CHILDREN",
    "INDUSTRY_PARENT_PATH",
  ];
  const validCatalogExamples = Object.fromEntries(operations.map((operation) => {
    const fixture = fixtures.find((candidate) =>
      candidate.target === "catalogResponse" &&
      candidate.payload?.success === true &&
      candidate.payload?.operation === operation &&
      candidate.payload?.data?.rows?.length > 0 &&
      validators.catalogResponse(candidate.payload));
    assert.ok(fixture, "missing valid non-empty response fixture for " + operation);
    return [operation, fixture.payload];
  }));

  for (const privateColumn of ["CRT_TIME", "UPDT_TIME", "MEMO"]) {
    const injectedPreflight = structuredClone(preflight);
    injectedPreflight.objects[0][privateColumn] = "synthetic-only";
    assert.equal(validators.preflightResponse(injectedPreflight), false);

    for (const operation of operations) {
      const injectedCatalog = structuredClone(validCatalogExamples[operation]);
      injectedCatalog.data.rows[0][privateColumn] = "synthetic-only";
      assert.equal(
        validators.catalogResponse(injectedCatalog),
        false,
        operation + " accepted " + privateColumn,
      );
    }
  }
});
