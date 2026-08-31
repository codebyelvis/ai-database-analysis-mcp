import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import Ajv2020 from "../../kingbase-readonly-mcp/node_modules/ajv/dist/2020.js";

import { compileContracts } from "../schema_harness.mjs";


const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONTRACT_ROOT = path.join(HERE, "..", "contracts");
const NAMES = [
  "entity-resolve.request.schema.json",
  "entity-resolve.response.schema.json",
  "business-query.request.schema.json",
  "business-query.response.schema.json",
];


function validators() {
  // The legacy Skill schemas use parent-defined required/type annotations.
  // All behavioral strict checks remain enabled; only those two Ajv lint rules
  // are disabled until a future schema-only cleanup.
  const ajv = new Ajv2020({
    strict: true,
    strictRequired: false,
    strictTypes: false,
    allErrors: true,
  });
  for (const name of NAMES) {
    ajv.addSchema(JSON.parse(fs.readFileSync(path.join(CONTRACT_ROOT, name), "utf8")));
  }
  return Object.fromEntries(NAMES.map((name) => [name, ajv.getSchema(name)]));
}


const ENTITY = {
  entityId: "PRODUCT:P1",
  entityType: "CATALOG_NODE",
  canonicalName: "产品一",
};
const STEP = {
  stepId: "s1",
  relation: "PARENT_PATH",
  input: { sourceType: "ENTITY", entity: ENTITY },
  outputType: "PATH_RESULT",
  presentation: { visibility: "VISIBLE" },
};


test("all four public contracts compile and accept real projected envelopes", () => {
  const compiled = compileContracts(CONTRACT_ROOT);
  const resolvedPlan = { planId: "plan1", steps: [STEP] };
  const entityResponse = {
    success: true,
    operation: "entity_resolve",
    mockData: false,
    resolutionResults: [
      {
        mentionId: "m1",
        resolutionStatus: "RESOLVED",
        mockData: false,
        resolved: ENTITY,
      },
    ],
    resolvedPlan,
  };
  const businessResponse = {
    success: true,
    operation: "business_query",
    planId: "plan1",
    executionStatus: "OK",
    mockData: false,
    stepResults: [
      {
        planId: "plan1",
        stepId: "s1",
        relation: "PARENT_PATH",
        dependsOn: [],
        executionStatus: "OK",
        resultType: "PATH_RESULT",
        dataAsOf: "2026-08-11",
        presentation: { visibility: "VISIBLE" },
        mockData: false,
        data: {
          mockData: false,
          sourceEntityId: "PRODUCT:P1",
          totalCount: 1,
          returnedCount: 1,
          truncated: false,
          paths: [
            {
              nodes: [
                {
                  entityId: "INDUSTRY_ROOT:Um9vdA",
                  entityType: "CATALOG_NODE",
                  canonicalName: "根产业",
                  nodeLevel: "ROOT",
                  mockData: false,
                },
              ],
            },
          ],
        },
      },
    ],
  };
  const entityRequest = {
    operation: "entity_resolve",
    mentions: [
      { mentionId: "m1", text: "产品一", expectedEntityTypes: ["CATALOG_NODE"] },
    ],
    queryPlan: {
      planId: "plan1",
      steps: [
        {
          stepId: "s1",
          relation: "PARENT_PATH",
          input: { sourceType: "MENTION", mentionId: "m1" },
          outputType: "PATH_RESULT",
          presentation: { visibility: "VISIBLE" },
        },
      ],
    },
  };
  assert.equal(compiled.entityResolveRequest(entityRequest), true);
  assert.equal(compiled.entityResolveResponse(entityResponse), true);
  assert.equal(compiled.businessQueryRequest({ operation: "business_query", resolvedPlan }), true);
  assert.equal(compiled.businessQueryResponse(businessResponse), true);
  for (const validate of Object.values(compiled)) {
    assert.equal(validate({ invalid: true }), false);
  }
});


test("private operation fields cannot leak through real response data", () => {
  const compiled = validators();
  const response = {
    success: true,
    operation: "business_query",
    planId: "plan1",
    executionStatus: "OK",
    mockData: false,
    stepResults: [
      {
        planId: "plan1",
        stepId: "s1",
        relation: "PARENT_PATH",
        dependsOn: [],
        executionStatus: "OK",
        resultType: "PATH_RESULT",
        dataAsOf: "2026-08-11",
        presentation: { visibility: "VISIBLE" },
        mockData: false,
        data: {
          mockData: false,
          totalCount: 0,
          returnedCount: 0,
          truncated: false,
          paths: [],
          privateOperation: "PRODUCT_INDUSTRIES",
        },
      },
    ],
  };
  assert.equal(compiled["business-query.response.schema.json"](response), false);
});
