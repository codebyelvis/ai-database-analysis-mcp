import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "ajv/dist/2020.js";


const HERE = path.dirname(fileURLToPath(import.meta.url));

const SCHEMA_FILES = {
  preflightRequest: "kingbase-readonly-preflight.request.schema.json",
  preflightResponse: "kingbase-readonly-preflight.response.schema.json",
  catalogRequest: "kingbase-catalog.request.schema.json",
  catalogResponse: "kingbase-catalog.response.schema.json",
  fixtures: "strict-negative-fixtures.json",
};


export function schemaDirectory() {
  return path.join(HERE, "schemas");
}


function readJson(schemaDir, name) {
  return JSON.parse(fs.readFileSync(path.join(schemaDir, name), "utf8"));
}


export function compileContracts(schemaDir) {
  const schemas = Object.fromEntries(
    Object.entries(SCHEMA_FILES).map(([contract, name]) => [
      contract,
      readJson(schemaDir, name),
    ]),
  );
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const validators = Object.fromEntries(
    Object.entries(schemas).map(([contract, schema]) => [
      contract,
      ajv.compile(schema),
    ]),
  );
  Object.defineProperty(validators, "schemas", {
    configurable: false,
    enumerable: false,
    value: schemas,
    writable: false,
  });
  return validators;
}


export function loadFixtures(schemaDir) {
  return readJson(schemaDir, SCHEMA_FILES.fixtures).examples;
}


export function runNegativeMatrix(validators, fixtures) {
  const caseIds = new Set();
  let schemaRejected = 0;
  let semanticReady = 0;
  let mustNotStartPsql = true;

  for (const fixture of fixtures) {
    caseIds.add(fixture.caseId);
    mustNotStartPsql &&= fixture.mustNotStartPsql === true;
    const targetValidator = validators[fixture.target];
    if (typeof targetValidator !== "function") {
      throw new Error("unknown fixture target: " + fixture.target);
    }
    if (fixture.semanticRule === undefined) {
      if (targetValidator(fixture.payload)) {
        throw new Error("schema case accepted: " + fixture.caseId);
      }
      schemaRejected += 1;
      continue;
    }

    if (!validators.catalogRequest(fixture.request)) {
      throw new Error("semantic request rejected: " + fixture.caseId);
    }
    if (!targetValidator(fixture.payload)) {
      throw new Error("semantic response rejected: " + fixture.caseId);
    }
    semanticReady += 1;
  }

  return {
    total: fixtures.length,
    uniqueCaseIds: caseIds.size === fixtures.length,
    schemaRejected,
    semanticReady,
    mustNotStartPsql,
  };
}


if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const validators = compileContracts(schemaDirectory());
  const fixtures = loadFixtures(schemaDirectory());
  if (!validators.fixtures(fixtures)) {
    throw new Error("fixture examples do not satisfy fixture schema");
  }
  const summary = runNegativeMatrix(validators, fixtures);
  process.stdout.write(
    "AJV_STRICT=5/5 SCHEMA_REJECTED=" + summary.schemaRejected +
      " SEMANTIC_READY=" + summary.semanticReady +
      " PSQL_STARTED=" + String(!summary.mustNotStartPsql) + "\n",
  );
}
