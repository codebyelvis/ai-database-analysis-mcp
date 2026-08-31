import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import Ajv2020 from "../kingbase-readonly-mcp/node_modules/ajv/dist/2020.js";


const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_FILES = {
  entityResolveRequest: "entity-resolve.request.schema.json",
  entityResolveResponse: "entity-resolve.response.schema.json",
  businessQueryRequest: "business-query.request.schema.json",
  businessQueryResponse: "business-query.response.schema.json",
};


export function contractDirectory() {
  return path.join(HERE, "contracts");
}


export function compileContracts(schemaDir = contractDirectory()) {
  const ajv = new Ajv2020({
    strict: true,
    strictRequired: false,
    strictTypes: false,
    allErrors: true,
  });
  const schemas = Object.fromEntries(
    Object.entries(SCHEMA_FILES).map(([contract, name]) => [
      contract,
      JSON.parse(fs.readFileSync(path.join(schemaDir, name), "utf8")),
    ]),
  );
  for (const schema of Object.values(schemas)) {
    ajv.addSchema(schema);
  }
  return Object.fromEntries(
    Object.entries(schemas).map(([contract, schema]) => {
      const validator = ajv.getSchema(schema.$id);
      if (typeof validator !== "function") {
        throw new Error("public contract unavailable");
      }
      return [contract, validator];
    }),
  );
}
