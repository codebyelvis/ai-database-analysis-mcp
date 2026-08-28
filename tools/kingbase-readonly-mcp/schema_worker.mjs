import readline from "node:readline";

import { compileContracts, schemaDirectory } from "./schema_harness.mjs";


const validators = compileContracts(schemaDirectory());
const publicContracts = new Set([
  "preflightRequest",
  "preflightResponse",
  "catalogRequest",
  "catalogResponse",
]);

const lines = readline.createInterface({
  crlfDelay: Infinity,
  input: process.stdin,
  terminal: false,
});

lines.on("line", (line) => {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    process.exitCode = 2;
    lines.close();
    return;
  }
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).sort().join(",") !== "contract,id,instance" ||
    !Number.isSafeInteger(request.id) ||
    request.id < 0 ||
    !publicContracts.has(request.contract)
  ) {
    process.exitCode = 2;
    lines.close();
    return;
  }
  const valid = validators[request.contract](request.instance);
  process.stdout.write(JSON.stringify({ id: request.id, valid }) + "\n");
});
