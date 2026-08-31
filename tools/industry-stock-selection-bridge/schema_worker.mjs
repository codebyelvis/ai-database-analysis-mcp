import readline from "node:readline";

import { compileContracts } from "./schema_harness.mjs";


const validators = compileContracts();
const contracts = new Set(Object.keys(validators));
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
    !contracts.has(request.contract)
  ) {
    process.exitCode = 2;
    lines.close();
    return;
  }
  const valid = validators[request.contract](request.instance);
  process.stdout.write(JSON.stringify({ id: request.id, valid }) + "\n");
});
