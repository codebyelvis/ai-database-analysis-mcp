#!/bin/sh
# Run the public bridge's strictly offline test matrix.

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; exit 1; fi
REPO_ROOT=$(CDPATH= cd -- "$ROOT/../.." 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$REPO_ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; exit 1; fi

PYTHON=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14
NODE=/opt/homebrew/Cellar/node@20/20.20.2/bin/node
NODE_SHA=d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4
SYSTEM_PATH=/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin
SCHEMA_RUNTIME=$ROOT/../kingbase-readonly-mcp
HOME_VALUE=$(/usr/bin/printenv HOME 2>/dev/null)
PY_CACHE=$ROOT/.bridge-source-only-pycache

fail() { printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; return 1; }

verify_node() {
    if [ ! -f "$NODE" ] || [ -L "$NODE" ] || [ ! -x "$NODE" ]; then return 1; fi
    real=$(/bin/realpath "$NODE" 2>/dev/null) || return 1
    if [ "$real" != "$NODE" ]; then return 1; fi
    record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$NODE" 2>/dev/null) || return 1
    actual=$(printf '%s\n' "$record" | /usr/bin/cut -d ' ' -f 1)
    [ "$actual" = "$NODE_SHA" ]
}

verify_ajv() {
    /usr/bin/env -i "$NODE" --input-type=module -e '
        import fs from "node:fs";
        import path from "node:path";
        import { pathToFileURL } from "node:url";
        const root = process.argv[1];
        const values = [
          JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8")),
          JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8")),
          JSON.parse(fs.readFileSync(path.join(root, "node_modules/.package-lock.json"), "utf8")),
          JSON.parse(fs.readFileSync(path.join(root, "node_modules/ajv/package.json"), "utf8")),
        ];
        if (
          values[0].devDependencies?.ajv !== "8.20.0" ||
          values[1].packages?.[""]?.devDependencies?.ajv !== "8.20.0" ||
          values[1].packages?.["node_modules/ajv"]?.version !== "8.20.0" ||
          values[2].packages?.["node_modules/ajv"]?.version !== "8.20.0" ||
          values[3].version !== "8.20.0"
        ) process.exit(1);
        const module = await import(pathToFileURL(path.join(root, "node_modules/ajv/dist/2020.js")).href);
        new module.default({strict:true,strictRequired:false,strictTypes:false,allErrors:true});
    ' "$SCHEMA_RUNTIME" >/dev/null 2>/dev/null
}

run_python() {
    test_file=$1
    /usr/bin/env -i HOME="$HOME_VALUE" PATH="$SYSTEM_PATH" \
        "$PYTHON" -I -S -B -X pycache_prefix="$PY_CACHE" "$test_file" \
        >/dev/null 2>/dev/null
}

main() {
    if [ "$#" -ne 0 ]; then fail; return 1; fi
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then fail; return 1; fi
    verify_node || { fail; return 1; }
    verify_ajv || { fail; return 1; }
    /bin/sh -n "$ROOT/run_industry_selection_bridge.sh" >/dev/null 2>/dev/null || { fail; return 1; }
    /bin/sh -n "$ROOT/run_tests.sh" >/dev/null 2>/dev/null || { fail; return 1; }
    for test_file in \
        "$ROOT/tests/test_contracts.py" \
        "$ROOT/tests/test_private_mcp_client.py" \
        "$ROOT/tests/test_bridge.py" \
        "$ROOT/tests/test_server.py" \
        "$ROOT/tests/test_schema_client.py" \
        "$ROOT/tests/test_launcher.py"; do
        run_python "$test_file" || { fail; return 1; }
        if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then fail; return 1; fi
    done
    /usr/bin/env -i HOME="$HOME_VALUE" PATH="$SYSTEM_PATH" \
        "$NODE" --test "$ROOT/tests/public_contracts.test.mjs" \
        >/dev/null 2>/dev/null || { fail; return 1; }
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then fail; return 1; fi
    printf '%s\n' INDUSTRY_SELECTION_BRIDGE_OFFLINE_OK
    return 0
}

main "$@"
exit $?
