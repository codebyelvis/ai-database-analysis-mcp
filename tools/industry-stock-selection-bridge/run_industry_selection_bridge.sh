#!/bin/sh
# Start the only Codex-visible industry-selection MCP and supervise its children.

ROOT=$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_FAILED >&2; exit 1; fi

PYTHON=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14
NODE=/opt/homebrew/Cellar/node@20/20.20.2/bin/node
PYTHON_SHA=00c07e4d31048b15eebbe4c883f229338c5b2d598e9ee061da39b7fccba20cad
NODE_SHA=d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4
SYSTEM_PATH=/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin
SCHEMA_RUNTIME=$ROOT/../kingbase-readonly-mcp
PY_CACHE=$ROOT/.bridge-source-only-pycache
HOME_VALUE=$(/usr/bin/printenv HOME 2>/dev/null)
FORBIDDEN_ENV_NAMES='PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT PYTHONWARNINGS PYTHONBREAKPOINT PYTHONPROFILEIMPORTTIME PYTHONEXECUTABLE __PYVENV_LAUNCHER__ NODE_OPTIONS NODE_PATH NODE_V8_COVERAGE NODE_REDIRECT_WARNINGS PERL5OPT PERL5LIB PERLLIB LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH DYLD_ROOT_PATH DYLD_IMAGE_SUFFIX DYLD_VERSIONED_LIBRARY_PATH DYLD_VERSIONED_FRAMEWORK_PATH DYLD_PRINT_LIBRARIES DYLD_PRINT_TO_FILE DYLD_PRINT_TO_STDERR DYLD_PRINT_PROTETED_MEMORY_STATUS'

safe_fail() { printf '%s\n' INDUSTRY_SELECTION_BRIDGE_FAILED >&2; return 1; }

check_environment() {
    if [ -z "$HOME_VALUE" ] || [ ! -d "$HOME_VALUE" ]; then return 1; fi
    for name in $FORBIDDEN_ENV_NAMES; do
        value=$(/usr/bin/printenv "$name" 2>/dev/null)
        value_status=$?
        if [ "$value_status" -eq 0 ] && [ -n "$value" ]; then return 1; fi
    done
    return 0
}

check_runtime() {
    if [ ! -f "$PYTHON" ] || [ -L "$PYTHON" ] || [ ! -x "$PYTHON" ]; then return 1; fi
    if [ ! -f "$NODE" ] || [ -L "$NODE" ] || [ ! -x "$NODE" ]; then return 1; fi
    for pair in "$PYTHON:$PYTHON_SHA" "$NODE:$NODE_SHA"; do
        candidate=${pair%%:*}
        expected=${pair#*:}
        real=$(/bin/realpath "$candidate" 2>/dev/null) || return 1
        if [ "$real" != "$candidate" ]; then return 1; fi
        record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$candidate" 2>/dev/null) || return 1
        actual=$(printf '%s\n' "$record" | /usr/bin/cut -d ' ' -f 1)
        if [ "$actual" != "$expected" ]; then return 1; fi
    done
    return 0
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
        const entry = path.join(root, "node_modules/ajv/dist/2020.js");
        const module = await import(pathToFileURL(entry).href);
        new module.default({
          strict: true,
          strictRequired: false,
          strictTypes: false,
          allErrors: true,
        });
    ' "$SCHEMA_RUNTIME" >/dev/null 2>/dev/null
}

group_alive() {
    /bin/kill -0 -"$1" 2>/dev/null
}

quiesce_group() {
    pid=$1
    attempts=0
    while [ "$attempts" -lt 3 ]; do
        if ! group_alive "$pid"; then return 0; fi
        /bin/sleep 1 || return 1
        attempts=$((attempts + 1))
    done
    /bin/kill -KILL -"$pid" 2>/dev/null || return 1
    attempts=0
    while [ "$attempts" -lt 3 ]; do
        if ! group_alive "$pid"; then return 0; fi
        /bin/sleep 1 || return 1
        attempts=$((attempts + 1))
    done
    return 1
}

forward_signal() {
    signal=$1
    if [ -n "$child_pid" ]; then
        /bin/kill -"$signal" -"$child_pid" 2>/dev/null || signal_failure=1
    fi
    return 0
}

run_server() {
    child_pid=
    signal_failure=0
    trap 'forward_signal HUP' HUP
    trap 'forward_signal INT' INT
    trap 'forward_signal TERM' TERM
    exec 3<&0
    /usr/bin/env -i HOME="$HOME_VALUE" PATH="$SYSTEM_PATH" INDUSTRY_SCHEMA_NODE_BINARY="$NODE" \
        "$PYTHON" -I -S -B -X pycache_prefix="$PY_CACHE" \
        -c 'import os,runpy,sys;os.setsid();sys.path.insert(0,sys.argv[1]);runpy.run_path(sys.argv[2],run_name="__main__")' \
        "$ROOT" "$ROOT/industry_selection_bridge_server.py" <&3 2>/dev/null &
    child_pid=$!
    exec 3<&-
    wait "$child_pid"
    child_status=$?
    trap - HUP INT TERM
    quiesce_group "$child_pid"
    quiet_status=$?
    if [ "$signal_failure" -ne 0 ] || [ "$quiet_status" -ne 0 ]; then return 1; fi
    return "$child_status"
}

main() {
    if [ "$#" -ne 0 ]; then safe_fail; return 1; fi
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then safe_fail; return 1; fi
    check_environment || { safe_fail; return 1; }
    check_runtime || { safe_fail; return 1; }
    verify_ajv || { safe_fail; return 1; }
    run_server
    server_status=$?
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then server_status=1; fi
    if [ "$server_status" -ne 0 ]; then safe_fail; return 1; fi
    return 0
}

main "$@"
exit $?
