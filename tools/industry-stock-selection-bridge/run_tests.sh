#!/bin/sh
# Run the public bridge's strictly offline test matrix.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; exit 1; fi
REPO_ROOT=$(CDPATH= cd -- "$ROOT/../.." 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$REPO_ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; exit 1; fi

PYTHON=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14
NODE=/opt/homebrew/Cellar/node@20/20.20.2/bin/node
SYSTEM_PATH=/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin
HOME_VALUE=$(/usr/bin/printenv HOME 2>/dev/null)
PY_CACHE=$ROOT/.bridge-source-only-pycache

fail() { printf '%s\n' INDUSTRY_SELECTION_BRIDGE_TESTS_FAILED >&2; return 1; }

run_python() {
    test_file=$1
    /usr/bin/env -i HOME="$HOME_VALUE" PATH="$SYSTEM_PATH" \
        "$PYTHON" -I -S -B -X pycache_prefix="$PY_CACHE" "$test_file" \
        >/dev/null 2>/dev/null
}

main() {
    if [ "$#" -ne 0 ]; then fail; return 1; fi
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then fail; return 1; fi
    /bin/sh -n "$ROOT/run_industry_selection_bridge.sh" >/dev/null 2>/dev/null || { fail; return 1; }
    /bin/sh -n "$ROOT/run_tests.sh" >/dev/null 2>/dev/null || { fail; return 1; }
    for test_file in \
        "$ROOT/tests/test_contracts.py" \
        "$ROOT/tests/test_private_mcp_client.py" \
        "$ROOT/tests/test_bridge.py" \
        "$ROOT/tests/test_server.py" \
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
