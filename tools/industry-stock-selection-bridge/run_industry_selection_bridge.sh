#!/bin/sh
# Start the only Codex-visible industry-selection MCP and supervise its children.

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$ROOT" ]; then printf '%s\n' INDUSTRY_SELECTION_BRIDGE_FAILED >&2; exit 1; fi

PYTHON=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14
PYTHON_SHA=00c07e4d31048b15eebbe4c883f229338c5b2d598e9ee061da39b7fccba20cad
SYSTEM_PATH=/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin
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
    real=$(/bin/realpath "$PYTHON" 2>/dev/null) || return 1
    if [ "$real" != "$PYTHON" ]; then return 1; fi
    record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$PYTHON" 2>/dev/null) || return 1
    actual=$(printf '%s\n' "$record" | /usr/bin/cut -d ' ' -f 1)
    if [ "$actual" != "$PYTHON_SHA" ]; then return 1; fi
    return 0
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
    /usr/bin/env -i HOME="$HOME_VALUE" PATH="$SYSTEM_PATH" \
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
    run_server
    server_status=$?
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then server_status=1; fi
    if [ "$server_status" -ne 0 ]; then safe_fail; return 1; fi
    return 0
}

main "$@"
exit $?
