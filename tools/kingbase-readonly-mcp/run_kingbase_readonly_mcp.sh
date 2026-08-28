#!/bin/sh
# 作者：liyan
# 日期：2026-08-26
# 作用：验证固定运行时后启动私有 Kingbase 只读 stdio server。

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$ROOT" ]; then printf '%s\n' TASK7_LAUNCHER_FAILED >&2; exit 1; fi
REPO_ROOT=$(CDPATH= cd -- "$ROOT/../.." 2>/dev/null && pwd)
status=$?
if [ "$status" -ne 0 ] || [ -z "$REPO_ROOT" ]; then printf '%s\n' TASK7_LAUNCHER_FAILED >&2; exit 1; fi

PYTHON_EXPECTED=/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14
NODE_EXPECTED=/opt/homebrew/Cellar/node@20/20.20.2/bin/node
PYTHON_SHA=00c07e4d31048b15eebbe4c883f229338c5b2d598e9ee061da39b7fccba20cad
NODE_SHA=d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4
PY_IDENTITY_SHA=d6bcdbd0be30c4964da861d38135633c348553845dbcd406eeea16c9a6963042
NODE_IDENTITY_SHA=253c8ad3f4ccaefcf2465ed95c6537f0ba112e1d9b527101fab04258cd65184f
PY_CACHE=$ROOT/.task7-source-only-pycache
SYSTEM_PATH=/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin
NODE_TREE_BOUND=c159f332d33ef9655805dd5c1438b87523a1d11d9a73f59b3efca94e9e0275da
SLICE_TREE_BOUND=0daf7bdd6ce358adbf33c9cc2e66d293f64686eca7b682ff2b49367b6b7e3df2
HOME_VALUE=$(/usr/bin/printenv HOME 2>/dev/null)
FORBIDDEN_ENV_NAMES='PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT PYTHONWARNINGS PYTHONBREAKPOINT PYTHONPROFILEIMPORTTIME PYTHONEXECUTABLE __PYVENV_LAUNCHER__ NODE_OPTIONS NODE_PATH NODE_V8_COVERAGE NODE_REDIRECT_WARNINGS PERL5OPT PERL5LIB PERLLIB LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH DYLD_ROOT_PATH DYLD_IMAGE_SUFFIX DYLD_VERSIONED_LIBRARY_PATH DYLD_VERSIONED_FRAMEWORK_PATH DYLD_PRINT_LIBRARIES DYLD_PRINT_TO_FILE DYLD_PRINT_TO_STDERR DYLD_PRINT_PROTETED_MEMORY_STATUS'

safe_fail() { printf '%s\n' TASK7_LAUNCHER_FAILED >&2; return 1; }

prefix_violation() {
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then
        printf '%s\n' TASK7_PREFIX_VIOLATION >&2
        return 1
    fi
    return 0
}

check_forbidden_environment() {
    for name in $FORBIDDEN_ENV_NAMES; do
        value=$(/usr/bin/printenv "$name" 2>/dev/null)
        value_status=$?
        if [ "$value_status" -eq 0 ] && [ -n "$value" ]; then return 1; fi
    done
    return 0
}

check_candidate() {
    candidate=$1
    expected=$2
    if [ ! -f "$candidate" ] || [ -L "$candidate" ] || [ ! -x "$candidate" ]; then return 1; fi
    real=$(/bin/realpath "$candidate" 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ] || [ "$real" != "$expected" ]; then return 1; fi
    return 0
}

file_sha_matches() {
    file=$1
    expected=$2
    if [ ! -f "$file" ] || [ -L "$file" ]; then return 1; fi
    record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$file" 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ]; then return "$status"; fi
    actual=$(printf '%s\n' "$record" | /usr/bin/cut -d ' ' -f 1)
    if [ "$actual" != "$expected" ]; then return 1; fi
    return 0
}

verify_runtime_inputs() {
    check_candidate "$PYTHON_EXPECTED" "$PYTHON_EXPECTED" || return $?
    check_candidate "$NODE_EXPECTED" "$NODE_EXPECTED" || return $?
    file_sha_matches "$PYTHON_EXPECTED" "$PYTHON_SHA" || return $?
    file_sha_matches "$NODE_EXPECTED" "$NODE_SHA" || return $?
    python_override=$(/usr/bin/printenv PYTHON_BIN 2>/dev/null)
    if [ -n "$python_override" ]; then check_candidate "$python_override" "$PYTHON_EXPECTED" || return $?; fi
    node_override=$(/usr/bin/printenv NODE_BIN 2>/dev/null)
    if [ -n "$node_override" ]; then check_candidate "$node_override" "$NODE_EXPECTED" || return $?; fi
    return 0
}

cleanup_stage() {
    stage=$1
    cleanup_status=0
    for name in python.out node.out symlinks special cache paths sorted raw_records records; do
        if [ -e "$stage/$name" ] || [ -L "$stage/$name" ]; then
            /bin/unlink "$stage/$name" 2>/dev/null
            cleanup_item_status=$?
            if [ "$cleanup_item_status" -ne 0 ]; then cleanup_status=1; fi
        fi
    done
    /bin/rmdir "$stage" 2>/dev/null
    cleanup_item_status=$?
    if [ "$cleanup_item_status" -ne 0 ]; then cleanup_status=1; fi
    return "$cleanup_status"
}

verify_identity() {
    stage=$(/usr/bin/mktemp -d /tmp/task7-identity.XXXXXX 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ] || [ -z "$stage" ]; then return 1; fi
    chmod 700 "$stage"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    "$PYTHON_EXPECTED" -I -S -B -c 'import platform,sys;sys.stdout.write("TASK7_PYTHON_IDENTITY_V1|"+sys.implementation.name+"|"+platform.python_version());raise SystemExit(73)' > "$stage/python.out" 2>/dev/null
    py_status=$?
    py_bytes=$(/usr/bin/wc -c < "$stage/python.out" 2>/dev/null)
    py_count_status=$?
    py_record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$stage/python.out" 2>/dev/null)
    py_hash_status=$?
    py_actual=$(printf '%s\n' "$py_record" | /usr/bin/cut -d ' ' -f 1)
    "$NODE_EXPECTED" -e 'process.stdout.write("TASK7_NODE_IDENTITY_V1|"+process.versions.node);process.exit(74)' > "$stage/node.out" 2>/dev/null
    node_status=$?
    node_bytes=$(/usr/bin/wc -c < "$stage/node.out" 2>/dev/null)
    node_count_status=$?
    node_record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$stage/node.out" 2>/dev/null)
    node_hash_status=$?
    node_actual=$(printf '%s\n' "$node_record" | /usr/bin/cut -d ' ' -f 1)
    result=0
    if [ "$py_status" -ne 73 ] || [ "$py_count_status" -ne 0 ] || [ "$py_bytes" -ne 39 ] || [ "$py_hash_status" -ne 0 ] || [ "$py_actual" != "$PY_IDENTITY_SHA" ]; then result=1; fi
    if [ "$node_status" -ne 74 ] || [ "$node_count_status" -ne 0 ] || [ "$node_bytes" -ne 30 ] || [ "$node_hash_status" -ne 0 ] || [ "$node_actual" != "$NODE_IDENTITY_SHA" ]; then result=1; fi
    cleanup_stage "$stage"
    cleanup_status=$?
    if [ "$cleanup_status" -ne 0 ]; then result=1; fi
    return "$result"
}

verify_ajv() {
    "$NODE_EXPECTED" -e 'const fs=require("node:fs");const path=require("node:path");const url=require("node:url");const root=process.cwd();const names=["package.json","package-lock.json","node_modules/.package-lock.json","node_modules/ajv/package.json"];const values=names.map((name)=>JSON.parse(fs.readFileSync(path.join(root,"tools/kingbase-readonly-mcp",name),"utf8")));if(values[0].devDependencies.ajv!=="8.20.0"||values[1].packages[""].devDependencies.ajv!=="8.20.0"||values[2].packages["node_modules/ajv"].version!=="8.20.0"||values[3].version!=="8.20.0")process.exit(1);import(url.pathToFileURL(path.join(root,"tools/kingbase-readonly-mcp/node_modules/ajv/dist/2020.js")).href).then((module)=>new module.default({strict:true,allErrors:true})).catch(()=>process.exit(1));' >/dev/null 2>/dev/null
    status=$?
    if [ "$status" -ne 0 ]; then return "$status"; fi
    return 0
}

manifest_verify() {
    tree=$1
    expected_count=$2
    expected_hash=${3:-}
    stage=$(/usr/bin/mktemp -d /tmp/task7-manifest.XXXXXX 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ] || [ -z "$stage" ]; then return 1; fi
    chmod 700 "$stage"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    find "$tree" -type l -print0 > "$stage/symlinks"
    status=$?
    if [ "$status" -ne 0 ] || [ -s "$stage/symlinks" ]; then cleanup_stage "$stage"; return 1; fi
    find "$tree" ! -type f ! -type d ! -type l -print0 > "$stage/special"
    status=$?
    if [ "$status" -ne 0 ] || [ -s "$stage/special" ]; then cleanup_stage "$stage"; return 1; fi
    find "$tree" \( -name '__pycache__' -o -name '*.pyc' \) -print0 > "$stage/cache"
    status=$?
    if [ "$status" -ne 0 ] || [ -s "$stage/cache" ]; then cleanup_stage "$stage"; return 1; fi
    find "$tree" -type f ! -path '*/__pycache__/*' ! -name '*.pyc' -print0 > "$stage/paths"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    LC_ALL=C sort -z "$stage/paths" > "$stage/sorted"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    /usr/bin/xargs -0 -n 1 /usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 < "$stage/sorted" > "$stage/raw_records"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    /usr/bin/sed "s| $REPO_ROOT/| |" "$stage/raw_records" > "$stage/records"
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    count=$(/usr/bin/wc -l < "$stage/records" 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    if [ "$expected_count" -gt 0 ] && [ "$count" -ne "$expected_count" ]; then cleanup_stage "$stage"; return 1; fi
    aggregate_record=$(/usr/bin/env -i PATH="$SYSTEM_PATH" /usr/bin/shasum -a 256 "$stage/records" 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ]; then cleanup_stage "$stage"; return "$status"; fi
    aggregate=$(printf '%s\n' "$aggregate_record" | /usr/bin/cut -d ' ' -f 1)
    if [ -n "$expected_hash" ] && [ "$aggregate" != "$expected_hash" ]; then
        cleanup_stage "$stage"
        return 1
    fi
    cleanup_stage "$stage"
    cleanup_status=$?
    if [ "$cleanup_status" -ne 0 ]; then return 1; fi
    return "$status"
}

verify_bound_files() {
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/adapter.py" 1df3ba2d0483b3f7ddc10ae7f0c4839d26272795f20f37422d5b9dd79b88f00e || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/canonical.py" dbdfc943ac589e61d3c440bcd54d68d2a30845b8be8bf31701d073ca02903572 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/contracts.py" b65522f0498b8a335201b160dd8ea72045c4c8ca964225253011c4dcf155b2d8 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/credentials.py" dea93d2e30eaf84f496bd628375388319fe0e35407510045316f5d55cc12f6c2 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/metadata_contract.py" 954d78427414d86bed7845402e2210e1ec349db3618f4b7ed31e277329ddeaff || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/metadata_contract.json" 74b15e86094d6b16429f861867f72bedf3c0d2a0536abd1c96119804739d105f || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/metadata_probe.py" a1627521c686bb8a20026dae9c87290455ae05fc2b798f5a75918ddd81f5a344 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/semantics.py" f92479505354f8c54ec06fc21b4ba253f7f8fe58622697ba526e193fce2cddd9 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/sql_templates.py" 2b7864ffafc6889bac6fe0bfc94795e21a0c7449af1ff7f3235eed1bde4ccdc2 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/psql_runner.py" c96e1af1efd9e59e15dfb27fbfc82f50addb9f0ff09df8bfb98c01f72f4cf244 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/schema_worker.mjs" d60b532f722382b10ec838936cbedacca9845457d9315711885666f8f7372d72 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/schema_harness.mjs" d6b0aea7e4400f589cc3b792be940659cd60b0192c6ec141af7a38046d6a5aff || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/package.json" 84c3ff2812f7ca54e3c9ac1fcbc44d82996e465f84b9e18a0f73a6cd8accf8d7 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/package-lock.json" f058c5cc29e041df8054c721a11aa588bba99bd32daaa5dd80f94088d7680c83 || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/node_modules/.package-lock.json" bd0b8228df2bccb0e46dd821d35aca404d669b62cf3f0178a804d40a64bf739d || return $?
    file_sha_matches "$REPO_ROOT/tools/kingbase-readonly-mcp/node_modules/ajv/package.json" 1f9033ee5a6515e7d76938b7072941862d1ed228a6879cc7fe10cdeb75107989 || return $?
    return 0
}

verify_mirrors() {
    public_root=/Users/elvis/file/develop/notes/Typora/10_Projects/ai-app-docs/模型开发工作台/openspec/changes/archive/2026-08-28-add-real-kingbase-readonly-mcp-v1/schemas
    for name in kingbase-readonly-preflight.request.schema.json kingbase-readonly-preflight.response.schema.json kingbase-catalog.request.schema.json kingbase-catalog.response.schema.json strict-negative-fixtures.json; do
        /usr/bin/cmp -s "$public_root/$name" "$ROOT/schemas/$name"
        status=$?
        if [ "$status" -ne 0 ]; then return "$status"; fi
    done
    return 0
}

make_wrapper() {
    wrapper_dir=$(/usr/bin/mktemp -d /tmp/task7-wrapper.XXXXXX 2>/dev/null)
    status=$?
    if [ "$status" -ne 0 ] || [ -z "$wrapper_dir" ]; then return 1; fi
    chmod 700 "$wrapper_dir"
    status=$?
    if [ "$status" -ne 0 ]; then /bin/rmdir "$wrapper_dir" 2>/dev/null; return "$status"; fi
    wrapper="$wrapper_dir/python-wrapper.sh"
    printf '%s\n' '#!/bin/sh' 'PYTHON_BIN="/opt/homebrew/Cellar/python@3.14/3.14.2_1/Frameworks/Python.framework/Versions/3.14/bin/python3.14"' 'NODE_BIN="/opt/homebrew/Cellar/node@20/20.20.2/bin/node"' 'PY_CACHE="/Users/elvis/file/develop/workspace/ai-database-analysis-mcp/tools/kingbase-readonly-mcp/.task7-source-only-pycache"' 'SYSTEM_PATH="/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin"' 'HOME_VALUE=$(/usr/bin/printenv HOME 2>/dev/null)' 'if [ "$#" -ge 1 ] && [ "$1" = "-c" ]; then code=$2; shift 2; exec /usr/bin/env -i PATH="$SYSTEM_PATH" HOME="$HOME_VALUE" TASK7_NODE_BINARY="$NODE_BIN" "$PYTHON_BIN" -I -S -B -X pycache_prefix="$PY_CACHE" -c "$code" "$@"; fi' 'if [ "$#" -ge 2 ] && [ "$1" = "-B" ]; then script=$2; shift 2; exec /usr/bin/env -i PATH="$SYSTEM_PATH" HOME="$HOME_VALUE" TASK7_NODE_BINARY="$NODE_BIN" "$PYTHON_BIN" -I -S -B -X pycache_prefix="$PY_CACHE" -c '\''import runpy,sys;sys.path.insert(0,"/Users/elvis/file/develop/workspace/ai-database-analysis-mcp/tools/kingbase-readonly-mcp");runpy.run_path(sys.argv[1],run_name="__main__")'\'' "$script" "$@"; fi' 'exit 1' > "$wrapper"
    status=$?
    if [ "$status" -ne 0 ]; then /bin/unlink "$wrapper" 2>/dev/null; /bin/rmdir "$wrapper_dir" 2>/dev/null; return "$status"; fi
    chmod 700 "$wrapper"
    status=$?
    if [ "$status" -ne 0 ]; then /bin/unlink "$wrapper" 2>/dev/null; /bin/rmdir "$wrapper_dir" 2>/dev/null; return "$status"; fi
    return 0
}

quiesce_group() {
    pid=$1
    attempts=0
    while [ "$attempts" -lt 3 ]; do
        /bin/kill -0 -"$pid" 2>/dev/null
        status=$?
        if [ "$status" -ne 0 ]; then return 0; fi
        /bin/sleep 1
        status=$?
        if [ "$status" -ne 0 ]; then return "$status"; fi
        attempts=$((attempts + 1))
    done
    /bin/kill -KILL -"$pid" 2>/dev/null
    status=$?
    if [ "$status" -ne 0 ]; then return "$status"; fi
    return 1
}

forward_signal() {
    signal=$1
    if [ -n "$child_pid" ]; then
        /bin/kill -"$signal" -"$child_pid" 2>/dev/null
        status=$?
        if [ "$status" -ne 0 ]; then signal_failure=1; fi
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
    "$wrapper" -c 'import os,runpy,sys;os.setsid();sys.path.insert(0,"/Users/elvis/file/develop/workspace/ai-database-analysis-mcp/tools/kingbase-readonly-mcp");runpy.run_path(sys.argv[1],run_name="__main__")' "$ROOT/kingbase_readonly_server.py" <&3 2>/dev/null &
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

run_and_check() {
    "$@" 2>/dev/null
    status=$?
    if [ "$status" -ne 0 ]; then printf '%s\n' TASK7_LAUNCHER_FAILED >&2; return "$status"; fi
    return 0
}

run_quiet_and_check() {
    "$@" >/dev/null 2>/dev/null
    status=$?
    if [ "$status" -ne 0 ]; then return "$status"; fi
    return 0
}

main() {
    if [ "$#" -ne 0 ]; then safe_fail; return 1; fi
    if [ -e "$PY_CACHE" ] || [ -L "$PY_CACHE" ]; then prefix_violation; return 1; fi
    check_forbidden_environment || { safe_fail; return 1; }
    verify_runtime_inputs || { safe_fail; return 1; }
    verify_identity || { safe_fail; return 1; }
    verify_bound_files || { safe_fail; return 1; }
    verify_mirrors || { safe_fail; return 1; }
    verify_ajv || { safe_fail; return 1; }
    manifest_verify "$ROOT" 0 "" || { safe_fail; return 1; }
    manifest_verify "$ROOT/node_modules" 538 "$NODE_TREE_BOUND" || { safe_fail; return 1; }
    manifest_verify "$REPO_ROOT/tools/local-database-analysis" 19 "$SLICE_TREE_BOUND" || { safe_fail; return 1; }
    make_wrapper || { safe_fail; return 1; }
    run_server
    server_status=$?
    /bin/unlink "$wrapper" 2>/dev/null
    cleanup_status=$?
    if [ "$cleanup_status" -ne 0 ]; then server_status=1; fi
    /bin/rmdir "$wrapper_dir" 2>/dev/null
    cleanup_status=$?
    if [ "$cleanup_status" -ne 0 ]; then server_status=1; fi
    prefix_violation
    prefix_status=$?
    if [ "$prefix_status" -ne 0 ]; then server_status=1; fi
    return "$server_status"
}

main "$@"
exit $?
