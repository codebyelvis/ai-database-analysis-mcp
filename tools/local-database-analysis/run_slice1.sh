#!/bin/sh
# 作者：elvis
# 日期：2026-08-18
# 作用：执行 Slice 1 无数据库依赖的确定性测试

set -eu

cd "$(dirname "$0")"

PYTHON_BIN=${PYTHON_BIN:-}
if [ -n "$PYTHON_BIN" ]; then
    if ! "$PYTHON_BIN" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
        echo "PYTHON_BIN must be Python 3.11 or newer" >&2
        exit 1
    fi
else
    for candidate in python3.12 python3.11 python3
    do
        if command -v "$candidate" >/dev/null 2>&1 && \
            "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1; then
            PYTHON_BIN=$(command -v "$candidate")
            break
        fi
    done
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "Slice 1 requires Python 3.11 or newer (plan target: 3.12)" >&2
    exit 1
fi

PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_dbar1.py
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_launch_scan_v1.py
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_ledger_sm.py
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_envelope.py
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_mcp_server.py
PYTHONDONTWRITEBYTECODE=1 "$PYTHON_BIN" -B tests/test_security_fixtures.py
echo SLICE1_OK
