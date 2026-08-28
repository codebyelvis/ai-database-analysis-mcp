#!/bin/sh
# 作者：elvis
# 日期：2026-08-19
# 作用：以受版本约束的 Python 启动无库 stdio MCP 适配层

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
    echo "MCP server requires Python 3.11 or newer (plan target: 3.12)" >&2
    exit 1
fi

PYTHONDONTWRITEBYTECODE=1 exec "$PYTHON_BIN" -B mcp_server.py
