"""
作者：liyan
日期：2026-08-26
作用：提供仅供本地执行链使用的 Kingbase 只读 MCP stdio server。
"""

import copy
import json
import math
import os
import sys
from pathlib import Path
from typing import Any, BinaryIO

from adapter import Adapter
from canonical import canonical_json
from schema_client import SchemaClient


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "kingbase-readonly-private"
SERVER_VERSION = "1.0.0"
MAX_JSON_LINE_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
TOOL_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False}
PREFLIGHT_DESCRIPTION = "Validate the fixed test-environment read-only Kingbase contract."
CATALOG_DESCRIPTION = "Query the fixed test-environment industry catalog."
SCHEMA_DIR = Path(__file__).with_name("schemas")
_TOOL_SCHEMAS = (
    ("kingbase_readonly_preflight", "kingbase-readonly-preflight.request.schema.json", PREFLIGHT_DESCRIPTION),
    ("kingbase_catalog_query", "kingbase-catalog.request.schema.json", CATALOG_DESCRIPTION),
)

_ERRORS = {
    "parse_error": -32700,
    "invalid_request": -32600,
    "method_not_found": -32601,
    "invalid_params": -32602,
    "internal_error": -32603,
}


class _ProtocolError(ValueError):
    def __init__(self, message: str, *, parse: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.parse = parse


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-finite number")


def _assert_safe_json(value: Any) -> None:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite number")
        if not isinstance(current, (dict, list)):
            continue
        child_depth = depth + 1
        if child_depth > MAX_JSON_DEPTH:
            raise ValueError("JSON depth exceeded")
        children = current.values() if isinstance(current, dict) else current
        pending.extend((child, child_depth) for child in children)


def _safe_id(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    if isinstance(value, str):
        return value
    return None


def _error_response(request_id: Any, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": _safe_id(request_id),
        "error": {"code": _ERRORS[message], "message": message},
    }


def _success_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": _safe_id(request_id), "result": result}


def _read_schema(name: str) -> dict[str, Any]:
    value = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("invalid request schema")
    return value


def tool_definitions() -> list[dict[str, Any]]:
    """返回两个私有工具的全新、无共享引用定义。"""
    return [
        {
            "name": name,
            "description": description,
            "annotations": copy.deepcopy(TOOL_ANNOTATIONS),
            "inputSchema": _read_schema(schema_name),
        }
        for name, schema_name, description in _TOOL_SCHEMAS
    ]


def _write_line(output_stream: BinaryIO, value: dict[str, Any]) -> None:
    encoded = canonical_json(value) + b"\n"
    written = output_stream.write(encoded)
    if written is None or written != len(encoded):
        raise OSError("short write")
    output_stream.flush()


def _drain_overlong(input_stream: BinaryIO, raw: bytes) -> None:
    if raw.endswith(b"\n"):
        return
    while True:
        chunk = input_stream.readline(MAX_JSON_LINE_BYTES + 2)
        if not chunk or chunk.endswith(b"\n"):
            return


def _decode_line(input_stream: BinaryIO) -> tuple[str | None, bool]:
    raw = input_stream.readline(MAX_JSON_LINE_BYTES + 2)
    if not raw:
        return None, False
    overlong = len(raw) > MAX_JSON_LINE_BYTES or not raw.endswith(b"\n")
    if overlong:
        _drain_overlong(input_stream, raw)
        return None, True
    try:
        return raw[:-1].decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


def _parse_request(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text, parse_constant=_reject_constant)
        _assert_safe_json(value)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _ProtocolError("parse_error", parse=True) from exc
    if not isinstance(value, dict):
        raise _ProtocolError("parse_error", parse=True)
    return value


def _is_notification(request: Any) -> bool:
    return isinstance(request, dict) and "id" not in request


def _validate_base_request(request: dict[str, Any]) -> tuple[Any, str, Any]:
    request_id = request.get("id")
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        raise _ProtocolError("invalid_request")
    if "id" in request and _safe_id(request_id) != request_id:
        raise _ProtocolError("invalid_request")
    return request_id, request["method"], request.get("params")


def _valid_initialize(params: Any) -> bool:
    return (
        isinstance(params, dict)
        and set(params) == {"protocolVersion", "capabilities", "clientInfo"}
        and isinstance(params["protocolVersion"], str)
        and isinstance(params["capabilities"], dict)
        and isinstance(params["clientInfo"], dict)
    )


def _valid_list_params(params: Any) -> bool:
    return params == {}


def _valid_call_params(params: Any) -> bool:
    return (
        isinstance(params, dict)
        and set(params) <= {"name", "arguments"}
        and isinstance(params.get("name"), str)
        and ("arguments" not in params or isinstance(params["arguments"], dict))
    )


def _tool_result(response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        raise RuntimeError("invalid adapter response")
    result = {
        "content": [
            {"type": "text", "text": canonical_json(response).decode("utf-8")}
        ]
    }
    if response.get("success") is False:
        result["isError"] = True
    return result


def _dispatch(request: dict[str, Any], adapter: Any) -> Any:
    request_id, method, params = _validate_base_request(request)
    if method == "notifications/initialized" or method == "notifications/cancelled":
        return None
    if method == "initialize":
        if not _valid_initialize(params):
            raise _ProtocolError("invalid_params")
        return _success_response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "ping":
        if params != {}:
            raise _ProtocolError("invalid_params")
        return _success_response(request_id, {})
    if method == "tools/list":
        if not _valid_list_params(params):
            raise _ProtocolError("invalid_params")
        return _success_response(request_id, {"tools": tool_definitions()})
    if method != "tools/call":
        raise _ProtocolError("method_not_found")
    if not _valid_call_params(params):
        raise _ProtocolError("invalid_params")
    name = params["name"]
    arguments = params.get("arguments", {})
    if name not in {item[0] for item in _TOOL_SCHEMAS}:
        raise _ProtocolError("invalid_params")
    if name == "kingbase_readonly_preflight":
        response = adapter.preflight(arguments)
    else:
        response = adapter.catalog(arguments)
    return _success_response(request_id, _tool_result(response))


def _close_adapter(adapter: Any) -> None:
    schema = getattr(adapter, "_schema", None)
    close = getattr(schema, "close", None)
    if callable(close):
        close()


def create_ready_adapter(node_binary: str) -> Adapter:
    """先完成 Schema worker bootstrap，再向 Adapter 注入 ready client。"""
    schema = SchemaClient(node_binary=node_binary)
    try:
        return Adapter(schema_factory=lambda: schema)
    except Exception:
        schema.close()
        raise


def _startup_adapter(node_binary: str | None) -> Any:
    if not isinstance(node_binary, str) or not os.path.isabs(node_binary):
        raise RuntimeError("verified node binary required")
    return create_ready_adapter(node_binary)


def serve(input_stream: BinaryIO, output_stream: BinaryIO, adapter: Any | None = None) -> int:
    """执行有界二进制 stdio 循环；adapter 注入仅用于离线测试。"""
    owned = adapter is None
    try:
        if adapter is None:
            adapter = _startup_adapter(os.environ.get("TASK7_NODE_BINARY"))
    except Exception:
        return 1
    try:
        while True:
            request = None
            text, malformed = _decode_line(input_stream)
            if text is None and not malformed:
                return 0
            if malformed:
                _write_line(output_stream, _error_response(None, "parse_error"))
                continue
            try:
                request = _parse_request(text)
                notification = _is_notification(request)
                # Notifications have no response and must never reach Adapter
                # dispatch, including a notification-shaped tools/call.
                if notification:
                    continue
                response = _dispatch(request, adapter)
                if notification or response is None:
                    continue
                _write_line(output_stream, response)
            except _ProtocolError as exc:
                if _is_notification(request):
                    continue
                request_id = request.get("id") if isinstance(request, dict) else None
                _write_line(output_stream, _error_response(request_id, exc.message))
            except Exception:
                if _is_notification(request):
                    continue
                request_id = request.get("id") if isinstance(request, dict) else None
                _write_line(output_stream, _error_response(request_id, "internal_error"))
    except Exception:
        return 1
    finally:
        if owned:
            try:
                _close_adapter(adapter)
            except Exception:
                pass


def main(node_binary: str | None = None) -> int:
    selected = node_binary or os.environ.get("TASK7_NODE_BINARY")
    try:
        instance = _startup_adapter(selected)
    except Exception:
        return 1
    try:
        return serve(sys.stdin.buffer, sys.stdout.buffer, adapter=instance)
    finally:
        _close_adapter(instance)


if __name__ == "__main__":
    raise SystemExit(main())
