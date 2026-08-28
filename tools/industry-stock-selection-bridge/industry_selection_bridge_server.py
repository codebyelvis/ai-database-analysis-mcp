"""Public two-tool MCP server for the real industry-selection bridge."""

from __future__ import annotations

import copy
import json
import math
import sys
from pathlib import Path
from typing import Any, BinaryIO

from industry_selection_bridge import IndustrySelectionBridge


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "industry-stock-selection-local"
SERVER_VERSION = "1.0.0"
MAX_JSON_LINE_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
TOOL_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False}
CONTRACT_ROOT = Path(__file__).with_name("contracts")
_TOOL_CONTRACTS = (
    (
        "entity_resolve",
        "entity-resolve.request.schema.json",
        "解析产品或产业目录 mention，并仅在全部 mention 唯一解析时返回 resolvedPlan。",
    ),
    (
        "business_query",
        "business-query.request.schema.json",
        "执行已解析计划中受支持的产业 CHILDREN 与产品或产业 PARENT_PATH 查询。",
    ),
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


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_schema(name: str) -> dict[str, Any]:
    value = json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("public contract unavailable")
    return value


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": description,
            "annotations": copy.deepcopy(TOOL_ANNOTATIONS),
            "inputSchema": _read_schema(schema_name),
        }
        for name, schema_name, description in _TOOL_CONTRACTS
    ]


def _reject_constant(_value: str) -> None:
    raise ValueError("invalid JSON constant")


def _parse_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _assert_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    if isinstance(value, dict):
        for child in value.values():
            _assert_finite(child)
    elif isinstance(value, list):
        for child in value:
            _assert_finite(child)


def _json_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(child) for child in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(child) for child in value), default=0)
    return 0


def _write_line(output_stream: BinaryIO, value: dict[str, Any]) -> None:
    encoded = _canonical_json(value) + b"\n"
    written = output_stream.write(encoded)
    if written is None or written != len(encoded):
        raise OSError("short protocol write")
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
    if len(raw) > MAX_JSON_LINE_BYTES or not raw.endswith(b"\n"):
        _drain_overlong(input_stream, raw)
        return None, True
    try:
        return raw[:-1].decode("utf-8"), False
    except UnicodeDecodeError:
        return None, True


def _parse_request(text: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
        _assert_finite(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _ProtocolError("parse_error", parse=True) from exc
    if not isinstance(value, dict) or _json_depth(value) > MAX_JSON_DEPTH:
        raise _ProtocolError("parse_error", parse=True)
    return value


def _safe_id(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise _ProtocolError("invalid_request")


def _error_response(request_id: Any, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": _ERRORS[message], "message": message},
    }


def _success_response(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _validate_base(request: dict[str, Any]) -> tuple[Any, str, Any]:
    if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        raise _ProtocolError("invalid_request")
    request_id = request.get("id")
    if "id" in request:
        _safe_id(request_id)
    if not set(request) <= {"jsonrpc", "id", "method", "params"}:
        raise _ProtocolError("invalid_request")
    return request_id, request["method"], request.get("params")


def _tool_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("invalid bridge result")
    result = {
        "content": [
            {"type": "text", "text": _canonical_json(value).decode("utf-8")}
        ]
    }
    if value.get("success") is False:
        result["isError"] = True
    return result


def _without_request_meta(params: Any) -> dict[str, Any] | None:
    """Validate and remove common MCP request metadata before dispatch."""
    if not isinstance(params, dict):
        return None
    if "_meta" in params and not isinstance(params["_meta"], dict):
        return None
    return {key: value for key, value in params.items() if key != "_meta"}


def _dispatch(request: dict[str, Any], bridge: Any) -> dict[str, Any] | None:
    request_id, method, params = _validate_base(request)
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    if method == "initialize":
        params = _without_request_meta(params)
        if not (
            isinstance(params, dict)
            and set(params) == {"protocolVersion", "capabilities", "clientInfo"}
            and isinstance(params.get("protocolVersion"), str)
            and isinstance(params.get("capabilities"), dict)
            and isinstance(params.get("clientInfo"), dict)
        ):
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
        params = _without_request_meta(params)
        if params != {}:
            raise _ProtocolError("invalid_params")
        return _success_response(request_id, {})
    if method == "tools/list":
        if params is None:
            params = {}
        params = _without_request_meta(params)
        if params != {}:
            raise _ProtocolError("invalid_params")
        return _success_response(request_id, {"tools": tool_definitions()})
    if method != "tools/call":
        raise _ProtocolError("method_not_found")
    params = _without_request_meta(params)
    if not (
        isinstance(params, dict)
        and set(params) <= {"name", "arguments"}
        and isinstance(params.get("name"), str)
        and ("arguments" not in params or isinstance(params["arguments"], dict))
    ):
        raise _ProtocolError("invalid_params")
    name = params["name"]
    arguments = params.get("arguments", {})
    if name == "entity_resolve":
        value = bridge.entity_resolve(arguments)
    elif name == "business_query":
        value = bridge.business_query(arguments)
    else:
        raise _ProtocolError("invalid_params")
    return _success_response(request_id, _tool_result(value))


def serve(input_stream: BinaryIO, output_stream: BinaryIO, *, bridge: Any) -> int:
    try:
        while True:
            try:
                text, malformed = _decode_line(input_stream)
            except Exception:
                return 1
            if text is None and not malformed:
                return 0
            if malformed:
                try:
                    _write_line(output_stream, _error_response(None, "parse_error"))
                except Exception:
                    return 1
                continue
            try:
                request = _parse_request(text)
            except _ProtocolError:
                try:
                    _write_line(output_stream, _error_response(None, "parse_error"))
                except Exception:
                    return 1
                continue
            if "id" not in request:
                continue
            request_id: Any = None
            try:
                request_id = _safe_id(request.get("id"))
                response = _dispatch(request, bridge)
                if response is not None:
                    _write_line(output_stream, response)
            except _ProtocolError as error:
                try:
                    _write_line(output_stream, _error_response(request_id, error.message))
                except Exception:
                    return 1
            except Exception:
                try:
                    _write_line(output_stream, _error_response(request_id, "internal_error"))
                except Exception:
                    return 1
    finally:
        close = getattr(bridge, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def create_bridge() -> IndustrySelectionBridge:
    return IndustrySelectionBridge()


def main() -> int:
    try:
        bridge = create_bridge()
    except Exception:
        sys.stderr.write("INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        sys.stderr.flush()
        return 1
    try:
        return serve(sys.stdin.buffer, sys.stdout.buffer, bridge=bridge)
    except Exception:
        sys.stderr.write("INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
