"""Public two-tool MCP server for the real industry-selection bridge."""

from __future__ import annotations

import copy
import importlib.util
import json
import math
import os
import signal
import sys
from pathlib import Path
from typing import Any, BinaryIO

from industry_selection_bridge import IndustrySelectionBridge


def _load_shared_schema_client() -> Any:
    module_path = (
        Path(__file__).resolve().parents[1]
        / "kingbase-readonly-mcp"
        / "schema_client.py"
    )
    spec = importlib.util.spec_from_file_location(
        "_industry_selection_shared_schema_client",
        module_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError("shared schema client unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SHARED_SCHEMA_CLIENT = _load_shared_schema_client()
SchemaClient = _SHARED_SCHEMA_CLIENT.SchemaClient
SchemaUnavailable = _SHARED_SCHEMA_CLIENT.SchemaUnavailable


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "industry-stock-selection-local"
SERVER_VERSION = "1.0.0"
MAX_JSON_LINE_BYTES = 1_048_576
MAX_JSON_DEPTH = 64
TOOL_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False}
CONTRACT_ROOT = Path(__file__).with_name("contracts")
SCHEMA_WORKER = Path(__file__).with_name("schema_worker.mjs")
PUBLIC_SCHEMA_CONTRACTS = frozenset(
    {
        "entityResolveRequest",
        "entityResolveResponse",
        "businessQueryRequest",
        "businessQueryResponse",
    }
)
SCHEMA_STARTUP_PROBE = (
    "entityResolveResponse",
    {
        "success": False,
        "operation": "entity_resolve",
        "mockData": False,
        "resolutionResults": [],
        "resolvedPlan": None,
        "errorCode": "INTERNAL_ERROR",
        "message": "catalog resolution is unavailable",
        "retryable": False,
    },
)
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


def _assert_safe_json(value: Any) -> None:
    pending = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if isinstance(current, float) and not math.isfinite(current):
            raise ValueError("non-finite JSON number")
        if not isinstance(current, (dict, list)):
            continue
        child_depth = depth + 1
        if child_depth > MAX_JSON_DEPTH:
            raise ValueError("JSON depth exceeded")
        children = current.values() if isinstance(current, dict) else current
        pending.extend((child, child_depth) for child in children)


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
        _assert_safe_json(value)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _ProtocolError("parse_error", parse=True) from exc
    if not isinstance(value, dict):
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


def _schema_valid(schema_client: Any, contract: str, instance: Any) -> bool:
    valid = schema_client.validate(contract, instance)
    if not isinstance(valid, bool):
        raise RuntimeError("invalid schema result")
    return valid


def _dispatch(
    request: dict[str, Any], bridge: Any, schema_client: Any
) -> dict[str, Any] | None:
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
        request_contract = "entityResolveRequest"
        response_contract = "entityResolveResponse"
    elif name == "business_query":
        request_contract = "businessQueryRequest"
        response_contract = "businessQueryResponse"
    else:
        raise _ProtocolError("invalid_params")
    if not _schema_valid(schema_client, request_contract, arguments):
        raise _ProtocolError("invalid_params")
    if name == "entity_resolve":
        value = bridge.entity_resolve(arguments)
    else:
        value = bridge.business_query(arguments)
    if not _schema_valid(schema_client, response_contract, value):
        raise RuntimeError("invalid bridge result")
    return _success_response(request_id, _tool_result(value))


def _close_resource(resource: Any) -> None:
    close = getattr(resource, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def serve(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    bridge: Any,
    schema_client: Any,
) -> int:
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
                response = _dispatch(request, bridge, schema_client)
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
        _close_resource(bridge)
        _close_resource(schema_client)


def create_bridge() -> IndustrySelectionBridge:
    return IndustrySelectionBridge()


def create_schema_client() -> SchemaClient:
    node_binary = os.environ.get("INDUSTRY_SCHEMA_NODE_BINARY")
    if not isinstance(node_binary, str) or not os.path.isabs(node_binary):
        raise RuntimeError("verified node binary required")
    return SchemaClient(
        node_binary=node_binary,
        worker_path=SCHEMA_WORKER,
        contracts=PUBLIC_SCHEMA_CONTRACTS,
        startup_probe=SCHEMA_STARTUP_PROBE,
    )


def _serve_with_signal_handlers(
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    bridge: Any,
    schema_client: Any,
) -> int:
    previous_handlers: list[tuple[int, Any]] = []
    entered_serve = False

    def stop(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    try:
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            previous_handlers.append((signum, signal.signal(signum, stop)))
        entered_serve = True
        return serve(
            input_stream,
            output_stream,
            bridge=bridge,
            schema_client=schema_client,
        )
    finally:
        if not entered_serve:
            _close_resource(bridge)
            _close_resource(schema_client)
        for signum, previous in reversed(previous_handlers):
            try:
                signal.signal(signum, previous)
            except Exception:
                pass


def main() -> int:
    schema_client = None
    try:
        schema_client = create_schema_client()
        bridge = create_bridge()
    except Exception:
        _close_resource(schema_client)
        sys.stderr.write("INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        sys.stderr.flush()
        return 1
    try:
        return _serve_with_signal_handlers(
            sys.stdin.buffer,
            sys.stdout.buffer,
            bridge=bridge,
            schema_client=schema_client,
        )
    except Exception:
        sys.stderr.write("INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
