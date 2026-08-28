"""
作者：elvis
日期：2026-08-19
作用：将无库 Slice 1 纯函数包装为只读 stdio MCP 工具
"""

import json
import math
import re
import sys
from typing import TextIO

from canonical import canon
from dbar1 import RecordRejected, scan_dbar1, validate_append_only
from envelope import EnvelopeTooLarge, build_result_too_large
from launch_scan_v1 import FakeProc, FdId, scan_v1
from ledger_sm import Ledger


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ai-database-analysis-local"
SERVER_VERSION = "0.1.0"
MAX_JSON_LINE_CHARS = 1_048_576
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ToolRejected(ValueError):
    """表示 MCP 工具输入或状态不符合无库 fixture 合同。"""


def _tool_result(value: object) -> dict:
    """将纯 JSON 值包装成不含额外诊断的 MCP text content。"""
    return _tool_text(canon(value).decode("utf-8"))


def _tool_text(text: str) -> dict:
    """将已经序列化的 JSON 文本原样放入 MCP content，避免二次编码。"""
    return {
        "content": [
            {
                "type": "text",
                "text": text,
            }
        ]
    }


def _tool_error(code: str) -> dict:
    """将安全错误码包装成 MCP 工具错误，不泄露 traceback。"""
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": canon({"error": code}).decode("utf-8"),
            }
        ],
    }


def _require_object(value: object, name: str) -> dict:
    """要求输入字段为 JSON object，并返回其字典值。"""
    if not isinstance(value, dict):
        raise ToolRejected(f"{name}_object")
    return value


def _require_exact_fields(
    value: object,
    allowed: set[str],
    required: set[str],
    name: str = "arguments",
) -> dict:
    """要求 object 只含合同字段，并拒绝缺失必填字段。"""
    obj = _require_object(value, name)
    if set(obj) - allowed:
        raise ToolRejected(f"{name}_extra_fields")
    if required - set(obj):
        raise ToolRejected(f"{name}_missing_fields")
    return obj


def _require_string(value: object, name: str) -> str:
    """要求输入字段为字符串，拒绝隐式类型转换。"""
    if not isinstance(value, str):
        raise ToolRejected(f"{name}_string")
    return value


def _require_integer(value: object, name: str) -> int:
    """要求输入字段为非布尔整数。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolRejected(f"{name}_integer")
    return value


def _require_positive_pid(value: object, name: str) -> int:
    """要求进程 fixture 的 PID 为正整数，与公开 schema 的 minimum=1 一致。"""
    pid = _require_integer(value, name)
    if pid < 1:
        raise ToolRejected(f"{name}_positive")
    return pid


def _require_sha256(value: object, name: str) -> str:
    """要求 digest fixture 为小写 64 位十六进制 SHA-256。"""
    digest = _require_string(value, name)
    if _SHA256_RE.fullmatch(digest) is None:
        raise ToolRejected(f"{name}_sha256")
    return digest


def _required(arguments: dict, name: str) -> object:
    """读取必填参数，不允许缺失字段静默降级。"""
    if name not in arguments:
        raise ToolRejected(f"missing_{name}")
    return arguments[name]


def _scan_dbar1_tool(arguments: dict) -> dict:
    """调用 DBAR1 扫描器并返回 recordKey 列表。"""
    arguments = _require_exact_fields(arguments, {"raw"}, {"raw"})
    raw = _require_string(_required(arguments, "raw"), "raw")
    return {"recordKeys": scan_dbar1(raw.encode("utf-8"))}


def _append_only_tool(arguments: dict) -> dict:
    """调用 SOURCE_REGISTER append-only validator。"""
    arguments = _require_exact_fields(
        arguments,
        {"preimage", "postimage", "recordKey"},
        {"preimage", "postimage", "recordKey"},
    )
    preimage = _require_string(_required(arguments, "preimage"), "preimage")
    postimage = _require_string(_required(arguments, "postimage"), "postimage")
    record_key = _require_string(_required(arguments, "recordKey"), "recordKey")
    validate_append_only(
        preimage.encode("utf-8"),
        postimage.encode("utf-8"),
        record_key,
    )
    return {"valid": True}


def _scan_v1_tool(arguments: dict) -> dict:
    """把 JSON fixture 映射为 V1 身份谓词输入，不接触真实进程表。"""
    arguments = _require_exact_fields(arguments, {"fd", "procs"}, {"fd", "procs"})
    fd_input = _require_exact_fields(
        _required(arguments, "fd"),
        {"canonicalPath", "device", "inode", "sha256"},
        {"canonicalPath", "device", "inode", "sha256"},
        "fd",
    )
    fd = FdId(
        canonical_path=_require_string(
            _required(fd_input, "canonicalPath"), "canonicalPath"
        ),
        device=_require_string(_required(fd_input, "device"), "device"),
        inode=_require_string(_required(fd_input, "inode"), "inode"),
        sha256=_require_sha256(_required(fd_input, "sha256"), "sha256"),
    )
    procs_input = _required(arguments, "procs")
    if procs_input is None:
        procs = None
    elif isinstance(procs_input, list):
        procs = []
        for index, proc_input in enumerate(procs_input):
            proc = _require_exact_fields(
                proc_input,
                {"pid", "device", "inode", "sha256"},
                {"pid", "device", "inode", "sha256"},
                f"procs_{index}",
            )
            procs.append(
                FakeProc(
                    pid=_require_positive_pid(_required(proc, "pid"), "pid"),
                    device=_require_string(_required(proc, "device"), "device"),
                    inode=_require_string(_required(proc, "inode"), "inode"),
                    sha256=_require_sha256(_required(proc, "sha256"), "sha256"),
                )
            )
    else:
        raise ToolRejected("procs_array_or_null")
    result = scan_v1(fd, procs)
    return {
        "scanComplete": result.scan_complete,
        "matchedPids": result.matched_pids,
    }


def _ledger_snapshot(ledger: Ledger) -> dict:
    """提取 Ledger 的确定性 fixture 状态，不暴露内部时钟或对象。"""
    return {
        "status": ledger.status,
        "session": ledger.session,
        "inFlight": ledger.in_flight,
        "spawned": ledger.spawned,
        "lastExternalPossible": ledger.last_external_possible,
        "cleanupChildPid": ledger.cleanup_child_pid,
        "reservedAtMs": ledger.reserved_at_ms,
    }


def _ledger_tool(arguments: dict) -> dict:
    """按显式事件序列运行最小 Ledger fixture，不持久化状态。"""
    arguments = _require_exact_fields(arguments, {"events"}, {"events"})
    events_input = _required(arguments, "events")
    if not isinstance(events_input, list):
        raise ToolRejected("events_array")
    ledger = Ledger()
    results = []
    for index, event_input in enumerate(events_input):
        event = _require_object(event_input, f"events_{index}")
        op = _require_string(_required(event, "op"), "op")
        field_rules = {
            "reserve": ({"op", "nowMs"}, {"op"}),
            "reportSpawnOk": ({"op", "pid", "audit", "nowMs"}, {"op", "pid", "audit"}),
            "reportSpawnFail": (
                {"op", "externalPossible", "digest", "nowMs"},
                {"op", "externalPossible", "digest"},
            ),
            "deadlineElapsed": ({"op", "nowMs"}, {"op"}),
            "refusePermit": ({"op", "reason"}, {"op", "reason"}),
        }
        if op not in field_rules:
            raise ToolRejected("unknown_ledger_op")
        allowed, required = field_rules[op]
        event = _require_exact_fields(event, allowed, required, f"events_{index}")
        now_ms = None
        if "nowMs" in event:
            now_ms = _require_integer(event["nowMs"], "nowMs")
        if op == "reserve":
            result = ledger.reserve(now_ms=now_ms)
        elif op == "reportSpawnOk":
            result = ledger.report_spawn_ok(
                pid=_require_integer(_required(event, "pid"), "pid"),
                audit=_require_string(_required(event, "audit"), "audit"),
                now_ms=now_ms,
            )
        elif op == "reportSpawnFail":
            external_possible = _required(event, "externalPossible")
            if not isinstance(external_possible, bool):
                raise ToolRejected("externalPossible_boolean")
            result = ledger.report_spawn_fail(
                external_possible=external_possible,
                digest=_require_string(_required(event, "digest"), "digest"),
                now_ms=now_ms,
            )
        elif op == "deadlineElapsed":
            result = ledger.deadline_elapsed(now_ms=now_ms)
        elif op == "refusePermit":
            result = ledger.refuse_permit(
                reason=_require_string(_required(event, "reason"), "reason")
            )
        results.append({"op": op, "result": result})
    return {"events": results, "snapshot": _ledger_snapshot(ledger)}


def _scope_item_schema(kind: str) -> dict:
    """返回无库 scope fixture 的封闭 item schema。"""
    if kind == "dataObject":
        properties = {
            "schema": {"type": "string"},
            "object": {"type": "string"},
            "objectKind": {"type": "string"},
        }
        required = ["schema", "object", "objectKind"]
    elif kind == "column":
        properties = {
            "schema": {"type": "string"},
            "object": {"type": "string"},
            "column": {"type": "string"},
        }
        required = ["schema", "object", "column"]
    else:
        properties = {
            "schema": {"type": "string"},
            "object": {"type": "string"},
            "metrics": {"type": "array", "items": {"type": "string"}},
        }
        required = ["schema", "object", "metrics"]
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _validate_scope_fixture(scope: object) -> dict:
    """严格校验 envelope fixture，避免忽略未知 scope 字段。"""
    fields = {
        "businessCatalogSchemas",
        "dataObjects",
        "valueColumns",
        "sampleColumns",
        "sqlColumns",
        "statsGrants",
        "metadataOnly",
    }
    scope = _require_exact_fields(scope, fields, fields, "scope")
    for name in fields - {"metadataOnly"}:
        if not isinstance(scope[name], list):
            raise ToolRejected(f"{name}_array")
    if not isinstance(scope["metadataOnly"], bool):
        raise ToolRejected("metadataOnly_boolean")
    for index, value in enumerate(scope["businessCatalogSchemas"]):
        _require_string(value, f"businessCatalogSchemas_{index}")
    for name, kind in (
        ("dataObjects", "dataObject"),
        ("valueColumns", "column"),
        ("sampleColumns", "column"),
        ("sqlColumns", "column"),
        ("statsGrants", "stats"),
    ):
        for index, value in enumerate(scope[name]):
            item = _require_exact_fields(
                value,
                set(_scope_item_schema(kind)["properties"]),
                set(_scope_item_schema(kind)["required"]),
                f"{name}_{index}",
            )
            for field in item:
                if field == "metrics":
                    if not isinstance(item[field], list):
                        raise ToolRejected(f"{name}_{index}_metrics_array")
                    for metric_index, metric in enumerate(item[field]):
                        _require_string(metric, f"{name}_{index}_metrics_{metric_index}")
                else:
                    _require_string(item[field], f"{name}_{index}_{field}")
    return scope


def _call_tool(name: object, arguments: object) -> dict:
    """分发固定工具名，并将所有拒绝收敛为安全 MCP 工具错误。"""
    if not isinstance(name, str):
        return _tool_error("tool_name_string")
    try:
        args = _require_object(arguments, "arguments")
        if name == "canonicalize":
            args = _require_exact_fields(args, {"value"}, {"value"})
            return _tool_text(canon(_required(args, "value")).decode("utf-8"))
        if name == "scan_dbar1":
            return _tool_result(_scan_dbar1_tool(args))
        if name == "validate_append_only":
            return _tool_result(_append_only_tool(args))
        if name == "scan_v1_fixture":
            return _tool_result(_scan_v1_tool(args))
        if name == "ledger_probe":
            return _tool_result(_ledger_tool(args))
        if name == "build_result_too_large":
            args = _require_exact_fields(args, {"scope"}, {"scope"})
            scope = _validate_scope_fixture(_required(args, "scope"))
            return _tool_result(build_result_too_large(scope))
        return _tool_error("unknown_tool")
    except RecordRejected as exc:
        return _tool_error(str(exc) or "record_rejected")
    except EnvelopeTooLarge:
        return _tool_error("envelope_rejected")
    except RuntimeError:
        return _tool_error("invalid_transition")
    except (KeyError, TypeError, UnicodeError, ValueError, ToolRejected):
        return _tool_error("invalid_input")


def _tool_definitions() -> list[dict]:
    """返回固定工具清单，所有工具显式标记为只读 fixture。"""
    annotation = {"readOnlyHint": True, "destructiveHint": False}
    sha256_schema = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    fd_schema = {
        "type": "object",
        "properties": {
            "canonicalPath": {"type": "string"},
            "device": {"type": "string"},
            "inode": {"type": "string"},
            "sha256": sha256_schema,
        },
        "required": ["canonicalPath", "device", "inode", "sha256"],
        "additionalProperties": False,
    }
    proc_schema = {
        "type": "object",
        "properties": {
            "pid": {"type": "integer", "minimum": 1},
            "device": {"type": "string"},
            "inode": {"type": "string"},
            "sha256": sha256_schema,
        },
        "required": ["pid", "device", "inode", "sha256"],
        "additionalProperties": False,
    }
    ledger_event_schemas = [
        {
            "type": "object",
            "properties": {"op": {"const": "reserve"}, "nowMs": {"type": "integer"}},
            "required": ["op"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "op": {"const": "reportSpawnOk"},
                "pid": {"type": "integer", "minimum": 1},
                "audit": sha256_schema,
                "nowMs": {"type": "integer"},
            },
            "required": ["op", "pid", "audit"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "op": {"const": "reportSpawnFail"},
                "externalPossible": {"type": "boolean"},
                "digest": sha256_schema,
                "nowMs": {"type": "integer"},
            },
            "required": ["op", "externalPossible", "digest"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {"op": {"const": "deadlineElapsed"}, "nowMs": {"type": "integer"}},
            "required": ["op"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {"op": {"const": "refusePermit"}, "reason": {"type": "string"}},
            "required": ["op", "reason"],
            "additionalProperties": False,
        },
    ]
    scope_fields = {
        "businessCatalogSchemas": {"type": "array", "items": {"type": "string"}},
        "dataObjects": {"type": "array", "items": _scope_item_schema("dataObject")},
        "valueColumns": {"type": "array", "items": _scope_item_schema("column")},
        "sampleColumns": {"type": "array", "items": _scope_item_schema("column")},
        "sqlColumns": {"type": "array", "items": _scope_item_schema("column")},
        "statsGrants": {"type": "array", "items": _scope_item_schema("stats")},
        "metadataOnly": {"type": "boolean"},
    }
    closed_scope_schema = {
        "type": "object",
        "properties": scope_fields,
        "required": list(scope_fields),
        "additionalProperties": False,
    }
    return [
        {
            "name": "canonicalize",
            "description": "Canonicalize a JSON fixture value; no external access.",
            "inputSchema": {
                "type": "object",
                "properties": {"value": {}},
                "required": ["value"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
        {
            "name": "scan_dbar1",
            "description": "Scan DBAR1 fixture text and return record keys.",
            "inputSchema": {
                "type": "object",
                "properties": {"raw": {"type": "string"}},
                "required": ["raw"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
        {
            "name": "validate_append_only",
            "description": "Validate one append-only DBAR1 fixture delta.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "preimage": {"type": "string"},
                    "postimage": {"type": "string"},
                    "recordKey": {"type": "string"},
                },
                "required": ["preimage", "postimage", "recordKey"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
        {
            "name": "scan_v1_fixture",
            "description": "Run the V1 launch identity predicate over injected fixtures.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "fd": fd_schema,
                    "procs": {
                        "anyOf": [
                            {"type": "null"},
                            {"type": "array", "items": proc_schema},
                        ]
                    },
                },
                "required": ["fd", "procs"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
        {
            "name": "ledger_probe",
            "description": "Run an explicit no-persistence Ledger event fixture.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "events": {
                        "type": "array",
                        "items": {"oneOf": ledger_event_schemas},
                    }
                },
                "required": ["events"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
        {
            "name": "build_result_too_large",
            "description": "Build the bounded RESULT_TOO_LARGE response fixture.",
            "inputSchema": {
                "type": "object",
                "properties": {"scope": closed_scope_schema},
                "required": ["scope"],
                "additionalProperties": False,
            },
            "annotations": annotation,
        },
    ]


def _response(request_id: object, result: dict) -> dict:
    """创建 JSON-RPC 成功响应。"""
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: object, code: int, message: str) -> dict:
    """创建不含内部细节的 JSON-RPC 错误响应。"""
    return {
        "jsonrpc": "2.0",
        "id": _safe_request_id(request_id),
        "error": {"code": code, "message": message},
    }


def _safe_request_id(value: object) -> object:
    """只允许可安全编码的 JSON-RPC id，非法值统一降为 null。"""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return None
        return value
    return None


def _invalid_params(is_notification: bool, request_id: object) -> dict | None:
    """为非法 params 生成 JSON-RPC 错误；通知仍不返回响应。"""
    if is_notification:
        return None
    return _error_response(request_id, -32602, "invalid_params")


def _valid_initialize_params(params: dict) -> bool:
    """验证 initialize 的最小固定 fixture 参数。"""
    if set(params) != {"protocolVersion", "capabilities", "clientInfo"}:
        return False
    return (
        isinstance(params["protocolVersion"], str)
        and isinstance(params["capabilities"], dict)
        and isinstance(params["clientInfo"], dict)
    )


def dispatch(request: object) -> dict | None:
    """分发单条 JSON-RPC 请求；通知不产生 stdout 响应。"""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return _error_response(None, -32600, "invalid_request")
    method = request.get("method")
    raw_request_id = request.get("id")
    request_id = _safe_request_id(raw_request_id)
    if "id" in request and raw_request_id is not None and request_id is None:
        return _error_response(None, -32600, "invalid_request")
    if not isinstance(method, str):
        return _error_response(None, -32600, "invalid_request")
    is_notification = "id" not in request
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    if method == "initialize":
        params = request.get("params", {})
        if not isinstance(params, dict) or not _valid_initialize_params(params):
            return _invalid_params(is_notification, request_id)
        if is_notification:
            return None
        return _response(
            request_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )
    if method == "ping":
        params = request.get("params", {})
        if not isinstance(params, dict) or params:
            return _invalid_params(is_notification, request_id)
        return None if is_notification else _response(request_id, {})
    if method == "tools/list":
        params = request.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            return _invalid_params(is_notification, request_id)
        if set(params) - {"cursor"} or (
            "cursor" in params and not isinstance(params["cursor"], str)
        ):
            return _invalid_params(is_notification, request_id)
        return None if is_notification else _response(request_id, {"tools": _tool_definitions()})
    if method == "tools/call":
        params = request.get("params")
        if not isinstance(params, dict):
            return _invalid_params(is_notification, request_id)
        if set(params) - {"name", "arguments"} or "name" not in params:
            return _invalid_params(is_notification, request_id)
        if not isinstance(params["name"], str):
            return _invalid_params(is_notification, request_id)
        if "arguments" in params and not isinstance(params["arguments"], dict):
            return _invalid_params(is_notification, request_id)
        result = _call_tool(params.get("name"), params.get("arguments", {}))
        return None if is_notification else _response(request_id, result)
    return None if is_notification else _error_response(request_id, -32601, "method_not_found")


def serve(input_stream: TextIO, output_stream: TextIO) -> None:
    """处理逐行 JSON-RPC stdio；stdout 仅输出协议 JSON。"""
    for line in input_stream:
        if not line.strip():
            continue
        response = None
        try:
            if len(line) > MAX_JSON_LINE_CHARS:
                raise ValueError("input line too large")
            request = json.loads(line)
        except (json.JSONDecodeError, RecursionError, TypeError, UnicodeError, ValueError):
            response = _error_response(None, -32700, "parse_error")
        else:
            try:
                response = dispatch(request)
            except Exception:
                response = _error_response(None, -32603, "internal_error")
        if response is not None:
            try:
                encoded_response = canon(response).decode("utf-8")
            except Exception:
                encoded_response = canon(
                    _error_response(None, -32603, "internal_error")
                ).decode("utf-8")
            output_stream.write(encoded_response + "\n")
            output_stream.flush()


def main() -> None:
    """启动标准输入输出上的无库 MCP 适配层。"""
    serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    main()
