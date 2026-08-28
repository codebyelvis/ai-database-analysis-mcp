"""
作者：elvis
日期：2026-08-18
作用：生成 compact evidence.scope 并校验工具响应字节上限
"""

import re
from hashlib import sha256

from canonical import canon


MAX_RESPONSE_BYTES = 32768
_SCOPE_FIELDS = (
    "businessCatalogSchemas",
    "dataObjects",
    "valueColumns",
    "sampleColumns",
    "sqlColumns",
    "statsGrants",
    "metadataOnly",
)
_COUNT_FIELDS = _SCOPE_FIELDS[:-1]


class EnvelopeTooLarge(ValueError):
    """表示 canonical response 超过固定的 UTF-8 字节预算。"""


def _scope_payload(scope: dict) -> dict:
    """提取 scope hash 的固定字段，避免把额外字段带入合同摘要。"""
    if not isinstance(scope, dict) or not set(_SCOPE_FIELDS).issubset(scope):
        raise EnvelopeTooLarge("scope must contain fixed fields")
    for field in _COUNT_FIELDS:
        if not isinstance(scope[field], list):
            raise EnvelopeTooLarge(f"scope.{field} must be an array")
    if not isinstance(scope["metadataOnly"], bool):
        raise EnvelopeTooLarge("scope.metadataOnly must be boolean")
    return {
        field: scope[field]
        for field in _SCOPE_FIELDS
    }


def _short_text(value: str) -> str:
    """按 Unicode code point 截取 compact preview。"""
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise EnvelopeTooLarge("preview text must be a safe string")
    return value[:32]


def _validate_preview_text(value: str) -> None:
    """验证 compact preview 的字符串类型、控制字符与 32 code point 上限。"""
    if not isinstance(value, str) or not 1 <= len(value) <= 32 or any(ord(char) < 32 for char in value):
        raise EnvelopeTooLarge("preview text is invalid")


def _preview_identifier(identifier: dict) -> dict:
    """生成不包含 oid 的短 identifier preview。"""
    preview = {}
    for key in ("schema", "object", "column"):
        if key in identifier:
            preview[key] = _short_text(identifier[key])
    return preview


def compact_scope(scope: dict) -> dict:
    """将完整授权范围压缩为固定 hash、计数和最多三项 preview。"""
    payload = _scope_payload(scope)
    for item in payload["dataObjects"]:
        if not isinstance(item, dict) or not {"schema", "object", "objectKind"}.issubset(item):
            raise EnvelopeTooLarge("dataObjects preview source is invalid")
    for item in payload["valueColumns"]:
        if not isinstance(item, dict) or not {"schema", "object", "column"}.issubset(item):
            raise EnvelopeTooLarge("valueColumns preview source is invalid")
    preview = {
        "businessCatalogSchemas": [
            _short_text(item)
            for item in payload["businessCatalogSchemas"][:3]
        ],
        "dataObjects": [
            {
                **_preview_identifier(item),
                "objectKind": _short_text(item["objectKind"]),
            }
            for item in payload["dataObjects"][:3]
        ],
        "valueColumns": [
            _preview_identifier(item)
            for item in payload["valueColumns"][:3]
        ],
    }
    counts = {field: len(payload[field]) for field in _COUNT_FIELDS}
    digest = sha256(canon(payload)).hexdigest()
    return {
        "scopeSha256": digest,
        "counts": counts,
        "preview": preview,
    }


def response_bytes(response: dict) -> int:
    """返回完整 canonical response 的 UTF-8 字节数。"""
    return len(canon(response))


def validate_response_size(response: dict) -> None:
    """拒绝超出字节预算或使用完整 scope 回显的 response。"""
    evidence = response.get("evidence")
    if not isinstance(evidence, dict):
        raise EnvelopeTooLarge("evidence must be an object")
    scope = evidence.get("scope")
    _validate_compact_scope(scope)
    serialized_bytes = evidence.get("serializedBytes")
    if (
        isinstance(serialized_bytes, bool)
        or not isinstance(serialized_bytes, int)
        or serialized_bytes < 0
    ):
        raise EnvelopeTooLarge("serializedBytes must be a non-negative integer")
    size = response_bytes(response)
    if serialized_bytes != size:
        raise EnvelopeTooLarge("serializedBytes does not match canonical response size")
    if size > MAX_RESPONSE_BYTES:
        raise EnvelopeTooLarge(f"response bytes={size}")


def _validate_compact_scope(scope: dict) -> None:
    """严格验证 compact scope，拒绝额外字段、错误类型与超长 preview。"""
    if not isinstance(scope, dict) or set(scope) != {"scopeSha256", "counts", "preview"}:
        raise EnvelopeTooLarge("evidence.scope must be compact")
    if not isinstance(scope["scopeSha256"], str) or re.fullmatch(r"[0-9a-f]{64}", scope["scopeSha256"]) is None:
        raise EnvelopeTooLarge("scopeSha256 is invalid")
    count_limits = {"businessCatalogSchemas": 3, "dataObjects": 50, "valueColumns": 100, "sampleColumns": 100, "sqlColumns": 100, "statsGrants": 100}
    if not isinstance(scope["counts"], dict) or set(scope["counts"]) != set(count_limits):
        raise EnvelopeTooLarge("scope counts are invalid")
    for field, maximum in count_limits.items():
        value = scope["counts"][field]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise EnvelopeTooLarge("scope count is invalid")
    preview = scope["preview"]
    if not isinstance(preview, dict) or set(preview) != {"businessCatalogSchemas", "dataObjects", "valueColumns"}:
        raise EnvelopeTooLarge("scope preview is invalid")
    schemas = preview["businessCatalogSchemas"]
    if not isinstance(schemas, list) or len(schemas) > 3:
        raise EnvelopeTooLarge("scope schema preview is invalid")
    for value in schemas:
        _validate_preview_text(value)
    for field, required in (
        ("dataObjects", {"schema", "object", "objectKind"}),
        ("valueColumns", {"schema", "object", "column"}),
    ):
        values = preview[field]
        if not isinstance(values, list) or len(values) > 3:
            raise EnvelopeTooLarge("scope identifier preview is invalid")
        for item in values:
            if not isinstance(item, dict) or set(item) != required:
                raise EnvelopeTooLarge("scope identifier preview is invalid")
            for key in required:
                _validate_preview_text(item[key])


def _finalize_serialized_bytes(response: dict) -> dict:
    """写入最终 serializedBytes，并在固定迭代次数内收敛。"""
    evidence = response["evidence"]
    evidence["serializedBytes"] = 0
    for _ in range(3):
        size = response_bytes(response)
        evidence["serializedBytes"] = size
        final_size = response_bytes(response)
        if final_size == size:
            validate_response_size(response)
            return response
        evidence["serializedBytes"] = final_size
    raise EnvelopeTooLarge("serializedBytes did not converge")


def build_result_too_large(scope: dict) -> dict:
    """创建不携带数据库行、且使用 compact scope 的最小失败 envelope。"""
    response = {
        "contractVersion": "1",
        "requestId": "00000000-0000-0000-0000-000000000001",
        "runId": "00000000-0000-0000-0000-000000000002",
        "callSequence": 1,
        "authorizationSha256": "0" * 64,
        "toolContractSha256": "0" * 64,
        "status": "RESULT_TOO_LARGE",
        "truncated": False,
        "data": None,
        "page": None,
        "evidence": {
            "toolName": "fixture",
            "profileId": "fixture",
            "scope": compact_scope(scope),
            "executedAt": "1970-01-01T00:00:00Z",
            "durationMs": 0,
            "rowsReturned": 0,
            "serializedBytes": 0,
            "queryFingerprint": "0" * 64,
            "databaseTouched": False,
        },
        "issues": [
            {
                "code": "EVIDENCE_TOO_LARGE",
                "safeMessage": "response exceeds byte limit",
                "retryable": False,
            }
        ],
    }
    return _finalize_serialized_bytes(response)
