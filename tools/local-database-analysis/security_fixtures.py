"""
作者：elvis
日期：2026-08-19
作用：提供 revision 12 完整无库安全边界的确定性 fixture 与校验器
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import random
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from canonical import canon


class FixtureRejected(ValueError):
    """表示无库安全 fixture 不满足冻结合同。"""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


LIVE_RUN_STATES = (
    "ACTIVE_UNPREFLIGHTED",
    "IN_FLIGHT_PREFLIGHT",
    "ACTIVE_READY",
    "IN_FLIGHT_TOOL",
    "QUERY_CLOSED",
    "EVIDENCE_IN_FLIGHT",
    "REVOKE_PENDING_CLEANUP",
)
TERMINAL_RUN_STATES = ("REVOKED", "EXPIRED", "CLOSED")
REPORT_SPAWN_DEADLINE_MS = 3000
CONNECT_TIMEOUT_MS = 3000
EXECUTION_DEADLINE_MS = 15000
TEARDOWN_GRACE_MS = 2000
DATABASE_PERMIT_LEASE_MS = 20000
EVIDENCE_PERMIT_LEASE_MS = 60000
MAX_DATABASE_CALLS = 15
MAX_SEARCH_PAGE_SIZE = 20
MAX_SEARCH_CANDIDATES = 60
PAGE_TOKEN_TTL_MS = 60_000
MAX_EVIDENCE_TARGETS = 3
MAX_EVIDENCE_FILE_BYTES = 65536
MAX_EVIDENCE_TOTAL_BYTES = 131072
MAX_RESPONSE_BYTES = 32768
LAUNCH_SCAN_ALGORITHM = "MACOS_PROCESS_LIST_MATCH_LAUNCH_IDENTITY_V1"
PAGE_TOKEN_MAC_KEY = b"fixture-page-token-mac-key-v1"
FIXTURE_EXECUTABLE_FD_IDENTITY = {
    "canonicalPath": "/fixture/toolbox",
    "device": "1",
    "inode": "2",
    "sha256": "b" * 64,
}
SYSTEM_ROUTINE_METADATA = {
    "pg_catalog.random": {
        "identityArguments": "()",
        "routineKind": "FUNCTION",
        "ownerPrincipal": "pg_catalog",
        "securityType": "INVOKER",
        "volatility": "VOLATILE",
    },
    "pg_catalog.clock_timestamp": {
        "identityArguments": "()",
        "routineKind": "FUNCTION",
        "ownerPrincipal": "pg_catalog",
        "securityType": "INVOKER",
        "volatility": "VOLATILE",
    },
}

ALL_COMPONENTS = (
    "BROKER",
    "LEDGER",
    "TRUSTED_HELPER",
    "GATEWAY",
    "PARSER",
    "TOOLBOX",
    "COMMIT_EVIDENCE",
    "TOOL_CONTRACT",
    "PROFILE",
    "CLASSIFICATION",
)
DATA_COMPONENTS = {"TOOL_CONTRACT", "PROFILE", "CLASSIFICATION"}
PRIVILEGE_CHECKS = (
    "CAPABILITY_SIGNATURE",
    "LEDGER_STATE",
    "COMPONENT_MANIFEST",
    "TRUSTED_HELPER",
    "CREDENTIAL_ISOLATION",
    "CONNECT",
    "BUSINESS_SCHEMA_USAGE",
    "PROFILE_DATA_SELECT_BOUND",
    "RUN_DATA_SCOPE_SUBSET",
    "NO_EXTRA_SELECT",
    "NO_BYPASSRLS",
    "NO_NON_SYSTEM_OWNERSHIP",
    "NO_SET_ROLE_ESCALATION",
    "NO_WRITE",
    "NO_CREATE_TEMP",
    "NO_FILE_PROGRAM",
    "ROUTINE",
    "IMPLEMENTATION_CATALOG",
    "SESSION_READ_ONLY",
    "TIMEOUTS",
    "COLUMN_CLASSIFICATION",
)
ISSUE_CODES = (
    "AUTH_SIGNATURE_INVALID",
    "AUTH_REPLAY",
    "AUTH_SCOPE_MISMATCH",
    "AUTH_EXPIRED",
    "CALL_BUDGET_EXHAUSTED",
    "PREFLIGHT_REQUIRED",
    "PREFLIGHT_PRIVILEGE",
    "CREDENTIAL_BOUNDARY",
    "ROUTINE_RISK",
    "OWNERSHIP_RISK",
    "OBJECT_KIND_DENIED",
    "CATALOG_IDENTITY_DRIFT",
    "SENSITIVE_COLUMN",
    "UNKNOWN_COLUMN",
    "TOOL_DISABLED",
    "INVALID_IDENTIFIER",
    "INVALID_QUERY",
    "OBJECT_DRIFT",
    "RESULT_TRUNCATED",
    "EVIDENCE_TOO_LARGE",
    "DB_ERROR_REDACTED",
    "DEPENDENCY_UNAVAILABLE",
    "LEDGER_UNAVAILABLE",
    "LEDGER_CORRUPT",
    "INTERNAL_FAILURE",
)
TOOL_NAMES = (
    "db_preflight",
    "search_objects",
    "describe_object",
    "get_table_stats",
    "sample_rows",
    "execute_readonly_sql",
)
TOOL_STATUSES = (
    "OK",
    "EMPTY",
    "TRUNCATED",
    "AUTH_EXPIRED",
    "CALL_BUDGET_EXHAUSTED",
    "SCOPE_DENIED",
    "POLICY_DENIED",
    "PREFLIGHT_FAILED",
    "INVALID_REQUEST",
    "NOT_FOUND",
    "DRIFT",
    "TIMEOUT",
    "DEPENDENCY_ERROR",
    "RESULT_TOO_LARGE",
    "INTERNAL_ERROR",
)
SUCCESS_STATUSES = {"OK", "EMPTY", "TRUNCATED"}
SCHEMA_NAMES = (
    "common",
    "gateway-error-v1",
    "db_preflight.request",
    "db_preflight.response",
    "search_objects.request",
    "search_objects.response",
    "describe_object.request",
    "describe_object.response",
    "get_table_stats.request",
    "get_table_stats.response",
    "sample_rows.request",
    "sample_rows.response",
    "execute_readonly_sql.request",
    "execute_readonly_sql.response",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
UUID_SCHEMA_PATTERN = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
OID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
RECORD_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
IDENTIFIER_RE = re.compile(r"^[^\x00\x01-\x1f\x7f]{1,128}$")
IDENTIFIER_SCHEMA_PATTERN = r"^[^\x00-\x1f\x7f]+$"


def _reject(code: str) -> None:
    raise FixtureRejected(code)


def _exact(value: Any, allowed: set[str], required: set[str], code: str) -> dict:
    if not isinstance(value, dict):
        _reject(code + "_object")
    if set(value) - allowed:
        _reject(code + "_extra")
    if required - set(value):
        _reject(code + "_missing")
    return value


def _string(value: Any, code: str, minimum: int = 1, maximum: int | None = None) -> str:
    if not isinstance(value, str) or len(value) < minimum:
        _reject(code + "_string")
    if maximum is not None and len(value) > maximum:
        _reject(code + "_length")
    if "\x00" in value or any(ord(char) < 32 for char in value):
        _reject(code + "_control")
    return value


def _integer(value: Any, code: str, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _reject(code + "_integer")
    if minimum is not None and value < minimum:
        _reject(code + "_minimum")
    return value


def _boolean(value: Any, code: str) -> bool:
    if not isinstance(value, bool):
        _reject(code + "_boolean")
    return value


def _sha(value: Any, code: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _reject(code + "_sha256")
    return value


def _uuid(value: Any, code: str) -> str:
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        _reject(code + "_uuid")
    return value


def _validate_reserved_call(value: Any) -> dict:
    """校验持久 reservation 的闭集字段，供终态消费与快照验证共用。"""
    try:
        reserved = _exact(
            value,
            {"kind", "tool", "requestId", "callSequence", "argumentsSha256", "reservedAtMs"},
            {"kind", "tool", "requestId", "callSequence", "argumentsSha256", "reservedAtMs"},
            "ledger_reserved_call",
        )
        if reserved["kind"] != "RESERVATION":
            _reject("LEDGER_CORRUPT")
        _string(reserved["tool"], "ledger_reserved_tool", 1, 128)
        _uuid(reserved["requestId"], "ledger_reserved_request")
        _integer(reserved["callSequence"], "ledger_reserved_sequence", 1)
        _sha(reserved["argumentsSha256"], "ledger_reserved_arguments")
        _integer(reserved["reservedAtMs"], "ledger_reserved_at", 0)
        return reserved
    except FixtureRejected as exc:
        if exc.code == "LEDGER_CORRUPT":
            raise
        raise FixtureRejected("LEDGER_CORRUPT") from exc


def _identifier(value: Any, code: str, maximum: int = 128) -> str:
    value = _string(value, code, 1, maximum)
    if IDENTIFIER_RE.fullmatch(value) is None:
        _reject(code + "_identifier")
    if any(marker in value for marker in ("%", "*", "?")):
        _reject("INVALID_IDENTIFIER")
    return value


def _digest(value: Any) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def _canonical_uuid(value: Any) -> str:
    """把确定性摘要编码为合同要求的 canonical UUID。"""
    digest = _digest(value)
    return "-".join((digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]))


def _nonce(value: Any, code: str) -> str:
    if not isinstance(value, str) or NONCE_RE.fullmatch(value) is None:
        _reject(code + "_nonce")
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        _reject(code + "_nonce")
    if len(decoded) != 32:
        _reject(code + "_nonce")
    return value


def _scan_for_secret_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lower = str(key).lower()
            if any(token in lower for token in ("password", "secret", "connectionstring", "privatekey")):
                _reject("secret_field")
            _scan_for_secret_keys(child)
    elif isinstance(value, list):
        for child in value:
            _scan_for_secret_keys(child)


def _default_component(name: str, index: int) -> dict:
    artifact_kind = "DATA" if name in DATA_COMPONENTS else "EXECUTABLE"
    mode = "0644" if artifact_kind == "DATA" else "0755"
    sign_requirement = "NOT_APPLICABLE_DATA" if artifact_kind == "DATA" else "REQUIRED_CODE_SIGN"
    if name == "TOOLBOX":
        sign_requirement = "UNSIGNED_HASH_PINNED"
    return {
        "name": name,
        "artifactKind": artifact_kind,
        "canonicalPath": f"/fixture/database-analysis/{index:02d}-{name.lower()}",
        "version": "fixture-1",
        "sha256": "a" * 64,
        "ownerUid": 0,
        "mode": mode,
        "codeSignRequirement": sign_requirement,
    }


def default_component_manifest() -> dict:
    """构造十项固定组件清单 fixture。"""
    return {
        "contractVersion": "1",
        "components": [_default_component(name, index) for index, name in enumerate(ALL_COMPONENTS, 1)],
    }


def validate_component_manifest(manifest: Any) -> str:
    """验证组件顺序、root owner、不可写 mode 与签名要求并返回 aggregate SHA。"""
    manifest = _exact(manifest, {"contractVersion", "components"}, {"contractVersion", "components"}, "components")
    if manifest["contractVersion"] != "1" or not isinstance(manifest["components"], list):
        _reject("component_manifest")
    if len(manifest["components"]) != len(ALL_COMPONENTS):
        _reject("component_count")
    fields = {
        "name", "artifactKind", "canonicalPath", "version", "sha256", "ownerUid", "mode", "codeSignRequirement"
    }
    for expected, component in zip(ALL_COMPONENTS, manifest["components"]):
        component = _exact(component, fields, fields, "component")
        if component["name"] != expected:
            _reject("component_order")
        expected_kind = "DATA" if expected in DATA_COMPONENTS else "EXECUTABLE"
        if component["artifactKind"] != expected_kind:
            _reject("component_kind")
        path = _string(component["canonicalPath"], "component_path", 1, 512)
        if not path.startswith("/") or unicodedata.normalize("NFC", path) != path:
            _reject("component_path")
        _string(component["version"], "component_version", 1, 256)
        _sha(component["sha256"], "component")
        if component["ownerUid"] != 0:
            _reject("component_owner")
        mode = _string(component["mode"], "component_mode", 4, 4)
        if re.fullmatch(r"0[0-7]{3}", mode) is None or int(mode, 8) & 0o022:
            _reject("component_mode")
        if component["artifactKind"] == "DATA" and component["codeSignRequirement"] != "NOT_APPLICABLE_DATA":
            _reject("component_sign")
        if component["artifactKind"] == "EXECUTABLE" and component["codeSignRequirement"] not in {
            "REQUIRED_CODE_SIGN", "UNSIGNED_HASH_PINNED"
        }:
            _reject("component_sign")
        if expected != "TOOLBOX" and component["codeSignRequirement"] == "UNSIGNED_HASH_PINNED":
            _reject("component_sign")
    return _digest(manifest)


def component_manifest_sha256(manifest: dict) -> str:
    """返回经合同校验的十项组件 aggregate SHA。"""
    return validate_component_manifest(manifest)


def data_object(schema: str = "ai_dw", obj: str = "T_EDW_VAR_PD_INFO_Q", oid: str = "101") -> dict:
    return {
        "schema": schema,
        "object": obj,
        "objectKind": "LOCAL_BASE_TABLE",
        "catalogIdentity": {"catalog": "PG_CLASS", "oid": oid},
    }


def validate_data_object(value: Any, code: str = "data_object") -> dict:
    value = _exact(value, {"schema", "object", "objectKind", "catalogIdentity"}, {"schema", "object", "objectKind", "catalogIdentity"}, code)
    _identifier(value["schema"], code + "_schema")
    _identifier(value["object"], code + "_object")
    if value["objectKind"] != "LOCAL_BASE_TABLE":
        _reject("OBJECT_KIND_DENIED")
    identity = _exact(value["catalogIdentity"], {"catalog", "oid"}, {"catalog", "oid"}, code + "_catalog")
    if identity["catalog"] != "PG_CLASS" or OID_RE.fullmatch(str(identity["oid"])) is None:
        _reject("CATALOG_IDENTITY_DRIFT")
    if isinstance(identity["oid"], int) or str(identity["oid"]).startswith("0"):
        _reject("CATALOG_IDENTITY_DRIFT")
    return value


def _column_ref(value: Any, code: str) -> dict:
    value = _exact(value, {"schema", "object", "column"}, {"schema", "object", "column"}, code)
    _identifier(value["schema"], code + "_schema")
    _identifier(value["object"], code + "_object")
    _identifier(value["column"], code + "_column")
    return value


def default_scope() -> dict:
    """构造一个非 metadata-only、可用于授权与 envelope 测试的最小 scope。"""
    obj = data_object()
    column = {"schema": obj["schema"], "object": obj["object"], "column": "metric"}
    return {
        "businessCatalogSchemas": ["ai_dw"],
        "dataObjects": [obj],
        "valueColumns": [column],
        "sampleColumns": [column],
        "sqlColumns": [column],
        "statsGrants": [{"schema": "ai_dw", "object": obj["object"], "metrics": ["ROW_COUNT"]}],
        "metadataOnly": False,
        "allowSample": True,
        "allowGenericSql": True,
        "purpose": "fixture validation",
    }


def validate_scope(scope: Any, authorization: bool = True) -> dict:
    """验证 scope 精确字段、对象身份、列引用和 metadata-only 互斥关系。"""
    base_fields = {
        "businessCatalogSchemas", "dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants", "metadataOnly"
    }
    extra_fields = {"allowSample", "allowGenericSql", "purpose"} if authorization else set()
    scope = _exact(scope, base_fields | extra_fields, base_fields | extra_fields, "scope")
    if not isinstance(scope["businessCatalogSchemas"], list) or not 1 <= len(scope["businessCatalogSchemas"]) <= 3:
        _reject("scope_schema_count")
    for index, schema in enumerate(scope["businessCatalogSchemas"]):
        _identifier(schema, f"scope_schema_{index}")
    list_limits = {
        "dataObjects": 50,
        "valueColumns": 100,
        "sampleColumns": 100,
        "sqlColumns": 100,
        "statsGrants": 100,
    }
    if not isinstance(scope["dataObjects"], list) or len(scope["dataObjects"]) > list_limits["dataObjects"]:
        _reject("scope_data_objects")
    objects = []
    for index, value in enumerate(scope["dataObjects"]):
        objects.append(validate_data_object(value, f"data_object_{index}"))
    object_pairs = {(item["schema"], item["object"]) for item in objects}
    for field in ("valueColumns", "sampleColumns", "sqlColumns"):
        if not isinstance(scope[field], list) or len(scope[field]) > list_limits[field]:
            _reject("scope_" + field)
        for index, item in enumerate(scope[field]):
            item = _column_ref(item, f"{field}_{index}")
            if (item["schema"], item["object"]) not in object_pairs:
                _reject("AUTH_SCOPE_MISMATCH")
    if not isinstance(scope["statsGrants"], list) or len(scope["statsGrants"]) > 100:
        _reject("scope_stats")
    for index, item in enumerate(scope["statsGrants"]):
        item = _exact(item, {"schema", "object", "metrics"}, {"schema", "object", "metrics"}, f"stats_{index}")
        _identifier(item["schema"], f"stats_{index}_schema")
        _identifier(item["object"], f"stats_{index}_object")
        if (item["schema"], item["object"]) not in object_pairs or not isinstance(item["metrics"], list) or not 1 <= len(item["metrics"]) <= 7:
            _reject("AUTH_SCOPE_MISMATCH")
        if any(
            not isinstance(metric, str)
            or metric not in {"ROW_COUNT", "NULL_COUNT", "DISTINCT_COUNT", "MIN", "MAX", "TOP_K"}
            for metric in item["metrics"]
        ):
            _reject("AUTH_SCOPE_MISMATCH")
    _boolean(scope["metadataOnly"], "metadataOnly")
    if authorization:
        _boolean(scope["allowSample"], "allowSample")
        _boolean(scope["allowGenericSql"], "allowGenericSql")
        _string(scope["purpose"], "purpose", 1, 512)
    if scope["metadataOnly"] and any(scope[field] for field in ("dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants")):
        _reject("AUTH_SCOPE_MISMATCH")
    if not scope.get("allowSample", True) and scope["sampleColumns"]:
        _reject("AUTH_SCOPE_MISMATCH")
    if not scope.get("allowGenericSql", True) and scope["sqlColumns"]:
        _reject("AUTH_SCOPE_MISMATCH")
    return scope


def validate_evidence_targets(targets: Any) -> list[dict]:
    """校验 0..3 个精确 evidence target 及 SOURCE_REGISTER 字符集。"""
    if not isinstance(targets, list) or len(targets) > MAX_EVIDENCE_TARGETS:
        _reject("evidence_targets")
    seen = set()
    fields = {"path", "operation", "expectedPreimage", "contentKind", "recordKey"}
    result = []
    for index, target in enumerate(targets):
        target = _exact(target, fields, {"path", "operation", "expectedPreimage", "contentKind"}, f"target_{index}")
        _string(target["path"], f"target_{index}_path", 1, 512)
        if target["operation"] not in {"CREATE_NEW", "APPEND_ONLY"}:
            _reject("target_operation")
        if target["operation"] == "APPEND_ONLY":
            if target["expectedPreimage"] == "ABSENT":
                _reject("target_preimage")
            _sha(target["expectedPreimage"], "target_preimage")
        elif target["expectedPreimage"] != "ABSENT":
            _reject("target_preimage")
        if target["contentKind"] not in {"VERIFIED_MARKDOWN", "VERIFIED_SQL", "SOURCE_REGISTER"}:
            _reject("target_content_kind")
        record_key = target.get("recordKey")
        if target["operation"] == "CREATE_NEW" and record_key is not None:
            _reject("target_record_key")
        if target["operation"] == "APPEND_ONLY" and (
            not isinstance(record_key, str) or RECORD_KEY_RE.fullmatch(record_key) is None
        ):
            _reject("target_record_key")
        if target["contentKind"] == "SOURCE_REGISTER":
            if target["operation"] != "APPEND_ONLY" or not isinstance(record_key, str) or RECORD_KEY_RE.fullmatch(record_key) is None:
                _reject("target_record_key")
        elif record_key is not None:
            if not isinstance(record_key, str) or RECORD_KEY_RE.fullmatch(record_key) is None:
                _reject("target_record_key")
        if record_key is not None and record_key in seen:
            _reject("target_record_key_duplicate")
        if record_key is not None:
            seen.add(record_key)
        result.append(target)
    return result


def default_capability_input(run_id: str = "11111111-1111-1111-1111-111111111111") -> dict:
    """构造带十项组件和精确 evidence target 的 capability 候选。"""
    components = default_component_manifest()
    return {
        "contractVersion": "1",
        "authorizationId": "22222222-2222-2222-2222-222222222222",
        "approvalRecordId": "33333333-3333-3333-3333-333333333333",
        "runId": run_id,
        "gatewaySessionNonce": "A" * 43,
        "challengeNonce": "B" * 43,
        "brokerEpoch": "broker-1",
        "ledgerEpoch": "ledger-1",
        "helperEpoch": "helper-1",
        "componentManifest": components,
        "componentManifestSha256": component_manifest_sha256(components),
        "profileId": "fixture-profile",
        "toolContractSha256": tool_contract_manifest_sha256(),
        "expiresAt": 3_600_000,
        "maxToolCalls": MAX_DATABASE_CALLS,
        "evidenceCommitBudget": 1,
        "scope": default_scope(),
        "evidenceTargets": [
            {
                "path": "evidence/fixture.md",
                "operation": "CREATE_NEW",
                "expectedPreimage": "ABSENT",
                "contentKind": "VERIFIED_MARKDOWN",
            }
        ],
        "userPresence": True,
        "signatureVerified": True,
    }


def issue_capability(candidate: dict, now_ms: int = 0) -> dict:
    """验证并冻结 capability 候选，返回不可变语义的深拷贝。"""
    _integer(now_ms, "now_ms", 0)
    _scan_for_secret_keys(candidate)
    fields = {
        "contractVersion", "authorizationId", "approvalRecordId", "runId", "gatewaySessionNonce", "challengeNonce",
        "brokerEpoch", "ledgerEpoch", "helperEpoch", "componentManifest", "componentManifestSha256", "profileId",
        "toolContractSha256", "expiresAt", "maxToolCalls", "evidenceCommitBudget", "scope", "evidenceTargets",
        "userPresence", "signatureVerified",
    }
    candidate = _exact(candidate, fields, fields, "capability")
    if candidate["contractVersion"] != "1":
        _reject("capability_contract")
    for field in ("authorizationId", "approvalRecordId", "runId"):
        _uuid(candidate[field], field)
    _nonce(candidate["gatewaySessionNonce"], "gatewaySessionNonce")
    _nonce(candidate["challengeNonce"], "challengeNonce")
    for field in ("brokerEpoch", "ledgerEpoch", "helperEpoch", "profileId"):
        _string(candidate[field], field, 1, 256)
    manifest_hash = component_manifest_sha256(candidate["componentManifest"])
    if manifest_hash != candidate["componentManifestSha256"]:
        _reject("component_manifest_drift")
    _sha(candidate["componentManifestSha256"], "componentManifestSha256")
    _sha(candidate["toolContractSha256"], "toolContractSha256")
    if candidate["toolContractSha256"] != tool_contract_manifest_sha256():
        _reject("tool_contract_drift")
    expires = _integer(candidate["expiresAt"], "expiresAt", now_ms + 1)
    if expires - now_ms > 60 * 60 * 1000:
        _reject("capability_expiry")
    if candidate["maxToolCalls"] != MAX_DATABASE_CALLS or candidate["evidenceCommitBudget"] not in {0, 1}:
        _reject("capability_budget")
    validate_scope(candidate["scope"], authorization=True)
    validate_evidence_targets(candidate["evidenceTargets"])
    if candidate["evidenceCommitBudget"] == 0 and candidate["evidenceTargets"]:
        _reject("capability_evidence_budget")
    if candidate["evidenceCommitBudget"] == 1 and not candidate["evidenceTargets"]:
        _reject("capability_evidence_budget")
    _boolean(candidate["userPresence"], "userPresence")
    _boolean(candidate["signatureVerified"], "signatureVerified")
    if not candidate["userPresence"] or not candidate["signatureVerified"]:
        _reject("AUTH_SIGNATURE_INVALID")
    return json.loads(json.dumps(candidate, ensure_ascii=False))


def validate_capability(
    capability: dict,
    now_ms: int,
    gateway_session_nonce: str | None = None,
    epochs: tuple[str, str, str] | None = None,
    component_hash: str | None = None,
    tool_contract_hash: str | None = None,
) -> bool:
    """验证 capability 未过期、未漂移且仍绑定当前会话。"""
    try:
        _integer(now_ms, "now_ms", 0)
    except FixtureRejected:
        return False
    try:
        issue_capability(capability, now_ms=0)
    except FixtureRejected:
        return False
    if capability["expiresAt"] <= now_ms:
        return False
    if gateway_session_nonce is not None and capability["gatewaySessionNonce"] != gateway_session_nonce:
        return False
    if epochs is not None and tuple(capability[field] for field in ("brokerEpoch", "ledgerEpoch", "helperEpoch")) != epochs:
        return False
    if component_hash is not None and capability["componentManifestSha256"] != component_hash:
        return False
    if tool_contract_hash is not None and capability["toolContractSha256"] != tool_contract_hash:
        return False
    return True


class ReplayGuard:
    """限制 requestId、runId 和 callSequence 的一次性消费。"""

    def __init__(self):
        self._seen: set[tuple[str, str]] = set()
        self._last: dict[str, int] = {}

    def accept(self, run_id: str, request_id: str, call_sequence: int) -> None:
        if (run_id, request_id) in self._seen:
            _reject("AUTH_REPLAY")
        previous = self._last.get(run_id, 0)
        if call_sequence != previous + 1:
            _reject("AUTH_REPLAY")
        self._seen.add((run_id, request_id))
        self._last[run_id] = call_sequence


class SingleRunRegistry:
    """全局单 live run fixture，cleanup/tombstone 期间不释放槽。"""

    def __init__(self):
        self.active: RunLedger | None = None
        self._terminal_run_ids: set[str] = set()

    def _record_terminal(self, run_id: str) -> None:
        """记录终态 run 身份，防止同一 runId 在 tombstone 后重新激活。"""
        self._terminal_run_ids.add(run_id)

    def begin(self, capability: dict, now_ms: int) -> "RunLedger":
        _integer(now_ms, "now_ms", 0)
        if self.active is not None and self.active.state in LIVE_RUN_STATES:
            _reject("AUTH_REPLAY")
        if not validate_capability(capability, now_ms):
            _reject("AUTH_EXPIRED")
        if capability["runId"] in self._terminal_run_ids:
            _reject("AUTH_REPLAY")
        self.active = RunLedger(capability, self)
        return self.active


class RunLedger:
    """覆盖七个 live state、单 child、database/evidence permit 与 recovery cleanup。"""

    def __init__(self, capability: dict, registry: SingleRunRegistry):
        self.capability = json.loads(json.dumps(capability, ensure_ascii=False))
        self.registry = registry
        self.state = "ACTIVE_UNPREFLIGHTED"
        self.preflight_passed = False
        self.call_count = 0
        self.evidence_commit_budget = capability["evidenceCommitBudget"]
        self.query_close_cleanup_ack = False
        self.toolbox_session_id: str | None = None
        self.child_identity: dict | None = None
        self.reserved_launch_identity: dict | None = None
        self.in_flight: dict | None = None
        self.reserved_call: dict | None = None
        self.cleanup_id: str | None = None
        self.epoch = capability["ledgerEpoch"]
        self.current_gateway_session_nonce = capability["gatewaySessionNonce"]
        self.current_ledger_epoch = capability["ledgerEpoch"]
        self.current_broker_epoch = capability["brokerEpoch"]
        self.current_helper_epoch = capability["helperEpoch"]
        self.replay = ReplayGuard()
        self.unique_candidate_digests: set[str] = set()

    def _check_live(self, now_ms: int) -> None:
        if self.state not in LIVE_RUN_STATES:
            _reject("AUTH_EXPIRED")
        if self.capability["expiresAt"] <= now_ms:
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        if self.capability["gatewaySessionNonce"] != self.current_gateway_session_nonce:
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        if (
            self.capability["brokerEpoch"] != self.current_broker_epoch
            or self.capability["ledgerEpoch"] != self.current_ledger_epoch
            or self.capability["helperEpoch"] != self.current_helper_epoch
        ):
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")

    def _enter_cleanup(self, cause: str) -> str:
        self.state = "REVOKE_PENDING_CLEANUP"
        self.cleanup_id = self.cleanup_id or _digest({"runId": self.capability["runId"], "cause": cause})
        return self.state

    def _mark_terminal(self, state: str) -> str:
        """原子登记终态 tombstone 并禁止该 runId 再次激活。"""
        if state not in TERMINAL_RUN_STATES:
            _reject("LEDGER_CORRUPT")
        if self.reserved_call is not None:
            _validate_reserved_call(self.reserved_call)
        if self.in_flight is not None and (
            not isinstance(self.in_flight, dict)
            or self.in_flight.get("kind") not in {"DATABASE", "EVIDENCE"}
        ):
            _reject("LEDGER_CORRUPT")
        self.in_flight = None
        self.reserved_call = None
        self.state = state
        self.registry._record_terminal(self.capability["runId"])
        return self.state

    def begin_call(self, tool: str, request_id: str, call_sequence: int, arguments: dict, now_ms: int) -> dict:
        """机械校验调用顺序、预算和 inFlight，返回 reservation 或 database permit 候选。"""
        _integer(now_ms, "now_ms", 0)
        self._check_live(now_ms)
        _string(tool, "tool", 1, 128)
        _uuid(request_id, "requestId")
        _integer(call_sequence, "callSequence", 1)
        if not isinstance(arguments, dict):
            _reject("arguments_object")
        if tool not in TOOL_NAMES:
            _reject("TOOL_DISABLED")
        self.replay.accept(self.capability["runId"], request_id, call_sequence)
        if self.in_flight is not None:
            _reject("LEDGER_UNAVAILABLE")
        if self.reserved_call is not None:
            _reject("LEDGER_UNAVAILABLE")
        if self.state in {"REVOKE_PENDING_CLEANUP", "EVIDENCE_IN_FLIGHT"}:
            _reject("LEDGER_UNAVAILABLE")
        if self.call_count >= MAX_DATABASE_CALLS:
            _reject("CALL_BUDGET_EXHAUSTED")
        if not self.preflight_passed:
            if self.state == "ACTIVE_UNPREFLIGHTED" and (tool != "db_preflight" or call_sequence != 1):
                self._enter_cleanup("PREFLIGHT_REQUIRED")
                _reject("PREFLIGHT_REQUIRED")
            if self.state != "ACTIVE_UNPREFLIGHTED" and tool != "db_preflight":
                self._enter_cleanup("PREFLIGHT_REQUIRED")
                _reject("PREFLIGHT_REQUIRED")
        if self.state == "QUERY_CLOSED":
            _reject("CALL_BUDGET_EXHAUSTED")
        args_hash = _digest(arguments)
        if self.toolbox_session_id is None:
            self.toolbox_session_id = "toolbox-" + self.capability["runId"]
            self.reserved_launch_identity = {
                "toolboxSessionId": self.toolbox_session_id,
                "executableFdIdentity": dict(FIXTURE_EXECUTABLE_FD_IDENTITY),
                "perLaunchNonce": "C" * 43,
            }
            self.state = "IN_FLIGHT_PREFLIGHT"
            self.reserved_call = {
                "kind": "RESERVATION",
                "tool": tool,
                "requestId": request_id,
                "callSequence": call_sequence,
                "argumentsSha256": args_hash,
                "reservedAtMs": now_ms,
            }
            return dict(self.reserved_call)
        if self.child_identity is None:
            _reject("CREDENTIAL_BOUNDARY")
        self.state = "IN_FLIGHT_PREFLIGHT" if tool == "db_preflight" else "IN_FLIGHT_TOOL"
        lease_until = min(self.capability["expiresAt"], now_ms + DATABASE_PERMIT_LEASE_MS)
        if lease_until - now_ms < CONNECT_TIMEOUT_MS + TEARDOWN_GRACE_MS:
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        self.in_flight = {
            "kind": "DATABASE",
            "tool": tool,
            "requestId": request_id,
            "callSequence": call_sequence,
            "argumentsSha256": args_hash,
            "toolboxSessionId": self.toolbox_session_id,
            "childIdentity": dict(self.child_identity),
            "beginCallAt": now_ms,
            "leaseUntil": lease_until,
            "helperEpoch": self.capability["helperEpoch"],
            "authorizationSha256": _digest(self.capability),
            "gatewaySessionNonce": self.capability["gatewaySessionNonce"],
            "ledgerEpoch": self.capability["ledgerEpoch"],
            "brokerEpoch": self.capability["brokerEpoch"],
        }
        self.call_count += 1
        return dict(self.in_flight)

    def report_spawn_ok(self, pid: int, audit: str, now_ms: int) -> bool:
        """只接受 RESERVED 三秒窗口内的非空 child identity。"""
        _integer(now_ms, "now_ms", 0)
        if (
            self.in_flight is not None
            or self.reserved_call is None
            or self.reserved_call.get("kind") != "RESERVATION"
        ):
            _reject("invalid_transition")
        if self.state != "IN_FLIGHT_PREFLIGHT":
            return False
        if self.capability["expiresAt"] <= now_ms:
            self._enter_cleanup("AUTH_EXPIRED")
            return False
        if now_ms - int(self.reserved_call.get("reservedAtMs", now_ms)) >= REPORT_SPAWN_DEADLINE_MS:
            self._enter_cleanup("SPAWN_FAILED")
            return False
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1 or not isinstance(audit, str) or SHA256_RE.fullmatch(audit) is None:
            self._enter_cleanup("SPAWN_FAILED")
            return False
        self.child_identity = {"pid": pid, "audit": audit}
        self.state = "IN_FLIGHT_PREFLIGHT"
        return True

    def issue_database_permit(self, begin_call_at: int, lease_ms: int = DATABASE_PERMIT_LEASE_MS) -> dict:
        """在 SPAWN_VERIFIED 后生成 20 秒 database permit。"""
        _integer(begin_call_at, "beginCallAt", 0)
        _integer(lease_ms, "lease_ms", 0)
        self._check_live(begin_call_at)
        if self.state != "IN_FLIGHT_PREFLIGHT":
            _reject("invalid_transition")
        if self.child_identity is None or self.in_flight is not None or self.reserved_call is None:
            if self.in_flight is not None and self.in_flight.get("kind") == "RESERVATION":
                _reject("CREDENTIAL_BOUNDARY")
            _reject("invalid_transition")
        if lease_ms != DATABASE_PERMIT_LEASE_MS:
            self._enter_cleanup("INVALID_LEASE")
            _reject("INVALID_LEASE")
        expires_at = min(self.capability["expiresAt"], begin_call_at + lease_ms)
        if expires_at - begin_call_at < CONNECT_TIMEOUT_MS + TEARDOWN_GRACE_MS:
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        if self.call_count >= MAX_DATABASE_CALLS:
            _reject("CALL_BUDGET_EXHAUSTED")
        permit = {
            "kind": "DATABASE",
            "runId": self.capability["runId"],
            "authorizationSha256": _digest(self.capability),
            "tool": self.reserved_call["tool"],
            "requestId": self.reserved_call["requestId"],
            "callSequence": self.reserved_call["callSequence"],
            "argumentsSha256": self.reserved_call["argumentsSha256"],
            "toolboxSessionId": self.toolbox_session_id,
            "childIdentity": dict(self.child_identity),
            "beginCallAt": begin_call_at,
            "leaseUntil": expires_at,
            "helperEpoch": self.capability["helperEpoch"],
            "gatewaySessionNonce": self.capability["gatewaySessionNonce"],
            "ledgerEpoch": self.capability["ledgerEpoch"],
            "brokerEpoch": self.capability["brokerEpoch"],
        }
        self.reserved_call = None
        self.in_flight = permit
        self.call_count += 1
        return dict(permit)

    def complete_database(
        self,
        permit: dict,
        success: bool,
        preflight_passed: bool | None,
        now_ms: int,
        candidate_digests: list[str] | None = None,
    ) -> str:
        """完成或拒绝一次 database permit，并保持 session/预算不变量。"""
        _integer(now_ms, "now_ms", 0)
        if self.state not in {"IN_FLIGHT_PREFLIGHT", "IN_FLIGHT_TOOL"}:
            _reject("AUTH_REPLAY")
        self._check_live(now_ms)
        if self.in_flight is None or permit != self.in_flight:
            _reject("AUTH_REPLAY")
        if now_ms > permit["leaseUntil"]:
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        is_preflight = permit.get("tool") == "db_preflight"
        if is_preflight and not isinstance(preflight_passed, bool):
            self.in_flight = None
            self._enter_cleanup("PREFLIGHT_REQUIRED")
            _reject("PREFLIGHT_REQUIRED")
        if not is_preflight and not self.preflight_passed:
            self.in_flight = None
            self._enter_cleanup("PREFLIGHT_REQUIRED")
            _reject("PREFLIGHT_REQUIRED")
        if not is_preflight and preflight_passed is not None:
            self.in_flight = None
            self._enter_cleanup("PREFLIGHT_REQUIRED")
            _reject("PREFLIGHT_REQUIRED")
        self.in_flight = None
        if not success:
            self._enter_cleanup("DB_ERROR_REDACTED")
            return self.state
        if candidate_digests:
            self.unique_candidate_digests.update(candidate_digests)
            if len(self.unique_candidate_digests) > MAX_SEARCH_CANDIDATES:
                self._enter_cleanup("CALL_BUDGET_EXHAUSTED")
                _reject("CALL_BUDGET_EXHAUSTED")
        if is_preflight and preflight_passed is False:
            self._enter_cleanup("PREFLIGHT_PRIVILEGE")
            return self.state
        if is_preflight and preflight_passed is True:
            self.preflight_passed = True
        if self.call_count >= MAX_DATABASE_CALLS:
            self.state = "QUERY_CLOSED"
            self.query_close_cleanup_ack = False
        else:
            self.state = "ACTIVE_READY"
        return self.state

    def deadline_elapsed(self, now_ms: int) -> str:
        _integer(now_ms, "now_ms", 0)
        if self.reserved_call is None or self.reserved_call.get("kind") != "RESERVATION":
            return self.state
        reserved_at = self.reserved_call.setdefault("reservedAtMs", now_ms - REPORT_SPAWN_DEADLINE_MS)
        if now_ms - reserved_at >= REPORT_SPAWN_DEADLINE_MS:
            self._enter_cleanup("SPAWN_FAILED")
        return self.state

    def fail_spawn(self, digest: str, now_ms: int) -> str:
        _integer(now_ms, "now_ms", 0)
        self._enter_cleanup("SPAWN_FAILED")
        self.in_flight = None
        self.reserved_call = None
        return self.state

    def report_spawn_fail(self, external_possible: bool, digest: str, now_ms: int) -> str:
        """将 false hint、非法 payload 和窗口外失败统一放入 cleanup。"""
        _integer(now_ms, "now_ms", 0)
        self._enter_cleanup("SPAWN_FAILED")
        self.in_flight = None
        self.reserved_call = None
        return self.state

    def abort_database(self, permit: dict, now_ms: int) -> str:
        """无法判定是否触库时不得重试旧 permit，先占用 cleanup 槽。"""
        _integer(now_ms, "now_ms", 0)
        if self.in_flight is None or permit != self.in_flight or permit.get("kind") != "DATABASE":
            _reject("AUTH_REPLAY")
        self.in_flight = None
        return self._enter_cleanup("DB_ERROR_REDACTED")

    def register_gateway_nonce(self, nonce: str) -> str:
        """新 Gateway 会话使旧 capability 失效，live run 保持清理槽。"""
        _nonce(nonce, "gatewaySessionNonce")
        self.current_gateway_session_nonce = nonce
        if self.state in LIVE_RUN_STATES:
            return self._enter_cleanup("AUTH_EXPIRED")
        return self.state

    def _validate_empty_launch_scan(self, launch_scan: dict) -> None:
        """验证未知 child 清理必须绑定 reservation 原像且完成 V1 空命中扫描。"""
        fields = {
            "algorithm", "executableFdIdentity", "perLaunchNonce", "toolboxSessionId",
            "scanComplete", "matchedPids", "scannedAt", "digest",
        }
        launch_scan = _exact(launch_scan, fields, fields, "launch_scan")
        if launch_scan["algorithm"] != LAUNCH_SCAN_ALGORITHM:
            _reject("LAUNCH_SCAN_ALGORITHM")
        reserved = _exact(
            self.reserved_launch_identity,
            {"toolboxSessionId", "executableFdIdentity", "perLaunchNonce"},
            {"toolboxSessionId", "executableFdIdentity", "perLaunchNonce"},
            "reserved_launch_identity",
        )
        fd_identity = _exact(
            launch_scan["executableFdIdentity"],
            {"canonicalPath", "device", "inode", "sha256"},
            {"canonicalPath", "device", "inode", "sha256"},
            "launch_scan_fd",
        )
        if fd_identity != reserved["executableFdIdentity"]:
            _reject("LAUNCH_SCAN_IDENTITY")
        if launch_scan["perLaunchNonce"] != reserved["perLaunchNonce"]:
            _reject("LAUNCH_SCAN_NONCE")
        if launch_scan["toolboxSessionId"] != reserved["toolboxSessionId"]:
            _reject("LAUNCH_SCAN_SESSION")
        _boolean(launch_scan["scanComplete"], "launch_scan_complete")
        if not isinstance(launch_scan["matchedPids"], list):
            _reject("LAUNCH_SCAN_MATCHES")
        for index, pid in enumerate(launch_scan["matchedPids"]):
            _integer(pid, f"launch_scan_pid_{index}", 1)
        if launch_scan["matchedPids"] != sorted(set(launch_scan["matchedPids"])):
            _reject("LAUNCH_SCAN_MATCHES")
        _string(launch_scan["scannedAt"], "launch_scan_scanned_at", 1, 64)
        _sha(launch_scan["digest"], "launch_scan_digest")
        digest_payload = {field: launch_scan[field] for field in fields if field != "digest"}
        if launch_scan["digest"] != _digest(digest_payload):
            _reject("LAUNCH_SCAN_DIGEST")
        if launch_scan["scanComplete"] is not True or launch_scan["matchedPids"]:
            _reject("LAUNCH_SCAN_INCOMPLETE")

    def ack_child_termination(
        self,
        identity: dict | None,
        cleanup_id: str | None = None,
        epoch: str | None = None,
        launch_scan: dict | None = None,
    ) -> str:
        """验证已知 child 或未知 child 的定向 cleanup ACK。"""
        if self.state not in {"REVOKE_PENDING_CLEANUP", "QUERY_CLOSED"}:
            _reject("invalid_transition")
        if self.state == "REVOKE_PENDING_CLEANUP" and (
            cleanup_id != self.cleanup_id or epoch != self.epoch
        ):
            _reject("AUTH_REPLAY")
        if cleanup_id is not None and cleanup_id != self.cleanup_id:
            _reject("AUTH_REPLAY")
        if epoch is not None and epoch != self.epoch:
            _reject("AUTH_REPLAY")
        if self.child_identity is None and identity is not None:
            _reject("OBJECT_DRIFT")
        if self.child_identity is not None and identity != self.child_identity:
            _reject("OBJECT_DRIFT")
        if self.child_identity is None:
            if launch_scan is None:
                _reject("LAUNCH_SCAN_REQUIRED")
            self._validate_empty_launch_scan(launch_scan)
        if self.state == "REVOKE_PENDING_CLEANUP":
            if self.in_flight is not None and (
                not isinstance(self.in_flight, dict)
                or self.in_flight.get("kind") != "DATABASE"
            ):
                _reject("LEDGER_CORRUPT")
            if self.reserved_call is not None:
                _validate_reserved_call(self.reserved_call)
        if self.state == "QUERY_CLOSED":
            self.query_close_cleanup_ack = True
            return self.state
        if self.state == "REVOKE_PENDING_CLEANUP":
            return self._mark_terminal("REVOKED")
        return self.state

    def recovery_command(self) -> dict:
        """生成不含数据库能力、绑定当前 epoch 的 recovery-only cleanup command。"""
        self.cleanup_id = self.cleanup_id or _digest({"runId": self.capability["runId"], "state": self.state})
        return copy.deepcopy({
            "cleanupId": self.cleanup_id,
            "toolboxSessionId": self.toolbox_session_id,
            "reservedLaunchIdentity": self.reserved_launch_identity,
            "toolboxChildIdentity": self.child_identity,
            "terminalTarget": "REVOKED",
            "epoch": self.epoch,
            "recoveryOnly": True,
            "auditToken": _digest({"cleanupId": self.cleanup_id, "epoch": self.epoch}),
        })

    def begin_evidence_commit(self, targets: list[dict], begin_ms: int, lease_ms: int, budget: int) -> dict:
        """只在 QUERY_CLOSED 且 child ACK 后生成独立 evidence permit。"""
        _integer(begin_ms, "begin_ms", 0)
        _integer(lease_ms, "lease_ms", 0)
        _integer(budget, "budget", 0)
        if self.state != "QUERY_CLOSED" or not self.query_close_cleanup_ack:
            _reject("PREFLIGHT_REQUIRED")
        if self.evidence_commit_budget != 1 or budget != 1 or not targets:
            _reject("AUTH_SCOPE_MISMATCH")
        if (
            lease_ms != EVIDENCE_PERMIT_LEASE_MS
            or self.capability["expiresAt"] <= begin_ms
        ):
            _reject("INVALID_LEASE")
        validated_targets = validate_evidence_targets(targets)
        if validated_targets != self.capability["evidenceTargets"]:
            _reject("AUTH_SCOPE_MISMATCH")
        permit = {
            "kind": "EVIDENCE",
            "runId": self.capability["runId"],
            "authorizationSha256": _digest(self.capability),
            "evidenceCommitId": "44444444-4444-4444-4444-444444444444",
            "evidenceWalId": _canonical_uuid({"runId": self.capability["runId"], "begin": begin_ms}),
            "targets": validated_targets,
            "beginEvidenceCommitAt": begin_ms,
            "leaseUntil": min(self.capability["expiresAt"], begin_ms + lease_ms),
            "ledgerAuditToken": _digest({"kind": "EVIDENCE", "run": self.capability["runId"]}),
            "commitSession": "commit-evidence-fixture",
        }
        self.in_flight = permit
        self.state = "EVIDENCE_IN_FLIGHT"
        return dict(permit)

    def complete_evidence(self, permit: dict, now_ms: int) -> str:
        _integer(now_ms, "now_ms", 0)
        if self.state != "EVIDENCE_IN_FLIGHT" or permit != self.in_flight:
            _reject("AUTH_REPLAY")
        if now_ms > permit["leaseUntil"]:
            self.in_flight = None
            self._enter_cleanup("AUTH_EXPIRED")
            _reject("AUTH_EXPIRED")
        self.in_flight = None
        self.evidence_commit_budget = 0
        return self._mark_terminal("CLOSED")

    def rotate_epoch(self, new_epoch: str) -> str:
        """重启/nonce 漂移立即使旧 capability 失效并保持 cleanup 槽。"""
        _string(new_epoch, "epoch")
        self.epoch = new_epoch
        self.current_ledger_epoch = new_epoch
        if self.state in TERMINAL_RUN_STATES:
            return self.state
        if self.state == "REVOKE_PENDING_CLEANUP":
            return self._enter_cleanup("DEPENDENCY_UNAVAILABLE")
        if self.child_identity is not None or self.in_flight is not None or self.reserved_call is not None:
            return self._enter_cleanup("DEPENDENCY_UNAVAILABLE")
        return self._mark_terminal("REVOKED")


def _validate_reserved_launch_identity(value: dict) -> dict:
    """校验已持久化的 Toolbox executable fd identity 与 launch nonce。"""
    reserved = _exact(
        value,
        {"executableFdIdentity", "perLaunchNonce"},
        {"executableFdIdentity", "perLaunchNonce"},
        "ledger_reserved_launch",
    )
    executable = _exact(
        reserved["executableFdIdentity"],
        {"canonicalPath", "device", "inode", "sha256"},
        {"canonicalPath", "device", "inode", "sha256"},
        "ledger_reserved_launch_fd",
    )
    path = _string(executable["canonicalPath"], "ledger_reserved_launch_path", 1, 256)
    if not path.startswith("/") or unicodedata.normalize("NFC", path) != path:
        _reject("LEDGER_CORRUPT")
    for field in ("device", "inode"):
        value = executable[field]
        if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
            _reject("LEDGER_CORRUPT")
    _sha(executable["sha256"], "ledger_reserved_launch_sha")
    _nonce(reserved["perLaunchNonce"], "ledger_reserved_launch_nonce")
    return reserved


def _validate_cleanup_snapshot(value: dict) -> dict:
    """校验 REVOKE_PENDING_CLEANUP 的 recovery/rollback 证据闭集。"""
    cleanup = _exact(
        value,
        {
            "cleanupId", "cause", "cleanupKind", "terminalTarget", "toolboxSessionId",
            "toolboxChildIdentity", "evidenceWalId", "startedAt",
            "ledgerRecoveryAuditTokenSha256", "recoveryComponentSha256",
            "recoveryExecutionSessionId",
        },
        {
            "cleanupId", "cause", "cleanupKind", "terminalTarget", "toolboxSessionId",
            "toolboxChildIdentity", "evidenceWalId", "startedAt",
            "ledgerRecoveryAuditTokenSha256", "recoveryComponentSha256",
            "recoveryExecutionSessionId",
        },
        "ledger_cleanup",
    )
    _uuid(cleanup["cleanupId"], "ledger_cleanup_id")
    if cleanup["cause"] not in {
        "USER_REVOKE", "GATEWAY_RESTART", "BROKER_RESTART", "LEDGER_RESTART",
        "HELPER_RESTART", "PREFLIGHT_FAILED", "ABORT", "LEASE_EXPIRED",
        "LEDGER_CORRUPT", "SPAWN_FAILED",
    }:
        _reject("LEDGER_CORRUPT")
    if cleanup["cleanupKind"] not in {"TOOLBOX_TERMINATION", "EVIDENCE_ROLLBACK"}:
        _reject("LEDGER_CORRUPT")
    if cleanup["terminalTarget"] not in {"REVOKED", "EXPIRED"}:
        _reject("LEDGER_CORRUPT")
    for field in ("toolboxSessionId", "evidenceWalId"):
        if cleanup[field] is not None:
            _uuid(cleanup[field], "ledger_cleanup_" + field)
    if cleanup["toolboxChildIdentity"] is not None:
        _string(cleanup["toolboxChildIdentity"], "ledger_cleanup_child", 1, 512)
    started_at = _string(cleanup["startedAt"], "ledger_cleanup_started_at", 1, 64)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z", started_at) is None:
        _reject("LEDGER_CORRUPT")
    _sha(cleanup["ledgerRecoveryAuditTokenSha256"], "ledger_cleanup_audit")
    _sha(cleanup["recoveryComponentSha256"], "ledger_cleanup_component")
    _uuid(cleanup["recoveryExecutionSessionId"], "ledger_cleanup_execution")
    if cleanup["cleanupKind"] == "TOOLBOX_TERMINATION":
        if cleanup["toolboxSessionId"] is None or cleanup["evidenceWalId"] is not None:
            _reject("LEDGER_CORRUPT")
    elif cleanup["evidenceWalId"] is None or cleanup["toolboxChildIdentity"] is not None:
        _reject("LEDGER_CORRUPT")
    return cleanup


def validate_ledger_snapshot(snapshot: dict) -> bool:
    """验证崩溃恢复时的最小 ledger 不变量，拒绝损坏快照。"""
    fields = {
        "state", "inFlight", "reservedCall", "toolboxSessionId", "childIdentity",
        "preflightPassed", "queryCloseCleanupAck", "callCount",
        "reservedLaunchIdentity", "cleanup",
    }
    snapshot = _exact(snapshot, fields, fields, "ledger_snapshot")
    if snapshot["state"] not in set(LIVE_RUN_STATES) | set(TERMINAL_RUN_STATES):
        _reject("LEDGER_CORRUPT")
    if snapshot["inFlight"] is not None and not isinstance(snapshot["inFlight"], dict):
        _reject("LEDGER_CORRUPT")
    if snapshot["inFlight"] is not None and snapshot["inFlight"].get("kind") == "RESERVATION":
        _reject("LEDGER_CORRUPT")
    if snapshot["reservedCall"] is not None:
        _validate_reserved_call(snapshot["reservedCall"])
    _boolean(snapshot["preflightPassed"], "ledger_preflight")
    if snapshot["toolboxSessionId"] is not None:
        _string(snapshot["toolboxSessionId"], "ledger_toolbox_session", 1, 128)
    if snapshot["childIdentity"] is not None:
        child = _exact(snapshot["childIdentity"], {"pid", "audit"}, {"pid", "audit"}, "ledger_child")
        _integer(child["pid"], "ledger_child_pid", 1)
        _sha(child["audit"], "ledger_child_audit")
    if snapshot["toolboxSessionId"] is None and snapshot["childIdentity"] is not None:
        _reject("LEDGER_CORRUPT")
    if snapshot["reservedLaunchIdentity"] is not None:
        _validate_reserved_launch_identity(snapshot["reservedLaunchIdentity"])
    if snapshot["cleanup"] is not None:
        cleanup = _validate_cleanup_snapshot(snapshot["cleanup"])
    else:
        cleanup = None
    _boolean(snapshot["queryCloseCleanupAck"], "ledger_ack")
    _integer(snapshot["callCount"], "ledger_count", 0)
    if snapshot["callCount"] > MAX_DATABASE_CALLS:
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "ACTIVE_UNPREFLIGHTED" and (
        snapshot["preflightPassed"]
        or snapshot["callCount"] != 0
        or snapshot["inFlight"] is not None
        or snapshot["reservedCall"] is not None
        or snapshot["toolboxSessionId"] is not None
        or snapshot["childIdentity"] is not None
        or snapshot["queryCloseCleanupAck"]
        or snapshot["reservedLaunchIdentity"] is not None
        or snapshot["cleanup"] is not None
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "IN_FLIGHT_PREFLIGHT":
        if snapshot["preflightPassed"] or snapshot["toolboxSessionId"] is None or snapshot["queryCloseCleanupAck"]:
            _reject("LEDGER_CORRUPT")
        reservation_state = snapshot["reservedCall"] is not None and snapshot["inFlight"] is None and snapshot["childIdentity"] is None
        database_state = (
            snapshot["reservedCall"] is None
            and isinstance(snapshot["inFlight"], dict)
            and snapshot["inFlight"].get("kind") == "DATABASE"
            and snapshot["childIdentity"] is not None
        )
        if not (reservation_state or database_state):
            _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "ACTIVE_READY":
        if (
            not snapshot["preflightPassed"]
            or snapshot["toolboxSessionId"] is None
            or snapshot["childIdentity"] is None
            or snapshot["inFlight"] is not None
            or snapshot["reservedCall"] is not None
            or snapshot["queryCloseCleanupAck"]
            or not 1 <= snapshot["callCount"] < MAX_DATABASE_CALLS
        ):
            _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "IN_FLIGHT_TOOL" and (
        snapshot["inFlight"] is None
        or snapshot["inFlight"].get("kind") != "DATABASE"
        or snapshot["reservedCall"] is not None
        or snapshot["toolboxSessionId"] is None
        or snapshot["childIdentity"] is None
        or not snapshot["preflightPassed"]
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "EVIDENCE_IN_FLIGHT" and (
        snapshot["inFlight"] is None or snapshot["inFlight"].get("kind") != "EVIDENCE"
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "QUERY_CLOSED" and (
        snapshot["callCount"] != MAX_DATABASE_CALLS
        or snapshot["inFlight"] is not None
        or snapshot["reservedCall"] is not None
        or not snapshot["preflightPassed"]
        or snapshot["toolboxSessionId"] is None
        or snapshot["childIdentity"] is None
        or snapshot["queryCloseCleanupAck"]
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "EVIDENCE_IN_FLIGHT" and (
        snapshot["inFlight"] is None
        or snapshot["inFlight"].get("kind") != "EVIDENCE"
        or snapshot["reservedCall"] is not None
        or not snapshot["preflightPassed"]
        or snapshot["callCount"] != MAX_DATABASE_CALLS
        or not snapshot["queryCloseCleanupAck"]
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] == "REVOKE_PENDING_CLEANUP":
        if (
            snapshot["toolboxSessionId"] is None
            or snapshot["reservedLaunchIdentity"] is None
            or cleanup is None
        ):
            _reject("LEDGER_CORRUPT")
        if cleanup["cleanupKind"] == "TOOLBOX_TERMINATION" and cleanup["toolboxSessionId"] != snapshot["toolboxSessionId"]:
            _reject("LEDGER_CORRUPT")
        if cleanup["cleanupKind"] == "TOOLBOX_TERMINATION":
            if snapshot["childIdentity"] is None and cleanup["toolboxChildIdentity"] is not None:
                _reject("LEDGER_CORRUPT")
            if snapshot["childIdentity"] is not None:
                expected_child = canon(snapshot["childIdentity"]).decode("utf-8")
                if cleanup["toolboxChildIdentity"] != expected_child:
                    _reject("LEDGER_CORRUPT")
    if snapshot["state"] in TERMINAL_RUN_STATES and (
        snapshot["inFlight"] is not None or snapshot["reservedCall"] is not None
    ):
        _reject("LEDGER_CORRUPT")
    if snapshot["state"] in TERMINAL_RUN_STATES and snapshot["queryCloseCleanupAck"] and (
        snapshot["callCount"] < 1
        or not snapshot["preflightPassed"]
        or snapshot["toolboxSessionId"] is None
        or snapshot["childIdentity"] is None
        or (
            snapshot["state"] == "REVOKED"
            and cleanup is not None
            and cleanup["cleanupKind"] == "TOOLBOX_TERMINATION"
        )
    ):
        _reject("LEDGER_CORRUPT")
    return True


def default_profile() -> dict:
    """构造不包含主机、密码或连接串的最小 profile fixture。"""
    obj = data_object()
    return {
        "profileId": "fixture-profile",
        "businessCatalogSchemas": ["ai_dw"],
        "implementationCatalog": ["information_schema.columns", "pg_catalog.pg_class"],
        "systemRoutineExposureBaseline": ["pg_catalog.random", "pg_catalog.clock_timestamp"],
        "systemRoutineCallAllowlist": ["COUNT", "MIN", "MAX", "SUM", "AVG"],
        "allowedObjects": [obj],
        "expectedDatabase": "fixture_db",
        "expectedPrincipal": "fixture_ro",
        "expectedCurrentSchema": "ai_dw",
        "expectedReadOnly": True,
        "accountLabel": "fixture-ro",
        "decisionRef": "DECISION-FIXTURE-1",
        "evidenceTopic": "fixture",
    }


def validate_profile(profile: dict) -> dict:
    fields = {
        "profileId", "businessCatalogSchemas", "implementationCatalog", "systemRoutineExposureBaseline",
        "systemRoutineCallAllowlist", "allowedObjects", "expectedDatabase", "expectedPrincipal",
        "expectedCurrentSchema", "expectedReadOnly", "accountLabel", "decisionRef", "evidenceTopic",
    }
    profile = _exact(profile, fields, fields, "profile")
    _string(profile["profileId"], "profile_id", 1, 128)
    for field in ("businessCatalogSchemas", "implementationCatalog", "systemRoutineExposureBaseline", "systemRoutineCallAllowlist", "allowedObjects"):
        if not isinstance(profile[field], list):
            _reject("profile_" + field)
    for index, schema in enumerate(profile["businessCatalogSchemas"]):
        _identifier(schema, f"profile_schema_{index}")
    for field in ("implementationCatalog", "systemRoutineExposureBaseline", "systemRoutineCallAllowlist"):
        for index, value in enumerate(profile[field]):
            _string(value, f"profile_{field}_{index}", 1, 256)
    if not profile["businessCatalogSchemas"]:
        _reject("profile_businessCatalogSchemas")
    if not set(profile["systemRoutineExposureBaseline"]).issubset(SYSTEM_ROUTINE_METADATA):
        _reject("profile_routine_baseline")
    if not set(profile["systemRoutineCallAllowlist"]).issubset(
        set(profile["systemRoutineExposureBaseline"]) | {"COUNT", "MIN", "MAX", "SUM", "AVG"}
    ):
        _reject("profile_routine_allowlist")
    for index, obj in enumerate(profile["allowedObjects"]):
        validate_data_object(obj, f"profile_object_{index}")
        if obj["schema"] not in profile["businessCatalogSchemas"]:
            _reject("profile_object_schema")
    for field in ("expectedDatabase", "expectedPrincipal", "expectedCurrentSchema"):
        _string(profile[field], field, 1, 128)
    if profile["expectedReadOnly"] is not True:
        _reject("profile_read_only")
    return profile


def validate_profile_run_scope(profile: dict, scope: dict) -> bool:
    """分别校验 profile 账号上界与当前 run dataObjects 子集。"""
    profile = validate_profile(profile)
    scope = validate_scope(scope, authorization=True)
    if not set(scope["businessCatalogSchemas"]).issubset(set(profile["businessCatalogSchemas"])):
        _reject("AUTH_SCOPE_MISMATCH")
    allowed = {(item["schema"], item["object"], item["catalogIdentity"]["oid"]) for item in profile["allowedObjects"]}
    requested = {(item["schema"], item["object"], item["catalogIdentity"]["oid"]) for item in scope["dataObjects"]}
    if not requested.issubset(allowed):
        _reject("AUTH_SCOPE_MISMATCH")
    return True


def preflight(snapshot: dict, profile: dict, scope: dict) -> dict:
    """对注入的数据库身份/权限快照生成不泄露原始身份的 21 项结论。"""
    snapshot = _exact(
        snapshot,
        {"identity", "transactionReadOnly", "timeouts", "privileges"},
        {"identity", "transactionReadOnly", "timeouts", "privileges"},
        "preflight_snapshot",
    )
    profile = validate_profile(profile)
    scope = validate_scope(scope, authorization=True)
    validate_profile_run_scope(profile, scope)
    identity = _exact(
        snapshot["identity"],
        {"database", "user", "currentSchema"},
        {"database", "user", "currentSchema"},
        "identity",
    )
    identity_matches = {
        "database": identity.get("database") == profile["expectedDatabase"],
        "user": identity.get("user") == profile["expectedPrincipal"],
        "currentSchema": identity.get("currentSchema") == profile["expectedCurrentSchema"],
    }
    privileges = snapshot["privileges"]
    if not isinstance(privileges, dict):
        privileges = {}
    privilege_ok = True
    try:
        validate_privilege_snapshot(privileges)
    except FixtureRejected:
        privilege_ok = False
    hard_fail = not privilege_ok
    timeouts = _exact(
        snapshot["timeouts"],
        {"statement", "lock", "idleInTransaction"},
        {"statement", "lock", "idleInTransaction"},
        "timeouts",
    )
    timeout_ok = (
        isinstance(timeouts["statement"], int)
        and not isinstance(timeouts["statement"], bool)
        and 1 <= timeouts["statement"] <= 15000
        and isinstance(timeouts["lock"], int)
        and not isinstance(timeouts["lock"], bool)
        and 1 <= timeouts["lock"] <= 5000
        and isinstance(timeouts["idleInTransaction"], int)
        and not isinstance(timeouts["idleInTransaction"], bool)
        and 1 <= timeouts["idleInTransaction"] <= 15000
    )
    checks = []
    positive_checks = {
        "CAPABILITY_SIGNATURE": "capabilitySignature",
        "LEDGER_STATE": "ledgerState",
        "COMPONENT_MANIFEST": "componentManifest",
        "TRUSTED_HELPER": "trustedHelper",
        "CREDENTIAL_ISOLATION": "credentialIsolation",
        "CONNECT": "connect",
        "BUSINESS_SCHEMA_USAGE": "schemaUsage",
        "PROFILE_DATA_SELECT_BOUND": "profileDataSelect",
        "RUN_DATA_SCOPE_SUBSET": "runScopeSubset",
        "IMPLEMENTATION_CATALOG": "implementationCatalog",
        "SESSION_READ_ONLY": "transactionReadOnly",
        "COLUMN_CLASSIFICATION": "columnClassification",
    }
    negative_checks = {
        "NO_BYPASSRLS": "bypassRls",
        "NO_NON_SYSTEM_OWNERSHIP": "ownership",
        "NO_SET_ROLE_ESCALATION": "setRole",
        "NO_WRITE": "write",
        "NO_CREATE_TEMP": "createTemp",
        "NO_FILE_PROGRAM": "fileProgram",
        "ROUTINE": "routineRisk",
    }
    for name in PRIVILEGE_CHECKS:
        if name in positive_checks:
            passed = privileges.get(positive_checks[name]) is True
        elif name == "NO_EXTRA_SELECT":
            passed = not any(
                privileges.get(field) is True
                for field in ("extraSelect", "columnSelect", "publicSelect", "inheritedSelect")
            )
        elif name in negative_checks:
            passed = privileges.get(negative_checks[name]) is False
        elif name == "TIMEOUTS":
            passed = timeout_ok
        else:
            passed = False
        checks.append({"check": name, "passed": bool(passed), "scope": "fixture", "detailCode": "PENDING"})
    if snapshot["transactionReadOnly"] is not privileges.get("transactionReadOnly"):
        hard_fail = True
    all_passed = all(identity_matches.values()) and not hard_fail and all(item["passed"] for item in checks)
    detail = "PASS" if all_passed else "PREFLIGHT_PRIVILEGE"
    for item in checks:
        item["detailCode"] = "PASS" if all_passed and item["passed"] else detail
    issues = []
    if not all(identity_matches.values()):
        issues.append("PREFLIGHT_PRIVILEGE")
    if hard_fail:
        issues.append("PREFLIGHT_PRIVILEGE")
    if not timeout_ok:
        issues.append("PREFLIGHT_PRIVILEGE")
    component_results = [
        {
            "name": component["name"],
            "version": component["version"],
            "sha256": component["sha256"],
            "codeSignRequirement": component["codeSignRequirement"],
        }
        for component in default_component_manifest()["components"]
    ]
    return {
        "passed": all_passed,
        "databaseProduct": "kingbase-postgresql-compatible",
        "version": "fixture",
        "sessionReadOnly": snapshot["transactionReadOnly"] is True,
        "identityMatches": identity_matches,
        "privilegeChecks": checks,
        "routineRisk": bool(privileges.get("routineRisk", False)),
        "timeoutsMs": {"statement": timeouts.get("statement"), "lock": timeouts.get("lock"), "idleInTransaction": timeouts.get("idleInTransaction")},
        "components": component_results,
        "profileId": profile["profileId"],
        "issues": sorted(set(issues)),
    }


def validate_live_object(signed: dict, live: dict) -> bool:
    """证明签名对象仍是同 oid、非分区、非继承的本地基表。"""
    validate_data_object(signed, "signed_object")
    fields = {"objectKind", "catalogIdentity", "relkind", "relispartition", "relhassubclass", "inheritsParent", "inheritsChild"}
    live = _exact(live, fields, fields, "live_object")
    if live["objectKind"] != "LOCAL_BASE_TABLE" or live["relkind"] != "r":
        _reject("OBJECT_KIND_DENIED")
    if any(live[field] is not False for field in ("relispartition", "relhassubclass", "inheritsParent", "inheritsChild")):
        _reject("OBJECT_KIND_DENIED")
    if live["catalogIdentity"] != signed["catalogIdentity"]:
        _reject("CATALOG_IDENTITY_DRIFT")
    return True


def validate_privilege_snapshot(snapshot: dict) -> bool:
    """反向权限 fixture：只读会话不是账号权限收敛的替代品。"""
    fields = {
        "capabilitySignature", "ledgerState", "componentManifest", "trustedHelper", "credentialIsolation",
        "connect", "schemaUsage", "profileDataSelect", "implementationCatalog", "runScopeSubset",
        "extraSelect", "columnSelect", "publicSelect", "inheritedSelect", "bypassRls", "ownership",
        "setRole", "write", "createTemp", "fileProgram", "routineRisk", "transactionReadOnly", "columnClassification",
    }
    snapshot = _exact(snapshot, fields, fields, "privileges")
    for key in fields:
        _boolean(snapshot[key], "privilege_" + key)
    if any(not snapshot[key] for key in (
        "capabilitySignature", "ledgerState", "componentManifest", "trustedHelper", "credentialIsolation",
        "connect", "schemaUsage", "profileDataSelect", "implementationCatalog", "runScopeSubset",
        "transactionReadOnly", "columnClassification",
    )):
        _reject("PREFLIGHT_PRIVILEGE")
    if any(snapshot[key] for key in ("extraSelect", "columnSelect", "publicSelect", "inheritedSelect", "bypassRls", "ownership", "setRole", "write", "createTemp", "fileProgram", "routineRisk")):
        _reject("PREFLIGHT_PRIVILEGE")
    return True


def validate_routine_exposure(routines: list[dict], exposure_baseline: set[str], call_allowlist: set[str]) -> bool:
    """区分 system exposure baseline 与更小的实际 routine call allowlist。"""
    if (
        not isinstance(routines, list)
        or not isinstance(exposure_baseline, (set, list, tuple))
        or not isinstance(call_allowlist, (set, list, tuple))
        or not set(exposure_baseline).issubset(SYSTEM_ROUTINE_METADATA)
        or not set(call_allowlist).issubset(set(exposure_baseline) | {"COUNT", "MIN", "MAX", "SUM", "AVG"})
    ):
        _reject("ROUTINE_RISK")
    fields = {"schema", "name", "identityArguments", "routineKind", "ownerPrincipal", "securityType", "volatility", "effectiveExecute"}
    seen = set()
    for index, routine in enumerate(routines):
        routine = _exact(routine, fields, fields, f"routine_{index}")
        for field in ("schema", "name", "identityArguments", "routineKind", "ownerPrincipal", "securityType", "volatility"):
            _string(routine[field], f"routine_{index}_{field}", 1, 256)
        _boolean(routine["effectiveExecute"], f"routine_{index}_execute")
        identity = routine["schema"] + "." + routine["name"]
        seen.add(identity)
        expected = SYSTEM_ROUTINE_METADATA.get(identity)
        if expected is None or any(routine[field] != expected[field] for field in expected):
            _reject("ROUTINE_RISK")
        if identity not in exposure_baseline and routine["effectiveExecute"]:
            _reject("ROUTINE_RISK")
    if not seen.issubset(exposure_baseline):
        _reject("ROUTINE_RISK")
    return True


def validate_search_query(query: str, search_in: list[str], page_size: int) -> bool:
    """拒绝空搜索、全量枚举和未绑定的 wildcard。"""
    query = _string(query, "query", 2, 128).strip()
    meaningful = sum(char.isalnum() or "\u4e00" <= char <= "\u9fff" for char in query)
    if meaningful < 2:
        _reject("INVALID_REQUEST")
    if not isinstance(search_in, list) or not 1 <= len(search_in) <= 3 or any(
        not isinstance(value, str) or value not in {"NAME", "COLUMN", "COMMENT"} for value in search_in
    ):
        _reject("INVALID_REQUEST")
    if (
        len(set(search_in)) != len(search_in)
        or isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= MAX_SEARCH_PAGE_SIZE
    ):
        _reject("INVALID_REQUEST")
    return True


def _validate_catalog_schema_request(tool: str, request: dict, scope: dict) -> None:
    """将 search/describe 的 metadata 请求绑定到当前 run 的 schema 上界。"""
    allowed_schemas = set(scope["businessCatalogSchemas"])
    if tool == "search_objects":
        schemas = request.get("schemas")
        if not isinstance(schemas, list) or not 1 <= len(schemas) <= 3:
            _reject("INVALID_REQUEST")
        normalized = []
        for index, schema in enumerate(schemas):
            normalized.append(_identifier(schema, f"search_schema_{index}"))
        if len(set(normalized)) != len(normalized):
            _reject("INVALID_REQUEST")
        if not set(normalized).issubset(allowed_schemas):
            _reject("AUTH_SCOPE_MISMATCH")
    elif tool == "describe_object":
        objects = request.get("objects")
        if not isinstance(objects, list) or not 1 <= len(objects) <= 5:
            _reject("INVALID_REQUEST")
        for index, value in enumerate(objects):
            identifier = _exact(
                value,
                {"schema", "object"},
                {"schema", "object"},
                f"describe_object_{index}",
            )
            schema = _identifier(identifier["schema"], f"describe_schema_{index}")
            _identifier(identifier["object"], f"describe_object_name_{index}")
            if schema not in allowed_schemas:
                _reject("AUTH_SCOPE_MISMATCH")


def validate_tool_access(tool: str, scope: dict, request: dict) -> bool:
    """验证 metadata-only、column grant 和 disabled generic SQL 的工具门禁。"""
    if not isinstance(request, dict):
        _reject("INVALID_REQUEST")
    scope = validate_scope(scope, authorization=True)
    if tool not in TOOL_NAMES:
        _reject("TOOL_DISABLED")
    _validate_catalog_schema_request(tool, request, scope)
    if scope["metadataOnly"]:
        if tool not in {"db_preflight", "search_objects", "describe_object", "get_table_stats"}:
            _reject("TOOL_DISABLED")
        if tool == "get_table_stats" and request.get("metric") not in {"CATALOG_ROW_ESTIMATE"}:
            _reject("AUTH_SCOPE_MISMATCH")
    if tool == "sample_rows" and (not scope["allowSample"] or not scope["sampleColumns"]):
        _reject("AUTH_SCOPE_MISMATCH")
    if tool == "execute_readonly_sql" and (not scope["allowGenericSql"] or not scope["sqlColumns"]):
        _reject("TOOL_DISABLED")
    return True


def validate_stats_request(request: dict, scope: dict) -> bool:
    """限制 TOP_K、列 metric 与 stats/value scope 的交集。"""
    scope = validate_scope(scope, authorization=True)
    request = _exact(request, {"metric", "column", "topK", "object"}, {"metric"}, "stats_request")
    if request["metric"] not in {"CATALOG_ROW_ESTIMATE", "ROW_COUNT", "NULL_COUNT", "DISTINCT_COUNT", "MIN", "MAX", "TOP_K"}:
        _reject("INVALID_REQUEST")
    if request.get("topK") is not None and (
        request["metric"] != "TOP_K"
        or isinstance(request["topK"], bool)
        or not isinstance(request["topK"], int)
        or not 1 <= request["topK"] <= 20
    ):
        _reject("INVALID_REQUEST")
    if request["metric"] in {"NULL_COUNT", "DISTINCT_COUNT", "MIN", "MAX", "TOP_K"} and not request.get("column"):
        _reject("AUTH_SCOPE_MISMATCH")
    if request["metric"] == "ROW_COUNT" and not request.get("column") and request.get("object") is None:
        _reject("AUTH_SCOPE_MISMATCH")
    if request.get("column") is not None and (
        not isinstance(request["column"], str)
        or request["column"] not in {item["column"] for item in scope["valueColumns"]}
    ):
        _reject("SENSITIVE_COLUMN")
    object_pairs = {(item["schema"], item["object"]) for item in scope["dataObjects"]}
    requested_pairs = object_pairs
    if request.get("object") is not None:
        requested_object = validate_data_object(request["object"], "stats_object")
        requested_pair = (requested_object["schema"], requested_object["object"])
        if requested_pair not in object_pairs:
            _reject("AUTH_SCOPE_MISMATCH")
        requested_pairs = {requested_pair}
    if request.get("column") is not None:
        column_pairs = {
            (item["schema"], item["object"])
            for item in scope["valueColumns"]
            if item["column"] == request["column"]
        }
        requested_pairs &= column_pairs
        if not requested_pairs:
            _reject("AUTH_SCOPE_MISMATCH")
    if request["metric"] != "CATALOG_ROW_ESTIMATE":
        granted = {
            (item["schema"], item["object"]): set(item["metrics"])
            for item in scope["statsGrants"]
        }
        if not any(request["metric"] in granted.get(pair, set()) for pair in requested_pairs):
            _reject("AUTH_SCOPE_MISMATCH")
    return True


def validate_sample_request(request: dict, scope: dict) -> bool:
    """样例只允许显式 sampleColumns，且每次最多十行/二十列。"""
    scope = validate_scope(scope, authorization=True)
    request = _exact(request, {"object", "columns", "limit"}, {"object", "columns"}, "sample_request")
    validate_data_object(request["object"], "sample_object")
    if request["object"] not in scope["dataObjects"] or not scope["allowSample"]:
        _reject("AUTH_SCOPE_MISMATCH")
    if not isinstance(request["columns"], list) or not 1 <= len(request["columns"]) <= 20:
        _reject("INVALID_REQUEST")
    requested_pair = (request["object"]["schema"], request["object"]["object"])
    allowed = {
        item["column"]
        for item in scope["sampleColumns"]
        if (item["schema"], item["object"]) == requested_pair
    }
    if any(column not in allowed for column in request["columns"]):
        _reject("SENSITIVE_COLUMN")
    if "limit" in request and (isinstance(request["limit"], bool) or not isinstance(request["limit"], int) or not 1 <= request["limit"] <= 10):
        _reject("INVALID_REQUEST")
    return True


def validate_evidence_content(target: dict, content: str | bytes) -> bool:
    """验证 evidence 单文件/总量上限与值级 DLP，禁止秘密落盘。"""
    validate_evidence_targets([target])
    raw = content.encode("utf-8") if isinstance(content, str) else content
    if not isinstance(raw, bytes) or len(raw) > MAX_EVIDENCE_FILE_BYTES or len(raw) > MAX_EVIDENCE_TOTAL_BYTES:
        _reject("EVIDENCE_TOO_LARGE")
    if scan_value(raw.decode("utf-8", errors="replace")):
        _reject("CREDENTIAL_BOUNDARY")
    return True


HARD_SENSITIVE_TOKENS = {
    "password", "passwd", "pwd", "token", "secret", "credential", "private_key", "mobile", "phone", "telephone", "email",
    "id_card", "idcard", "id_no", "idno", "cert_no", "passport", "bank_account", "card_number", "手机号", "电话", "邮箱", "身份证", "证件号", "护照", "银行卡号",
}


def classify_column(name: str, comment: str = "", explicit: str | None = None) -> str:
    """按硬敏感 token、显式 profile 分类和 fail-closed 默认值分类列。"""
    _string(name, "column_name", 1, 128)
    _string(comment, "column_comment", 0, 256)
    normalized_fields = {
        re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
        for value in (name, comment)
        if isinstance(value, str)
    }
    tokens = normalized_fields | set(re.split(r"[^a-z0-9]+", name.lower())) | set(re.split(r"[^a-z0-9]+", comment.lower()))
    if any(token in HARD_SENSITIVE_TOKENS for token in tokens) or any(token in comment for token in HARD_SENSITIVE_TOKENS if not token.isascii()):
        return "SENSITIVE"
    if explicit in {"SENSITIVE", "UNKNOWN", "PUBLIC_INTERNAL"}:
        return explicit
    return "UNKNOWN"


def scan_value(value: Any) -> bool:
    """检测疑似邮箱、手机号、连接串或秘密键值，命中即阻断原值。"""
    if value is None:
        return False
    text = str(value)
    patterns = (
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        r"(?i)(password|passwd|token|secret|apikey)\s*=",
        r"(?i)(jdbc|postgres(?:ql)?|kingbase)://",
        r"(?<!\d)1[3-9]\d{9}(?!\d)",
    )
    return any(re.search(pattern, text) for pattern in patterns)


def _quote_identifier(value: str, code: str) -> str:
    _identifier(value, code)
    return '"' + value.replace('"', '""') + '"'


def _decode_quoted_identifier(value: str, code: str) -> str:
    """解析 SQL 双引号 identifier，并还原标准 SQL 的双引号转义。"""
    match = re.fullmatch(r'"((?:""|[^"])*)"', value)
    if match is None:
        _reject("INVALID_QUERY")
    return _identifier(match.group(1).replace('""', '"'), code)


def render_only_select(schema: str, table: str, columns: list[str]) -> str:
    """生成固定 ONLY、双引号 identifier 的最小查询 fixture。"""
    if not isinstance(columns, list) or not columns:
        _reject("INVALID_IDENTIFIER")
    quoted_columns = ", ".join(_quote_identifier(column, "column") for column in columns)
    return f'SELECT {quoted_columns} FROM ONLY {_quote_identifier(schema, "schema")}.{_quote_identifier(table, "table")}'


def validate_sql(
    sql: str,
    allow_generic_sql: bool,
    allowed_columns: dict[str, str],
    expected_object: dict,
) -> bool:
    """对绑定对象和完整列 allowlist 的受限 SELECT 做 fail-closed 校验。"""
    if not allow_generic_sql:
        _reject("TOOL_DISABLED")
    validate_data_object(expected_object, "sql_object")
    if not isinstance(allowed_columns, dict) or not allowed_columns:
        _reject("UNKNOWN_COLUMN")
    for column, classification in allowed_columns.items():
        _identifier(column, "sql_column")
        if classification not in {"PUBLIC_INTERNAL", "SENSITIVE", "UNKNOWN"}:
            _reject("UNKNOWN_COLUMN")
    sql = _string(sql, "sql", 1, 4096)
    normalized = re.sub(r"\s+", " ", sql.strip())
    upper = normalized.upper()
    if "--" in normalized or "/*" in normalized or "*/" in normalized:
        _reject("INVALID_QUERY")
    if normalized.count(";") > 1 or (";" in normalized and not normalized.endswith(";")):
        _reject("INVALID_QUERY")
    forbidden = (" INSERT ", " UPDATE ", " DELETE ", " MERGE ", " COPY ", " CREATE ", " ALTER ", " DROP ", " TRUNCATE ", " GRANT ", " REVOKE ", " SET ROLE ", " SHOW ", " DESCRIBE ", " WITH RECURSIVE", " UNION ", " INTERSECT ", " EXCEPT ", " VALUES ", " LATERAL ", " EXPLAIN ANALYZE", " LOCK ", " FOR UPDATE", " FOR SHARE", " FOR NO KEY", " SELECT INTO")
    padded = " " + upper + " "
    if any(token in padded for token in forbidden):
        _reject("INVALID_QUERY")
    query_match = re.fullmatch(
        r'SELECT\s+(?P<projection>.+?)\s+FROM\s+ONLY\s+"(?P<schema>(?:""|[^"])*)"\."(?P<object>(?:""|[^"])*)"\s+LIMIT\s+(?P<limit>[1-9][0-9]*)\s*;?',
        normalized,
        re.IGNORECASE,
    )
    if query_match is None:
        _reject("INVALID_QUERY")
    if (
        _decode_quoted_identifier('"' + query_match.group("schema") + '"', "sql_schema") != expected_object["schema"]
        or _decode_quoted_identifier('"' + query_match.group("object") + '"', "sql_object") != expected_object["object"]
    ):
        _reject("OBJECT_DRIFT")
    if int(query_match.group("limit")) > MAX_SEARCH_PAGE_SIZE:
        _reject("INVALID_QUERY")

    def split_projection(value: str) -> list[str]:
        parts = []
        start = 0
        depth = 0
        quoted = False
        index = 0
        while index < len(value):
            char = value[index]
            if char == '"':
                if quoted and index + 1 < len(value) and value[index + 1] == '"':
                    index += 2
                    continue
                quoted = not quoted
            elif not quoted and char == "(":
                depth += 1
            elif not quoted and char == ")":
                depth -= 1
                if depth < 0:
                    _reject("INVALID_QUERY")
            elif not quoted and char == "," and depth == 0:
                parts.append(value[start:index].strip())
                start = index + 1
            index += 1
        if quoted or depth != 0:
            _reject("INVALID_QUERY")
        parts.append(value[start:].strip())
        if any(not part for part in parts):
            _reject("INVALID_QUERY")
        return parts

    def check_column(value: str) -> None:
        try:
            column = _decode_quoted_identifier(value.strip(), "sql_column")
        except FixtureRejected:
            _reject("UNKNOWN_COLUMN")
        if column not in allowed_columns:
            _reject("UNKNOWN_COLUMN")
        classification = allowed_columns[column]
        if classification != "PUBLIC_INTERNAL":
            _reject("SENSITIVE_COLUMN" if classification == "SENSITIVE" else "UNKNOWN_COLUMN")

    for expression in split_projection(query_match.group("projection")):
        function_match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((.*)\)", expression)
        if function_match is None:
            check_column(expression)
            continue
        function_name = function_match.group(1).upper()
        if function_name not in {"COUNT", "MIN", "MAX", "SUM", "AVG"}:
            _reject("ROUTINE_RISK")
        argument = function_match.group(2).strip()
        if function_name == "COUNT" and argument == "*":
            continue
        check_column(argument)
    return True


def _schema_definitions() -> dict[str, dict]:
    """生成十四份闭集 Draft-like schema fixture。"""
    common = {"type": "object", "properties": {}, "additionalProperties": False}
    compact_scope = {
        "type": "object",
        "properties": {
            "scopeSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "counts": {
                "type": "object",
                "properties": {
                    field: {"type": "integer", "minimum": 0, "maximum": limit}
                    for field in ("businessCatalogSchemas", "dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants")
                    for limit in ({
                        "businessCatalogSchemas": 3,
                        "dataObjects": 50,
                        "valueColumns": 100,
                        "sampleColumns": 100,
                        "sqlColumns": 100,
                        "statsGrants": 100,
                    }[field],)
                },
                "required": ["businessCatalogSchemas", "dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants"],
                "additionalProperties": False,
            },
            "preview": {
                "type": "object",
                "properties": {
                    "businessCatalogSchemas": {"type": "array", "maxItems": 3, "items": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
                    "dataObjects": {
                        "type": "array",
                        "maxItems": 3,
                        "items": {
                            "type": "object",
                            "properties": {
                                "schema": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN},
                                "object": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN},
                                "objectKind": {"type": "string", "maxLength": 32},
                            },
                            "required": ["schema", "object", "objectKind"],
                            "additionalProperties": False,
                        },
                    },
                    "valueColumns": {
                        "type": "array",
                        "maxItems": 3,
                        "items": {
                            "type": "object",
                            "properties": {
                                "schema": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN},
                                "object": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN},
                                "column": {"type": "string", "maxLength": 32, "pattern": IDENTIFIER_SCHEMA_PATTERN},
                            },
                            "required": ["schema", "object", "column"],
                            "additionalProperties": False,
                        },
                    },
                },
                "required": ["businessCatalogSchemas", "dataObjects", "valueColumns"],
                "additionalProperties": False,
            },
        },
        "required": ["scopeSha256", "counts", "preview"],
        "additionalProperties": False,
    }
    page = {
        "type": ["object", "null"],
        "properties": {
            "pageSize": {"type": "integer", "minimum": 1, "maximum": 20},
            "nextPageToken": {"type": ["string", "null"], "minLength": 1, "maxLength": 2048},
        },
        "required": ["pageSize", "nextPageToken"],
        "additionalProperties": False,
    }
    evidence = {
        "type": "object",
        "properties": {
            "toolName": {"type": "string"},
            "profileId": {"type": "string"},
            "scope": compact_scope,
            "executedAt": {"type": "string"},
            "durationMs": {"type": "integer", "minimum": 0},
            "rowsReturned": {"type": "integer", "minimum": 0},
            "serializedBytes": {"type": "integer", "minimum": 0, "maximum": MAX_RESPONSE_BYTES},
            "queryFingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "databaseTouched": {"type": "boolean"},
        },
        "required": ["toolName", "profileId", "scope", "executedAt", "durationMs", "rowsReturned", "serializedBytes", "queryFingerprint", "databaseTouched"],
        "additionalProperties": False,
    }
    issue = {
        "type": "object",
        "properties": {
            "code": {"enum": list(ISSUE_CODES)},
            "safeMessage": {"type": "string", "minLength": 1, "maxLength": 512},
            "retryable": {"type": "boolean"},
        },
        "required": ["code", "safeMessage", "retryable"],
        "additionalProperties": False,
    }
    data_object_schema = {
        "type": "object",
        "properties": {
            "schema": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "object": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "objectKind": {"const": "LOCAL_BASE_TABLE"},
            "catalogIdentity": {
                "type": "object",
                "properties": {
                    "catalog": {"const": "PG_CLASS"},
                    "oid": {"type": "string", "pattern": "^[1-9][0-9]{0,19}$"},
                },
                "required": ["catalog", "oid"],
                "additionalProperties": False,
            },
        },
        "required": ["schema", "object", "objectKind", "catalogIdentity"],
        "additionalProperties": False,
    }
    identifier_schema = {
        "type": "object",
        "properties": {
            "schema": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "object": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
        },
        "required": ["schema", "object"],
        "additionalProperties": False,
    }
    column_identifier_schema = {
        "type": "object",
        "properties": {
            "schema": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "object": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "column": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
        },
        "required": ["schema", "object", "column"],
        "additionalProperties": False,
    }
    cell_schema = {
        "oneOf": [
            {
                "type": "object",
                "properties": {"kind": {"const": "NULL"}, "text": {"type": "null"}},
                "required": ["kind", "text"],
                "additionalProperties": False,
            },
            {
                "type": "object",
                "properties": {
                    "kind": {"enum": ["BOOLEAN", "INTEGER", "DECIMAL", "TEXT", "DATE", "TIMESTAMP"]},
                    "text": {"type": "string", "maxLength": 4096},
                },
                "required": ["kind", "text"],
                "additionalProperties": False,
            },
        ]
    }
    catalog_identity_schema = {
        "type": "object",
        "properties": {
            "catalog": {"const": "PG_CLASS"},
            "oid": {"type": "string", "pattern": "^[1-9][0-9]{0,19}$"},
        },
        "required": ["catalog", "oid"],
        "additionalProperties": False,
    }
    search_candidate_schema = {
        "type": "object",
        "properties": {
            "identifier": identifier_schema,
            "objectType": {"const": "BASE_TABLE"},
            "catalogIdentity": catalog_identity_schema,
            "matchedOn": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"enum": ["NAME", "COLUMN", "COMMENT"]}},
            "commentSnippet": {"type": ["string", "null"], "maxLength": 256},
        },
        "required": ["identifier", "objectType", "catalogIdentity", "matchedOn", "commentSnippet"],
        "additionalProperties": False,
    }
    preflight_privilege_schema = {
        "type": "object",
        "properties": {
            "check": {"enum": list(PRIVILEGE_CHECKS)},
            "passed": {"type": "boolean"},
            "scope": {"type": "string", "minLength": 1, "maxLength": 256},
            "detailCode": {"enum": ["PASS", *ISSUE_CODES]},
        },
        "required": ["check", "passed", "scope", "detailCode"],
        "additionalProperties": False,
    }
    component_result_schema = {
        "type": "object",
        "properties": {
            "name": {"enum": list(ALL_COMPONENTS)},
            "version": {"type": "string", "minLength": 1, "maxLength": 256},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "codeSignRequirement": {"type": "string", "minLength": 1, "maxLength": 256},
        },
        "required": ["name", "version", "sha256", "codeSignRequirement"],
        "additionalProperties": False,
    }
    describe_column_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "type": {"type": "string", "minLength": 1, "maxLength": 128},
            "nullable": {"type": "boolean"},
            "comment": {"type": ["string", "null"], "maxLength": 256},
            "classification": {"enum": ["PUBLIC_INTERNAL", "SENSITIVE", "UNKNOWN"]},
        },
        "required": ["name", "type", "nullable", "comment", "classification"],
        "additionalProperties": False,
    }
    describe_foreign_key_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "columns": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
            "referencedObject": {"oneOf": [identifier_schema, {"type": "null"}]},
            "referencedColumns": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
            "externalReference": {"type": "boolean"},
        },
        "required": ["name", "columns", "referencedObject", "referencedColumns", "externalReference"],
        "additionalProperties": False,
    }
    describe_index_schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "unique": {"type": "boolean"},
            "method": {"type": "string", "minLength": 1, "maxLength": 64},
            "columns": {"type": "array", "minItems": 1, "maxItems": 32, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
        },
        "required": ["name", "unique", "method", "columns"],
        "additionalProperties": False,
    }
    describe_object_result_schema = copy_schema(data_object_schema)
    describe_object_result_schema["properties"].update({
        "columns": {"type": "array", "maxItems": 200, "items": describe_column_schema},
        "primaryKey": {"type": "array", "maxItems": 32, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
        "foreignKeys": {"type": "array", "maxItems": 50, "items": describe_foreign_key_schema},
        "indexes": {"type": "array", "maxItems": 50, "items": describe_index_schema},
        "metadataSource": {"enum": ["INFORMATION_SCHEMA", "SYSTEM_CATALOG"]},
    })
    describe_object_result_schema["required"].extend(["columns", "primaryKey", "foreignKeys", "indexes", "metadataSource"])
    stats_item_schema = {
        "type": "object",
        "properties": {
            "metric": {"enum": ["CATALOG_ROW_ESTIMATE", "ROW_COUNT", "NULL_COUNT", "DISTINCT_COUNT", "MIN", "MAX", "TOP_K"]},
            "column": {"type": ["string", "null"], "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN},
            "value": {"oneOf": [cell_schema, {"type": "null"}]},
            "count": {"type": ["string", "null"], "pattern": "^(0|[1-9][0-9]*)$"},
            "approximate": {"type": "boolean"},
            "metadataSource": {"enum": ["INFORMATION_SCHEMA", "SYSTEM_CATALOG", "BOUNDED_QUERY"]},
        },
        "required": ["metric", "column", "value", "count", "approximate", "metadataSource"],
        "additionalProperties": False,
    }
    response_data_schemas = {
        "db_preflight": {
            "type": "object",
            "properties": {
                "passed": {"type": "boolean"},
                "databaseProduct": {"type": "string", "minLength": 1, "maxLength": 64},
                "version": {"type": "string", "minLength": 1, "maxLength": 64},
                "sessionReadOnly": {"type": "boolean"},
                "identityMatches": {
                    "type": "object",
                    "properties": {field: {"type": "boolean"} for field in ("database", "user", "currentSchema")},
                    "required": ["database", "user", "currentSchema"],
                    "additionalProperties": False,
                },
                "privilegeChecks": {"type": "array", "minItems": 21, "maxItems": 21, "items": preflight_privilege_schema},
                "routineRisk": {"type": "boolean"},
                "timeoutsMs": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "integer", "minimum": 1, "maximum": 15000},
                        "lock": {"type": "integer", "minimum": 1, "maximum": 5000},
                        "idleInTransaction": {"type": "integer", "minimum": 1, "maximum": 15000},
                    },
                    "required": ["statement", "lock", "idleInTransaction"],
                    "additionalProperties": False,
                },
                "components": {"type": "array", "minItems": 10, "maxItems": 10, "items": component_result_schema},
                "profileId": {"type": "string", "minLength": 1, "maxLength": 128},
                "issues": {"type": "array", "items": {"enum": list(ISSUE_CODES)}},
            },
            "required": ["passed", "databaseProduct", "version", "sessionReadOnly", "identityMatches", "privilegeChecks", "routineRisk", "timeoutsMs", "components", "profileId", "issues"],
            "additionalProperties": False,
        },
        "search_objects": {
            "type": "object",
            "properties": {"candidates": {"type": "array", "maxItems": 20, "items": search_candidate_schema}},
            "required": ["candidates"],
            "additionalProperties": False,
        },
        "describe_object": {
            "type": "object",
            "properties": {"objects": {"type": "array", "maxItems": 5, "items": describe_object_result_schema}},
            "required": ["objects"],
            "additionalProperties": False,
        },
        "get_table_stats": {
            "type": "object",
            "properties": {"stats": {"type": "array", "maxItems": 100, "items": stats_item_schema}},
            "required": ["stats"],
            "additionalProperties": False,
        },
        "sample_rows": {
            "type": "object",
            "properties": {
                "sourceColumns": {"type": "array", "minItems": 1, "maxItems": 20, "items": column_identifier_schema},
                "rows": {"type": "array", "maxItems": 10, "items": {"type": "array", "maxItems": 20, "items": cell_schema}},
                "maskingApplied": {"type": "boolean"},
            },
            "required": ["sourceColumns", "rows", "maskingApplied"],
            "additionalProperties": False,
        },
        "execute_readonly_sql": {
            "type": "object",
            "properties": {
                "resultColumns": {
                    "type": "array", "minItems": 1, "maxItems": 100,
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "minLength": 1, "maxLength": 128},
                            "type": {"type": "string", "minLength": 1, "maxLength": 128},
                            "sourceColumns": {"type": "array", "minItems": 1, "maxItems": 20, "items": column_identifier_schema},
                        },
                        "required": ["label", "type", "sourceColumns"],
                        "additionalProperties": False,
                    },
                },
                "rows": {"type": "array", "maxItems": 100, "items": {"type": "array", "maxItems": 100, "items": cell_schema}},
                "maskingApplied": {"type": "boolean"},
            },
            "required": ["resultColumns", "rows", "maskingApplied"],
            "additionalProperties": False,
        },
    }
    gateway = {
        "type": "object",
        "properties": {
            "contractVersion": {"const": "1"},
            "errorCode": {"enum": ["AUTH_REQUIRED", "INVALID_REQUEST", "POLICY_DENIED", "AUTH_EXPIRED", "DEPENDENCY_UNAVAILABLE"]},
            "databaseTouched": {"const": False},
            "safeMessage": {"type": "string", "minLength": 1, "maxLength": 512},
            "retryable": {"type": "boolean"},
            "requestId": {"type": ["string", "null"], "pattern": UUID_SCHEMA_PATTERN},
            "runId": {"type": ["string", "null"], "pattern": UUID_SCHEMA_PATTERN},
        },
        "required": ["contractVersion", "errorCode", "databaseTouched", "safeMessage", "retryable", "requestId", "runId"],
        "additionalProperties": False,
    }
    base_request = {
        "type": "object",
        "properties": {
            "contractVersion": {"const": "1"},
            "requestId": {"type": "string", "pattern": UUID_SCHEMA_PATTERN},
            "runId": {"type": "string", "pattern": UUID_SCHEMA_PATTERN},
            "callSequence": {"type": "integer", "minimum": 1, "maximum": MAX_DATABASE_CALLS},
            "authorizationSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "toolContractSha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "required": ["contractVersion", "requestId", "runId", "callSequence", "authorizationSha256", "toolContractSha256"],
        "additionalProperties": False,
    }
    base_response = {
        "type": "object",
        "properties": {
            "contractVersion": {"const": "1"},
            "requestId": {"type": "string", "pattern": UUID_SCHEMA_PATTERN},
            "runId": {"type": "string", "pattern": UUID_SCHEMA_PATTERN},
            "status": {"enum": list(TOOL_STATUSES)},
            "truncated": {"type": "boolean"},
            "data": {"type": "null"},
            "page": page,
            "evidence": evidence,
            "issues": {"type": "array", "maxItems": 20, "items": issue},
        },
        "required": ["contractVersion", "requestId", "runId", "status", "truncated", "data", "page", "evidence", "issues"],
        "additionalProperties": False,
    }
    definitions = {"common": common, "gateway-error-v1": gateway}
    request_fields = {
        "db_preflight": {},
        "search_objects": {
            "schemas": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
            "query": {"type": "string", "minLength": 2, "maxLength": 128},
            "searchIn": {"type": "array", "minItems": 1, "maxItems": 3, "items": {"enum": ["NAME", "COLUMN", "COMMENT"]}},
            "objectTypes": {"type": "array", "minItems": 1, "maxItems": 1, "items": {"const": "BASE_TABLE"}},
            "pageSize": {"type": "integer", "minimum": 1, "maximum": MAX_SEARCH_PAGE_SIZE},
            "pageToken": {"type": ["string", "null"], "minLength": 1, "maxLength": 2048},
        },
        "describe_object": {
            "objects": {"type": "array", "minItems": 1, "maxItems": 5, "items": identifier_schema},
        },
        "get_table_stats": {
            "object": data_object_schema,
            "metrics": {
                "type": "array", "minItems": 1, "maxItems": 7,
                "items": {"enum": ["CATALOG_ROW_ESTIMATE", "ROW_COUNT", "NULL_COUNT", "DISTINCT_COUNT", "MIN", "MAX", "TOP_K"]},
            },
            "columns": {"type": "array", "maxItems": 10, "items": column_identifier_schema},
            "topK": {"type": ["integer", "null"], "minimum": 1, "maximum": 20},
        },
        "sample_rows": {
            "object": data_object_schema,
            "columns": {"type": "array", "minItems": 1, "maxItems": 20, "items": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": IDENTIFIER_SCHEMA_PATTERN}},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10},
        },
        "execute_readonly_sql": {
            "sql": {"type": "string", "minLength": 1, "maxLength": 4096},
            "maxRows": {"type": "integer", "minimum": 1, "maximum": 100},
        },
    }
    request_required = {
        "db_preflight": [],
        "search_objects": ["schemas", "query", "searchIn", "objectTypes", "pageSize", "pageToken"],
        "describe_object": ["objects"],
        "get_table_stats": ["object", "metrics", "columns", "topK"],
        "sample_rows": ["object", "columns", "limit"],
        "execute_readonly_sql": ["sql", "maxRows"],
    }
    for tool in TOOL_NAMES:
        request_schema = copy_schema(base_request)
        request_schema["properties"].update(request_fields[tool])
        request_schema["required"].extend(request_required[tool])
        definitions[tool + ".request"] = request_schema
        response_schema = copy_schema(base_response)
        response_schema["properties"]["data"] = {
            "oneOf": [response_data_schemas[tool], {"type": "null"}]
        }
        if tool != "search_objects":
            response_schema["properties"]["page"] = {"type": "null"}
        definitions[tool + ".response"] = response_schema
    return definitions


def copy_schema(value: Any) -> Any:
    return json.loads(json.dumps(value))


def schema_manifest() -> list[dict]:
    """按 ASCII schema 文件名顺序返回 14 项 path/SHA manifest。"""
    definitions = _schema_definitions()
    def schema_path(name: str) -> str:
        if name == "common":
            return "common.schema.json"
        if name == "gateway-error-v1":
            return "gateway-error.schema.json"
        tool, kind = name.rsplit(".", 1)
        return f"{tool}.{kind}.schema.json"

    entries = [
        {"path": schema_path(name), "sha256": _digest(definitions[name])}
        for name in definitions
    ]
    return sorted(entries, key=lambda entry: entry["path"].encode("utf-8"))


def tool_contract_manifest_sha256() -> str:
    """计算四份公共/十二份工具 schema 的冻结 aggregate SHA-256。"""
    return _digest(schema_manifest())


def _matches_schema(schema: dict, value: Any, path: str = "$") -> None:
    if "oneOf" in schema:
        successes = 0
        for option in schema["oneOf"]:
            try:
                _matches_schema(option, value, path)
                successes += 1
            except FixtureRejected:
                pass
        if successes != 1:
            _reject("schema_one_of")
        return
    if "anyOf" in schema:
        for option in schema["anyOf"]:
            try:
                _matches_schema(option, value, path)
                return
            except FixtureRejected:
                pass
        _reject("schema_any_of")
    if "const" in schema and value != schema["const"]:
        _reject("schema_const")
    if "enum" in schema and value not in schema["enum"]:
        _reject("schema_enum")
    type_value = schema.get("type")
    types = type_value if isinstance(type_value, list) else [type_value]
    if type_value is not None:
        valid = any(
            (kind == "object" and isinstance(value, dict))
            or (kind == "array" and isinstance(value, list))
            or (kind == "string" and isinstance(value, str))
            or (kind == "integer" and isinstance(value, int) and not isinstance(value, bool))
            or (kind == "boolean" and isinstance(value, bool))
            or (kind == "null" and value is None)
            for kind in types
        )
        if not valid:
            _reject("schema_type")
    if isinstance(value, dict):
        required = set(schema.get("required", []))
        if required - set(value):
            _reject("schema_required")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and set(value) - set(properties):
            _reject("schema_extra")
        for key, child_schema in properties.items():
            if key in value:
                _matches_schema(child_schema, value[key], path + "." + key)
    if isinstance(value, list) and "items" in schema:
        if "minItems" in schema and len(value) < schema["minItems"]:
            _reject("schema_items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            _reject("schema_items")
        for child in value:
            _matches_schema(schema["items"], child, path + "[]")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            _reject("schema_length")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            _reject("schema_length")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            _reject("schema_pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            _reject("schema_minimum")
        if "maximum" in schema and value > schema["maximum"]:
            _reject("schema_maximum")


def _validate_response_semantics(name: str, response: dict) -> None:
    """校验 JSON schema 无法表达的状态、权限结论与行宽不变量。"""
    tool = name.split(".")[0]
    status = response["status"]
    success = status in SUCCESS_STATUSES
    data = response["data"]
    if success and data is None:
        _reject("response_data")
    if not success:
        if data is not None or response["page"] is not None:
            _reject("response_error_data")
        return
    if tool == "search_objects" and response["page"] is None:
        _reject("response_page")
    if tool == "db_preflight":
        if (
            status == "TRUNCATED"
            or data["sessionReadOnly"] is not True
            or data["passed"] is not True
            or any(value is not True for value in data["identityMatches"].values())
            or data["routineRisk"] is not False
            or [item["check"] for item in data["privilegeChecks"]] != list(PRIVILEGE_CHECKS)
            or any(item["passed"] is not True or item["detailCode"] != "PASS" for item in data["privilegeChecks"])
            or [item["name"] for item in data["components"]] != list(ALL_COMPONENTS)
        ):
            _reject("PREFLIGHT_PRIVILEGE")
    elif tool == "get_table_stats":
        for item in data["stats"]:
            metric = item["metric"]
            if metric in {"CATALOG_ROW_ESTIMATE", "ROW_COUNT"}:
                if (
                    item["column"] is not None
                    or item["value"] is not None
                    or item["count"] is None
                    or (metric == "ROW_COUNT" and item["approximate"] is not False)
                ):
                    _reject("response_stats")
            elif metric in {"NULL_COUNT", "DISTINCT_COUNT"}:
                if item["column"] is None or item["value"] is not None or item["count"] is None or item["approximate"] is not False:
                    _reject("response_stats")
            elif metric in {"MIN", "MAX"}:
                if item["column"] is None or item["value"] is None or item["count"] is not None or item["approximate"] is not False:
                    _reject("response_stats")
            elif metric == "TOP_K":
                if item["column"] is None or item["value"] is None or item["count"] is None or item["approximate"] is not False:
                    _reject("response_stats")
    elif tool == "sample_rows":
        width = len(data["sourceColumns"])
        if any(len(row) != width for row in data["rows"]):
            _reject("response_rows")
    elif tool == "execute_readonly_sql":
        width = len(data["resultColumns"])
        if any(len(row) != width for row in data["rows"]):
            _reject("response_rows")


def validate_schema_instance(name: str, value: Any) -> bool:
    """验证指定 schema 实例并拒绝未知 schema。"""
    definitions = _schema_definitions()
    if name not in definitions:
        _reject("schema_unknown")
    _matches_schema(definitions[name], value)
    if name == "search_objects.request":
        validate_search_query(value["query"], value["searchIn"], value["pageSize"])
    if name.endswith(".response"):
        _validate_response_semantics(name, value)
    return True


def _validate_compact_scope(scope: dict) -> dict:
    """校验 response 中 compact evidence.scope 的三键及计数/preview 形状。"""
    scope = _exact(scope, {"scopeSha256", "counts", "preview"}, {"scopeSha256", "counts", "preview"}, "evidence_scope")
    _sha(scope["scopeSha256"], "scopeSha256")
    count_fields = {"businessCatalogSchemas", "dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants"}
    counts = _exact(scope["counts"], count_fields, count_fields, "scope_counts")
    for field, value in counts.items():
        _integer(value, "scope_count_" + field, 0)
        if value > {"businessCatalogSchemas": 3, "dataObjects": 50, "valueColumns": 100, "sampleColumns": 100, "sqlColumns": 100, "statsGrants": 100}[field]:
            _reject("scope_count")
    preview_fields = {"businessCatalogSchemas", "dataObjects", "valueColumns"}
    preview = _exact(scope["preview"], preview_fields, preview_fields, "scope_preview")
    if not isinstance(preview["businessCatalogSchemas"], list) or len(preview["businessCatalogSchemas"]) > 3:
        _reject("scope_preview")
    for index, value in enumerate(preview["businessCatalogSchemas"]):
        _string(value, f"scope_preview_schema_{index}", 1, 32)
    for field, required in (
        ("dataObjects", {"schema", "object", "objectKind"}),
        ("valueColumns", {"schema", "object", "column"}),
    ):
        if not isinstance(preview[field], list) or len(preview[field]) > 3:
            _reject("scope_preview")
        for index, item in enumerate(preview[field]):
            item = _exact(item, required, required, f"scope_preview_{field}_{index}")
            for key in required:
                _string(item[key], f"scope_preview_{field}_{index}_{key}", 1, 32)
    return scope


def build_gateway_error(code: str, request_id: str | None, run_id: str | None) -> dict:
    """构造不带 evidence 的 pre-auth gateway-error-v1。"""
    if code not in {"AUTH_REQUIRED", "INVALID_REQUEST", "POLICY_DENIED", "AUTH_EXPIRED", "DEPENDENCY_UNAVAILABLE"}:
        _reject("issue_code")
    def public_id(value: str | None, code_name: str) -> str | None:
        if value is None:
            return None
        try:
            return _uuid(value, code_name)
        except FixtureRejected:
            return None

    result = {
        "contractVersion": "1",
        "errorCode": code,
        "databaseTouched": False,
        "safeMessage": "safe gateway error",
        "retryable": code in {"AUTH_REQUIRED", "DEPENDENCY_UNAVAILABLE"},
        "requestId": public_id(request_id, "requestId"),
        "runId": public_id(run_id, "runId"),
    }
    if len(canon(result)) > 4096:
        _reject("EVIDENCE_TOO_LARGE")
    return result


def build_tool_response(tool: str, status: str, request_id: str, run_id: str, evidence_scope: dict, data: Any) -> dict:
    """构造绑定 canonical id/evidence 的稳定 tool response fixture。"""
    if tool not in TOOL_NAMES:
        _reject("tool_name")
    _uuid(request_id, "requestId")
    _uuid(run_id, "runId")
    if status not in TOOL_STATUSES:
        _reject("status")
    if status in SUCCESS_STATUSES and data is None:
        _reject("response_data")
    evidence_scope = _validate_compact_scope(evidence_scope)
    status_issue = {
        "AUTH_EXPIRED": "AUTH_EXPIRED",
        "CALL_BUDGET_EXHAUSTED": "CALL_BUDGET_EXHAUSTED",
        "SCOPE_DENIED": "AUTH_SCOPE_MISMATCH",
        "POLICY_DENIED": "PREFLIGHT_PRIVILEGE",
        "PREFLIGHT_FAILED": "PREFLIGHT_PRIVILEGE",
        "INVALID_REQUEST": "INVALID_IDENTIFIER",
        "NOT_FOUND": "OBJECT_DRIFT",
        "DRIFT": "OBJECT_DRIFT",
        "TIMEOUT": "DEPENDENCY_UNAVAILABLE",
        "DEPENDENCY_ERROR": "DEPENDENCY_UNAVAILABLE",
        "RESULT_TOO_LARGE": "EVIDENCE_TOO_LARGE",
        "INTERNAL_ERROR": "INTERNAL_FAILURE",
    }
    response = {
        "contractVersion": "1",
        "requestId": request_id,
        "runId": run_id,
        "status": status,
        "truncated": status == "TRUNCATED",
        "data": data,
        "page": {"pageSize": MAX_SEARCH_PAGE_SIZE, "nextPageToken": None}
        if tool == "search_objects" and status in SUCCESS_STATUSES
        else None,
        "evidence": {
            "toolName": tool,
            "profileId": "fixture-profile",
            "scope": evidence_scope,
            "executedAt": "1970-01-01T00:00:00Z",
            "durationMs": 0,
            "rowsReturned": 0,
            "serializedBytes": 0,
            "queryFingerprint": "0" * 64,
            "databaseTouched": False,
        },
        "issues": [] if status in SUCCESS_STATUSES else [{"code": status_issue[status], "safeMessage": "fixture", "retryable": False}],
    }
    for _ in range(3):
        size = len(canon(response))
        if size > MAX_RESPONSE_BYTES:
            _reject("EVIDENCE_TOO_LARGE")
        response["evidence"]["serializedBytes"] = size
        if len(canon(response)) == size:
            break
    final_size = len(canon(response))
    if final_size > MAX_RESPONSE_BYTES or response["evidence"]["serializedBytes"] != final_size:
        _reject("EVIDENCE_TOO_LARGE")
    return response


def validate_response_contract(name: str, response: dict) -> bool:
    """验证 gateway error 或 tool response 的外层状态不变量。"""
    if name == "gateway-error-v1":
        validate_schema_instance(name, response)
        if "evidence" in response:
            _reject("gateway_evidence")
        return True
    if not name.endswith(".response") or name.split(".")[0] not in TOOL_NAMES:
        _reject("response_name")
    validate_schema_instance(name, response)
    if set(response) != {"contractVersion", "requestId", "runId", "status", "truncated", "data", "page", "evidence", "issues"}:
        _reject("response_fields")
    if response["status"] not in TOOL_STATUSES:
        _reject("response_status")
    if not isinstance(response["truncated"], bool):
        _reject("response_truncated")
    if response["page"] is not None and not isinstance(response["page"], dict):
        _reject("response_page")
    tool_name = name.split(".")[0]
    if tool_name != "search_objects" and response["page"] is not None:
        _reject("response_page")
    if tool_name == "search_objects" and response["page"] is not None:
        page = _exact(response["page"], {"pageSize", "nextPageToken"}, {"pageSize", "nextPageToken"}, "response_page")
        _integer(page["pageSize"], "pageSize", 1)
        if page["pageSize"] > MAX_SEARCH_PAGE_SIZE:
            _reject("response_page")
        if page["nextPageToken"] is not None:
            _string(page["nextPageToken"], "nextPageToken", 1, 2048)
    if not isinstance(response["issues"], list):
        _reject("response_issues")
    if response["status"] in SUCCESS_STATUSES and response["data"] is None:
        _reject("response_data")
    if response["status"] == "TRUNCATED" and response["truncated"] is not True:
        _reject("response_truncated")
    if response["status"] != "TRUNCATED" and response["truncated"] is not False:
        _reject("response_truncated")
    if response["status"] not in SUCCESS_STATUSES and not response["issues"]:
        _reject("response_issue")
    if response["status"] not in SUCCESS_STATUSES and (
        response["data"] is not None or response["page"] is not None
    ):
        _reject("response_error_data")
    _uuid(response["requestId"], "requestId")
    _uuid(response["runId"], "runId")
    evidence = response["evidence"]
    evidence_fields = {
        "toolName", "profileId", "scope", "executedAt", "durationMs", "rowsReturned",
        "serializedBytes", "queryFingerprint", "databaseTouched",
    }
    if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
        _reject("response_evidence")
    if evidence["toolName"] != name.split(".")[0] or not isinstance(evidence["profileId"], str):
        _reject("response_evidence")
    if not isinstance(evidence["executedAt"], str) or evidence["executedAt"] != "1970-01-01T00:00:00Z":
        _reject("response_evidence")
    for field in ("durationMs", "rowsReturned"):
        _integer(evidence[field], "evidence_" + field, 0)
    _integer(evidence["serializedBytes"], "evidence_serializedBytes", 0)
    if evidence["serializedBytes"] > MAX_RESPONSE_BYTES:
        _reject("EVIDENCE_TOO_LARGE")
    _sha(evidence["queryFingerprint"], "queryFingerprint")
    if not isinstance(evidence["databaseTouched"], bool):
        _reject("response_database_touched")
    if response["status"] not in SUCCESS_STATUSES and evidence["databaseTouched"]:
        _reject("response_database_touched")
    _validate_compact_scope(evidence["scope"])
    if response["status"] == "EMPTY" and evidence["rowsReturned"] != 0:
        _reject("response_rows")
    if len(canon(response)) > MAX_RESPONSE_BYTES:
        _reject("EVIDENCE_TOO_LARGE")
    if evidence["serializedBytes"] != len(canon(response)):
        _reject("response_bytes")
    for issue in response["issues"]:
        issue = _exact(issue, {"code", "safeMessage", "retryable"}, {"code", "safeMessage", "retryable"}, "issue")
        if issue["code"] not in ISSUE_CODES:
            _reject("issue_code")
        _string(issue["safeMessage"], "issue_message", 1, 512)
        _boolean(issue["retryable"], "issue_retryable")
    return True


def issue_page_token(token_context: dict, last_key: list[str], page: int, expires_at: int, *, candidate_count: int) -> str:
    """生成带完整性 MAC、绑定会话、候选总量和最后披露候选的 opaque token。"""
    fields = {"authorizationSha256", "runId", "gatewaySessionNonce", "toolName", "queryFingerprint"}
    if not isinstance(token_context, dict):
        _reject("page_context")
    if set(token_context) != fields:
        _reject("page_context")
    for field in ("authorizationSha256", "queryFingerprint"):
        _sha(token_context[field], field)
    _uuid(token_context["runId"], "runId")
    _nonce(token_context["gatewaySessionNonce"], "gatewaySessionNonce")
    if token_context["toolName"] != "search_objects":
        _reject("page_context")
    if not isinstance(last_key, list) or len(last_key) != 3 or any(not isinstance(value, str) for value in last_key):
        _reject("page_key")
    for value in last_key:
        _string(value, "page_key_value", 1, 256)
    _integer(page, "page", 1)
    if page > 5:
        _reject("page")
    _integer(expires_at, "expiresAt", 1)
    _integer(candidate_count, "candidateCount", 1)
    if candidate_count > MAX_SEARCH_CANDIDATES:
        _reject("candidate_budget")
    payload = {
        **token_context,
        "lastKey": last_key,
        "page": page,
        "expiresAt": expires_at,
        "candidateCount": candidate_count,
    }
    mac = hmac.new(PAGE_TOKEN_MAC_KEY, canon(payload), hashlib.sha256).hexdigest()
    raw = base64.urlsafe_b64encode(canon({"payload": payload, "mac": mac})).decode("ascii").rstrip("=")
    return raw


def verify_page_token(token: str, token_context: dict, now_ms: int) -> dict:
    """验证 token 的 MAC、run/session/query 绑定和五页上限。"""
    if not isinstance(token, str) or re.fullmatch(r"[A-Za-z0-9_-]+", token) is None:
        _reject("INVALID_REQUEST")
    try:
        decoded = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8")
        envelope = json.loads(decoded)
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        _reject("INVALID_REQUEST")
    envelope = _exact(envelope, {"payload", "mac"}, {"payload", "mac"}, "page_token")
    _sha(envelope["mac"], "page_token_mac")
    payload = envelope["payload"]
    fields = {"authorizationSha256", "runId", "gatewaySessionNonce", "toolName", "queryFingerprint", "lastKey", "page", "expiresAt", "candidateCount"}
    if not isinstance(payload, dict) or set(payload) != fields:
        _reject("INVALID_REQUEST")
    if not isinstance(token_context, dict) or set(token_context) != {"authorizationSha256", "runId", "gatewaySessionNonce", "toolName", "queryFingerprint"}:
        _reject("INVALID_REQUEST")
    for field in ("authorizationSha256", "queryFingerprint"):
        _sha(token_context[field], field)
    _uuid(token_context["runId"], "runId")
    _nonce(token_context["gatewaySessionNonce"], "gatewaySessionNonce")
    if token_context["toolName"] != "search_objects":
        _reject("INVALID_REQUEST")
    if any(payload.get(key) != token_context.get(key) for key in ("authorizationSha256", "runId", "gatewaySessionNonce", "toolName", "queryFingerprint")):
        _reject("INVALID_REQUEST")
    expected_mac = hmac.new(PAGE_TOKEN_MAC_KEY, canon(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(envelope["mac"], expected_mac):
        _reject("INVALID_REQUEST")
    if not isinstance(payload["lastKey"], list) or len(payload["lastKey"]) != 3 or any(not isinstance(value, str) for value in payload["lastKey"]):
        _reject("INVALID_REQUEST")
    for value in payload["lastKey"]:
        _string(value, "page_key_value", 1, 256)
    _integer(payload["page"], "page", 1)
    _integer(payload["expiresAt"], "expiresAt", 1)
    _integer(payload["candidateCount"], "candidateCount", 1)
    if payload["candidateCount"] > MAX_SEARCH_CANDIDATES:
        _reject("candidate_budget")
    _integer(now_ms, "now_ms", 0)
    if payload["page"] > 5 or payload["expiresAt"] <= now_ms:
        _reject("INVALID_REQUEST")
    return payload


def paginate_candidates(
    candidates: list[dict],
    page_size: int,
    token: str | None,
    context: dict,
    max_bytes: int = 32768,
    *,
    now_ms: int | None = None,
    expires_at: int | None = None,
) -> tuple[list[dict], str | None]:
    """按固定排序和完整 response 字节预算分页，裁剪不计入 candidate digest。"""
    if (
        not isinstance(candidates, list)
        or isinstance(page_size, bool)
        or not isinstance(page_size, int)
        or not 1 <= page_size <= MAX_SEARCH_PAGE_SIZE
        or isinstance(max_bytes, bool)
        or not isinstance(max_bytes, int)
        or max_bytes < 1
    ):
        _reject("INVALID_REQUEST")
    _integer(now_ms, "now_ms", 0)
    if expires_at is not None:
        _integer(expires_at, "expiresAt", 1)
    if len(candidates) > MAX_SEARCH_CANDIDATES:
        _reject("candidate_budget")
    normalized = []
    for index, candidate in enumerate(candidates):
        candidate = _exact(candidate, {"schema", "object", "objectType"}, {"schema", "object", "objectType"}, f"candidate_{index}")
        for field in ("schema", "object", "objectType"):
            _string(candidate[field], f"candidate_{index}_{field}", 1, 256)
        normalized.append(candidate)
    ordered = sorted(normalized, key=lambda item: (item["schema"], item["object"], item["objectType"]))
    start = 0
    page_number = 1
    token_expires_at = expires_at
    if token is not None:
        previous = verify_page_token(token, context, now_ms)
        if previous["candidateCount"] != len(ordered):
            _reject("INVALID_REQUEST")
        if expires_at is not None and expires_at != previous["expiresAt"]:
            _reject("INVALID_REQUEST")
        token_expires_at = previous["expiresAt"]
        key = tuple(previous["lastKey"])
        found = False
        for index, candidate in enumerate(ordered):
            if (candidate["schema"], candidate["object"], candidate["objectType"]) == key:
                start = index + 1
                found = True
                break
        if not found:
            _reject("INVALID_REQUEST")
        page_number = previous["page"] + 1
    elif token_expires_at is None:
        token_expires_at = now_ms + PAGE_TOKEN_TTL_MS
    if token_expires_at <= now_ms:
        _reject("INVALID_REQUEST")
    selected = ordered[start : start + page_size]
    while selected:
        response = canon({"candidates": selected})
        if len(response) <= max_bytes:
            break
        selected.pop()
    if not selected and ordered[start : start + page_size]:
        _reject("EVIDENCE_TOO_LARGE")
    if not selected:
        return [], None
    end = start + len(selected)
    next_token = None
    if end < len(ordered):
        last = selected[-1]
        next_token = issue_page_token(
            context,
            [last["schema"], last["object"], last["objectType"]],
            page_number,
            token_expires_at,
            candidate_count=len(ordered),
        )
    return selected, next_token


def hidden_discovery_fixture(seed: int = 1) -> dict:
    """生成不依赖工作台已知表名的干净随机 catalog fixture。"""
    rng = random.Random(seed)
    schema = "s_" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(8))
    tables = []
    for index in range(6):
        table = "t_" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(10))
        tables.append({"schema": schema, "object": table, "objectType": "BASE_TABLE", "comment": f"业务实体 {index}"})
    target = tables[rng.randrange(len(tables))]
    return {"problem": f"定位 {target['comment']}", "catalog": tables, "expected": target}


def tool_surface() -> dict:
    """返回固定六工具暴露面及禁止的 prebuilt/dynamic 工具。"""
    return {
        "enabled": list(TOOL_NAMES),
        "disabled": ["list_tables", "postgres-execute-sql", "default-toolset", "dynamic-reload", "shell", "psql"],
    }
