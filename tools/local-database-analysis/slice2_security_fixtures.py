"""
作者：elvis
日期：2026-08-20
作用：提供 Slice 2 批准、账本、Trusted Helper 与 evidence 的纯本地安全 fixture

本模块刻意不实现 macOS 特权服务、代码签名、Keychain、Toolbox 或数据库连接。
它只把这些组件之间的安全合同压缩成可注入、可重复的 Python 边界，供 RED/GREEN
测试验证调用方、状态、摘要、窗口、permit variant 与 evidence manifest。
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from canonical import canon
from security_fixtures import (
    DATABASE_PERMIT_LEASE_MS,
    EVIDENCE_PERMIT_LEASE_MS,
    FixtureRejected,
    LIVE_RUN_STATES,
    MAX_EVIDENCE_FILE_BYTES,
    MAX_EVIDENCE_TOTAL_BYTES,
    REPORT_SPAWN_DEADLINE_MS,
    SingleRunRegistry,
    TERMINAL_RUN_STATES,
    validate_capability,
    validate_evidence_content,
    validate_evidence_targets,
    issue_capability,
)


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
MAX_CHILD_PID = 4_194_304


class Slice2Rejected(FixtureRejected):
    """表示 Slice 2 的本地安全边界拒绝了输入。"""


def _reject(code: str) -> None:
    """以稳定 issue code fail closed。"""
    raise Slice2Rejected(code)


def _digest(value: Any) -> str:
    """计算 fixture 使用的 canonical JSON SHA-256。"""
    return hashlib.sha256(canon(value)).hexdigest()


def _response_digest(value: Any) -> str:
    """计算已交付响应的摘要；不接受仅凭格式伪造的 digest。"""
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    try:
        return _digest(value)
    except (TypeError, ValueError) as exc:
        raise Slice2Rejected("RESPONSE_EVIDENCE_INVALID") from exc


def _sha(value: Any, code: str = "DIGEST_INVALID") -> str:
    """校验小写 SHA-256 字符串。"""
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        _reject(code)
    return value


def _uuid(value: Any, code: str = "UUID_INVALID") -> str:
    """校验 canonical UUID。"""
    if not isinstance(value, str) or UUID_RE.fullmatch(value) is None:
        _reject(code)
    return value


def _integer(value: Any, code: str, minimum: int = 0) -> int:
    """校验非 bool 整数时间/预算。"""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        _reject(code)
    return value


def _rfc3339_ms(value: int) -> str:
    """把 fixture 毫秒时间转换为稳定 UTC 文本。"""
    _integer(value, "TIMESTAMP_INVALID")
    stamp = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _started_at(value: Any, code: str = "CHILD_IDENTITY_INVALID") -> str:
    """校验 RFC3339 UTC startedAt，而不是仅检查尾随字符。"""
    if not isinstance(value, str) or RFC3339_UTC_RE.fullmatch(value) is None:
        _reject(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise Slice2Rejected(code) from exc
    if parsed.tzinfo != timezone.utc:
        _reject(code)
    return value


def _uuid5(label: str) -> str:
    """以 fixture namespace 生成可重复的 UUID。"""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "slice2-fixture:" + label))


def _canonical_child(identity: Mapping[str, Any]) -> str:
    """把已验证 child identity 固定为不含秘密的稳定序列化。"""
    if not isinstance(identity, Mapping):
        _reject("CHILD_IDENTITY_INVALID")
    if set(identity) != {"pid", "auditTokenSha256", "startedAt"}:
        _reject("CHILD_IDENTITY_INVALID")
    pid = _integer(identity["pid"], "CHILD_IDENTITY_INVALID", 1)
    if pid > MAX_CHILD_PID:
        _reject("CHILD_IDENTITY_INVALID")
    _sha(identity["auditTokenSha256"], "CHILD_IDENTITY_INVALID")
    _started_at(identity["startedAt"])
    return canon(dict(identity)).decode("utf-8")


class ApprovedCapability(dict):
    """Broker fixture 的批准结果；mapping 内容仍只包含原 capability 字段。"""

    def __init__(
        self,
        capability: dict,
        broker_key_id: str,
        authorization_sha256: str,
        signature: str,
        broker: "ApprovalBrokerFixture | None" = None,
    ):
        self.capability = copy.deepcopy(capability)
        super().__init__(copy.deepcopy(self.capability))
        self.broker_key_id = broker_key_id
        self.authorization_sha256 = authorization_sha256
        self.signature = signature
        self.run_id = capability["runId"]
        self._broker = broker

    def __getitem__(self, key: str) -> Any:
        """允许测试以 mapping 方式读取 Broker 元数据。"""
        if key == "brokerKeyId":
            return self.broker_key_id
        if key == "authorizationSha256":
            return self.authorization_sha256
        if key == "signature":
            return self.signature
        if key in self.capability:
            return self.capability[key]
        return super().__getitem__(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """让 mapping 级篡改同步到验证属性，确保伪造不会被忽略。"""
        if key == "brokerKeyId":
            self.broker_key_id = value
            return
        if key == "authorizationSha256":
            self.authorization_sha256 = value
            return
        if key == "signature":
            self.signature = value
            return
        copied = copy.deepcopy(value)
        dict.__setitem__(self, key, copied)
        if hasattr(self, "capability"):
            self.capability[key] = copy.deepcopy(copied)

    def update(self, *args: Any, **kwargs: Any) -> None:
        """让 dict.update() 走同一 canonical mapping 写入路径。"""
        updates = dict(*args, **kwargs)
        for key, value in updates.items():
            self[key] = value

    def __ior__(self, other: Mapping[str, Any]):
        """让 mapping |= 也保持批准视图与 capability 同步。"""
        self.update(other)
        return self

    def __delitem__(self, key: str) -> None:
        """删除字段时同步 canonical capability，避免双重可变视图。"""
        dict.__delitem__(self, key)
        if hasattr(self, "capability"):
            self.capability.pop(key, None)

    def clear(self) -> None:
        """清空 mapping 时同步清空 canonical capability。"""
        dict.clear(self)
        if hasattr(self, "capability"):
            self.capability.clear()

    def pop(self, key: str, *args: Any) -> Any:
        """弹出字段时同步 canonical capability。"""
        value = dict.pop(self, key, *args)
        if hasattr(self, "capability"):
            self.capability.pop(key, None)
        return value

    def to_capability(self) -> dict:
        """返回不含 Broker 外层元数据的 capability 深拷贝。"""
        return copy.deepcopy(self.capability)

    def __deepcopy__(self, memo: dict) -> "ApprovedCapability":
        """保持测试篡改副本与原批准结果相互隔离。"""
        duplicate = type(self)(
            copy.deepcopy(self.capability, memo),
            self.broker_key_id,
            self.authorization_sha256,
            self.signature,
            self._broker,
        )
        memo[id(self)] = duplicate
        return duplicate


class ApprovalBrokerFixture:
    """模拟必须具备完整 UI 与 userPresence 的本地批准 Broker。"""

    def __init__(self, broker_key_id: str = "fixture-broker-key-v1", broker_epoch: str = "broker-1"):
        self.broker_key_id = broker_key_id
        self.broker_epoch = broker_epoch
        # 这是测试材料，不是文件、环境变量或 Keychain credential。
        self._fixture_material = b"slice2-broker-fixture-material-v1"

    @staticmethod
    def ui_snapshot(candidate: Mapping[str, Any]) -> dict:
        """构造 Approval UI 必须显示的完整、可比较快照。"""
        try:
            return {
                "profileId": candidate["profileId"],
                "scope": copy.deepcopy(candidate["scope"]),
                "componentManifest": copy.deepcopy(candidate["componentManifest"]),
                "evidenceTargets": copy.deepcopy(candidate["evidenceTargets"]),
                "expiresAt": candidate["expiresAt"],
                "maxToolCalls": candidate["maxToolCalls"],
                "evidenceCommitBudget": candidate["evidenceCommitBudget"],
                "userPresence": True,
            }
        except (KeyError, TypeError) as exc:
            raise Slice2Rejected("AUTH_UI_INVALID") from exc

    def _signature(self, authorization_sha256: str) -> str:
        """计算 fixture-only 签名摘要，不声称为 ES256/macOS 签名。"""
        payload = canon({"brokerKeyId": self.broker_key_id, "authorizationSha256": authorization_sha256})
        return hmac.new(self._fixture_material, payload, hashlib.sha256).hexdigest()

    def approve(self, candidate: dict, ui: dict, now_ms: int = 0) -> ApprovedCapability:
        """仅对完整 UI 快照和明确 userPresence 的 capability 签发批准结果。"""
        _integer(now_ms, "now_ms")
        if not isinstance(candidate, dict) or not isinstance(ui, dict):
            _reject("AUTH_UI_INVALID")
        expected = self.ui_snapshot(candidate)
        if set(ui) != set(expected):
            _reject("AUTH_UI_FIELDS")
        if ui.get("userPresence") is not True:
            _reject("AUTH_USER_PRESENCE_REQUIRED")
        for field in expected:
            if field != "userPresence" and ui[field] != expected[field]:
                if field == "scope":
                    _reject("AUTH_UI_SCOPE_MISMATCH")
                if field == "componentManifest":
                    _reject("AUTH_COMPONENT_MISMATCH")
                _reject("AUTH_UI_MISMATCH")
        if candidate.get("brokerEpoch") != self.broker_epoch:
            _reject("AUTH_EPOCH_MISMATCH")
        capability = issue_capability(candidate, now_ms=now_ms)
        authorization_sha256 = _digest(capability)
        signature = self._signature(authorization_sha256)
        return ApprovedCapability(capability, self.broker_key_id, authorization_sha256, signature, self)

    def verify(self, approved: Any, now_ms: int = 0) -> bool:
        """验证批准结果的 capability、期限、broker epoch 与签名摘要。"""
        try:
            if not isinstance(approved, ApprovedCapability):
                return False
            capability = approved.to_capability()
            if approved.broker_key_id != self.broker_key_id:
                return False
            if capability.get("brokerEpoch") != self.broker_epoch:
                return False
            if dict(approved) != capability:
                return False
            if not validate_capability(capability, now_ms=now_ms):
                return False
            authorization_sha256 = _digest(capability)
            if not hmac.compare_digest(authorization_sha256, approved.authorization_sha256):
                return False
            expected = self._signature(authorization_sha256)
            return hmac.compare_digest(expected, approved.signature)
        except (FixtureRejected, KeyError, TypeError):
            return False


class LedgerServiceFixture:
    """把 Slice 1 状态机包装为 caller/permit/cleanup 绑定的 Slice 2 ledger。"""

    def __init__(self, approved: ApprovedCapability, now_ms: int = 0, registry: SingleRunRegistry | None = None):
        _integer(now_ms, "now_ms")
        if not isinstance(approved, ApprovedCapability):
            _reject("AUTH_SIGNATURE_INVALID")
        self.approved = copy.deepcopy(approved)
        self.capability = self.approved.to_capability()
        self.authorization_sha256 = self.approved.authorization_sha256
        self.registry = registry or SingleRunRegistry()
        self._inner = None
        self._pending = True
        self._helper_ipc_token = object()
        self._commit_ipc_token = object()
        self._session_id = _uuid5(self.capability["runId"] + ":toolbox-session")
        self._helper_execution_session_id = _uuid5(self.capability["runId"] + ":helper-execution")
        self._commit_execution_session_id = _uuid5(self.capability["runId"] + ":commit-execution")
        self._toolbox_component_sha256 = self._component_sha("TOOLBOX")
        self._trusted_helper_component_sha256 = self._component_sha("TRUSTED_HELPER")
        self._commit_component_sha256 = self._component_sha("COMMIT_EVIDENCE")
        self._reservation: dict | None = None
        self._toolbox_state: str | None = None
        self._spawned_child_identity: dict | None = None
        self._persisted_child_identity: str | None = None
        self._current_database_permit: dict | None = None
        self._database_permit_inner: dict | None = None
        self._database_permit_delivered = False
        self._database_completion_evidence: dict | None = None
        self._completed_database_permit_ids: set[str] = set()
        self._evidence_permit: dict | None = None
        self._evidence_permit_inner: dict | None = None
        self._recovery_generation = 0
        self._active_recovery_command: dict | None = None
        self._cleanup_id: str | None = None
        self._cleanup_kind: str | None = None
        self._cleanup_evidence_wal_id: str | None = None
        self._cleanup_terminal_target = "REVOKED"
        self._accepts_late_spawn = True

    def _component_sha(self, name: str) -> str:
        """读取批准 manifest 中单一组件摘要。"""
        for component in self.capability["componentManifest"]["components"]:
            if component["name"] == name:
                return component["sha256"]
        _reject("AUTH_COMPONENT_MISMATCH")

    def _remember_cleanup(
        self,
        kind: str,
        evidence_wal_id: str | None = None,
        terminal_target: str = "REVOKED",
    ) -> None:
        """记录 recovery command 应绑定的外部资源类型。"""
        if kind not in {"TOOLBOX_TERMINATION", "EVIDENCE_ROLLBACK"}:
            _reject("LEDGER_CORRUPT")
        if terminal_target not in {"REVOKED", "EXPIRED"}:
            _reject("LEDGER_CORRUPT")
        if kind == "EVIDENCE_ROLLBACK":
            _uuid(evidence_wal_id, "LEDGER_CORRUPT")
        elif evidence_wal_id is not None:
            _reject("LEDGER_CORRUPT")
        self._cleanup_kind = kind
        self._cleanup_evidence_wal_id = evidence_wal_id
        self._cleanup_terminal_target = terminal_target

    @property
    def state(self) -> str:
        """返回 PENDING_APPROVAL 或底层七态/终态。"""
        return "PENDING_APPROVAL" if self._inner is None else self._inner.state

    @property
    def in_flight(self) -> dict | None:
        """返回对 Helper 可见的 permit；RESERVED 永远返回 None。"""
        if self._inner is None or self._inner.reserved_call is not None:
            return None
        if self._inner.in_flight is None:
            return None
        if self._evidence_permit is not None and self._inner.in_flight.get("kind") == "EVIDENCE":
            return copy.deepcopy(self._evidence_permit)
        return copy.deepcopy(self._current_database_permit)

    @property
    def reserved_call(self) -> dict | None:
        """返回第一段 reservation 的非 secret 摘要。"""
        return copy.deepcopy(self._reservation)

    @property
    def database_completion_evidence(self) -> dict | None:
        """返回最近一次 database completion 的持久摘要，不返回原始响应。"""
        return copy.deepcopy(self._database_completion_evidence)

    @property
    def completed_database_permit_ids(self) -> set[str]:
        """返回已消费的 database permit ID 闭集。"""
        return set(self._completed_database_permit_ids)

    @property
    def child_identity(self) -> dict | None:
        """返回已验证 child identity 的 fixture 副本。"""
        return copy.deepcopy(self._spawned_child_identity)

    def _inner_child_identity(self) -> dict | None:
        """把合同 child identity 映射到底层 Slice 1 的兼容表示。"""
        if self._inner is None or self._inner.child_identity is None:
            if self._persisted_child_identity is not None:
                _reject("OBJECT_DRIFT")
            return None
        expected = self._validate_persisted_child_identity()
        if expected is None or set(self._inner.child_identity) != {"pid", "audit"}:
            _reject("OBJECT_DRIFT")
        if (
            self._inner.child_identity["pid"] != self._spawned_child_identity["pid"]
            or self._inner.child_identity["audit"] != self._spawned_child_identity["auditTokenSha256"]
        ):
            _reject("OBJECT_DRIFT")
        return copy.deepcopy(self._inner.child_identity)

    def _validate_persisted_child_identity(self) -> str | None:
        """核对 rich child identity 与其首次持久化的 canonical 序列化。"""
        if self._spawned_child_identity is None:
            if self._persisted_child_identity is not None:
                _reject("OBJECT_DRIFT")
            return None
        current = _canonical_child(self._spawned_child_identity)
        if self._persisted_child_identity != current:
            _reject("OBJECT_DRIFT")
        return current

    @property
    def toolbox_session(self) -> dict | None:
        """返回持久化 Toolbox session 的非秘密状态快照。"""
        if self._inner is None or self._toolbox_state is None:
            return None
        return {
            "toolboxSessionId": self._session_id,
            "state": self._toolbox_state,
            "reservedLaunchIdentity": copy.deepcopy(self._inner.reserved_launch_identity),
            "spawnedChildIdentity": copy.deepcopy(self.child_identity),
            "toolboxComponentSha256": self._toolbox_component_sha256,
        }

    @property
    def accepts_late_spawn(self) -> bool:
        """标记 RESERVED 窗口是否仍可能接受成功 payload。"""
        return bool(
            self._accepts_late_spawn
            and self._inner is not None
            and self._inner.state == "IN_FLIGHT_PREFLIGHT"
            and self._inner.reserved_call is not None
            and self._inner.in_flight is None
        )

    def activate(self, now_ms: int = 0) -> str:
        """把批准结果一次性激活为 ACTIVE_UNPREFLIGHTED。"""
        _integer(now_ms, "now_ms")
        if not self._pending or self._inner is not None:
            _reject("AUTH_REPLAY")
        if self.approved._broker is None or not self.approved._broker.verify(self.approved, now_ms=now_ms):
            _reject("AUTH_SIGNATURE_INVALID")
        try:
            self._inner = self.registry.begin(self.capability, now_ms)
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._pending = False
        return self._inner.state

    def _require_active(self, caller: str) -> None:
        """校验 Gateway 入口和已激活 ledger。"""
        if caller != "gateway":
            _reject("GATEWAY_REQUIRED")
        if self._inner is None:
            _reject("LEDGER_UNAVAILABLE")

    def _check_request(self, request: Mapping[str, Any]) -> tuple[str, str, int, dict]:
        """校验绑定 run/auth/request 的公共请求字段。"""
        required = {"runId", "authorizationSha256", "requestId", "callSequence", "toolName", "arguments"}
        if not isinstance(request, Mapping) or set(request) != required:
            _reject("INVALID_REQUEST")
        if request["runId"] != self.capability["runId"]:
            _reject("AUTH_SCOPE_MISMATCH")
        if request["authorizationSha256"] != self.authorization_sha256:
            _reject("AUTH_SIGNATURE_INVALID")
        if not isinstance(request["requestId"], str) or UUID_RE.fullmatch(request["requestId"]) is None:
            _reject("INVALID_REQUEST")
        _integer(request["callSequence"], "INVALID_REQUEST", 1)
        if not isinstance(request["toolName"], str) or not request["toolName"]:
            _reject("INVALID_REQUEST")
        if not isinstance(request["arguments"], dict):
            _reject("INVALID_REQUEST")
        return request["toolName"], request["requestId"], request["callSequence"], copy.deepcopy(request["arguments"])

    def begin_call(self, request: Mapping[str, Any], now_ms: int, caller: str = "gateway") -> dict:
        """由 Gateway 建立 reservation 或排队一个后续数据库调用。"""
        _integer(now_ms, "now_ms")
        self._require_active(caller)
        tool, request_id, sequence, arguments = self._check_request(request)
        try:
            result = self._inner.begin_call(tool, request_id, sequence, arguments, now_ms)
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        if result.get("kind") == "RESERVATION":
            self._reservation = {
                "kind": "RESERVATION",
                "runId": self.capability["runId"],
                "authorizationSha256": self.authorization_sha256,
                "requestId": request_id,
                "callSequence": sequence,
                "toolName": tool,
                "effectiveArgumentsSha256": result["argumentsSha256"],
                "reservedAtMs": now_ms,
                "toolboxSessionId": self._session_id,
                "toolboxComponentSha256": self._toolbox_component_sha256,
                "helperExecutionSessionId": self._helper_execution_session_id,
            }
            self._toolbox_state = "RESERVED"
            self._accepts_late_spawn = True
            return copy.deepcopy(self._reservation)
        # 后续调用的底层 fixture 已建立 database inFlight；Gateway 只拿 BEGIN_ACK。
        self._current_database_permit = self._make_database_permit(result, now_ms, sequence)
        self._database_permit_inner = copy.deepcopy(result)
        self._database_permit_delivered = False
        return {
            "kind": "BEGIN_ACK",
            "runId": self.capability["runId"],
            "requestId": request_id,
            "callSequence": sequence,
        }

    def _validate_report_spawn_scan(self, scan: Mapping[str, Any]) -> dict:
        """验证失败 reportSpawn 的完整 V1 扫描原像，不把缺失扫描当作空命中。"""
        fields = {
            "algorithm",
            "executableFdIdentity",
            "perLaunchNonce",
            "toolboxSessionId",
            "scanComplete",
            "matchedPids",
            "scannedAt",
            "digest",
        }
        if not isinstance(scan, Mapping) or set(scan) != fields:
            _reject("SPAWN_FAILED")
        if scan["algorithm"] != "MACOS_PROCESS_LIST_MATCH_LAUNCH_IDENTITY_V1":
            _reject("SPAWN_FAILED")
        reserved = self._inner.reserved_launch_identity
        if not isinstance(reserved, Mapping):
            _reject("SPAWN_FAILED")
        if scan["executableFdIdentity"] != reserved["executableFdIdentity"]:
            _reject("SPAWN_FAILED")
        if scan["perLaunchNonce"] != reserved["perLaunchNonce"]:
            _reject("SPAWN_FAILED")
        if scan["toolboxSessionId"] != reserved["toolboxSessionId"]:
            _reject("SPAWN_FAILED")
        if not isinstance(scan["scanComplete"], bool) or not isinstance(scan["matchedPids"], list):
            _reject("SPAWN_FAILED")
        for pid in scan["matchedPids"]:
            _integer(pid, "SPAWN_FAILED", 1)
        if scan["matchedPids"] != sorted(set(scan["matchedPids"])):
            _reject("SPAWN_FAILED")
        if not isinstance(scan["scannedAt"], str) or not scan["scannedAt"]:
            _reject("SPAWN_FAILED")
        body = {field: scan[field] for field in fields if field != "digest"}
        if scan["digest"] != _digest(body):
            _reject("SPAWN_FAILED")
        return copy.deepcopy(dict(scan))

    def launch_scan_fixture(self, scan_complete: bool = True, matched_pids: list[int] | None = None) -> dict:
        """为测试构造绑定当前 reservation 的 V1 launch scan，不读取真实进程表。"""
        if self._inner is None or self._inner.reserved_launch_identity is None:
            _reject("SPAWN_FAILED")
        if matched_pids is None:
            matched_pids = []
        body = {
            "algorithm": "MACOS_PROCESS_LIST_MATCH_LAUNCH_IDENTITY_V1",
            "executableFdIdentity": copy.deepcopy(self._inner.reserved_launch_identity["executableFdIdentity"]),
            "perLaunchNonce": self._inner.reserved_launch_identity["perLaunchNonce"],
            "toolboxSessionId": self._inner.reserved_launch_identity["toolboxSessionId"],
            "scanComplete": scan_complete,
            "matchedPids": list(matched_pids),
            "scannedAt": "1970-01-01T00:00:00Z",
        }
        return {**body, "digest": _digest(body)}

    def _make_database_permit(self, inner_permit: Mapping[str, Any], begin_ms: int, sequence: int) -> dict:
        """把底层 permit 装配为不混入 evidence 字段的 database variant。"""
        child = self.child_identity
        if child is None:
            _reject("CREDENTIAL_BOUNDARY")
        child_text = self._validate_persisted_child_identity()
        if child_text is None:
            _reject("OBJECT_DRIFT")
        permit_id = _uuid5(f"{self.capability['runId']}:database:{sequence}:{begin_ms}")
        ledger_audit = _digest({"kind": "DATABASE", "runId": self.capability["runId"], "permitId": permit_id})
        helper_audit = _digest({"kind": "DATABASE", "permitId": permit_id, "helper": self._helper_execution_session_id})
        lease_until = int(inner_permit["leaseUntil"])
        return {
            "kind": "DATABASE",
            "permitId": permit_id,
            "runId": self.capability["runId"],
            "authorizationSha256": self.authorization_sha256,
            "requestId": inner_permit["requestId"],
            "callSequence": inner_permit["callSequence"],
            "toolName": inner_permit.get("tool", inner_permit.get("toolName")),
            "effectiveArgumentsSha256": inner_permit.get("argumentsSha256", inner_permit.get("effectiveArgumentsSha256")),
            "startedAt": _rfc3339_ms(begin_ms),
            "leaseUntil": _rfc3339_ms(lease_until),
            "ledgerAuditTokenSha256": ledger_audit,
            "helperAuditTokenSha256": helper_audit,
            "helperExecutionSessionId": self._helper_execution_session_id,
            "toolboxSessionId": self._session_id,
            "toolboxComponentSha256": self._toolbox_component_sha256,
            "toolboxChildIdentity": child_text,
        }

    def _report_spawn(self, token: object, payload: Mapping[str, Any], now_ms: int) -> bool:
        """仅接受 Trusted Helper 通过直接 IPC 交付的 reportSpawn。"""
        _integer(now_ms, "now_ms")
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        if self._inner is None or self._inner.reserved_call is None or not self.accepts_late_spawn:
            _reject("SPAWN_FAILED")
        if not isinstance(payload, Mapping) or "ok" not in payload:
            self._accepts_late_spawn = False
            self._inner.report_spawn_fail(False, "0" * 64, now_ms)
            self._reservation = None
            self._remember_cleanup("TOOLBOX_TERMINATION")
            _reject("SPAWN_FAILED")
        try:
            if payload["ok"] is True:
                if set(payload) != {"ok", "pid", "auditTokenSha256", "startedAt"}:
                    raise Slice2Rejected("SPAWN_FAILED")
                pid = _integer(payload["pid"], "SPAWN_FAILED", 1)
                if pid > MAX_CHILD_PID:
                    _reject("SPAWN_FAILED")
                _sha(payload["auditTokenSha256"], "SPAWN_FAILED")
                started_at = _started_at(payload["startedAt"], "SPAWN_FAILED")
                accepted = self._inner.report_spawn_ok(pid, payload["auditTokenSha256"], now_ms)
                if not accepted:
                    _reject("SPAWN_FAILED")
                self._spawned_child_identity = {
                    "pid": pid,
                    "auditTokenSha256": payload["auditTokenSha256"],
                    "startedAt": started_at,
                }
                self._persisted_child_identity = _canonical_child(self._spawned_child_identity)
                self._accepts_late_spawn = False
                self._toolbox_state = "SPAWN_VERIFIED"
                return True
            if payload["ok"] is False:
                if set(payload) != {"ok", "externalProcessPossible", "launchScan"}:
                    raise Slice2Rejected("SPAWN_FAILED")
                if not isinstance(payload["externalProcessPossible"], bool):
                    raise Slice2Rejected("SPAWN_FAILED")
                scan = self._validate_report_spawn_scan(payload["launchScan"])
                self._inner.report_spawn_fail(
                    payload["externalProcessPossible"],
                    scan["digest"],
                    now_ms,
                )
                self._accepts_late_spawn = False
                self._reservation = None
                self._remember_cleanup("TOOLBOX_TERMINATION")
                _reject("SPAWN_FAILED")
            _reject("SPAWN_FAILED")
        except (FixtureRejected, KeyError, TypeError) as exc:
            self._accepts_late_spawn = False
            if self._inner.state in LIVE_RUN_STATES:
                self._inner.report_spawn_fail(False, "0" * 64, now_ms)
                self._reservation = None
                self._remember_cleanup("TOOLBOX_TERMINATION")
            raise Slice2Rejected("SPAWN_FAILED") from exc

    def _deliver_database_permit(self, token: object, now_ms: int) -> dict:
        """通过不可伪造的 fixture IPC token 交付 database permit。"""
        _integer(now_ms, "now_ms")
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        self._require_database_live()
        if self._current_database_permit is not None:
            if self._database_permit_delivered:
                _reject("AUTH_REPLAY")
            self._database_permit_delivered = True
            return copy.deepcopy(self._current_database_permit)
        if self._inner.reserved_call is None:
            _reject("INVALID_TRANSITION")
        try:
            inner_permit = self._inner.issue_database_permit(now_ms)
        except FixtureRejected as exc:
            code = "INVALID_TRANSITION" if exc.code == "invalid_transition" else exc.code
            raise Slice2Rejected(code) from exc
        self._database_permit_inner = copy.deepcopy(inner_permit)
        self._current_database_permit = self._make_database_permit(inner_permit, now_ms, inner_permit["callSequence"])
        self._reservation = None
        self._accepts_late_spawn = False
        self._toolbox_state = "SPAWN_VERIFIED"
        self._database_permit_delivered = True
        return copy.deepcopy(self._current_database_permit)

    def deliver_database_permit(self, caller: str = "gateway", now_ms: int = 0) -> dict:
        """公开拒绝路径：Gateway/Codex 不能直接取得 Helper permit。"""
        if caller != "trusted-helper":
            _reject("TRUSTED_HELPER_REQUIRED")
        _reject("TRUSTED_HELPER_REQUIRED")

    def _validate_database_outer(self, permit: Mapping[str, Any]) -> dict:
        """验证 database variant 与 Ledger 当前一次性 permit 完全相等。"""
        self._require_database_live()
        if not isinstance(permit, Mapping) or permit.get("kind") != "DATABASE":
            _reject("PERMIT_VARIANT_INVALID")
        _sha(permit.get("authorizationSha256"), "AUTH_SIGNATURE_INVALID")
        if self._current_database_permit is None or dict(permit) != self._current_database_permit:
            _reject("AUTH_REPLAY")
        return copy.deepcopy(self._database_permit_inner)

    def _require_database_live(self) -> None:
        """拒绝 cleanup/epoch 轮换后的旧 database permit。"""
        if self._inner is None:
            _reject("LEDGER_UNAVAILABLE")
        if self._inner.state not in LIVE_RUN_STATES:
            _reject("AUTH_EXPIRED")
        if (
            self._inner.epoch != self.capability["ledgerEpoch"]
            or self._inner.current_ledger_epoch != self.capability["ledgerEpoch"]
        ):
            _reject("AUTH_EXPIRED")

    def _mark_connected(self, token: object, permit: Mapping[str, Any]) -> str:
        """仅在 Helper 持有匹配 database permit 后推进 session 到 CONNECTED。"""
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        self._validate_database_outer(permit)
        self._toolbox_state = "CONNECTED"
        return self._toolbox_state

    def _complete_database(
        self,
        token: object,
        permit: Mapping[str, Any],
        success: bool,
        preflight_passed: bool | None,
        response_digest: str,
        now_ms: int,
        candidate_digests: list[str] | None = None,
        response: Any | None = None,
        database_touched: bool | None = None,
    ) -> str:
        """仅由 Trusted Helper 完成 database permit。"""
        _integer(now_ms, "now_ms")
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        if not isinstance(success, bool):
            _reject("INVALID_RESPONSE")
        _sha(response_digest, "RESPONSE_DIGEST_INVALID")
        if not isinstance(database_touched, bool):
            _reject("DATABASE_TOUCH_EVIDENCE_REQUIRED")
        if response is None:
            _reject("RESPONSE_EVIDENCE_REQUIRED")
        if not hmac.compare_digest(response_digest, _response_digest(response)):
            _reject("RESPONSE_DIGEST_MISMATCH")
        if self._toolbox_state != "CONNECTED":
            _reject("CREDENTIAL_BOUNDARY")
        inner_permit = self._validate_database_outer(permit)
        try:
            state = self._inner.complete_database(inner_permit, success, preflight_passed, now_ms, candidate_digests)
        except FixtureRejected as exc:
            self._current_database_permit = None
            self._database_permit_inner = None
            self._database_permit_delivered = False
            if self._inner.state == "REVOKE_PENDING_CLEANUP":
                self._remember_cleanup(
                    "TOOLBOX_TERMINATION",
                    terminal_target="EXPIRED" if exc.code == "AUTH_EXPIRED" else "REVOKED",
                )
            raise Slice2Rejected(exc.code) from exc
        self._current_database_permit = None
        self._database_permit_inner = None
        self._database_permit_delivered = False
        permit_id = permit["permitId"]
        self._completed_database_permit_ids.add(permit_id)
        self._database_completion_evidence = {
            "permitId": permit_id,
            "responseDigest": response_digest,
            "databaseTouched": database_touched,
            "completedAt": _rfc3339_ms(now_ms),
            "callSequence": permit["callSequence"],
        }
        if state == "REVOKE_PENDING_CLEANUP":
            self._accepts_late_spawn = False
            self._reservation = None
            self._remember_cleanup("TOOLBOX_TERMINATION")
        return state

    def _abort_database(self, token: object, permit: Mapping[str, Any], now_ms: int) -> str:
        """无法判定是否触库时先进入 cleanup，不重试旧 permit。"""
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        inner_permit = self._validate_database_outer(permit)
        try:
            state = self._inner.abort_database(inner_permit, now_ms)
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._current_database_permit = None
        self._database_permit_inner = None
        self._database_permit_delivered = False
        self._accepts_late_spawn = False
        self._remember_cleanup("TOOLBOX_TERMINATION")
        return state

    def timeout(self, now_ms: int) -> str:
        """让静默 RESERVED 超时进入 cleanup，不合成 false。"""
        _integer(now_ms, "now_ms")
        if self._inner is None:
            _reject("LEDGER_UNAVAILABLE")
        state = self._inner.deadline_elapsed(now_ms)
        if state == "REVOKE_PENDING_CLEANUP":
            self._accepts_late_spawn = False
            self._reservation = None
            self._remember_cleanup("TOOLBOX_TERMINATION")
        return state

    def rotate_epoch(self, new_epoch: str) -> str:
        """模拟可信服务重启并使旧 permit 失效。"""
        if self._inner is None:
            _reject("LEDGER_UNAVAILABLE")
        existing_cleanup_kind = self._cleanup_kind
        existing_cleanup_wal_id = self._cleanup_evidence_wal_id
        if existing_cleanup_kind not in {None, "TOOLBOX_TERMINATION", "EVIDENCE_ROLLBACK"}:
            _reject("LEDGER_CORRUPT")
        if existing_cleanup_kind == "EVIDENCE_ROLLBACK":
            _uuid(existing_cleanup_wal_id, "LEDGER_CORRUPT")
        elif existing_cleanup_kind == "TOOLBOX_TERMINATION" and existing_cleanup_wal_id is not None:
            _reject("LEDGER_CORRUPT")
        inner_evidence_in_flight = (
            isinstance(self._inner.in_flight, Mapping)
            and self._inner.in_flight.get("kind") == "EVIDENCE"
        )
        inner_evidence_wal_id = None
        if inner_evidence_in_flight:
            inner_evidence_wal_id = self._inner.in_flight.get("evidenceWalId")
            _uuid(inner_evidence_wal_id, "LEDGER_CORRUPT")
        outer_evidence_wal_id = self._evidence_permit.get("evidenceWalId") if self._evidence_permit is not None else None
        if outer_evidence_wal_id is not None:
            _uuid(outer_evidence_wal_id, "LEDGER_CORRUPT")
        evidence_wal_id = outer_evidence_wal_id
        if existing_cleanup_kind == "EVIDENCE_ROLLBACK":
            evidence_wal_id = existing_cleanup_wal_id
        elif inner_evidence_in_flight:
            if outer_evidence_wal_id is None or outer_evidence_wal_id != inner_evidence_wal_id:
                _reject("LEDGER_CORRUPT")
        if inner_evidence_in_flight and evidence_wal_id != inner_evidence_wal_id:
            _reject("LEDGER_CORRUPT")
        evidence_in_flight = inner_evidence_in_flight
        try:
            state = self._inner.rotate_epoch(new_epoch)
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._current_database_permit = None
        self._database_permit_inner = None
        self._database_permit_delivered = False
        self._evidence_permit = None
        self._evidence_permit_inner = None
        self._active_recovery_command = None
        self._accepts_late_spawn = False
        if state == "REVOKE_PENDING_CLEANUP":
            if existing_cleanup_kind == "EVIDENCE_ROLLBACK":
                self._remember_cleanup(
                    "EVIDENCE_ROLLBACK",
                    existing_cleanup_wal_id,
                    terminal_target=self._cleanup_terminal_target,
                )
            elif existing_cleanup_kind == "TOOLBOX_TERMINATION":
                self._remember_cleanup(
                    "TOOLBOX_TERMINATION",
                    terminal_target=self._cleanup_terminal_target,
                )
            elif evidence_in_flight:
                self._remember_cleanup("EVIDENCE_ROLLBACK", evidence_wal_id)
            else:
                self._remember_cleanup("TOOLBOX_TERMINATION")
        return state

    def close_query(self) -> str:
        """在未达到 15 次时显式关闭 query phase，等待 child ACK。"""
        if self._inner is None or self._inner.state != "ACTIVE_READY":
            _reject("INVALID_TRANSITION")
        self._inner.state = "QUERY_CLOSED"
        self._inner.query_close_cleanup_ack = False
        return self._inner.state

    def _ack_query_close(self, token: object) -> str:
        """只接受 Helper 绑定当前 child 的 query-close termination ACK。"""
        if token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        if self._inner is None or self._inner.state != "QUERY_CLOSED":
            _reject("INVALID_TRANSITION")
        if self.child_identity is None:
            _reject("OBJECT_DRIFT")
        try:
            state = self._inner.ack_child_termination(self._inner_child_identity())
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._toolbox_state = "TERMINATED"
        return state

    def recovery_command(self) -> dict:
        """生成轮换 execution session 的 recovery-only cleanup command。"""
        if self._inner is None or self._inner.state != "REVOKE_PENDING_CLEANUP":
            _reject("INVALID_TRANSITION")
        self._validate_persisted_child_identity()
        inner_command = self._inner.recovery_command()
        self._cleanup_id = self._cleanup_id or _uuid5(self.capability["runId"] + ":cleanup:" + str(inner_command["cleanupId"]))
        cleanup_kind = self._cleanup_kind or "TOOLBOX_TERMINATION"
        recovery_component_sha256 = (
            self._commit_component_sha256
            if cleanup_kind == "EVIDENCE_ROLLBACK"
            else self._trusted_helper_component_sha256
        )
        self._recovery_generation += 1
        recovery_session = _uuid5(self.capability["runId"] + f":recovery:{self._recovery_generation}")
        ledger_recovery_audit = _digest({
            "cleanupId": self._cleanup_id,
            "epoch": self._inner.epoch,
            "session": recovery_session,
            "componentManifestSha256": self.capability["componentManifestSha256"],
            "recoveryComponentSha256": recovery_component_sha256,
        })
        command = {
            "cleanupId": self._cleanup_id,
            "cleanupKind": cleanup_kind,
            "toolboxSessionId": self._session_id if cleanup_kind == "TOOLBOX_TERMINATION" else None,
            "reservedLaunchIdentity": copy.deepcopy(inner_command.get("reservedLaunchIdentity")) if cleanup_kind == "TOOLBOX_TERMINATION" else None,
            "toolboxChildIdentity": (
                None
                if cleanup_kind != "TOOLBOX_TERMINATION" or self.child_identity is None
                else _canonical_child(self.child_identity)
            ),
            "evidenceWalId": self._cleanup_evidence_wal_id if cleanup_kind == "EVIDENCE_ROLLBACK" else None,
            "terminalTarget": self._cleanup_terminal_target,
            "epoch": self._inner.epoch,
            "recoveryOnly": True,
            "recoveryExecutionSessionId": recovery_session,
            "componentManifestSha256": self.capability["componentManifestSha256"],
            "recoveryComponentSha256": recovery_component_sha256,
            "ledgerRecoveryAuditTokenSha256": ledger_recovery_audit,
            "auditTokenSha256": ledger_recovery_audit,
        }
        self._active_recovery_command = copy.deepcopy(command)
        return copy.deepcopy(command)

    def cleanup_evidence_fixture(
        self,
        command: Mapping[str, Any],
        launch_scan: Mapping[str, Any] | None = None,
    ) -> dict:
        """为测试构造绑定资源身份与 command 的 termination/rollback ACK。"""
        if not isinstance(command, Mapping):
            _reject("INVALID_REQUEST")
        cleanup_kind = command.get("cleanupKind")
        if cleanup_kind not in {"TOOLBOX_TERMINATION", "EVIDENCE_ROLLBACK"}:
            _reject("LEDGER_CORRUPT")
        recovery_component = command.get("recoveryComponentSha256")
        _sha(recovery_component, "LEDGER_CORRUPT")
        if cleanup_kind == "TOOLBOX_TERMINATION":
            if command.get("toolboxChildIdentity") is None:
                if launch_scan is None:
                    launch_scan = self.launch_scan_fixture()
            elif launch_scan is not None:
                _reject("LEDGER_CORRUPT")
        elif launch_scan is not None:
            _reject("LEDGER_CORRUPT")
        resource_binding = {
            "toolboxSessionId": command.get("toolboxSessionId"),
            "reservedLaunchIdentity": copy.deepcopy(command.get("reservedLaunchIdentity")),
            "toolboxChildIdentity": command.get("toolboxChildIdentity"),
            "launchScan": copy.deepcopy(launch_scan),
        }
        return {
            "cleanupId": command.get("cleanupId"),
            "recoveryExecutionSessionId": command.get("recoveryExecutionSessionId"),
            "componentManifestSha256": command.get("componentManifestSha256"),
            "recoveryComponentSha256": recovery_component,
            "ledgerRecoveryAuditTokenSha256": command.get("ledgerRecoveryAuditTokenSha256"),
            **resource_binding,
            "terminationAck": cleanup_kind == "TOOLBOX_TERMINATION",
            "rollbackAck": cleanup_kind == "EVIDENCE_ROLLBACK",
            "finalBindingSha256": _digest({
                "cleanupId": command.get("cleanupId"),
                "recoveryExecutionSessionId": command.get("recoveryExecutionSessionId"),
                "cleanupKind": cleanup_kind,
                "terminalTarget": command.get("terminalTarget"),
                "evidenceWalId": command.get("evidenceWalId"),
                **resource_binding,
                "fsyncAck": True,
            }),
            "fsyncAck": True,
        }

    def _validate_cleanup_evidence(
        self,
        command: Mapping[str, Any],
        evidence: Mapping[str, Any] | None,
        launch_scan: Mapping[str, Any] | None = None,
    ) -> None:
        """校验 cleanup ACK 的字段闭集、component 绑定与最终绑定摘要。"""
        if not isinstance(evidence, Mapping):
            _reject("CLEANUP_EVIDENCE_REQUIRED")
        fields = {
            "cleanupId",
            "recoveryExecutionSessionId",
            "componentManifestSha256",
            "recoveryComponentSha256",
            "ledgerRecoveryAuditTokenSha256",
            "toolboxSessionId",
            "reservedLaunchIdentity",
            "toolboxChildIdentity",
            "launchScan",
            "terminationAck",
            "rollbackAck",
            "finalBindingSha256",
            "fsyncAck",
        }
        if set(evidence) != fields:
            _reject("LEDGER_CORRUPT")
        cleanup_kind = command.get("cleanupKind")
        if cleanup_kind == "TOOLBOX_TERMINATION" and command.get("toolboxChildIdentity") is None:
            if launch_scan is None:
                _reject("LAUNCH_SCAN_REQUIRED")
            try:
                self._validate_report_spawn_scan(launch_scan)
            except (Slice2Rejected, KeyError, TypeError) as exc:
                raise Slice2Rejected("LEDGER_CORRUPT") from exc
        elif launch_scan is not None:
            _reject("LEDGER_CORRUPT")
        expected = self.cleanup_evidence_fixture(command, launch_scan=launch_scan)
        if dict(evidence) != expected:
            _reject("LEDGER_CORRUPT")
        _uuid(evidence["cleanupId"], "LEDGER_CORRUPT")
        _uuid(evidence["recoveryExecutionSessionId"], "LEDGER_CORRUPT")
        _sha(evidence["componentManifestSha256"], "LEDGER_CORRUPT")
        _sha(evidence["recoveryComponentSha256"], "LEDGER_CORRUPT")
        _sha(evidence["ledgerRecoveryAuditTokenSha256"], "LEDGER_CORRUPT")
        _sha(evidence["finalBindingSha256"], "LEDGER_CORRUPT")
        if evidence["fsyncAck"] is not True:
            _reject("LEDGER_CORRUPT")

    def _ack_cleanup(
        self,
        token: object,
        command: Mapping[str, Any],
        launch_scan: dict | None = None,
        cleanup_evidence: Mapping[str, Any] | None = None,
    ) -> str:
        """验证当前 recovery command 并提交已知 child/未知 child 清理 ACK。"""
        if not isinstance(command, Mapping):
            _reject("INVALID_REQUEST")
        if self._active_recovery_command is None or dict(command) != self._active_recovery_command:
            _reject("AUTH_REPLAY")
        if self._inner is None:
            _reject("LEDGER_UNAVAILABLE")
        if command.get("epoch") != self._inner.epoch:
            _reject("AUTH_REPLAY")
        cleanup_kind = command.get("cleanupKind")
        if cleanup_kind == "EVIDENCE_ROLLBACK":
            if token is not self._commit_ipc_token:
                _reject("COMMIT_EVIDENCE_REQUIRED")
        elif token is not self._helper_ipc_token:
            _reject("TRUSTED_HELPER_REQUIRED")
        if cleanup_kind == "TOOLBOX_TERMINATION":
            expected_child = self._validate_persisted_child_identity()
            if command.get("toolboxSessionId") != self._session_id:
                _reject("OBJECT_DRIFT")
            if command.get("reservedLaunchIdentity") != self._inner.reserved_launch_identity:
                _reject("OBJECT_DRIFT")
            if command.get("toolboxChildIdentity") != expected_child:
                _reject("OBJECT_DRIFT")
        self._validate_cleanup_evidence(command, cleanup_evidence, launch_scan=launch_scan)
        try:
            if cleanup_kind == "EVIDENCE_ROLLBACK":
                if launch_scan is not None or command.get("evidenceWalId") is None:
                    _reject("LEDGER_CORRUPT")
                command_wal_id = command.get("evidenceWalId")
                _uuid(command_wal_id, "LEDGER_CORRUPT")
                if (
                    self._cleanup_kind != "EVIDENCE_ROLLBACK"
                    or self._cleanup_evidence_wal_id != command_wal_id
                ):
                    _reject("LEDGER_CORRUPT")
                if self._inner.in_flight is not None and (
                    not isinstance(self._inner.in_flight, dict)
                    or self._inner.in_flight.get("kind") != "EVIDENCE"
                ):
                    _reject("LEDGER_CORRUPT")
                if self._inner.in_flight is not None:
                    inner_wal_id = self._inner.in_flight.get("evidenceWalId")
                    _uuid(inner_wal_id, "LEDGER_CORRUPT")
                    if inner_wal_id != command_wal_id:
                        _reject("LEDGER_CORRUPT")
                for permit in (self._evidence_permit_inner, self._evidence_permit):
                    if permit is not None:
                        permit_wal_id = permit.get("evidenceWalId")
                        _uuid(permit_wal_id, "LEDGER_CORRUPT")
                        if permit_wal_id != command_wal_id:
                            _reject("LEDGER_CORRUPT")
                state = self._inner._mark_terminal(command["terminalTarget"])
            elif self.child_identity is not None:
                state = self._inner.ack_child_termination(
                    self._inner_child_identity(),
                    self._inner.cleanup_id,
                    self._inner.epoch,
                )
            else:
                if launch_scan is None:
                    _reject("LAUNCH_SCAN_REQUIRED")
                state = self._inner.ack_child_termination(
                    None,
                    self._inner.cleanup_id,
                    self._inner.epoch,
                    launch_scan,
                )
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._active_recovery_command = None
        self._accepts_late_spawn = False
        if command.get("cleanupKind") == "TOOLBOX_TERMINATION":
            self._toolbox_state = "TERMINATED"
        return state

    def _normalize_contents(self, targets: list[dict], contents: Mapping[str, bytes | str]) -> dict[str, bytes]:
        """校验每个 evidence target 的字节上限、DLP 与精确路径集合。"""
        if not isinstance(contents, Mapping):
            _reject("EVIDENCE_CONTENT_INVALID")
        expected_paths = [target["path"] for target in targets]
        if set(contents) != set(expected_paths) or len(contents) != len(expected_paths):
            _reject("AUTH_SCOPE_MISMATCH")
        normalized: dict[str, bytes] = {}
        total = 0
        for target in targets:
            raw = contents[target["path"]]
            if isinstance(raw, str):
                raw = raw.encode("utf-8")
            if not isinstance(raw, bytes):
                _reject("EVIDENCE_CONTENT_INVALID")
            try:
                validate_evidence_content(target, raw)
            except FixtureRejected as exc:
                raise Slice2Rejected(exc.code) from exc
            total += len(raw)
            normalized[target["path"]] = bytes(raw)
        if total > MAX_EVIDENCE_TOTAL_BYTES:
            _reject("EVIDENCE_TOO_LARGE")
        return normalized

    @staticmethod
    def _target_manifest(targets: list[dict]) -> list[dict]:
        """形成排序且显式 recordKey=null 的 target manifest。"""
        result = []
        for target in sorted(targets, key=lambda item: item["path"]):
            normalized = copy.deepcopy(target)
            normalized.setdefault("recordKey", None)
            result.append(normalized)
        return result

    @staticmethod
    def _content_manifest(contents: Mapping[str, bytes]) -> list[dict]:
        """形成与 target 同序的内容摘要 manifest。"""
        return [
            {
                "path": path,
                "contentSha256": hashlib.sha256(contents[path]).hexdigest(),
                "byteLength": str(len(contents[path])),
            }
            for path in sorted(contents)
        ]

    def _make_evidence_permit(self, inner_permit: Mapping[str, Any], targets: list[dict], contents: Mapping[str, bytes], begin_ms: int) -> dict:
        """装配不含 database/toolbox 字段的 evidence variant。"""
        target_manifest = self._target_manifest(targets)
        content_manifest = self._content_manifest(contents)
        permit_id = _uuid5(f"{self.capability['runId']}:evidence:{begin_ms}")
        evidence_commit_id = _uuid5(self.capability["runId"] + ":evidence-commit")
        evidence_wal_id = inner_permit.get("evidenceWalId")
        _uuid(evidence_wal_id, "LEDGER_CORRUPT")
        return {
            "kind": "EVIDENCE",
            "permitId": permit_id,
            "runId": self.capability["runId"],
            "authorizationSha256": self.authorization_sha256,
            "evidenceCommitId": evidence_commit_id,
            "evidenceWalId": evidence_wal_id,
            "targetManifestSha256": _digest(target_manifest),
            "contentManifestSha256": _digest(content_manifest),
            "contentBytes": str(sum(int(item["byteLength"]) for item in content_manifest)),
            "startedAt": _rfc3339_ms(begin_ms),
            "leaseUntil": _rfc3339_ms(int(inner_permit["leaseUntil"])),
            "ledgerAuditTokenSha256": _digest({"kind": "EVIDENCE", "runId": self.capability["runId"], "permitId": permit_id}),
            "commitEvidenceAuditTokenSha256": _digest({"kind": "EVIDENCE", "permitId": permit_id, "component": self._commit_component_sha256}),
            "commitEvidenceExecutionSessionId": self._commit_execution_session_id,
            "componentManifestSha256": self.capability["componentManifestSha256"],
            "commitEvidenceComponentSha256": self._commit_component_sha256,
        }

    def _deliver_evidence_permit(self, token: object, targets: list[dict], contents: Mapping[str, bytes | str], now_ms: int) -> dict:
        """仅由 commit-evidence 组件获得独立 evidence permit。"""
        _integer(now_ms, "now_ms")
        if token is not self._commit_ipc_token:
            _reject("COMMIT_EVIDENCE_REQUIRED")
        if self._inner is None or self._inner.state != "QUERY_CLOSED" or not self._inner.query_close_cleanup_ack:
            _reject("PREFLIGHT_REQUIRED")
        try:
            validated_targets = validate_evidence_targets(targets)
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        if validated_targets != self.capability["evidenceTargets"]:
            _reject("AUTH_SCOPE_MISMATCH")
        normalized = self._normalize_contents(validated_targets, contents)
        try:
            inner_permit = self._inner.begin_evidence_commit(
                validated_targets,
                now_ms,
                EVIDENCE_PERMIT_LEASE_MS,
                1,
            )
        except FixtureRejected as exc:
            raise Slice2Rejected(exc.code) from exc
        self._evidence_permit = self._make_evidence_permit(inner_permit, validated_targets, normalized, now_ms)
        self._evidence_permit_inner = copy.deepcopy(inner_permit)
        self._evidence_targets = copy.deepcopy(validated_targets)
        self._evidence_contents = normalized
        return copy.deepcopy(self._evidence_permit)

    def deliver_evidence_permit(self, targets: list[dict], contents: Mapping[str, bytes | str], now_ms: int, caller: str = "gateway") -> dict:
        """公开拒绝路径：Gateway/Codex 不能直接取得 evidence permit。"""
        if caller != "commit-evidence":
            _reject("COMMIT_EVIDENCE_REQUIRED")
        _reject("COMMIT_EVIDENCE_REQUIRED")

    def _validate_evidence_outer(self, permit: Mapping[str, Any]) -> dict:
        """验证 evidence variant 与当前 inFlight 完全匹配。"""
        if not isinstance(permit, Mapping) or permit.get("kind") != "EVIDENCE":
            _reject("PERMIT_VARIANT_INVALID")
        if self._evidence_permit is None or dict(permit) != self._evidence_permit:
            _reject("AUTH_REPLAY")
        if any(field in permit for field in ("requestId", "callSequence", "toolName", "toolboxSessionId", "toolboxChildIdentity")):
            _reject("PERMIT_VARIANT_INVALID")
        if self._evidence_permit_inner is None:
            _reject("AUTH_REPLAY")
        return copy.deepcopy(self._evidence_permit_inner)

    def _complete_evidence(self, token: object, permit: Mapping[str, Any], contents: Mapping[str, bytes | str], now_ms: int) -> str:
        """仅由 commit-evidence 完成一次 evidence permit。"""
        if token is not self._commit_ipc_token:
            _reject("COMMIT_EVIDENCE_REQUIRED")
        self._validate_evidence_outer(permit)
        try:
            normalized = self._normalize_contents(self._evidence_targets, contents)
        except Slice2Rejected:
            self._abort_evidence(token, permit, now_ms)
            raise
        if _digest(self._content_manifest(normalized)) != permit["contentManifestSha256"]:
            self._abort_evidence(token, permit, now_ms)
            _reject("EVIDENCE_MANIFEST_MISMATCH")
        try:
            state = self._inner.complete_evidence(self._evidence_permit_inner, now_ms)
        except FixtureRejected as exc:
            if self._inner.state == "REVOKE_PENDING_CLEANUP":
                self._remember_cleanup(
                    "EVIDENCE_ROLLBACK",
                    self._evidence_permit["evidenceWalId"],
                    terminal_target="EXPIRED" if exc.code == "AUTH_EXPIRED" else "REVOKED",
                )
            self._evidence_permit = None
            self._evidence_permit_inner = None
            raise Slice2Rejected(exc.code) from exc
        self._evidence_permit = None
        self._evidence_permit_inner = None
        return state

    def _abort_evidence(self, token: object, permit: Mapping[str, Any], now_ms: int) -> str:
        """evidence 失败只进入 rollback cleanup，不释放旧 run 槽。"""
        if token is not self._commit_ipc_token:
            _reject("COMMIT_EVIDENCE_REQUIRED")
        self._validate_evidence_outer(permit)
        self._remember_cleanup("EVIDENCE_ROLLBACK", permit["evidenceWalId"])
        self._inner.in_flight = None
        self._inner._enter_cleanup("EVIDENCE_ROLLBACK")
        self._evidence_permit = None
        self._evidence_permit_inner = None
        self._accepts_late_spawn = False
        return self._inner.state


class TrustedExecutionHelperFixture:
    """只通过 Ledger 私有 IPC token 接收 permit 的 Helper fixture。"""

    def __init__(self, ledger: LedgerServiceFixture):
        if not isinstance(ledger, LedgerServiceFixture):
            _reject("TRUSTED_HELPER_REQUIRED")
        self.ledger = ledger
        self._permit: dict | None = None

    def report_spawn(self, payload: Mapping[str, Any], now_ms: int) -> bool:
        """以 Helper 身份转发严格的 reportSpawn payload。"""
        return self.ledger._report_spawn(self.ledger._helper_ipc_token, payload, now_ms)

    def obtain_database_permit(self, now_ms: int) -> dict:
        """在 spawn verified 后接收 database permit。"""
        self._permit = self.ledger._deliver_database_permit(self.ledger._helper_ipc_token, now_ms)
        return copy.deepcopy(self._permit)

    def read_secret(self) -> dict:
        """证明 permit 前没有凭据读取路径；通过后仅返回非秘密占位。"""
        if self._permit is None:
            _reject("CREDENTIAL_BOUNDARY")
        self.ledger._validate_database_outer(self._permit)
        return {"credentialAccess": "PERMIT_BOUND_FIXTURE_ONLY"}

    def connect(self, permit: Mapping[str, Any]) -> str:
        """仅在收到 database permit 后标记受控 Toolbox session 为 CONNECTED。"""
        if self._permit is None or dict(permit) != self._permit:
            _reject("AUTH_REPLAY")
        return self.ledger._mark_connected(self.ledger._helper_ipc_token, permit)

    def complete_database(
        self,
        permit: Mapping[str, Any],
        success: bool,
        preflight_passed: bool | None,
        response_digest: str,
        now_ms: int,
        candidate_digests: list[str] | None = None,
        response: Any | None = None,
        database_touched: bool | None = None,
    ) -> str:
        """完成 database permit，并在返回可信响应前校验 digest。"""
        state = self.ledger._complete_database(
            self.ledger._helper_ipc_token,
            permit,
            success,
            preflight_passed,
            response_digest,
            now_ms,
            candidate_digests,
            response,
            database_touched,
        )
        self._permit = None
        return state

    def abort_database(self, permit: Mapping[str, Any], now_ms: int) -> str:
        """以 cleanup 语义中止 database permit。"""
        state = self.ledger._abort_database(self.ledger._helper_ipc_token, permit, now_ms)
        self._permit = None
        return state

    def ack_query_close(self) -> str:
        """提交匹配 Toolbox child 的终止 ACK。"""
        return self.ledger._ack_query_close(self.ledger._helper_ipc_token)

    def ack_cleanup(
        self,
        command: Mapping[str, Any],
        launch_scan: dict | None = None,
        cleanup_evidence: Mapping[str, Any] | None = None,
    ) -> str:
        """提交当前 recovery-only command 的清理 ACK。"""
        return self.ledger._ack_cleanup(
            self.ledger._helper_ipc_token,
            command,
            launch_scan,
            cleanup_evidence,
        )


class CommitEvidenceFixture:
    """独立于 database permit 的 commit-evidence 组件 fixture。"""

    def __init__(self, ledger: LedgerServiceFixture):
        if not isinstance(ledger, LedgerServiceFixture):
            _reject("COMMIT_EVIDENCE_REQUIRED")
        self.ledger = ledger

    def obtain_permit(self, targets: list[dict], contents: Mapping[str, bytes | str], now_ms: int) -> dict:
        """接收 Ledger 直接交付的独立 evidence permit。"""
        return self.ledger._deliver_evidence_permit(self.ledger._commit_ipc_token, targets, contents, now_ms)

    def complete(self, permit: Mapping[str, Any], contents: Mapping[str, bytes | str], now_ms: int) -> str:
        """校验 content manifest 后完成 evidence commit。"""
        return self.ledger._complete_evidence(self.ledger._commit_ipc_token, permit, contents, now_ms)

    def abort(self, permit: Mapping[str, Any], now_ms: int) -> str:
        """提交器失败时进入 EVIDENCE_ROLLBACK cleanup。"""
        return self.ledger._abort_evidence(self.ledger._commit_ipc_token, permit, now_ms)

    def ack_cleanup(self, command: Mapping[str, Any], cleanup_evidence: Mapping[str, Any] | None = None) -> str:
        """提交器确认 WAL rollback/fsync 后释放 evidence cleanup 槽。"""
        return self.ledger._ack_cleanup(self.ledger._commit_ipc_token, command, cleanup_evidence=cleanup_evidence)
