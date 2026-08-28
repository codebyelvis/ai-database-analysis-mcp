"""
作者：elvis
日期：2026-08-18
作用：reportSpawn 窗口与七态中的 spawn 失败转换
"""

import re
import time

from security_fixtures import (
    LIVE_RUN_STATES,
    RunLedger as SecurityRunLedger,
    SingleRunRegistry as SecurityRunRegistry,
)


SPAWN_FAILED = "SPAWN_FAILED"
REPORT_SPAWN_DEADLINE_MS = 3000
MAX_CHILD_PID = 4_194_304
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _valid_sha256(value: object) -> bool:
    """判断 fixture 中的 digest/audit 是否为小写 64 位 SHA-256。"""
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _valid_pid(value: object) -> bool:
    """限制 child identity 为明确的正整数 PID fixture。"""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 < value <= MAX_CHILD_PID
    )


class Ledger:
    """Slice 1 用于验证启动窗口和清理转移的最小账本模型。"""

    def __init__(self, clock_ms=None):
        self.status = "PENDING_APPROVAL"
        self.session = None
        self.in_flight = None
        self.spawned = None
        self.last_external_possible = None
        self.cleanup_child_pid = None
        self.reserved_at_ms = None
        self._clock_ms = (
            clock_ms
            if clock_ms is not None
            else lambda: time.monotonic_ns() // 1_000_000
        )

    def reserve(self, now_ms=None):
        """进入预检保留窗口，且在 permit 前保持无 secret 的 RESERVED 状态。"""
        if self.status != "PENDING_APPROVAL" or self.session is not None:
            raise RuntimeError("invalid_transition")
        self.status = "IN_FLIGHT_PREFLIGHT"
        self.session = "RESERVED"
        self.in_flight = None
        self.spawned = None
        self.cleanup_child_pid = None
        self.reserved_at_ms = self._now(now_ms)

    def _now(self, now_ms=None) -> int:
        return self._clock_ms() if now_ms is None else now_ms

    def _enter_cleanup(self, child_pid=None) -> str:
        """进入清理状态，只沿用已可信登记的 child identity。"""
        if child_pid is None:
            child_pid = self.cleanup_child_pid
        if child_pid is None and isinstance(self.spawned, dict):
            child_pid = self.spawned.get("pid")
        self.status = "REVOKE_PENDING_CLEANUP"
        self.cleanup_child_pid = child_pid
        return self.status

    def _window_open(self, now_ms=None) -> bool:
        window_open = (
            self.status == "IN_FLIGHT_PREFLIGHT"
            and self.session == "RESERVED"
            and self.in_flight is None
            and self.spawned is None
        )
        if not window_open:
            return False
        if (
            self.reserved_at_ms is not None
            and self._now(now_ms) - self.reserved_at_ms
            >= REPORT_SPAWN_DEADLINE_MS
        ):
            self._enter_cleanup()
            return False
        return True

    def report_spawn_fail(
        self,
        external_possible: bool,
        digest: str,
        now_ms=None,
    ) -> str:
        """将启动失败或 false hint 统一转入待可信清理状态。"""
        valid_external_possible = isinstance(external_possible, bool)
        valid_digest = _valid_sha256(digest)
        if valid_external_possible:
            self.last_external_possible = external_possible
        if not valid_external_possible or not valid_digest:
            return self._enter_cleanup()
        if not self._window_open(now_ms):
            return self._enter_cleanup()
        return self._enter_cleanup()

    def deadline_elapsed(self, now_ms=None) -> str:
        """将静默超时转入清理，不合成 external_possible=false。"""
        if not self._window_open(now_ms):
            return self.status
        self.last_external_possible = None
        return self._enter_cleanup()

    def report_spawn_ok(self, pid: int, audit: str, now_ms=None) -> bool:
        """仅在 RESERVED 接受窗内登记已校验的 child。"""
        if self.session == "SPAWN_VERIFIED":
            return False
        if not _valid_pid(pid) or not _valid_sha256(audit):
            self._enter_cleanup()
            return False
        if not self._window_open(now_ms):
            self._enter_cleanup()
            return False
        self.spawned = {"pid": pid, "audit": audit}
        self.session = "SPAWN_VERIFIED"
        return True

    def refuse_permit(self, reason: str) -> str:
        """拒绝第二阶段 permit，并保留已知 child 供可信清理。"""
        if self.session != "SPAWN_VERIFIED" or self.in_flight is not None:
            raise RuntimeError(reason)
        self.status = "REVOKE_PENDING_CLEANUP"
        self.cleanup_child_pid = self.spawned["pid"]
        return self.status


# 完整七态/双 permit fixture 位于 security_fixtures，保留明确别名供独立测试与审查导入。
FullLedger = SecurityRunLedger
FullRunRegistry = SecurityRunRegistry
