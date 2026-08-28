"""
作者：elvis
日期：2026-08-18
作用：验证 Ledger 启动窗口、超时与清理状态转换
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from ledger_sm import Ledger, REPORT_SPAWN_DEADLINE_MS


class LedgerTest(unittest.TestCase):
    def test_false_hint_goes_cleanup_not_revoked(self):
        ledger = Ledger()
        ledger.reserve()
        status = ledger.report_spawn_fail(
            external_possible=False,
            digest="a" * 64,
        )
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")
        self.assertNotEqual(status, "REVOKED")

    def test_timeout_not_synthesized_false(self):
        ledger = Ledger()
        ledger.reserve()
        status = ledger.deadline_elapsed()
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")
        self.assertIsNone(ledger.last_external_possible)

    def test_late_success_rejected(self):
        ledger = Ledger()
        ledger.reserve()
        ledger.deadline_elapsed()
        self.assertFalse(ledger.report_spawn_ok(pid=12, audit="c" * 64))
        self.assertIsNone(ledger.spawned)

    def test_second_phase_fail_cleans_known_child(self):
        ledger = Ledger()
        ledger.reserve()
        self.assertTrue(ledger.report_spawn_ok(pid=4, audit="d" * 64))
        status = ledger.refuse_permit(reason="remaining<5000")
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.cleanup_child_pid, 4)

    def test_spawn_fail_outside_window_enters_cleanup(self):
        ledger = Ledger()
        status = ledger.report_spawn_fail(
            external_possible=False,
            digest="a" * 64,
        )
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")

    def test_spawn_fail_after_verified_child_cleans_child(self):
        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        self.assertTrue(ledger.report_spawn_ok(pid=4, audit="d" * 64, now_ms=1001))
        status = ledger.report_spawn_fail(
            external_possible=False,
            digest="a" * 64,
            now_ms=1002,
        )
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.cleanup_child_pid, 4)

    def test_late_success_at_deadline_enters_cleanup(self):
        self.assertEqual(REPORT_SPAWN_DEADLINE_MS, 3000)
        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        self.assertFalse(
            ledger.report_spawn_ok(pid=12, audit="c" * 64, now_ms=4000)
        )
        self.assertEqual(ledger.status, "REVOKE_PENDING_CLEANUP")
        self.assertIsNone(ledger.spawned)

    def test_duplicate_spawn_success_is_rejected_without_cleanup(self):
        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        self.assertTrue(ledger.report_spawn_ok(pid=4, audit="d" * 64, now_ms=1001))

        self.assertFalse(ledger.report_spawn_ok(pid=9, audit="e" * 64, now_ms=1002))
        self.assertEqual(ledger.status, "IN_FLIGHT_PREFLIGHT")
        self.assertEqual(ledger.session, "SPAWN_VERIFIED")
        self.assertEqual(ledger.spawned, {"pid": 4, "audit": "d" * 64})
        self.assertIsNone(ledger.cleanup_child_pid)

    def test_reserve_after_cleanup_is_rejected(self):
        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        ledger.deadline_elapsed(now_ms=4000)
        with self.assertRaises(RuntimeError):
            ledger.reserve(now_ms=4001)

    def test_invalid_spawn_payload_enters_cleanup_without_child(self):
        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        self.assertFalse(ledger.report_spawn_ok(pid=-1, audit="", now_ms=1001))
        self.assertEqual(ledger.status, "REVOKE_PENDING_CLEANUP")
        self.assertIsNone(ledger.spawned)

        ledger = Ledger()
        ledger.reserve(now_ms=1000)
        status = ledger.report_spawn_fail(
            external_possible=False,
            digest="not-hex",
            now_ms=1001,
        )
        self.assertEqual(status, "REVOKE_PENDING_CLEANUP")
        self.assertIsNone(ledger.spawned)


if __name__ == "__main__":
    unittest.main()
