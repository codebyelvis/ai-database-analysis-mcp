"""
作者：elvis
日期：2026-08-19
作用：验证 revision 12 完整无库安全 fixture 的授权、策略、状态与合同边界
"""

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from security_fixtures import (
    ALL_COMPONENTS,
    ISSUE_CODES,
    LIVE_RUN_STATES,
    PRIVILEGE_CHECKS,
    SCHEMA_NAMES,
    TOOL_NAMES,
    FixtureRejected,
    ReplayGuard,
    RunLedger,
    SingleRunRegistry,
    build_gateway_error,
    build_tool_response,
    classify_column,
    component_manifest_sha256,
    data_object,
    default_capability_input,
    default_component_manifest,
    default_profile,
    default_scope,
    hidden_discovery_fixture,
    paginate_candidates,
    preflight,
    render_only_select,
    scan_value,
    schema_manifest,
    tool_contract_manifest_sha256,
    tool_surface,
    validate_capability,
    validate_response_contract,
    validate_schema_instance,
    validate_sql,
    validate_live_object,
    validate_ledger_snapshot,
    validate_scope,
    validate_privilege_snapshot,
    validate_routine_exposure,
    validate_profile_run_scope,
    validate_profile,
    validate_search_query,
    validate_tool_access,
    validate_stats_request,
    validate_sample_request,
    validate_evidence_content,
    verify_page_token,
    issue_page_token,
    issue_capability,
)

from canonical import canon


def _rid(sequence: int) -> str:
    """为 Ledger fixture 生成合同格式的 UUID requestId。"""
    return f"00000000-0000-0000-0000-{sequence:012d}"


def _launch_scan_fixture(reserved, scan_complete=True, matched_pids=None):
    """构造绑定 reservation 的空 V1 扫描 ACK，供未知 child 清理测试使用。"""
    payload = {
        "algorithm": "MACOS_PROCESS_LIST_MATCH_LAUNCH_IDENTITY_V1",
        "executableFdIdentity": reserved.get(
            "executableFdIdentity",
            {"canonicalPath": "/fixture/toolbox", "device": "1", "inode": "2", "sha256": "b" * 64},
        ),
        "perLaunchNonce": reserved.get("perLaunchNonce", reserved.get("launchNonce", "C" * 43)),
        "toolboxSessionId": reserved["toolboxSessionId"],
        "scanComplete": scan_complete,
        "matchedPids": [] if matched_pids is None else matched_pids,
        "scannedAt": "1970-01-01T00:00:00Z",
    }
    return {**payload, "digest": hashlib.sha256(canon(payload)).hexdigest()}


class CapabilityFixtureTest(unittest.TestCase):
    def setUp(self):
        self.scope = default_scope()
        self.components = default_component_manifest()

    def test_capability_binds_scope_components_presence_and_budget(self):
        capability = issue_capability(default_capability_input())
        self.assertTrue(validate_capability(capability, now_ms=1_000))
        self.assertEqual(capability["maxToolCalls"], 15)
        self.assertEqual(capability["toolContractSha256"], tool_contract_manifest_sha256())
        self.assertIn(capability["scope"]["dataObjects"][0]["objectKind"], {"LOCAL_BASE_TABLE"})
        self.assertEqual(len(capability["componentManifest"]["components"]), 10)

    def test_component_manifest_enforces_fixed_artifact_kind(self):
        manifest = default_component_manifest()
        manifest["components"][0]["artifactKind"] = "DATA"
        manifest["components"][0]["mode"] = "0644"
        manifest["components"][0]["codeSignRequirement"] = "NOT_APPLICABLE_DATA"
        with self.assertRaises(FixtureRejected):
            component_manifest_sha256(manifest)

    def test_capability_rejects_user_presence_scope_and_component_drift(self):
        for mutate in (
            lambda value: value.update({"userPresence": False}),
            lambda value: value["scope"].update({"metadataOnly": True}),
            lambda value: value["componentManifest"]["components"][0].update(
                {"sha256": "f" * 64}
            ),
            lambda value: value.update({"expiresAt": 3_601_001}),
        ):
            candidate = copy.deepcopy(default_capability_input())
            mutate(candidate)
            with self.subTest(candidate=candidate):
                with self.assertRaises(FixtureRejected):
                    issue_capability(candidate)

    def test_capability_rejects_source_record_key_and_secret_fields(self):
        candidate = copy.deepcopy(default_capability_input())
        candidate["evidenceTargets"] = [
            {
                "path": "sources/index/source-register.md",
                "operation": "APPEND_ONLY",
                "expectedPreimage": "a" * 64,
                "contentKind": "SOURCE_REGISTER",
                "recordKey": "记录-1",
            }
        ]
        with self.assertRaises(FixtureRejected):
            issue_capability(candidate)

        candidate = copy.deepcopy(default_capability_input())
        candidate["password"] = "secret"
        with self.assertRaises(FixtureRejected):
            issue_capability(candidate)

    def test_append_only_requires_record_key_and_sha256_preimage(self):
        target = {
            "path": "evidence/append.md",
            "operation": "APPEND_ONLY",
            "expectedPreimage": "ABSENT",
            "contentKind": "VERIFIED_MARKDOWN",
        }
        with self.assertRaises(FixtureRejected):
            issue_capability({**default_capability_input(), "evidenceTargets": [target]})
        target["expectedPreimage"] = "a" * 64
        with self.assertRaises(FixtureRejected):
            issue_capability({**default_capability_input(), "evidenceTargets": [target]})
        target["recordKey"] = "append-1"
        capability = issue_capability({**default_capability_input(), "evidenceTargets": [target]})
        self.assertEqual(capability["evidenceTargets"][0]["recordKey"], "append-1")

    def test_replay_guard_rejects_duplicate_request_sequence_and_cross_run(self):
        guard = ReplayGuard()
        guard.accept("run-1", "req-1", 1)
        with self.assertRaises(FixtureRejected):
            guard.accept("run-1", "req-1", 1)
        with self.assertRaises(FixtureRejected):
            guard.accept("run-1", "req-2", 1)
        with self.assertRaises(FixtureRejected):
            guard.accept("run-2", "req-3", 2)


class LedgerFixtureTest(unittest.TestCase):
    def setUp(self):
        self.capability = issue_capability(default_capability_input())

    def test_single_live_run_and_first_call_gate(self):
        registry = SingleRunRegistry()
        ledger = registry.begin(self.capability, now_ms=1_000)
        self.assertEqual(ledger.state, "ACTIVE_UNPREFLIGHTED")
        with self.assertRaises(FixtureRejected):
            ledger.begin_call("search_objects", _rid(1), 1, {}, now_ms=1_001)
        with self.assertRaises(FixtureRejected):
            registry.begin(issue_capability(default_capability_input(run_id="run-2")), 1_002)
        self.assertIn(ledger.state, LIVE_RUN_STATES)

    def test_reserved_spawn_and_database_permit_are_ordered(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        reservation = ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        self.assertEqual(reservation["kind"], "RESERVATION")
        self.assertIsNone(ledger.in_flight)
        self.assertEqual(ledger.reserved_call["kind"], "RESERVATION")
        self.assertEqual(ledger.call_count, 0)
        with self.assertRaises(FixtureRejected):
            ledger.issue_database_permit(1_002)
        ledger.report_spawn_ok(4, "a" * 64, 1_003)
        permit = ledger.issue_database_permit(1_004)
        self.assertEqual(permit["kind"], "DATABASE")
        self.assertEqual(permit["tool"], "db_preflight")
        self.assertEqual(permit["requestId"], _rid(1))
        self.assertEqual(permit["callSequence"], 1)
        self.assertEqual(permit["argumentsSha256"], reservation["argumentsSha256"])
        self.assertEqual(ledger.call_count, 1)

    def test_reserved_spawn_failure_does_not_consume_database_budget(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        self.assertEqual(ledger.deadline_elapsed(4_001), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.call_count, 0)

    def test_database_calls_require_explicit_preflight_success(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        permit = ledger.issue_database_permit(1_003)
        with self.assertRaises(FixtureRejected):
            ledger.complete_database(permit, success=True, preflight_passed=None, now_ms=1_004)
        self.assertEqual(ledger.state, "REVOKE_PENDING_CLEANUP")

    def test_preflight_pass_then_fifteen_calls_close_query_and_require_child_ack(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        permit = ledger.issue_database_permit(1_003)
        ledger.complete_database(permit, success=True, preflight_passed=True, now_ms=1_004)
        for sequence in range(2, 16):
            reservation = ledger.begin_call(
                "describe_object", _rid(sequence), sequence, {}, 1_004 + sequence
            )
            self.assertEqual(reservation["kind"], "DATABASE")
            ledger.complete_database(
                reservation,
                success=True,
                preflight_passed=None,
                now_ms=1_005 + sequence,
            )
        self.assertEqual(ledger.state, "QUERY_CLOSED")
        self.assertFalse(ledger.query_close_cleanup_ack)
        with self.assertRaises(FixtureRejected):
            ledger.begin_evidence_commit([], 2_000, 60_000, 0)
        ledger.ack_child_termination({"pid": 4, "audit": "a" * 64})
        self.assertTrue(ledger.query_close_cleanup_ack)
        unbound_targets = copy.deepcopy(self.capability["evidenceTargets"])
        unbound_targets[0]["path"] = "outside-capability.md"
        with self.assertRaises(FixtureRejected):
            ledger.begin_evidence_commit(unbound_targets, 2_000, 60_000, 1)
        evidence = ledger.begin_evidence_commit(
            copy.deepcopy(self.capability["evidenceTargets"]),
            2_000,
            60_000,
            1,
        )
        self.assertEqual(evidence["kind"], "EVIDENCE")
        ledger.complete_evidence(evidence, 2_001)
        self.assertEqual(ledger.state, "CLOSED")

    def test_failed_preflight_and_evidence_in_flight_keep_global_slot(self):
        registry = SingleRunRegistry()
        ledger = registry.begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        permit = ledger.issue_database_permit(1_003)
        ledger.complete_database(permit, success=True, preflight_passed=False, now_ms=1_004)
        self.assertEqual(ledger.state, "REVOKE_PENDING_CLEANUP")
        with self.assertRaises(FixtureRejected):
            ledger.begin_call("describe_object", _rid(2), 2, {}, 1_005)
        with self.assertRaises(FixtureRejected):
            registry.begin(issue_capability(default_capability_input(run_id="66666666-6666-6666-6666-666666666666")), 1_005)

        registry2 = SingleRunRegistry()
        second = registry2.begin(self.capability, 1_000)
        second.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        second.report_spawn_ok(4, "a" * 64, 1_002)
        permit = second.issue_database_permit(1_003)
        second.complete_database(permit, True, True, 1_004)
        for sequence in range(2, 16):
            call = second.begin_call("describe_object", _rid(sequence), sequence, {}, 1_004 + sequence)
            second.complete_database(call, True, None, 1_005 + sequence)
        second.ack_child_termination({"pid": 4, "audit": "a" * 64})
        evidence = second.begin_evidence_commit(
            copy.deepcopy(second.capability["evidenceTargets"]),
            2_000, 60_000, 1,
        )
        self.assertEqual(second.state, "EVIDENCE_IN_FLIGHT")
        with self.assertRaises(FixtureRejected):
            second.begin_call("describe_object", _rid(16), 16, {}, 2_001)
        with self.assertRaises(FixtureRejected):
            registry2.begin(issue_capability(default_capability_input(run_id="77777777-7777-7777-7777-777777777777")), 2_001)
        second.complete_evidence(evidence, 2_001)

    def test_terminal_run_tombstone_rejects_registry_reactivation(self):
        registry = SingleRunRegistry()
        ledger = registry.begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        self.assertEqual(ledger.deadline_elapsed(4_001), "REVOKE_PENDING_CLEANUP")
        command = ledger.recovery_command()
        ledger.ack_child_termination(
            None,
            command["cleanupId"],
            command["epoch"],
            _launch_scan_fixture(command["reservedLaunchIdentity"]),
        )
        self.assertEqual(ledger.state, "REVOKED")
        self.assertFalse(ledger.query_close_cleanup_ack)
        with self.assertRaises(FixtureRejected):
            registry.begin(self.capability, 5_000)

    def test_spawn_timeout_late_payload_cleanup_and_restart_tombstone(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        self.assertEqual(ledger.deadline_elapsed(4_001), "REVOKE_PENDING_CLEANUP")
        self.assertFalse(ledger.report_spawn_ok(4, "a" * 64, 4_002))
        self.assertIsNone(ledger.child_identity)
        command = ledger.recovery_command()
        self.assertIsNone(command["toolboxChildIdentity"])
        with self.assertRaises(FixtureRejected):
            ledger.ack_child_termination({"pid": 4, "audit": "a" * 64}, command["cleanupId"], command["epoch"])
        with self.assertRaises(FixtureRejected):
            ledger.ack_child_termination(None, command["cleanupId"], command["epoch"])
        ledger.ack_child_termination(
            None,
            command["cleanupId"],
            command["epoch"],
            _launch_scan_fixture(command["reservedLaunchIdentity"]),
        )
        self.assertEqual(ledger.state, "REVOKED")
        with self.assertRaises(FixtureRejected):
            ledger.begin_call("db_preflight", _rid(2), 1, {}, 5_000)

    def test_invalid_database_lease_and_evidence_target_budget_are_rejected(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        with self.assertRaises(FixtureRejected):
            ledger.issue_database_permit(1_003, lease_ms=0)
        ledger.fail_spawn("a" * 64, 1_003)
        self.assertEqual(ledger.state, "REVOKE_PENDING_CLEANUP")

    def test_abort_and_cleanup_ack_never_reactivate_run(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.fail_spawn("a" * 64, 1_002)
        command = ledger.recovery_command()
        ledger.ack_child_termination(
            None,
            command["cleanupId"],
            command["epoch"],
            _launch_scan_fixture(command["reservedLaunchIdentity"]),
        )
        self.assertEqual(ledger.state, "REVOKED")
        with self.assertRaises(FixtureRejected):
            ledger.begin_call("db_preflight", _rid(2), 1, {}, 1_003)

    def test_recovery_command_is_a_snapshot_not_a_live_reference(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        command = ledger.recovery_command()
        command["reservedLaunchIdentity"]["perLaunchNonce"] = "Z" * 43
        command["toolboxChildIdentity"]["pid"] = 99
        self.assertNotEqual(ledger.reserved_launch_identity["perLaunchNonce"], "Z" * 43)
        self.assertEqual(ledger.child_identity, {"pid": 4, "audit": "a" * 64})

    def test_epoch_rotation_invalidates_old_run_and_cleanup_command(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        original_capability = copy.deepcopy(ledger.capability)
        self.assertEqual(ledger.rotate_epoch("ledger-2"), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.capability, original_capability)
        command = ledger.recovery_command()
        with self.assertRaises(FixtureRejected):
            ledger.ack_child_termination({"pid": 4, "audit": "a" * 64}, command["cleanupId"], "ledger-1")
        with self.assertRaises(FixtureRejected):
            ledger.ack_child_termination(
                None,
                command["cleanupId"],
                command["epoch"],
                _launch_scan_fixture(command["reservedLaunchIdentity"], matched_pids=[9]),
            )

    def test_old_database_permit_cannot_reactivate_after_epoch_or_nonce_rotation(self):
        epoch_ledger = SingleRunRegistry().begin(self.capability, 1_000)
        epoch_ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        epoch_ledger.report_spawn_ok(4, "a" * 64, 1_002)
        epoch_permit = epoch_ledger.issue_database_permit(1_003)
        epoch_ledger.rotate_epoch("ledger-2")
        with self.assertRaises(FixtureRejected):
            epoch_ledger.complete_database(epoch_permit, True, True, 1_004)
        self.assertEqual(epoch_ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(epoch_ledger.child_identity, {"pid": 4, "audit": "a" * 64})

        nonce_ledger = SingleRunRegistry().begin(
            issue_capability(default_capability_input(run_id="88888888-8888-8888-8888-888888888888")),
            1_000,
        )
        nonce_ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        nonce_ledger.report_spawn_ok(4, "a" * 64, 1_002)
        nonce_permit = nonce_ledger.issue_database_permit(1_003)
        nonce_ledger.register_gateway_nonce("C" * 43)
        with self.assertRaises(FixtureRejected):
            nonce_ledger.complete_database(nonce_permit, True, True, 1_004)
        self.assertEqual(nonce_ledger.state, "REVOKE_PENDING_CLEANUP")

    def test_known_child_survives_spawn_failure_until_matching_cleanup_ack(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        ledger.report_spawn_fail(False, "not-a-digest", 1_003)
        self.assertEqual(ledger.child_identity, {"pid": 4, "audit": "a" * 64})
        command = ledger.recovery_command()
        with self.assertRaises(FixtureRejected):
            ledger.ack_child_termination(
                None,
                command["cleanupId"],
                command["epoch"],
                _launch_scan_fixture(command["reservedLaunchIdentity"], scan_complete=False),
            )
        self.assertEqual(
            ledger.ack_child_termination(
                {"pid": 4, "audit": "a" * 64}, command["cleanupId"], command["epoch"]
            ),
            "REVOKED",
        )

    def test_abort_nonce_rotation_lease_types_and_corrupt_snapshot(self):
        ledger = SingleRunRegistry().begin(self.capability, 1_000)
        first = ledger.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
        ledger.report_spawn_ok(4, "a" * 64, 1_002)
        permit = ledger.issue_database_permit(1_003)
        for invalid_lease in (0, -1, True, "20000", 20001):
            with self.subTest(invalid_lease=invalid_lease):
                probe = SingleRunRegistry().begin(issue_capability(default_capability_input(run_id="55555555-5555-5555-5555-555555555555")), 1_000)
                probe.begin_call("db_preflight", _rid(1), 1, {}, 1_001)
                probe.report_spawn_ok(4, "a" * 64, 1_002)
                with self.assertRaises(FixtureRejected):
                    probe.issue_database_permit(1_003, invalid_lease)
        self.assertEqual(ledger.abort_database(permit, 1_004), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.register_gateway_nonce("C" * 43), "REVOKE_PENDING_CLEANUP")
        self.assertTrue(validate_ledger_snapshot({
            "state": "ACTIVE_READY", "inFlight": None, "toolboxSessionId": "s",
            "childIdentity": {"pid": 4, "audit": "a" * 64},
            "preflightPassed": True, "reservedCall": None,
            "queryCloseCleanupAck": False, "callCount": 1,
            "reservedLaunchIdentity": None, "cleanup": None,
        }))
        with self.assertRaises(FixtureRejected):
            validate_ledger_snapshot({
                "state": "ACTIVE_READY", "inFlight": None, "toolboxSessionId": None, "childIdentity": {"pid": 4},
                "queryCloseCleanupAck": False, "callCount": 1,
            })
        with self.assertRaises(FixtureRejected):
            validate_ledger_snapshot({
                "state": "IN_FLIGHT_PREFLIGHT",
                "inFlight": {"kind": "RESERVATION"},
                "toolboxSessionId": "s",
                "childIdentity": None,
                "queryCloseCleanupAck": False,
                "callCount": 0,
            })

    def test_cleanup_snapshot_requires_reservation_and_cleanup_evidence(self):
        with self.assertRaises(FixtureRejected):
            validate_ledger_snapshot({
                "state": "REVOKE_PENDING_CLEANUP",
                "inFlight": None,
                "reservedCall": None,
                "toolboxSessionId": None,
                "childIdentity": None,
                "preflightPassed": False,
                "queryCloseCleanupAck": False,
                "callCount": 0,
                "reservedLaunchIdentity": None,
                "cleanup": None,
            })
        session_id = "00000000-0000-0000-0000-000000000003"
        self.assertTrue(validate_ledger_snapshot({
            "state": "REVOKE_PENDING_CLEANUP",
            "inFlight": None,
            "reservedCall": None,
            "toolboxSessionId": session_id,
            "childIdentity": None,
            "preflightPassed": False,
            "queryCloseCleanupAck": False,
            "callCount": 0,
            "reservedLaunchIdentity": {
                "executableFdIdentity": {
                    "canonicalPath": "/fixture/toolbox",
                    "device": "1",
                    "inode": "2",
                    "sha256": "b" * 64,
                },
                "perLaunchNonce": "C" * 43,
            },
            "cleanup": {
                "cleanupId": "00000000-0000-0000-0000-000000000004",
                "cause": "SPAWN_FAILED",
                "cleanupKind": "TOOLBOX_TERMINATION",
                "terminalTarget": "REVOKED",
                "toolboxSessionId": session_id,
                "toolboxChildIdentity": None,
                "evidenceWalId": None,
                "startedAt": "1970-01-01T00:00:00Z",
                "ledgerRecoveryAuditTokenSha256": "a" * 64,
                "recoveryComponentSha256": "b" * 64,
                "recoveryExecutionSessionId": "00000000-0000-0000-0000-000000000005",
            },
        }))
        child = {"pid": 4, "audit": "a" * 64}
        child_snapshot = {
            "state": "REVOKE_PENDING_CLEANUP",
            "inFlight": None,
            "reservedCall": None,
            "toolboxSessionId": session_id,
            "childIdentity": child,
            "preflightPassed": False,
            "queryCloseCleanupAck": False,
            "callCount": 0,
            "reservedLaunchIdentity": {
                "executableFdIdentity": {
                    "canonicalPath": "/fixture/toolbox",
                    "device": "1",
                    "inode": "2",
                    "sha256": "b" * 64,
                },
                "perLaunchNonce": "C" * 43,
            },
            "cleanup": {
                "cleanupId": "00000000-0000-0000-0000-000000000004",
                "cause": "SPAWN_FAILED",
                "cleanupKind": "TOOLBOX_TERMINATION",
                "terminalTarget": "REVOKED",
                "toolboxSessionId": session_id,
                "toolboxChildIdentity": canon(child).decode("utf-8"),
                "evidenceWalId": None,
                "startedAt": "1970-01-01T00:00:00Z",
                "ledgerRecoveryAuditTokenSha256": "a" * 64,
                "recoveryComponentSha256": "b" * 64,
                "recoveryExecutionSessionId": "00000000-0000-0000-0000-000000000005",
            },
        }
        self.assertTrue(validate_ledger_snapshot(child_snapshot))
        broken_child_snapshot = copy.deepcopy(child_snapshot)
        broken_child_snapshot["cleanup"]["toolboxChildIdentity"] = "different-child"
        with self.assertRaises(FixtureRejected):
            validate_ledger_snapshot(broken_child_snapshot)

    def test_corrupt_live_snapshot_requires_state_evidence(self):
        for state in ("IN_FLIGHT_PREFLIGHT", "ACTIVE_READY"):
            with self.subTest(state=state):
                with self.assertRaises(FixtureRejected):
                    validate_ledger_snapshot({
                        "state": state,
                        "inFlight": None,
                        "toolboxSessionId": None,
                        "childIdentity": None,
                        "queryCloseCleanupAck": False,
                        "callCount": 0,
                    })

    def test_evidence_content_limits_and_no_secret_fallback(self):
        target = {
            "path": "evidence.md",
            "operation": "CREATE_NEW",
            "expectedPreimage": "ABSENT",
            "contentKind": "VERIFIED_MARKDOWN",
        }
        self.assertTrue(validate_evidence_content(target, "safe evidence"))
        with self.assertRaises(FixtureRejected):
            validate_evidence_content(target, "password=do-not-write")
        with self.assertRaises(FixtureRejected):
            validate_evidence_content(target, "x" * 65537)


class PolicyFixtureTest(unittest.TestCase):
    def test_preflight_has_exact_identity_and_twenty_one_privilege_checks(self):
        profile = default_profile()
        result = preflight(
            {
                "identity": {
                    "database": "fixture_db",
                    "user": "fixture_ro",
                    "currentSchema": "ai_dw",
                },
                "transactionReadOnly": True,
                "timeouts": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
                "privileges": {
                    "capabilitySignature": True, "ledgerState": True, "componentManifest": True, "trustedHelper": True,
                    "credentialIsolation": True, "columnClassification": True,
                    "connect": True, "schemaUsage": True, "profileDataSelect": True, "implementationCatalog": True, "runScopeSubset": True,
                    "extraSelect": False, "columnSelect": False, "publicSelect": False, "inheritedSelect": False, "bypassRls": False,
                    "ownership": False, "setRole": False, "write": False, "createTemp": False, "fileProgram": False,
                    "routineRisk": False, "transactionReadOnly": True,
                },
            },
            profile,
            default_capability_input()["scope"],
        )
        self.assertTrue(result["passed"])
        self.assertEqual(set(result["identityMatches"]), {"database", "user", "currentSchema"})
        self.assertEqual([item["check"] for item in result["privilegeChecks"]], list(PRIVILEGE_CHECKS))
        self.assertEqual(len(result["privilegeChecks"]), 21)
        self.assertNotIn("fixture_db", repr(result))
        self.assertNotIn("fixture_ro", repr(result))

    def test_preflight_rejects_overbroad_privileges_and_object_drift(self):
        profile = default_profile()
        snapshot = {
            "identity": {"database": "fixture_db", "user": "fixture_ro", "currentSchema": "ai_dw"},
            "transactionReadOnly": True,
            "timeouts": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
            "privileges": {
                "capabilitySignature": True, "ledgerState": True, "componentManifest": True, "trustedHelper": True,
                "credentialIsolation": True, "columnClassification": True,
                "connect": True, "schemaUsage": True, "profileDataSelect": True, "implementationCatalog": True, "runScopeSubset": True,
                "extraSelect": True, "columnSelect": False, "publicSelect": False, "inheritedSelect": False, "bypassRls": False,
                "ownership": False, "setRole": False, "write": False, "createTemp": False, "fileProgram": False,
                "routineRisk": False, "transactionReadOnly": True,
            },
        }
        result = preflight(snapshot, profile, default_capability_input()["scope"])
        self.assertFalse(result["passed"])
        self.assertIn("PREFLIGHT_PRIVILEGE", result["issues"])

    def test_preflight_does_not_synthesize_missing_security_evidence(self):
        profile = default_profile()
        snapshot = {
            "identity": {"database": "fixture_db", "user": "fixture_ro", "currentSchema": "ai_dw"},
            "transactionReadOnly": True,
            "timeouts": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
            "privileges": {
                "ledgerState": True, "componentManifest": True, "trustedHelper": True, "credentialIsolation": True,
                "connect": True, "schemaUsage": True, "profileDataSelect": True, "implementationCatalog": True, "runScopeSubset": True,
                "extraSelect": False, "columnSelect": False, "publicSelect": False, "inheritedSelect": False, "bypassRls": False,
                "ownership": False, "setRole": False, "write": False, "createTemp": False, "fileProgram": False,
                "routineRisk": False, "transactionReadOnly": True,
            },
        }
        result = preflight(snapshot, profile, default_capability_input()["scope"])
        self.assertFalse(result["passed"])
        capability_check = next(item for item in result["privilegeChecks"] if item["check"] == "CAPABILITY_SIGNATURE")
        self.assertFalse(capability_check["passed"])

    def test_profile_account_upper_bound_is_separate_from_metadata_only_run_scope(self):
        profile = default_profile()
        metadata_scope = copy.deepcopy(default_scope())
        metadata_scope["metadataOnly"] = True
        for field in ("dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants"):
            metadata_scope[field] = []
        self.assertTrue(validate_profile_run_scope(profile, metadata_scope))
        expanded = copy.deepcopy(default_scope())
        expanded["dataObjects"][0]["object"] = "outside_allowlist"
        with self.assertRaises(FixtureRejected):
            validate_profile_run_scope(profile, expanded)

    def test_identifier_wildcards_cannot_expand_scope(self):
        expanded = copy.deepcopy(default_scope())
        expanded["dataObjects"][0]["object"] = "*"
        with self.assertRaises(FixtureRejected):
            issue_capability({**default_capability_input(), "scope": expanded})

    def test_column_classification_and_value_dlp_are_fail_closed(self):
        self.assertEqual(classify_column("PD_ID", ""), "UNKNOWN")
        self.assertEqual(classify_column("customer_email", ""), "SENSITIVE")
        self.assertEqual(classify_column("id_card", "", "PUBLIC_INTERNAL"), "SENSITIVE")
        self.assertEqual(classify_column("bank_account", "", "PUBLIC_INTERNAL"), "SENSITIVE")
        self.assertEqual(classify_column("public_name", "", "PUBLIC_INTERNAL"), "PUBLIC_INTERNAL")
        self.assertEqual(classify_column("password_hash", "", "PUBLIC_INTERNAL"), "SENSITIVE")
        self.assertTrue(scan_value("alice@example.com"))
        self.assertTrue(scan_value("password=not-for-output"))
        self.assertFalse(scan_value("ordinary industry text"))

    def test_only_renderer_and_sql_policy_reject_bypass_paths(self):
        sql = render_only_select("ai_dw", 'T_EDW_VAR_PD_INFO_Q', ["metric", "public_name"])
        self.assertIn('FROM ONLY "ai_dw"."T_EDW_VAR_PD_INFO_Q"', sql)
        self.assertIn('"public_name"', sql)
        allowed = validate_sql(
            'SELECT COUNT(*) FROM ONLY "ai_dw"."T_EDW_VAR_PD_INFO_Q" LIMIT 10',
            allow_generic_sql=True,
            allowed_columns={"metric": "PUBLIC_INTERNAL"},
            expected_object=data_object(),
        )
        self.assertTrue(allowed)
        for query in (
            "SELECT * FROM ONLY ai_dw.t",
            "SELECT x FROM ai_dw.t",
            "SHOW search_path",
            "SELECT x FROM ONLY ai_dw.t; DELETE FROM t",
            "SELECT x FROM ONLY ai_dw.t FOR UPDATE",
            "SELECT x FROM ONLY ai_dw.t UNION SELECT x FROM ONLY ai_dw.t",
            "SELECT secret FROM ONLY ai_dw.t",
        ):
            with self.subTest(query=query):
                with self.assertRaises(FixtureRejected):
                    validate_sql(
                        query,
                        allow_generic_sql=True,
                        allowed_columns={"x": "PUBLIC_INTERNAL", "secret": "SENSITIVE"},
                        expected_object=data_object(),
                    )
        with self.assertRaises(FixtureRejected):
            validate_sql(
                "SELECT x FROM ONLY ai_dw.t",
                allow_generic_sql=False,
                allowed_columns={"x": "PUBLIC_INTERNAL"},
                expected_object=data_object(),
            )

    def test_sql_fixture_covers_all_frozen_write_set_and_routine_rejections(self):
        forbidden_queries = (
            "INSERT INTO ONLY ai_dw.t VALUES (1)",
            "UPDATE ONLY ai_dw.t SET x=1",
            "DELETE FROM ONLY ai_dw.t",
            "MERGE INTO ONLY ai_dw.t USING ONLY ai_dw.u ON 1=1 WHEN MATCHED THEN UPDATE SET x=1",
            "COPY ai_dw.t TO STDOUT",
            "CREATE TABLE x(a int)",
            "ALTER TABLE ai_dw.t ADD COLUMN y int",
            "DROP TABLE ai_dw.t",
            "TRUNCATE ONLY ai_dw.t",
            "GRANT SELECT ON ai_dw.t TO public",
            "REVOKE SELECT ON ai_dw.t FROM public",
            "WITH RECURSIVE x AS (SELECT 1) SELECT x FROM ONLY ai_dw.t LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\" UNION SELECT x FROM ONLY \"ai_dw\".\"u\" LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\" INTERSECT SELECT x FROM ONLY \"ai_dw\".\"u\" LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\" EXCEPT SELECT x FROM ONLY \"ai_dw\".\"u\" LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\" LATERAL LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\" FOR SHARE LIMIT 1",
            "EXPLAIN ANALYZE SELECT x FROM ONLY \"ai_dw\".\"t\" LIMIT 1",
            "SELECT pg_sleep(1) FROM ONLY \"ai_dw\".\"t\" LIMIT 1",
            "SELECT x FROM ONLY \"ai_dw\".\"t\"; SELECT x FROM ONLY \"ai_dw\".\"t\" LIMIT 1",
        )
        for query in forbidden_queries:
            with self.subTest(query=query):
                with self.assertRaises(FixtureRejected):
                    validate_sql(
                        query,
                        allow_generic_sql=True,
                        allowed_columns={"x": "PUBLIC_INTERNAL"},
                        expected_object=data_object(),
                    )

    def test_sql_binds_exact_object_and_complete_column_allowlist(self):
        expected = data_object()
        self.assertTrue(
            validate_sql(
                'SELECT "metric" FROM ONLY "ai_dw"."T_EDW_VAR_PD_INFO_Q" LIMIT 10',
                allow_generic_sql=True,
                allowed_columns={"metric": "PUBLIC_INTERNAL"},
                expected_object=expected,
            )
        )
        with self.assertRaises(FixtureRejected):
            validate_sql(
                'SELECT "unknown" FROM ONLY "ai_dw"."T_EDW_VAR_PD_INFO_Q" LIMIT 10',
                allow_generic_sql=True,
                allowed_columns={"metric": "PUBLIC_INTERNAL"},
                expected_object=expected,
            )
        with self.assertRaises(FixtureRejected):
            validate_sql(
                'SELECT "metric" FROM ONLY "ai_dw"."other_table" LIMIT 10',
                allow_generic_sql=True,
                allowed_columns={"metric": "PUBLIC_INTERNAL"},
                expected_object=expected,
            )

    def test_quoted_identifier_renderer_round_trips_through_sql_validator(self):
        expected = data_object(schema='A"B', obj='T"Q')
        sql = render_only_select('A"B', 'T"Q', ['C"D']) + " LIMIT 10"
        self.assertTrue(
            validate_sql(
                sql,
                allow_generic_sql=True,
                allowed_columns={'C"D': "PUBLIC_INTERNAL"},
                expected_object=expected,
            )
        )

    def test_system_routine_exposure_does_not_equal_call_allowlist(self):
        routines = [
            {
                "schema": "pg_catalog", "name": "random", "identityArguments": "()",
                "routineKind": "FUNCTION", "ownerPrincipal": "pg_catalog", "securityType": "INVOKER",
                "volatility": "VOLATILE", "effectiveExecute": True,
            },
            {
                "schema": "pg_catalog", "name": "clock_timestamp", "identityArguments": "()",
                "routineKind": "FUNCTION", "ownerPrincipal": "pg_catalog", "securityType": "INVOKER",
                "volatility": "VOLATILE", "effectiveExecute": True,
            },
        ]
        self.assertTrue(validate_routine_exposure(
            routines,
            {"pg_catalog.random", "pg_catalog.clock_timestamp"},
            {"COUNT", "MIN", "MAX", "SUM", "AVG"},
        ))
        changed = copy.deepcopy(routines)
        changed[0]["schema"] = "public"
        with self.assertRaises(FixtureRejected):
            validate_routine_exposure(changed, {"pg_catalog.random", "pg_catalog.clock_timestamp"}, {"COUNT"})
        for field in ("identityArguments", "routineKind", "volatility"):
            changed = copy.deepcopy(routines)
            changed[0][field] = "DRIFT"
            with self.subTest(field=field):
                with self.assertRaises(FixtureRejected):
                    validate_routine_exposure(changed, {"pg_catalog.random", "pg_catalog.clock_timestamp"}, {"COUNT"})

    def test_object_identity_and_reverse_privilege_checks_are_fail_closed(self):
        signed = {
            "schema": "ai_dw",
            "object": "T_EDW_VAR_PD_INFO_Q",
            "objectKind": "LOCAL_BASE_TABLE",
            "catalogIdentity": {"catalog": "PG_CLASS", "oid": "101"},
        }
        live = {
            "objectKind": "LOCAL_BASE_TABLE",
            "catalogIdentity": {"catalog": "PG_CLASS", "oid": "101"},
            "relkind": "r",
            "relispartition": False,
            "relhassubclass": False,
            "inheritsParent": False,
            "inheritsChild": False,
        }
        self.assertTrue(validate_live_object(signed, live))
        for field, value in (("relhassubclass", True), ("inheritsParent", True), ("relkind", "v")):
            changed = dict(live)
            changed[field] = value
            with self.assertRaises(FixtureRejected):
                validate_live_object(signed, changed)
        privilege_snapshot = {
            "capabilitySignature": True, "ledgerState": True, "componentManifest": True, "trustedHelper": True,
            "credentialIsolation": True, "columnClassification": True,
            "connect": True, "schemaUsage": True, "profileDataSelect": True, "implementationCatalog": True, "runScopeSubset": True,
            "extraSelect": False, "columnSelect": False, "publicSelect": False, "inheritedSelect": False, "bypassRls": False,
            "ownership": False, "setRole": False, "write": False, "createTemp": False, "fileProgram": False,
            "routineRisk": False, "transactionReadOnly": True,
        }
        self.assertTrue(validate_privilege_snapshot(privilege_snapshot))
        privilege_snapshot["publicSelect"] = True
        with self.assertRaises(FixtureRejected):
            validate_privilege_snapshot(privilege_snapshot)

    def test_metadata_only_and_column_grants_are_separate(self):
        scope = copy.deepcopy(default_scope())
        scope["metadataOnly"] = True
        scope["dataObjects"] = []
        scope["valueColumns"] = []
        scope["sampleColumns"] = []
        scope["sqlColumns"] = []
        scope["statsGrants"] = []
        with self.assertRaises(FixtureRejected):
            validate_tool_access("sample_rows", scope, {})
        self.assertTrue(validate_tool_access("get_table_stats", scope, {"metric": "CATALOG_ROW_ESTIMATE"}))
        with self.assertRaises(FixtureRejected):
            validate_tool_access("get_table_stats", scope, {"metric": "ROW_COUNT"})

        full_scope = default_scope()
        self.assertTrue(validate_stats_request({"metric": "ROW_COUNT", "column": "metric"}, full_scope))
        self.assertTrue(
            validate_stats_request(
                {"metric": "ROW_COUNT", "object": full_scope["dataObjects"][0]},
                full_scope,
            )
        )
        mixed_scope = copy.deepcopy(full_scope)
        other_object = data_object(obj="OTHER_TABLE", oid="102")
        mixed_scope["dataObjects"].append(other_object)
        mixed_scope["valueColumns"] = [{"schema": "ai_dw", "object": "OTHER_TABLE", "column": "metric"}]
        mixed_scope["statsGrants"][0]["metrics"] = ["NULL_COUNT"]
        mixed_scope["statsGrants"].append({"schema": "ai_dw", "object": "OTHER_TABLE", "metrics": ["NULL_COUNT"]})
        with self.assertRaises(FixtureRejected):
            validate_stats_request(
                {
                    "metric": "NULL_COUNT",
                    "object": full_scope["dataObjects"][0],
                    "column": "metric",
                },
                mixed_scope,
            )
        without_row_count = copy.deepcopy(full_scope)
        without_row_count["statsGrants"][0]["metrics"] = ["NULL_COUNT"]
        with self.assertRaises(FixtureRejected):
            validate_stats_request({"metric": "ROW_COUNT", "column": "metric"}, without_row_count)
        with self.assertRaises(FixtureRejected):
            validate_stats_request({"metric": "TOP_K", "column": "secret", "topK": 20}, full_scope)
        self.assertTrue(validate_sample_request({"object": full_scope["dataObjects"][0], "columns": ["metric"], "limit": 10}, full_scope))
        with self.assertRaises(FixtureRejected):
            validate_sample_request({"object": full_scope["dataObjects"][0], "columns": ["secret"], "limit": 10}, full_scope)

    def test_profile_and_metadata_scope_lists_fail_closed(self):
        profile = default_profile()
        scope = copy.deepcopy(default_scope())
        scope["metadataOnly"] = True
        scope["businessCatalogSchemas"] = ["outside"]
        for field in ("dataObjects", "valueColumns", "sampleColumns", "sqlColumns", "statsGrants"):
            scope[field] = []
        with self.assertRaises(FixtureRejected):
            validate_profile_run_scope(profile, scope)
        for field in (
            "businessCatalogSchemas",
            "implementationCatalog",
            "systemRoutineExposureBaseline",
            "systemRoutineCallAllowlist",
        ):
            malformed = copy.deepcopy(profile)
            malformed[field] = [None]
            with self.subTest(field=field):
                with self.assertRaises(FixtureRejected):
                    validate_profile(malformed)
        malformed = copy.deepcopy(profile)
        malformed["systemRoutineCallAllowlist"] = ["DROP"]
        with self.assertRaises(FixtureRejected):
            validate_profile(malformed)

    def test_search_and_describe_requests_bind_to_business_schema_scope(self):
        scope = default_scope()
        self.assertTrue(validate_tool_access("search_objects", scope, {"schemas": ["ai_dw"]}))
        with self.assertRaises(FixtureRejected):
            validate_tool_access("search_objects", scope, {"schemas": ["outside"]})
        self.assertTrue(validate_tool_access(
            "describe_object", scope, {"objects": [{"schema": "ai_dw", "object": "outside_table"}]}
        ))
        with self.assertRaises(FixtureRejected):
            validate_tool_access(
                "describe_object", scope, {"objects": [{"schema": "outside", "object": "outside_table"}]}
            )

    def test_sample_columns_are_bound_to_the_requested_object(self):
        scope = default_scope()
        other_object = data_object(obj="OTHER_TABLE", oid="102")
        scope["dataObjects"].append(other_object)
        scope["sampleColumns"] = [{"schema": "ai_dw", "object": "OTHER_TABLE", "column": "metric"}]
        with self.assertRaises(FixtureRejected):
            validate_sample_request(
                {"object": scope["dataObjects"][0], "columns": ["metric"], "limit": 10},
                scope,
            )

    def test_malformed_optional_inputs_fail_closed_without_runtime_exceptions(self):
        capability = issue_capability(default_capability_input())
        self.assertFalse(validate_capability(capability, now_ms=None))

        malformed_profile = default_profile()
        malformed_profile["allowedObjects"] = None
        with self.assertRaises(FixtureRejected):
            validate_profile(malformed_profile)

        with self.assertRaises(FixtureRejected):
            issue_page_token(None, ["s", "t", "BASE_TABLE"], 1, 60_000, candidate_count=1)
        with self.assertRaises(FixtureRejected):
            classify_column(None)

    def test_search_input_rejects_full_enumeration_and_pagination_limits(self):
        self.assertTrue(validate_search_query("产业", ["NAME", "COMMENT"], 20))
        for query in ("", "   ", "%%", "_*", "?", "a!"):
            with self.assertRaises(FixtureRejected):
                validate_search_query(query, ["NAME"], 20)
        with self.assertRaises(FixtureRejected):
            validate_search_query("ab", ["NAME"], 21)
        with self.assertRaises(FixtureRejected):
            validate_search_query("ab", ["NAME"], None)

    def test_malformed_scope_and_preflight_privileges_fail_closed(self):
        malformed_scope = copy.deepcopy(default_scope())
        malformed_scope["dataObjects"] = None
        with self.assertRaises(FixtureRejected):
            validate_scope(malformed_scope, authorization=True)

        privileges = {
            "capabilitySignature": True, "ledgerState": True, "componentManifest": True, "trustedHelper": True,
            "credentialIsolation": True, "columnClassification": True,
            "connect": True, "schemaUsage": True, "profileDataSelect": True, "implementationCatalog": True, "runScopeSubset": True,
            "extraSelect": False, "columnSelect": False, "publicSelect": False, "inheritedSelect": False, "bypassRls": False,
            "ownership": False, "setRole": False, "write": False, "createTemp": False, "fileProgram": False,
            "routineRisk": False,
        }
        result = preflight(
            {
                "identity": {"database": "fixture_db", "user": "fixture_ro", "currentSchema": "ai_dw"},
                "transactionReadOnly": True,
                "timeouts": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
                "privileges": privileges,
            },
            default_profile(),
            default_scope(),
        )
        self.assertFalse(result["passed"])


class ContractFixtureTest(unittest.TestCase):
    def test_fourteen_schema_manifest_is_closed_and_stable(self):
        self.assertEqual(len(SCHEMA_NAMES), 14)
        self.assertEqual(len(schema_manifest()), 14)
        base = {
            "contractVersion": "1",
            "requestId": "00000000-0000-0000-0000-000000000001",
            "runId": "00000000-0000-0000-0000-000000000002",
            "callSequence": 1,
            "authorizationSha256": "a" * 64,
            "toolContractSha256": "b" * 64,
        }
        object_fixture = {
            "schema": "ai_dw",
            "object": "T_EDW_VAR_PD_INFO_Q",
            "objectKind": "LOCAL_BASE_TABLE",
            "catalogIdentity": {"catalog": "PG_CLASS", "oid": "101"},
        }
        requests = {
            "db_preflight": {},
            "search_objects": {"schemas": ["ai_dw"], "query": "ab", "searchIn": ["NAME"], "objectTypes": ["BASE_TABLE"], "pageSize": 20, "pageToken": None},
            "describe_object": {"objects": [{"schema": "ai_dw", "object": "T_EDW_VAR_PD_INFO_Q"}]},
            "get_table_stats": {"object": object_fixture, "metrics": ["ROW_COUNT"], "columns": [], "topK": None},
            "sample_rows": {"object": object_fixture, "columns": ["metric"], "limit": 10},
            "execute_readonly_sql": {"sql": "SELECT 1", "maxRows": 1},
        }
        response_data = {
            "db_preflight": {
                "passed": True,
                "databaseProduct": "kingbase",
                "version": "fixture",
                "identityMatches": {"database": True, "user": True, "currentSchema": True},
                "sessionReadOnly": True,
                "privilegeChecks": [
                    {"check": check, "passed": True, "scope": "fixture", "detailCode": "PASS"}
                    for check in PRIVILEGE_CHECKS
                ],
                "routineRisk": False,
                "timeoutsMs": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
                "components": [
                    {"name": name, "version": "fixture-1", "sha256": "a" * 64, "codeSignRequirement": "REQUIRED_CODE_SIGN"}
                    for name in ALL_COMPONENTS
                ],
                "profileId": "fixture-profile",
                "issues": [],
            },
            "search_objects": {"candidates": []},
            "describe_object": {"objects": []},
            "get_table_stats": {"stats": []},
            "sample_rows": {
                "sourceColumns": [{"schema": "ai_dw", "object": "T_EDW_VAR_PD_INFO_Q", "column": "metric"}],
                "rows": [],
                "maskingApplied": False,
            },
            "execute_readonly_sql": {
                "resultColumns": [{
                    "label": "metric",
                    "type": "integer",
                    "sourceColumns": [{"schema": "ai_dw", "object": "T_EDW_VAR_PD_INFO_Q", "column": "metric"}],
                }],
                "rows": [],
                "maskingApplied": False,
            },
        }
        validate_schema_instance("common", {})
        validate_schema_instance("gateway-error-v1", build_gateway_error("AUTH_REQUIRED", None, None))
        for tool, extra in requests.items():
            validate_schema_instance(tool + ".request", {**base, **extra})
            response = {
                "contractVersion": "1",
                "requestId": "00000000-0000-0000-0000-000000000001",
                "runId": "00000000-0000-0000-0000-000000000002",
                "status": "OK",
                "truncated": False,
                "data": response_data[tool],
                "page": {"pageSize": 20, "nextPageToken": None} if tool == "search_objects" else None,
                "evidence": {
                    "toolName": tool,
                    "profileId": "fixture-profile",
                    "scope": {
                        "scopeSha256": "a" * 64,
                        "counts": {
                            "businessCatalogSchemas": 0,
                            "dataObjects": 0,
                            "valueColumns": 0,
                            "sampleColumns": 0,
                            "sqlColumns": 0,
                            "statsGrants": 0,
                        },
                        "preview": {
                            "businessCatalogSchemas": [],
                            "dataObjects": [],
                            "valueColumns": [],
                        },
                    },
                    "executedAt": "1970-01-01T00:00:00Z",
                    "durationMs": 0,
                    "rowsReturned": 0,
                    "serializedBytes": 0,
                    "queryFingerprint": "0" * 64,
                    "databaseTouched": False,
                },
                "issues": [],
            }
            validate_schema_instance(tool + ".response", response)
            with self.assertRaises(FixtureRejected):
                validate_schema_instance(tool + ".request", {**base, **extra, "extra": 1})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance(
                "search_objects.request",
                {**base, **requests["search_objects"], "pageSize": 21},
            )
        self.assertEqual(len(ALL_COMPONENTS), 10)
        self.assertEqual(len(ISSUE_CODES), 25)

    def test_request_schema_enforces_frozen_bounds_and_item_types(self):
        base = {
            "contractVersion": "1",
            "requestId": "00000000-0000-0000-0000-000000000001",
            "runId": "00000000-0000-0000-0000-000000000002",
            "callSequence": 1,
            "authorizationSha256": "a" * 64,
            "toolContractSha256": "b" * 64,
        }
        object_fixture = {
            "schema": "ai_dw",
            "object": "T_EDW_VAR_PD_INFO_Q",
            "objectKind": "LOCAL_BASE_TABLE",
            "catalogIdentity": {"catalog": "PG_CLASS", "oid": "101"},
        }
        search = {"query": "ab", "searchIn": ["NAME"], "objectTypes": ["BASE_TABLE"], "pageSize": 20, "pageToken": None}
        search["schemas"] = ["ai_dw"]
        stats = {"object": object_fixture, "metrics": ["ROW_COUNT"], "columns": [], "topK": None}
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.request", {**base, **{key: value for key, value in search.items() if key != "schemas"}})
        nul_object = copy.deepcopy(object_fixture)
        nul_object["schema"] = "ai_dw\x00"
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("get_table_stats.request", {**base, **{**stats, "object": nul_object}})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.request", {**base, **search, "callSequence": 16})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.request", {**base, **search, "searchIn": []})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.request", {**base, **search, "objectTypes": []})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.request", {**base, **search, "query": "a!"})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("get_table_stats.request", {**base, **stats, "metrics": [None]})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("get_table_stats.request", {**base, **stats, "columns": [None]})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("get_table_stats.request", {**base, **stats, "topK": 0})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("sample_rows.request", {**base, "object": object_fixture, "columns": ["metric"], "limit": 11})
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("execute_readonly_sql.request", {**base, "sql": "SELECT 1", "maxRows": 101})

    def test_response_schema_enforces_frozen_semantics(self):
        request_id = "00000000-0000-0000-0000-000000000001"
        run_id = "00000000-0000-0000-0000-000000000002"
        evidence_scope = {
            "scopeSha256": "a" * 64,
            "counts": {
                "businessCatalogSchemas": 0,
                "dataObjects": 0,
                "valueColumns": 0,
                "sampleColumns": 0,
                "sqlColumns": 0,
                "statsGrants": 0,
            },
            "preview": {"businessCatalogSchemas": [], "dataObjects": [], "valueColumns": []},
        }
        preflight_data = {
            "passed": True,
            "databaseProduct": "kingbase",
            "version": "fixture",
            "identityMatches": {"database": True, "user": True, "currentSchema": True},
            "sessionReadOnly": True,
            "privilegeChecks": [
                {"check": check, "passed": True, "scope": "fixture", "detailCode": "PASS"}
                for check in PRIVILEGE_CHECKS
            ],
            "routineRisk": False,
            "timeoutsMs": {"statement": 15000, "lock": 5000, "idleInTransaction": 15000},
            "components": [
                {"name": name, "version": "fixture", "sha256": "a" * 64, "codeSignRequirement": "REQUIRED_CODE_SIGN"}
                for name in ALL_COMPONENTS
            ],
            "profileId": "fixture-profile",
            "issues": [],
        }
        invalid_preflight = build_tool_response(
            "db_preflight", "OK", request_id, run_id, evidence_scope, preflight_data
        )
        invalid_preflight["data"]["passed"] = False
        invalid_preflight["data"]["identityMatches"]["database"] = False
        invalid_preflight["data"]["privilegeChecks"][0]["passed"] = False
        invalid_preflight["data"]["routineRisk"] = True
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("db_preflight.response", invalid_preflight)

        invalid_sample = build_tool_response(
            "sample_rows",
            "OK",
            request_id,
            run_id,
            evidence_scope,
            {
                "sourceColumns": [{"schema": "ai_dw", "object": "T", "column": "metric"}],
                "rows": [[]],
                "maskingApplied": False,
            },
        )
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("sample_rows.response", invalid_sample)

        invalid_scope = build_tool_response(
            "describe_object", "OK", request_id, run_id, evidence_scope, {"objects": []}
        )
        invalid_scope["evidence"]["scope"]["counts"]["dataObjects"] = 51
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("describe_object.response", invalid_scope)
        evidence_scope["counts"]["dataObjects"] = 0

        duplicate_components = build_tool_response(
            "db_preflight", "OK", request_id, run_id, copy.deepcopy(evidence_scope), preflight_data
        )
        duplicate_components["data"]["components"] = [
            copy.deepcopy(duplicate_components["data"]["components"][0])
            for _ in range(10)
        ]
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("db_preflight.response", duplicate_components)

        truncated_preflight = build_tool_response(
            "db_preflight", "TRUNCATED", request_id, run_id, copy.deepcopy(evidence_scope), preflight_data
        )
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("db_preflight.response", truncated_preflight)

        invalid_row_count = build_tool_response(
            "get_table_stats", "OK", request_id, run_id, copy.deepcopy(evidence_scope),
            {"stats": [{
                "metric": "ROW_COUNT", "column": "metric", "value": None,
                "count": None, "approximate": True, "metadataSource": "SYSTEM_CATALOG",
            }]},
        )
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("get_table_stats.response", invalid_row_count)

        invalid_search_page = build_tool_response(
            "search_objects", "OK", request_id, run_id, copy.deepcopy(evidence_scope), {"candidates": []}
        )
        invalid_search_page["page"] = None
        with self.assertRaises(FixtureRejected):
            validate_schema_instance("search_objects.response", invalid_search_page)

    def test_describe_request_uses_name_identifier(self):
        base = {
            "contractVersion": "1",
            "requestId": "00000000-0000-0000-0000-000000000001",
            "runId": "00000000-0000-0000-0000-000000000002",
            "callSequence": 1,
            "authorizationSha256": "a" * 64,
            "toolContractSha256": "b" * 64,
        }
        self.assertTrue(validate_schema_instance(
            "describe_object.request",
            {
                **base,
                "objects": [{"schema": "ai_dw", "object": "T_EDW_VAR_PD_INFO_Q"}],
            },
        ))

    def test_each_tool_response_rejects_untyped_empty_data(self):
        response = {
            "contractVersion": "1",
            "requestId": "00000000-0000-0000-0000-000000000001",
            "runId": "00000000-0000-0000-0000-000000000002",
            "status": "OK",
            "truncated": False,
            "data": {},
            "page": None,
            "evidence": {
                "toolName": "db_preflight",
                "profileId": "fixture-profile",
                "scope": {
                    "scopeSha256": "a" * 64,
                    "counts": {
                        "businessCatalogSchemas": 0, "dataObjects": 0, "valueColumns": 0,
                        "sampleColumns": 0, "sqlColumns": 0, "statsGrants": 0,
                    },
                    "preview": {"businessCatalogSchemas": [], "dataObjects": [], "valueColumns": []},
                },
                "executedAt": "1970-01-01T00:00:00Z",
                "durationMs": 0,
                "rowsReturned": 0,
                "serializedBytes": 0,
                "queryFingerprint": "0" * 64,
                "databaseTouched": False,
            },
            "issues": [],
        }
        for tool in TOOL_NAMES:
            with self.subTest(tool=tool):
                response["evidence"]["toolName"] = tool
                with self.assertRaises(FixtureRejected):
                    validate_schema_instance(tool + ".response", response)

    def test_gateway_error_has_no_evidence_and_tool_response_has_evidence(self):
        error = build_gateway_error("AUTH_REQUIRED", None, None)
        self.assertNotIn("evidence", error)
        validate_response_contract("gateway-error-v1", error)
        response = build_tool_response(
            "describe_object",
            "OK",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            {
                "scopeSha256": "a" * 64,
                "counts": {
                    "businessCatalogSchemas": 0,
                    "dataObjects": 0,
                    "valueColumns": 0,
                    "sampleColumns": 0,
                    "sqlColumns": 0,
                    "statsGrants": 0,
                },
                "preview": {
                    "businessCatalogSchemas": [],
                    "dataObjects": [],
                    "valueColumns": [],
                },
            },
            {"objects": []},
        )
        validate_response_contract("describe_object.response", response)
        with self.assertRaises(FixtureRejected):
            broken = copy.deepcopy(response)
            broken["truncated"] = True
            broken["data"] = None
            validate_response_contract("describe_object.response", broken)
        with self.assertRaises(FixtureRejected):
            build_tool_response(
                "describe_object",
                "OK",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000002",
                response["evidence"]["scope"],
                {"rows": ["x" * 40_000]},
            )

    def test_compact_scope_preview_is_closed_and_bounded(self):
        response = build_tool_response(
            "describe_object",
            "OK",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            {
                "scopeSha256": "a" * 64,
                "counts": {
                    "businessCatalogSchemas": 0,
                    "dataObjects": 0,
                    "valueColumns": 0,
                    "sampleColumns": 0,
                    "sqlColumns": 0,
                    "statsGrants": 0,
                },
                "preview": {"businessCatalogSchemas": [], "dataObjects": [], "valueColumns": []},
            },
            {"rows": []},
        )
        broken = copy.deepcopy(response)
        broken["evidence"]["scope"]["preview"]["valueColumns"] = [
            {"schema": "ai_dw", "object": "t", "column": "x", "secret": "leak"}
        ]
        broken["evidence"]["serializedBytes"] = len(canon(broken))
        with self.assertRaises(FixtureRejected):
            validate_response_contract("describe_object.response", broken)

    def test_page_token_binds_session_query_and_last_disclosed_candidate(self):
        context = {
            "authorizationSha256": "a" * 64,
            "runId": "00000000-0000-0000-0000-000000000002",
            "gatewaySessionNonce": "N" * 43,
            "toolName": "search_objects",
            "queryFingerprint": "b" * 64,
        }
        candidates = [
            {"schema": "s", "object": f"t-{i:02d}", "objectType": "BASE_TABLE"}
            for i in range(25)
        ]
        page, token = paginate_candidates(candidates, 20, None, context, now_ms=1)
        self.assertEqual(len(page), 20)
        self.assertIsNotNone(token)
        decoded = verify_page_token(token, context, now_ms=1)
        self.assertEqual(decoded["lastKey"], ["s", "t-19", "BASE_TABLE"])
        with self.assertRaises(FixtureRejected):
            verify_page_token(token, {**context, "runId": "00000000-0000-0000-0000-000000000003"}, now_ms=1)
        with self.assertRaises(FixtureRejected):
            paginate_candidates(candidates, 20, token, context, now_ms=60_001)
        with self.assertRaises(FixtureRejected):
            paginate_candidates(candidates[:-1], 20, token, context, now_ms=1)

    def test_page_token_rejects_tampering_and_unknown_last_key(self):
        context = {
            "authorizationSha256": "a" * 64,
            "runId": "00000000-0000-0000-0000-000000000002",
            "gatewaySessionNonce": "N" * 43,
            "toolName": "search_objects",
            "queryFingerprint": "b" * 64,
        }
        candidates = [
            {"schema": "s", "object": f"t-{i:02d}", "objectType": "BASE_TABLE"}
            for i in range(25)
        ]
        _, token = paginate_candidates(candidates, 20, None, context, now_ms=1)
        decoded = json.loads(base64.urlsafe_b64decode(token + "===").decode("utf-8"))
        if "payload" in decoded:
            decoded["payload"]["lastKey"] = ["s", "t-99", "BASE_TABLE"]
        else:
            decoded["lastKey"] = ["s", "t-99", "BASE_TABLE"]
        tampered = base64.urlsafe_b64encode(json.dumps(decoded, separators=(",", ":")).encode()).decode().rstrip("=")
        with self.assertRaises(FixtureRejected):
            verify_page_token(tampered, context, now_ms=1)
        with self.assertRaises(FixtureRejected):
            verify_page_token("a", context, now_ms=1)

        unknown = issue_page_token(context, ["s", "missing", "BASE_TABLE"], 2, 60_000, candidate_count=25)
        with self.assertRaises(FixtureRejected):
            paginate_candidates(candidates, 20, unknown, context, now_ms=1)

        too_many = [
            {"schema": "s", "object": f"t-{i:02d}", "objectType": "BASE_TABLE"}
            for i in range(61)
        ]
        with self.assertRaises(FixtureRejected):
            paginate_candidates(too_many, 20, None, context, now_ms=1)

        epoch_now = 1_700_000_000_000
        _, epoch_token = paginate_candidates(candidates, 20, None, context, now_ms=epoch_now)
        self.assertIsNotNone(epoch_token)
        verify_page_token(epoch_token, context, now_ms=epoch_now)

    def test_hidden_fixture_and_tool_surface_do_not_leak_known_workbench_names(self):
        fixture = hidden_discovery_fixture(seed=7)
        self.assertNotIn("ai_dw", fixture["problem"])
        self.assertNotIn("T_EDW_VAR_PD_INFO_Q", repr(fixture))
        self.assertEqual(set(tool_surface()["enabled"]), set(TOOL_NAMES))
        self.assertIn("postgres-execute-sql", tool_surface()["disabled"])


if __name__ == "__main__":
    unittest.main()
