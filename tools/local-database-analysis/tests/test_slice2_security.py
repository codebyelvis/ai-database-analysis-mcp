"""
作者：elvis
日期：2026-08-20
作用：验证 Slice 2 本地无数据库的批准、账本、Helper 与 evidence 边界
"""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from security_fixtures import FixtureRejected, default_capability_input, validate_ledger_snapshot
from canonical import canon
from slice2_security_fixtures import (
    ApprovalBrokerFixture,
    CommitEvidenceFixture,
    LedgerServiceFixture,
    Slice2Rejected,
    TrustedExecutionHelperFixture,
)


def _rid(sequence: int) -> str:
    """构造确定性的 requestId。"""
    return f"00000000-0000-0000-0000-{sequence:012d}"


def _candidate(run_id: str = "11111111-1111-1111-1111-111111111111") -> dict:
    """返回最小合法批准候选。"""
    return default_capability_input(run_id=run_id)


def _approved(run_id: str = "11111111-1111-1111-1111-111111111111"):
    """签发本地 fixture capability，并返回 broker 与批准结果。"""
    broker = ApprovalBrokerFixture()
    candidate = _candidate(run_id)
    approved = broker.approve(candidate, broker.ui_snapshot(candidate), now_ms=0)
    return broker, approved


def _request(approved, sequence: int, tool: str = "db_preflight", arguments=None) -> dict:
    """构造绑定 run、authorization digest 与 call sequence 的请求。"""
    return {
        "runId": approved.run_id,
        "authorizationSha256": approved.authorization_sha256,
        "requestId": _rid(sequence),
        "callSequence": sequence,
        "toolName": tool,
        "arguments": {} if arguments is None else arguments,
    }


def _response_digest(response: object) -> str:
    """计算与 fixture completion contract 相同的响应摘要。"""
    return hashlib.sha256(canon(response)).hexdigest()


def _raw_terminal_snapshot(ledger: LedgerServiceFixture) -> dict:
    """提取底层 ledger 的原始终态字段，验证终态清理不变量。"""
    inner = ledger._inner
    return {
        "state": inner.state,
        "inFlight": copy.deepcopy(inner.in_flight),
        "reservedCall": copy.deepcopy(inner.reserved_call),
        "toolboxSessionId": inner.toolbox_session_id,
        "childIdentity": copy.deepcopy(inner.child_identity),
        "preflightPassed": inner.preflight_passed,
        "queryCloseCleanupAck": inner.query_close_cleanup_ack,
        "callCount": inner.call_count,
        "reservedLaunchIdentity": None,
        "cleanup": None,
    }


class ApprovalBoundaryTest(unittest.TestCase):
    def test_user_presence_is_required_before_signature(self):
        broker = ApprovalBrokerFixture()
        candidate = _candidate()
        ui = broker.ui_snapshot(candidate)
        ui["userPresence"] = False
        with self.assertRaises(Slice2Rejected) as caught:
            broker.approve(candidate, ui, now_ms=0)
        self.assertEqual(caught.exception.code, "AUTH_USER_PRESENCE_REQUIRED")

    def test_ui_must_display_exact_scope_and_component_manifest(self):
        broker = ApprovalBrokerFixture()
        candidate = _candidate()
        ui = broker.ui_snapshot(candidate)
        ui["scope"]["businessCatalogSchemas"] = ["outside"]
        with self.assertRaises(Slice2Rejected) as caught:
            broker.approve(candidate, ui, now_ms=0)
        self.assertEqual(caught.exception.code, "AUTH_UI_SCOPE_MISMATCH")

    def test_forged_signature_and_tampered_capability_are_rejected(self):
        broker, approved = _approved()
        forged = copy.deepcopy(approved)
        forged.signature = "0" * 64
        self.assertFalse(broker.verify(forged, now_ms=1))
        forged_mapping = copy.deepcopy(approved)
        forged_mapping["signature"] = "0" * 64
        self.assertFalse(broker.verify(forged_mapping, now_ms=1))
        forged_key = copy.deepcopy(approved)
        forged_key["brokerKeyId"] = "other-broker"
        self.assertFalse(broker.verify(forged_key, now_ms=1))
        tampered = copy.deepcopy(approved)
        tampered.capability["scope"]["businessCatalogSchemas"] = ["outside"]
        self.assertFalse(broker.verify(tampered, now_ms=1))

    def test_capability_does_not_expose_fixture_signing_material(self):
        _, approved = _approved()
        serialized = repr(approved)
        self.assertNotIn("fixture_signing_material", serialized)
        self.assertNotIn("password", serialized.lower())


class LedgerAndHelperBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.broker, self.approved = _approved()
        self.ledger = LedgerServiceFixture(self.approved, now_ms=0)
        self.helper = TrustedExecutionHelperFixture(self.ledger)

    def _reserve(self):
        self.ledger.activate(now_ms=0)
        reservation = self.ledger.begin_call(_request(self.approved, 1), now_ms=1)
        self.assertEqual(reservation["kind"], "RESERVATION")
        self.assertIsNone(self.ledger.in_flight)
        return reservation

    def _preflight(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        permit = self.helper.obtain_database_permit(now_ms=3)
        self.assertEqual(self.ledger.toolbox_session["state"], "SPAWN_VERIFIED")
        self.assertEqual(self.helper.connect(permit), "CONNECTED")
        self.helper.complete_database(
            permit,
            success=True,
            preflight_passed=True,
            response_digest=_response_digest({"status": "OK"}),
            now_ms=4,
            response={"status": "OK"},
            database_touched=True,
        )
        self.assertEqual(self.ledger.database_completion_evidence["databaseTouched"], True)
        self.assertIn(permit["permitId"], self.ledger.completed_database_permit_ids)

    def test_second_run_is_rejected_while_first_live(self):
        self._reserve()
        second_broker, second = _approved("22222222-2222-2222-2222-222222222222")
        second_ledger = LedgerServiceFixture(second, registry=self.ledger.registry)
        with self.assertRaises(Slice2Rejected) as caught:
            second_ledger.activate(now_ms=2)
        self.assertEqual(caught.exception.code, "AUTH_REPLAY")

    def test_permit_is_unavailable_before_report_spawn_and_reserved_has_no_inflight(self):
        self._reserve()
        self.assertEqual(self.ledger.toolbox_session["state"], "RESERVED")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.obtain_database_permit(now_ms=2)
        self.assertEqual(caught.exception.code, "INVALID_TRANSITION")
        self.assertIsNone(self.ledger.in_flight)

    def test_report_spawn_window_and_late_success_fail_closed(self):
        self._reserve()
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.report_spawn(
                {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
                now_ms=3001,
            )
        self.assertEqual(caught.exception.code, "SPAWN_FAILED")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertFalse(self.ledger.accepts_late_spawn)

    def test_invalid_failure_payload_cannot_claim_no_external_process(self):
        self._reserve()
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.report_spawn(
                {"ok": False, "externalProcessPossible": False},
                now_ms=2,
            )
        self.assertEqual(caught.exception.code, "SPAWN_FAILED")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")

    def test_report_spawn_failure_requires_bound_scan_digest(self):
        self._reserve()
        scan = self.ledger.launch_scan_fixture()
        scan["digest"] = "0" * 64
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.report_spawn(
                {"ok": False, "externalProcessPossible": False, "launchScan": scan},
                now_ms=2,
            )
        self.assertEqual(caught.exception.code, "SPAWN_FAILED")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")

    def test_spawned_child_identity_has_bounded_pid_and_strict_timestamp(self):
        self._reserve()
        with self.assertRaises(Slice2Rejected):
            self.helper.report_spawn(
                {"ok": True, "pid": 4_194_305, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
                now_ms=2,
            )
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")

        ledger = LedgerServiceFixture(self.approved)
        helper = TrustedExecutionHelperFixture(ledger)
        ledger.activate(now_ms=0)
        ledger.begin_call(_request(self.approved, 1), now_ms=1)
        with self.assertRaises(Slice2Rejected):
            helper.report_spawn(
                {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "not-a-timeZ"},
                now_ms=2,
            )
        self.assertEqual(ledger.state, "REVOKE_PENDING_CLEANUP")

        ledger = LedgerServiceFixture(self.approved)
        helper = TrustedExecutionHelperFixture(ledger)
        ledger.activate(now_ms=0)
        ledger.begin_call(_request(self.approved, 1), now_ms=1)
        helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        self.assertEqual(
            ledger.child_identity,
            {"pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
        )

    def test_unknown_child_cleanup_requires_complete_empty_scan(self):
        self._reserve()
        self.ledger.timeout(now_ms=3001)
        command = self.ledger.recovery_command()
        incomplete = self.ledger.launch_scan_fixture(scan_complete=False)
        with self.assertRaises(Slice2Rejected):
            self.helper.ack_cleanup(command, incomplete, None)
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        evidence = self.ledger.cleanup_evidence_fixture(command)
        self.assertEqual(
            self.helper.ack_cleanup(command, self.ledger.launch_scan_fixture(), evidence),
            "REVOKED",
        )

    def test_database_cleanup_ack_consumes_inner_permit_and_validates_terminal_snapshot(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        self.helper.obtain_database_permit(now_ms=3)
        self.assertEqual(self.ledger._inner.in_flight["kind"], "DATABASE")

        self.ledger.rotate_epoch("ledger-terminal")
        command = self.ledger.recovery_command()
        evidence = self.ledger.cleanup_evidence_fixture(command)
        self.assertEqual(self.helper.ack_cleanup(command, cleanup_evidence=evidence), "REVOKED")

        self.assertIsNone(self.ledger._inner.in_flight)
        self.assertIsNone(self.ledger._inner.reserved_call)
        self.assertFalse(self.ledger._inner.query_close_cleanup_ack)
        self.assertTrue(validate_ledger_snapshot(_raw_terminal_snapshot(self.ledger)))

        invalid_audit_snapshot = _raw_terminal_snapshot(self.ledger)
        invalid_audit_snapshot["queryCloseCleanupAck"] = True
        with self.assertRaises(FixtureRejected):
            validate_ledger_snapshot(invalid_audit_snapshot)

    def test_cleanup_rejects_corrupt_reserved_call_before_terminal_transition(self):
        self._reserve()
        self.ledger.timeout(now_ms=3001)
        corrupt_reserved_call = {"kind": "CORRUPT"}
        self.ledger._inner.reserved_call = copy.deepcopy(corrupt_reserved_call)
        command = self.ledger.recovery_command()
        launch_scan = self.ledger.launch_scan_fixture()
        evidence = self.ledger.cleanup_evidence_fixture(command, launch_scan=launch_scan)

        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(command, launch_scan, evidence)
        self.assertEqual(caught.exception.code, "LEDGER_CORRUPT")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger._inner.reserved_call, corrupt_reserved_call)
        self.assertFalse(self.ledger._inner.query_close_cleanup_ack)

    def test_gateway_cannot_read_secret_or_obtain_helper_permit(self):
        self._reserve()
        with self.assertRaises(Slice2Rejected) as caught:
            self.ledger.deliver_database_permit(caller="gateway", now_ms=2)
        self.assertEqual(caught.exception.code, "TRUSTED_HELPER_REQUIRED")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.read_secret()
        self.assertEqual(caught.exception.code, "CREDENTIAL_BOUNDARY")

    def test_helper_permit_binds_normalized_arguments_and_response_digest(self):
        self._preflight()
        request = _request(self.approved, 2, tool="describe_object", arguments={"objects": []})
        self.ledger.begin_call(request, now_ms=5)
        permit = self.helper.obtain_database_permit(now_ms=6)
        self.assertEqual(permit["kind"], "DATABASE")
        self.assertNotIn("evidenceCommitId", permit)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.obtain_database_permit(now_ms=6)
        self.assertEqual(caught.exception.code, "AUTH_REPLAY")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.complete_database(
                permit,
                success=True,
                preflight_passed=None,
                response_digest="not-a-digest",
                now_ms=7,
            )
        self.assertEqual(caught.exception.code, "RESPONSE_DIGEST_INVALID")

    def test_database_completion_requires_actual_response_and_touch_evidence(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        permit = self.helper.obtain_database_permit(now_ms=3)
        self.helper.connect(permit)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.complete_database(
                permit,
                True,
                True,
                "b" * 64,
                now_ms=4,
                response={"status": "OK"},
                database_touched=True,
            )
        self.assertEqual(caught.exception.code, "RESPONSE_DIGEST_MISMATCH")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.complete_database(
                permit,
                True,
                True,
                _response_digest({"status": "OK"}),
                now_ms=4,
                response={"status": "OK"},
            )
        self.assertEqual(caught.exception.code, "DATABASE_TOUCH_EVIDENCE_REQUIRED")

    def test_second_stage_permit_rejection_keeps_known_child_for_cleanup(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        self.ledger.rotate_epoch("ledger-2")
        with self.assertRaises(Slice2Rejected):
            self.helper.obtain_database_permit(now_ms=3)
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger.child_identity["pid"], 4)

    def test_epoch_rotation_invalidates_database_permit_and_helper_view(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        permit = self.helper.obtain_database_permit(now_ms=3)
        self.ledger.rotate_epoch("ledger-rotated")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.read_secret()
        self.assertEqual(caught.exception.code, "AUTH_EXPIRED")
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.connect(permit)
        self.assertEqual(caught.exception.code, "AUTH_EXPIRED")
        self.assertIsNone(self.ledger.in_flight)

    def test_epoch_rotation_invalidates_old_recovery_command(self):
        self._reserve()
        self.ledger.timeout(now_ms=3001)
        command = self.ledger.recovery_command()
        self.ledger.rotate_epoch("ledger-rotated")
        evidence = self.ledger.cleanup_evidence_fixture(command)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(command, self.ledger.launch_scan_fixture(), evidence)
        self.assertEqual(caught.exception.code, "AUTH_REPLAY")

    def test_cleanup_command_child_identity_must_match_persistent_child(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        self.ledger.rotate_epoch("ledger-rotated")
        command = self.ledger.recovery_command()
        self.ledger._spawned_child_identity["startedAt"] = "1970-01-01T00:00:02Z"
        evidence = self.ledger.cleanup_evidence_fixture(command)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(command, cleanup_evidence=evidence)
        self.assertEqual(caught.exception.code, "OBJECT_DRIFT")

    def test_cleanup_rejects_ledger_child_identity_drift(self):
        self._reserve()
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        self.ledger.rotate_epoch("ledger-rotated")
        command = self.ledger.recovery_command()
        self.ledger._inner.child_identity["audit"] = "b" * 64
        evidence = self.ledger.cleanup_evidence_fixture(command)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(command, cleanup_evidence=evidence)
        self.assertEqual(caught.exception.code, "OBJECT_DRIFT")

    def test_cleanup_evidence_binds_session_launch_and_child_resources(self):
        def build_cleanup(ledger, helper, pid, audit):
            ledger.activate(now_ms=0)
            ledger.begin_call(_request(self.approved, 1), now_ms=1)
            helper.report_spawn(
                {"ok": True, "pid": pid, "auditTokenSha256": audit, "startedAt": "1970-01-01T00:00:01Z"},
                now_ms=2,
            )
            ledger.rotate_epoch("ledger-rotated")
            command = ledger.recovery_command()
            return command, ledger.cleanup_evidence_fixture(command)

        command_a, evidence_a = build_cleanup(self.ledger, self.helper, 4, "a" * 64)
        other_ledger = LedgerServiceFixture(copy.deepcopy(self.approved))
        other_helper = TrustedExecutionHelperFixture(other_ledger)
        command_b, evidence_b = build_cleanup(other_ledger, other_helper, 5, "b" * 64)

        self.assertNotEqual(command_a["toolboxChildIdentity"], command_b["toolboxChildIdentity"])
        self.assertNotEqual(evidence_a, evidence_b)
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(command_a, cleanup_evidence=evidence_b)
        self.assertEqual(caught.exception.code, "LEDGER_CORRUPT")

    def test_approved_capability_update_keeps_single_canonical_mapping(self):
        broker, approved = _approved()
        forged = copy.deepcopy(approved)
        forged.update({"scope": {"businessCatalogSchemas": ["outside"]}})
        self.assertEqual(dict(forged)["scope"], forged.to_capability()["scope"])
        self.assertFalse(broker.verify(forged, now_ms=1))

        bypass = copy.deepcopy(approved)
        dict.update(bypass, {"scope": {"businessCatalogSchemas": ["outside"]}})
        self.assertFalse(broker.verify(bypass, now_ms=1))

    def test_second_stage_expiry_rejection_keeps_known_child_for_cleanup(self):
        broker = ApprovalBrokerFixture()
        candidate = _candidate("33333333-3333-3333-3333-333333333333")
        candidate["expiresAt"] = 4000
        approved = broker.approve(candidate, broker.ui_snapshot(candidate), now_ms=0)
        ledger = LedgerServiceFixture(approved, now_ms=0)
        helper = TrustedExecutionHelperFixture(ledger)
        ledger.activate(now_ms=0)
        ledger.begin_call(_request(approved, 1), now_ms=1)
        helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        with self.assertRaises(Slice2Rejected) as caught:
            helper.obtain_database_permit(now_ms=3)
        self.assertEqual(caught.exception.code, "AUTH_EXPIRED")
        self.assertEqual(ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(ledger.child_identity["pid"], 4)

    def test_recovery_command_rotation_invalidates_old_command(self):
        self._reserve()
        self.ledger.timeout(now_ms=3001)
        first = self.ledger.recovery_command()
        second = self.ledger.recovery_command()
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(None)
        self.assertEqual(caught.exception.code, "INVALID_REQUEST")
        self.assertNotEqual(first["recoveryExecutionSessionId"], second["recoveryExecutionSessionId"])
        with self.assertRaises(Slice2Rejected) as caught:
            self.helper.ack_cleanup(first)
        self.assertEqual(caught.exception.code, "AUTH_REPLAY")


class EvidenceBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.broker, self.approved = _approved()
        self.ledger = LedgerServiceFixture(self.approved, now_ms=0)
        self.helper = TrustedExecutionHelperFixture(self.ledger)
        self.committer = CommitEvidenceFixture(self.ledger)

    def _close_query(self, call_count: int = 15):
        self.ledger.activate(now_ms=0)
        self.ledger.begin_call(_request(self.approved, 1), now_ms=1)
        self.helper.report_spawn(
            {"ok": True, "pid": 4, "auditTokenSha256": "a" * 64, "startedAt": "1970-01-01T00:00:01Z"},
            now_ms=2,
        )
        preflight = self.helper.obtain_database_permit(now_ms=3)
        self.helper.connect(preflight)
        preflight_response = {"status": "OK"}
        self.helper.complete_database(
            preflight,
            True,
            True,
            _response_digest(preflight_response),
            now_ms=4,
            response=preflight_response,
            database_touched=True,
        )
        for sequence in range(2, call_count + 1):
            self.ledger.begin_call(
                _request(self.approved, sequence, tool="describe_object", arguments={"objects": []}),
                now_ms=sequence + 4,
            )
            permit = self.helper.obtain_database_permit(now_ms=sequence + 5)
            self.helper.connect(permit)
            response = {"status": "OK", "sequence": sequence}
            self.helper.complete_database(
                permit,
                True,
                None,
                _response_digest(response),
                now_ms=sequence + 6,
                response=response,
                database_touched=True,
            )
        if call_count < 15:
            self.ledger.close_query()
        self.assertEqual(self.ledger.state, "QUERY_CLOSED")
        self.helper.ack_query_close()

    def test_evidence_permit_is_independent_and_variant_fields_do_not_mix(self):
        self._close_query(call_count=1)
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        manifest = self.ledger._content_manifest(contents)
        self.assertIsInstance(manifest[0]["byteLength"], str)
        self.assertEqual(manifest[0]["byteLength"], str(len(contents[targets[0]["path"]])))
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        self.assertEqual(permit["kind"], "EVIDENCE")
        self.assertNotIn("requestId", permit)
        self.assertNotIn("toolName", permit)
        self.assertNotIn("toolboxChildIdentity", permit)
        self.committer.complete(permit, contents, now_ms=101)
        self.assertEqual(self.ledger.state, "CLOSED")
        self.assertTrue(validate_ledger_snapshot(_raw_terminal_snapshot(self.ledger)))

    def test_evidence_target_and_content_manifest_are_bound(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        altered = copy.deepcopy(targets)
        altered[0]["path"] = "outside.md"
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.obtain_permit(altered, contents, now_ms=100)
        self.assertEqual(caught.exception.code, "AUTH_SCOPE_MISMATCH")

    def test_evidence_size_and_dlp_fail_before_permit(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.obtain_permit(targets, {targets[0]["path"]: b"x" * 65537}, now_ms=100)
        self.assertEqual(caught.exception.code, "EVIDENCE_TOO_LARGE")
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.obtain_permit(targets, {targets[0]["path"]: b"password=never\n"}, now_ms=100)
        self.assertEqual(caught.exception.code, "CREDENTIAL_BOUNDARY")

    def test_gateway_cannot_directly_commit_evidence(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        with self.assertRaises(Slice2Rejected) as caught:
            self.ledger.deliver_evidence_permit(targets, contents, now_ms=100, caller="gateway")
        self.assertEqual(caught.exception.code, "COMMIT_EVIDENCE_REQUIRED")

    def test_commit_failure_enters_evidence_rollback_and_requires_commit_ack(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.complete(
                permit,
                {targets[0]["path"]: b"password=never\n"},
                now_ms=101,
            )
        self.assertEqual(caught.exception.code, "CREDENTIAL_BOUNDARY")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        command = self.ledger.recovery_command()
        self.assertEqual(command["cleanupKind"], "EVIDENCE_ROLLBACK")
        self.assertEqual(
            self.committer.ack_cleanup(command, self.ledger.cleanup_evidence_fixture(command)),
            "REVOKED",
        )

    def test_epoch_rotation_preserves_evidence_wal_rollback_cleanup(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        wal_id = permit["evidenceWalId"]

        self.assertEqual(self.ledger.rotate_epoch("ledger-rotated"), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger._cleanup_kind, "EVIDENCE_ROLLBACK")
        self.assertEqual(self.ledger._cleanup_evidence_wal_id, wal_id)
        command = self.ledger.recovery_command()
        self.assertEqual(command["cleanupKind"], "EVIDENCE_ROLLBACK")
        self.assertEqual(command["evidenceWalId"], wal_id)
        self.assertEqual(
            self.committer.ack_cleanup(command, self.ledger.cleanup_evidence_fixture(command)),
            "REVOKED",
        )

    def test_repeated_epoch_rotation_preserves_evidence_rollback_cleanup(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        wal_id = permit["evidenceWalId"]

        self.assertEqual(self.ledger.rotate_epoch("ledger-first"), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger.rotate_epoch("ledger-second"), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger._cleanup_kind, "EVIDENCE_ROLLBACK")
        self.assertEqual(self.ledger._cleanup_evidence_wal_id, wal_id)
        command = self.ledger.recovery_command()
        self.assertEqual(command["cleanupKind"], "EVIDENCE_ROLLBACK")
        self.assertEqual(command["evidenceWalId"], wal_id)

    def test_failed_evidence_rollback_survives_epoch_rotation(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        wal_id = permit["evidenceWalId"]
        self.assertEqual(self.committer.abort(permit, now_ms=101), "REVOKE_PENDING_CLEANUP")

        self.assertEqual(self.ledger.rotate_epoch("ledger-after-abort"), "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger._cleanup_kind, "EVIDENCE_ROLLBACK")
        self.assertEqual(self.ledger._cleanup_evidence_wal_id, wal_id)
        command = self.ledger.recovery_command()
        self.assertEqual(command["cleanupKind"], "EVIDENCE_ROLLBACK")
        self.assertEqual(command["evidenceWalId"], wal_id)

    def test_evidence_cleanup_ack_consumes_inner_permit_and_validates_terminal_snapshot(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        self.assertEqual(self.ledger._inner.in_flight["kind"], "EVIDENCE")

        self.ledger.rotate_epoch("ledger-evidence-terminal")
        command = self.ledger.recovery_command()
        evidence = self.ledger.cleanup_evidence_fixture(command)
        self.assertEqual(
            self.committer.ack_cleanup(command, evidence),
            "REVOKED",
        )

        self.assertIsNone(self.ledger._inner.in_flight)
        self.assertIsNone(self.ledger._inner.reserved_call)
        self.assertTrue(validate_ledger_snapshot(_raw_terminal_snapshot(self.ledger)))

    def test_evidence_wal_id_is_canonical_and_wrong_cleanup_wal_is_rejected(self):
        self._close_query()
        targets = copy.deepcopy(self.approved.capability["evidenceTargets"])
        contents = {targets[0]["path"]: b"verified fixture\n"}
        permit = self.committer.obtain_permit(targets, contents, now_ms=100)
        inner_wal_id = self.ledger._inner.in_flight["evidenceWalId"]
        self.assertEqual(permit["evidenceWalId"], inner_wal_id)
        self.assertEqual(self.ledger._evidence_permit_inner["evidenceWalId"], inner_wal_id)

        self.ledger.rotate_epoch("ledger-canonical-wal")
        command = self.ledger.recovery_command()
        self.assertEqual(command["evidenceWalId"], inner_wal_id)
        evidence = self.ledger.cleanup_evidence_fixture(command)

        self.ledger._inner.in_flight["evidenceWalId"] = "00000000-0000-0000-0000-000000000098"
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.ack_cleanup(command, evidence)
        self.assertEqual(caught.exception.code, "LEDGER_CORRUPT")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        self.ledger._inner.in_flight["evidenceWalId"] = inner_wal_id

        self.ledger._cleanup_evidence_wal_id = "00000000-0000-0000-0000-000000000099"
        with self.assertRaises(Slice2Rejected) as caught:
            self.committer.ack_cleanup(command, evidence)
        self.assertEqual(caught.exception.code, "LEDGER_CORRUPT")
        self.assertEqual(self.ledger.state, "REVOKE_PENDING_CLEANUP")
        self.assertEqual(self.ledger._inner.in_flight["evidenceWalId"], inner_wal_id)

        self.ledger._cleanup_evidence_wal_id = inner_wal_id
        self.assertEqual(self.committer.ack_cleanup(command, evidence), "REVOKED")


if __name__ == "__main__":
    unittest.main()
