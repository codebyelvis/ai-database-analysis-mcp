import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from credentials import Secret  # noqa: E402
import metadata_contract  # noqa: E402
import psql_runner  # noqa: E402
from psql_runner import (  # noqa: E402
    BoundedCompleted,
    OutputLimitExceeded,
    QueryFailed,
    ResultTooLarge,
    bounded_run,
    enforce_public_response_cap,
    run_psql,
)
import sql_templates  # noqa: E402
from test_metadata_contract import valid_metadata  # noqa: E402


VALID_STDOUT = (
    b'KBRM1_PREFLIGHT_OK|{"dataAsOfRaw":"20260811","productCount":1,'
    b'"relationCount":1,"industryCount":1,"privilegeMode":'
    b'"CLIENT_ENFORCED_READ_ONLY","databasePrivilegeRisk":'
    b'"WRITE_CAPABLE_ACCOUNT"}\n'
)
PSQL_BINARY = "/opt/homebrew/Cellar/postgresql@17/17.7_1/bin/psql"


class RecordingRun:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def preflight_plan():
    cls = getattr(metadata_contract, "BoundSnapshot", None)
    if cls is None:
        raise AssertionError("BoundSnapshot is not implemented")
    snapshot = cls.from_value(metadata_contract.freeze_snapshot(valid_metadata()))
    builder = getattr(sql_templates, "build_preflight_plan", None)
    if builder is None:
        raise AssertionError("build_preflight_plan is not implemented")
    return builder(snapshot)


class PsqlRunnerTest(unittest.TestCase):
    def test_psql_spawned_once(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        result = run_psql(preflight_plan(), Secret("s3cr3t"), run=run)
        self.assertEqual(len(run.calls), 1)
        self.assertIsNone(result.error_code)
        self.assertEqual(result.preflight["dataAsOfRaw"], "20260811")

    def test_password_exists_only_in_child_environment(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        result = run_psql(preflight_plan(), Secret("s3cr3t"), run=run)
        args, kwargs = run.calls[0]
        self.assertEqual(kwargs["env"]["PGPASSWORD"], "s3cr3t")
        exposed = repr(args) + repr(result) + repr(kwargs["input_bytes"])
        self.assertNotIn("s3cr3t", exposed)

    def test_psql_uses_bound_absolute_binary_and_allowlisted_environment(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        with patch.dict(
            os.environ,
            {
                "HOME": "/Users/elvis",
                "PATH": "/attacker",
                "PGHOST": "attacker.invalid",
                "PGSERVICE": "attacker",
                "PGPASSFILE": "/attacker/pass",
            },
            clear=True,
        ):
            run_psql(
                preflight_plan(),
                Secret("s3cr3t"),
                run=run,
                psql_binary=PSQL_BINARY,
            )
        args, kwargs = run.calls[0]
        self.assertEqual(args[0], PSQL_BINARY)
        self.assertEqual(
            set(kwargs["env"]),
            {
                "HOME",
                "PGPASSWORD",
                "PSQL_HISTORY",
                "PGCONNECT_TIMEOUT",
                "PGOPTIONS",
                "PGAPPNAME",
            },
        )
        self.assertEqual(kwargs["env"]["HOME"], "/Users/elvis")
        self.assertNotIn("PATH", kwargs["env"])
        self.assertNotIn("PGHOST", kwargs["env"])

    def test_connect_timeout_is_five_seconds(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        run_psql(preflight_plan(), Secret("x"), run=run)
        env = run.calls[0][1]["env"]
        self.assertEqual(env["PGCONNECT_TIMEOUT"], "5")

    def test_pgoptions_freezes_read_only_string_mode_ai_dw_search_path_and_server_timeouts(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        run_psql(preflight_plan(), Secret("x"), run=run)
        env = run.calls[0][1]["env"]
        self.assertEqual(
            env["PGOPTIONS"],
            "-c default_transaction_read_only=on "
            "-c search_path=ai_dw -c standard_conforming_strings=on "
            "-c statement_timeout=15000 -c lock_timeout=3000",
        )
        self.assertEqual(env["PSQL_HISTORY"], "/dev/null")
        self.assertRegex(env["PGAPPNAME"], r"^kingbase-readonly-v1:[a-f0-9]{32}$")

    def test_parent_pgoptions_cannot_append_or_replace_fixed_settings(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        with patch.dict(
            os.environ,
            {"PGOPTIONS": "-c search_path=public,pg_catalog -c statement_timeout=0"},
        ):
            run_psql(preflight_plan(), Secret("x"), run=run)
        self.assertEqual(
            run.calls[0][1]["env"]["PGOPTIONS"],
            "-c default_transaction_read_only=on "
            "-c search_path=ai_dw -c standard_conforming_strings=on "
            "-c statement_timeout=15000 -c lock_timeout=3000",
        )

    def test_service_options_cannot_override_fixed_conninfo_options(self):
        expected = (
            "-c default_transaction_read_only=on "
            "-c search_path=ai_dw -c standard_conforming_strings=on "
            "-c statement_timeout=15000 -c lock_timeout=3000"
        )
        self.assertEqual(
            getattr(psql_runner, "FIXED_LIBPQ_OPTIONS", None),
            expected,
        )
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        with patch.dict(os.environ, {"PGOPTIONS": "-c search_path=public"}):
            run_psql(preflight_plan(), Secret("x"), run=run)
        args, kwargs = run.calls[0]
        self.assertEqual(kwargs["env"]["PGOPTIONS"], expected)
        self.assertEqual(
            args[-1],
            "service=ai_app_industry_test_ro options='" + expected + "'",
        )
        self.assertNotRegex(args[-1], r"(?:host|user|password)=")

    def test_fixed_argv_and_stdin(self):
        run = RecordingRun(BoundedCompleted(0, VALID_STDOUT, b""))
        plan = preflight_plan()
        run_psql(plan, Secret("x"), run=run)
        args, kwargs = run.calls[0]
        self.assertEqual(
            args,
            [
                PSQL_BINARY,
                "-X",
                "-w",
                "-v",
                "ON_ERROR_STOP=1",
                "--dbname",
                "service=ai_app_industry_test_ro options='"
                "-c default_transaction_read_only=on "
                "-c search_path=ai_dw -c standard_conforming_strings=on "
                "-c statement_timeout=15000 -c lock_timeout=3000'",
            ],
        )
        self.assertEqual(kwargs["input_bytes"], plan.sql.encode())
        self.assertEqual(kwargs["timeout_seconds"], 20)
        self.assertEqual(kwargs["stdout_cap"], 1_048_576)
        self.assertEqual(kwargs["stderr_cap"], 65_536)

    def test_stdout_cap_terminates_only_child(self):
        run = RecordingRun(OutputLimitExceeded("stdout"))
        with self.assertRaises(ResultTooLarge):
            run_psql(preflight_plan(), Secret("x"), run=run)
        self.assertEqual(len(run.calls), 1)

    def test_stderr_cap_is_not_published(self):
        run = RecordingRun(OutputLimitExceeded("stderr"))
        with self.assertRaises(ResultTooLarge) as caught:
            run_psql(preflight_plan(), Secret("x"), run=run)
        self.assertNotIn("stderr", str(caught.exception))
        self.assertEqual(len(run.calls), 1)

    def test_wall_timeout_terminates_without_retry(self):
        run = RecordingRun(TimeoutError("20 seconds"))
        with self.assertRaises(QueryFailed):
            run_psql(preflight_plan(), Secret("x"), run=run)
        self.assertEqual(len(run.calls), 1)

    def test_nonzero_exit_is_query_failed_without_raw_stderr(self):
        run = RecordingRun(BoundedCompleted(2, b"", b"endpoint password traceback"))
        with self.assertRaises(QueryFailed) as caught:
            run_psql(preflight_plan(), Secret("x"), run=run)
        self.assertEqual(str(caught.exception), "query failed")
        self.assertEqual(len(run.calls), 1)

    def test_read_only_and_contract_failure_markers_are_structured(self):
        for marker, code in (
            (b"KBRM1_READ_ONLY_REQUIRED\n", "READ_ONLY_REQUIRED"),
            (b"KBRM1_DATA_CONTRACT_MISMATCH\n", "DATA_CONTRACT_MISMATCH"),
        ):
            run = RecordingRun(BoundedCompleted(0, marker, b""))
            with self.subTest(marker=marker):
                result = run_psql(preflight_plan(), Secret("x"), run=run)
                self.assertEqual(result.error_code, code)

    def test_canonical_response_cap_is_utf8_bytes(self):
        enforce_public_response_cap({"value": "a"})
        with self.assertRaises(ResultTooLarge):
            enforce_public_response_cap({"value": "产" * 400_000})


class BoundedRunTest(unittest.TestCase):
    def test_incremental_capture(self):
        completed = bounded_run(
            [sys.executable, "-c", "import sys;sys.stdout.write('ok');sys.stderr.write('e')"],
            timeout_seconds=2,
            stdout_cap=16,
            stderr_cap=16,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"ok")
        self.assertEqual(completed.stderr, b"e")

    def test_actual_stdout_cap(self):
        with self.assertRaises(OutputLimitExceeded):
            bounded_run(
                [sys.executable, "-c", "print('x'*10000)"],
                timeout_seconds=2,
                stdout_cap=64,
                stderr_cap=64,
            )


if __name__ == "__main__":
    unittest.main()
