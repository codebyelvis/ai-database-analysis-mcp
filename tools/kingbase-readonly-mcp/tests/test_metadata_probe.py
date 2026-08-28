import copy
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from credentials import Secret  # noqa: E402
import metadata_contract  # noqa: E402
import metadata_probe  # noqa: E402
from psql_runner import PsqlResult, QueryFailed  # noqa: E402
from test_metadata_contract import valid_metadata  # noqa: E402


PRIVATE_COLUMNS = ("CRT_TIME", "UPDT_TIME", "MEMO")
VALID_DECODER_CANDIDATES = [
    {
        "schema": "pg_catalog",
        "name": "decoding",
        "argumentTypes": [
            {"schema": "pg_catalog", "name": "text"},
            {"schema": "pg_catalog", "name": "text"},
        ],
        "resultType": {"schema": "pg_catalog", "name": "bytea"},
        "routineKind": "f",
        "returnsSet": False,
    },
    {
        "schema": "pg_catalog",
        "name": "convert_from",
        "argumentTypes": [
            {"schema": "pg_catalog", "name": "bytea"},
            {"schema": "pg_catalog", "name": "name"},
        ],
        "resultType": {"schema": "pg_catalog", "name": "text"},
        "routineKind": "f",
        "returnsSet": False,
    },
]
AMBIGUOUS_OR_MISSING_CANDIDATES = VALID_DECODER_CANDIDATES + [
    {
        "schema": "sys",
        "name": "decoding",
        "argumentTypes": [
            {"schema": "sys", "name": "text"},
            {"schema": "sys", "name": "text"},
        ],
        "resultType": {"schema": "sys", "name": "bytea"},
        "routineKind": "f",
        "returnsSet": False,
    }
]


def bound_snapshot():
    cls = getattr(metadata_contract, "BoundSnapshot", None)
    if cls is None:
        raise AssertionError("BoundSnapshot is not implemented")
    return cls.from_value(metadata_contract.freeze_snapshot(valid_metadata()))


def run_capability_cli(candidates):
    password_calls = []
    executor_calls = []

    def password_reader():
        password_calls.append(True)
        return Secret("x")

    def executor(plan, secret):
        executor_calls.append((plan, secret))
        return PsqlResult({"functionCandidates": candidates}, None, None)

    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = metadata_probe.main(
            ["--profile", "ai_app_industry_test_ro", "--decoder-capability"],
            password_reader=password_reader,
            executor=executor,
        )
    return (
        code,
        stdout.getvalue(),
        stderr.getvalue(),
        len(password_calls),
        len(executor_calls),
    )


class MetadataProbePlanTest(unittest.TestCase):
    def test_probe_checks_target_kingbase_session_before_metadata(self):
        sql = metadata_probe.METADATA_PROBE_SQL
        self.assertIn("pg_catalog.current_setting('search_path') = 'ai_dw'", sql)
        self.assertIn("pg_catalog.current_schema() = 'ai_dw'", sql)
        self.assertIn(
            "pg_catalog.current_schemas(false) = ARRAY['ai_dw']::name[]",
            sql,
        )
        self.assertIn(
            "pg_catalog.current_schemas(true) = "
            "ARRAY['sys','pg_catalog','sys_catalog','ai_dw']::name[]",
            sql,
        )
        self.assertNotIn("(pg_catalog.current_schemas(true))[1]", sql)
        for schema_name in ("sys", "pg_catalog", "sys_catalog"):
            self.assertIn(
                "NOT pg_catalog.has_schema_privilege(current_user, "
                f"'{schema_name}', 'CREATE')",
                sql,
            )
        self.assertLess(sql.index("current_schemas(true)"), sql.index("information_schema.columns"))

    def test_probe_discovers_ordered_primary_keys_from_catalogs(self):
        sql = metadata_probe.METADATA_PROBE_SQL
        self.assertIn("pg_catalog.pg_index", sql)
        self.assertIn("pg_catalog.pg_attribute", sql)
        self.assertIn("WITH ORDINALITY", sql)
        self.assertNotIn("'keyColumns', json_build_array('PD_ID')", sql)
        self.assertNotIn(
            "'keyColumns', json_build_array('PD_ID', 'TERT_IDTY_ID')",
            sql,
        )

    def test_probe_never_value_reads_private_columns(self):
        sql = metadata_probe.METADATA_PROBE_SQL
        for name in PRIVATE_COLUMNS:
            self.assertNotIn(f'"{name}"', sql)
        self.assertNotIn("KBRM1_BUSINESS_V1", sql)

    def test_parser_has_runtime_guard_mode(self):
        args = metadata_probe._parser().parse_args(
            [
                "--profile",
                "ai_app_industry_test_ro",
                "--runtime-guard",
                str(metadata_probe.SNAPSHOT_PATH),
            ]
        )
        self.assertEqual(Path(args.runtime_guard), metadata_probe.SNAPSHOT_PATH)


class DecoderCapabilityTest(unittest.TestCase):
    def test_decoder_capability_plan_queries_only_system_function_metadata(self):
        sql = metadata_probe.DECODER_CAPABILITY_V1.sql
        self.assertIn("FROM pg_catalog.pg_proc p", sql)
        self.assertIn("JOIN pg_catalog.pg_namespace n", sql)
        self.assertIn("JOIN pg_catalog.pg_type result_type", sql)
        self.assertIn(
            "JOIN pg_catalog.pg_namespace argument_type_namespace",
            sql,
        )
        self.assertIn(
            "JOIN pg_catalog.pg_namespace result_type_namespace",
            sql,
        )
        self.assertIn("p.prokind::text AS routine_kind", sql)
        self.assertIn("p.proretset::boolean AS returns_set", sql)
        self.assertIn("BEGIN READ ONLY;", sql)
        self.assertIn("\\if :kb_session_ok", sql)
        self.assertEqual(sql.count("KBRM1_PREFLIGHT_OK|"), 1)
        self.assertEqual(sql.count("KBRM1_READ_ONLY_REQUIRED"), 1)
        self.assertNotIn('ONLY ai_dw."', sql)
        self.assertNotIn("KBRM1_BUSINESS_V1", sql)
        for name in (
            "T_EDW_VAR_PD_INFO_Q",
            "T_EDW_VAR_PD_IDTY_RELA_Q",
            "T_EDW_VAR_HCZQ_IDTY_CLAS_Q",
        ):
            self.assertNotIn(name, sql)

    def test_decoder_capability_requires_unique_protected_signatures(self):
        capability = metadata_probe.validate_decoder_capability(
            VALID_DECODER_CANDIDATES
        )
        self.assertEqual(capability.decoder_schema, "pg_catalog")
        self.assertEqual(capability.convert_from_schema, "pg_catalog")
        with self.assertRaises(metadata_contract.MetadataMismatch):
            metadata_probe.validate_decoder_capability(
                AMBIGUOUS_OR_MISSING_CANDIDATES
            )
        with self.assertRaises(metadata_contract.MetadataMismatch):
            metadata_probe.validate_decoder_capability(
                VALID_DECODER_CANDIDATES[:1]
            )

    def test_decoder_capability_rejects_shadow_and_unprotected_type_namespaces(self):
        shadow = copy.deepcopy(VALID_DECODER_CANDIDATES)
        shadow.append(
            {
                **copy.deepcopy(VALID_DECODER_CANDIDATES[0]),
                "schema": "ai_dw",
            }
        )
        application_argument_type = copy.deepcopy(VALID_DECODER_CANDIDATES)
        application_argument_type[0]["argumentTypes"][0]["schema"] = "ai_dw"
        application_result_type = copy.deepcopy(VALID_DECODER_CANDIDATES)
        application_result_type[1]["resultType"]["schema"] = "ai_dw"
        for candidates in (
            shadow,
            application_argument_type,
            application_result_type,
        ):
            with self.subTest(candidates=candidates):
                with self.assertRaises(metadata_contract.MetadataMismatch):
                    metadata_probe.validate_decoder_capability(candidates)

    def test_decoder_capability_rejects_wrong_signature_kind_or_set_return(self):
        mutations = []
        for key, value in (
            ("routineKind", "p"),
            ("routineKind", "a"),
            ("routineKind", "w"),
            ("routineKind", "P"),
            ("returnsSet", True),
        ):
            candidates = copy.deepcopy(VALID_DECODER_CANDIDATES)
            candidates[0][key] = value
            mutations.append(candidates)
        wrong_argument = copy.deepcopy(VALID_DECODER_CANDIDATES)
        wrong_argument[0]["argumentTypes"][1]["name"] = "name"
        mutations.append(wrong_argument)
        wrong_result = copy.deepcopy(VALID_DECODER_CANDIDATES)
        wrong_result[1]["resultType"]["name"] = "bytea"
        mutations.append(wrong_result)
        for candidates in mutations:
            with self.subTest(candidates=candidates):
                with self.assertRaises(metadata_contract.MetadataMismatch):
                    metadata_probe.validate_decoder_capability(candidates)

    def test_decoder_capability_rejects_legacy_decode_signature(self):
        legacy = copy.deepcopy(VALID_DECODER_CANDIDATES)
        legacy.append(
            {
                **copy.deepcopy(VALID_DECODER_CANDIDATES[0]),
                "name": "decode",
            }
        )
        with self.assertRaises(metadata_contract.MetadataMismatch):
            metadata_probe.validate_decoder_capability(legacy)

    def test_decoder_capability_rejects_malformed_extra_and_unsafe_fields(self):
        extra_field = copy.deepcopy(VALID_DECODER_CANDIDATES)
        extra_field[0]["owner"] = "private-owner"
        malformed_type = copy.deepcopy(VALID_DECODER_CANDIDATES)
        malformed_type[0]["argumentTypes"][0] = "pg_catalog.text"
        unsafe_c0 = copy.deepcopy(VALID_DECODER_CANDIDATES)
        unsafe_c0[0]["schema"] = "pg_catalog\x00"
        unsafe_c1 = copy.deepcopy(VALID_DECODER_CANDIDATES)
        unsafe_c1[0]["name"] = "decoding\x85"
        for candidates in (
            extra_field,
            malformed_type,
            unsafe_c0,
            unsafe_c1,
        ):
            with self.subTest(candidates=candidates):
                with self.assertRaises(metadata_contract.MetadataMismatch):
                    metadata_probe.validate_decoder_capability(candidates)

    def test_decoder_capability_cli_uses_one_keychain_read_and_one_psql_call(self):
        code, stdout, stderr, password_calls, executor_calls = run_capability_cli(
            VALID_DECODER_CANDIDATES
        )
        self.assertEqual((code, password_calls, executor_calls), (0, 1, 1))
        self.assertEqual(
            stdout,
            "DECODER_CAPABILITY_OK decoderSchema=pg_catalog "
            "convertFromSchema=pg_catalog legacyDecodeTextTextBytea=0\n",
        )
        self.assertEqual(stderr, "")

    def test_decoder_capability_cli_failures_are_sanitized_without_retry(self):
        unsafe = copy.deepcopy(VALID_DECODER_CANDIDATES)
        unsafe[0]["schema"] = "ai_dw\x85private-identity"
        code, stdout, stderr, password_calls, executor_calls = run_capability_cli(
            unsafe
        )
        self.assertEqual((code, password_calls, executor_calls), (5, 1, 1))
        self.assertEqual(stdout, "")
        self.assertEqual(stderr, "DATA_CONTRACT_MISMATCH\n")
        self.assertNotIn("private-identity", stderr)

        for result, expected_code, expected_error in (
            (PsqlResult(None, None, "READ_ONLY_REQUIRED"), 4, "READ_ONLY_REQUIRED\n"),
            (QueryFailed(), 7, "QUERY_FAILED\n"),
        ):
            calls = []

            def executor(plan, secret):
                calls.append((plan, secret))
                if isinstance(result, Exception):
                    raise result
                return result

            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()
            with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                code = metadata_probe.main(
                    [
                        "--profile",
                        "ai_app_industry_test_ro",
                        "--decoder-capability",
                    ],
                    password_reader=lambda: Secret("x"),
                    executor=executor,
                )
            with self.subTest(expected_error=expected_error):
                self.assertEqual(code, expected_code)
                self.assertEqual(stdout_buffer.getvalue(), "")
                self.assertEqual(stderr_buffer.getvalue(), expected_error)
                self.assertEqual(len(calls), 1)


class RuntimeGuardTest(unittest.TestCase):
    def test_missing_or_tampered_snapshot_stops_before_keychain(self):
        password_calls = []
        psql_calls = []

        def password_reader():
            password_calls.append(True)
            return Secret("x")

        def executor(plan, secret):
            psql_calls.append((plan, secret))
            return PsqlResult(
                {
                    "dataAsOfRaw": "20260811",
                    "productCount": 1,
                    "relationCount": 1,
                    "industryCount": 1,
                    "privilegeMode": "CLIENT_ENFORCED_READ_ONLY",
                    "databasePrivilegeRisk": "WRITE_CAPABLE_ACCOUNT",
                },
                None,
                None,
            )

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            valid_code = metadata_probe.main(
                [
                    "--profile",
                    "ai_app_industry_test_ro",
                    "--runtime-guard",
                    str(metadata_probe.SNAPSHOT_PATH),
                ],
                password_reader=password_reader,
                executor=executor,
            )
        self.assertEqual(valid_code, 0)
        self.assertEqual(len(password_calls), 1)
        self.assertEqual(len(psql_calls), 1)

        original = metadata_probe.SNAPSHOT_PATH.read_bytes()
        for payload in (None, original + b" "):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "metadata_contract.json"
                if payload is not None:
                    path.write_bytes(payload)
                password_calls.clear()
                psql_calls.clear()
                with patch.object(metadata_probe, "SNAPSHOT_PATH", path):
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        code = metadata_probe.main(
                            [
                                "--profile",
                                "ai_app_industry_test_ro",
                                "--runtime-guard",
                                str(path),
                            ],
                            password_reader=password_reader,
                            executor=executor,
                        )
                with self.subTest(payload_present=payload is not None):
                    self.assertEqual(code, 5)
                    self.assertEqual(password_calls, [])
                    self.assertEqual(psql_calls, [])

    def test_runtime_guard_uses_one_secret_one_psql_and_no_business_marker(self):
        runner = getattr(metadata_probe, "run_runtime_guard", None)
        self.assertIsNotNone(runner)
        password_calls = []
        psql_calls = []

        def password_reader():
            password_calls.append(True)
            return Secret("x")

        def executor(plan, secret):
            psql_calls.append((plan, secret))
            self.assertNotIn("KBRM1_BUSINESS_V1", plan.sql)
            self.assertIn("live_columns EXCEPT ALL SELECT * FROM expected_columns", plan.sql)
            return PsqlResult(
                {
                    "dataAsOfRaw": "20260811",
                    "productCount": 1,
                    "relationCount": 1,
                    "industryCount": 1,
                    "privilegeMode": "CLIENT_ENFORCED_READ_ONLY",
                    "databasePrivilegeRisk": "WRITE_CAPABLE_ACCOUNT",
                },
                None,
                None,
            )

        runner(
            bound_snapshot(),
            password_reader=password_reader,
            executor=executor,
        )
        self.assertEqual(len(password_calls), 1)
        self.assertEqual(len(psql_calls), 1)

    def test_live_snapshot_drift_skips_business_marker(self):
        runner = getattr(metadata_probe, "run_runtime_guard", None)
        self.assertIsNotNone(runner)
        calls = []

        def executor(plan, secret):
            calls.append(plan)
            return PsqlResult(None, None, "DATA_CONTRACT_MISMATCH")

        with self.assertRaises(metadata_contract.MetadataMismatch):
            runner(
                bound_snapshot(),
                password_reader=lambda: Secret("x"),
                executor=executor,
            )
        self.assertEqual(len(calls), 1)
        self.assertNotIn("KBRM1_BUSINESS_V1", calls[0].sql)

    def test_runtime_guard_preserves_read_only_failure(self):
        runner = getattr(metadata_probe, "run_runtime_guard", None)
        self.assertIsNotNone(runner)
        read_only_error = getattr(metadata_probe, "ReadOnlyRequired", None)
        self.assertIsNotNone(read_only_error)

        with self.assertRaises(read_only_error):
            runner(
                bound_snapshot(),
                password_reader=lambda: Secret("x"),
                executor=lambda plan, secret: PsqlResult(
                    None,
                    None,
                    "READ_ONLY_REQUIRED",
                ),
            )


if __name__ == "__main__":
    unittest.main()
