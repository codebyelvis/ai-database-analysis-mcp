import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from credentials import Secret  # noqa: E402
import metadata_contract as metadata_contract_module  # noqa: E402
from metadata_contract import (  # noqa: E402
    MetadataMismatch,
    freeze_snapshot,
    parse_bus_date,
    validate_live_metadata,
    validate_snapshot,
)
from metadata_probe import METADATA_PROBE_SQL, collect_metadata  # noqa: E402
from psql_runner import PsqlResult  # noqa: E402


TABLE_COLUMNS = {
    "T_EDW_VAR_PD_INFO_Q": (
        ("PD_ID", "identifier"),
        ("YC11_PD_CD", "identifier"),
        ("PD_NAME", "name"),
        ("IS_EFF", "status"),
        ("BUS_DATE", "bus_date"),
    ),
    "T_EDW_VAR_PD_IDTY_RELA_Q": (
        ("PD_ID", "identifier"),
        ("TERT_IDTY_ID", "identifier"),
        ("IS_EFF", "status"),
        ("BUS_DATE", "bus_date"),
    ),
    "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": (
        ("IDTY_CLAS", "name"),
        ("PRI_IDTY_ID", "identifier"),
        ("PRI_IDTY_NAME", "name"),
        ("SCD_IDTY_ID", "identifier"),
        ("SCD_IDTY_NAME", "name"),
        ("TERT_IDTY_ID", "identifier"),
        ("TERT_IDTY_NAME", "name"),
        ("IS_EFF", "status"),
        ("BUS_DATE", "bus_date"),
    ),
}

KEYS = {
    "T_EDW_VAR_PD_INFO_Q": ["PD_ID"],
    "T_EDW_VAR_PD_IDTY_RELA_Q": ["PD_ID", "TERT_IDTY_ID"],
    "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": ["TERT_IDTY_ID"],
}

PRIVATE_COLUMNS = ("CRT_TIME", "UPDT_TIME", "MEMO")


def column(name, ordinal, role):
    if role == "name":
        data_type, udt_name, length, precision, scale = (
            "character varying",
            "varchar",
            500,
            None,
            None,
        )
    elif role in {"identifier", "status", "bus_date"}:
        data_type, udt_name, length, precision, scale = (
            "character varying",
            "varchar",
            64,
            None,
            None,
        )
    elif role == "private_time":
        data_type, udt_name, length, precision, scale = (
            "timestamp without time zone",
            "timestamp",
            None,
            None,
            None,
        )
    elif role == "private_note":
        data_type, udt_name, length, precision, scale = (
            "character varying",
            "varchar",
            2000,
            None,
            None,
        )
    return {
        "name": name,
        "ordinalPosition": ordinal,
        "dataType": data_type,
        "udtName": udt_name,
        "characterMaximumLength": length,
        "numericPrecision": precision,
        "numericScale": scale,
        "isNullable": "YES" if role.startswith("private_") else "NO",
    }


def valid_metadata():
    tables = []
    for table_name, columns in TABLE_COLUMNS.items():
        tables.append(
            {
                "table": table_name,
                "relkind": "r",
                "isPartition": False,
                "inherits": False,
                "keyColumns": KEYS[table_name],
                "columns": [
                    column(name, ordinal, role)
                    for ordinal, (name, role) in enumerate(columns, 1)
                ]
                + [
                    column("CRT_TIME", len(columns) + 1, "private_time"),
                    column("UPDT_TIME", len(columns) + 2, "private_time"),
                    column("MEMO", len(columns) + 3, "private_note"),
                ],
            }
        )
    return {
        "profile": "ai_app_industry_test_ro",
        "schema": "ai_dw",
        "capturedAt": "2026-08-24T10:00:00Z",
        "tables": tables,
        "observations": {
            "rowCounts": {
                "T_EDW_VAR_PD_INFO_Q": 3,
                "T_EDW_VAR_PD_IDTY_RELA_Q": 4,
                "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": 2,
            },
            "uniqueKeyCounts": {
                "T_EDW_VAR_PD_INFO_Q": 3,
                "T_EDW_VAR_PD_IDTY_RELA_Q": 4,
                "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": 2,
            },
            "emptyKeyCounts": {
                "T_EDW_VAR_PD_INFO_Q": 0,
                "T_EDW_VAR_PD_IDTY_RELA_Q": 0,
                "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": 0,
            },
            "busDates": {
                "T_EDW_VAR_PD_INFO_Q": ["20260811"],
                "T_EDW_VAR_PD_IDTY_RELA_Q": ["20260811"],
                "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": ["20260811"],
            },
            "orphanCounts": {
                "relationToProduct": 0,
                "relationToIndustry": 0,
            },
        },
    }


class MetadataContractTest(unittest.TestCase):
    def test_bound_snapshot_sha_matches_runtime_file(self):
        expected = "74b15e86094d6b16429f861867f72bedf3c0d2a0536abd1c96119804739d105f"
        snapshot_path = ROOT / "metadata_contract.json"
        actual = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
        self.assertEqual(actual, expected)
        self.assertEqual(metadata_contract_module.BOUND_SNAPSHOT_SHA256, expected)
        source = Path(metadata_contract_module.__file__).read_text(encoding="utf-8")
        self.assertEqual(
            source.count(f'BOUND_SNAPSHOT_SHA256 = "{expected}"'),
            1,
        )
        bound = metadata_contract_module.load_bound_snapshot()
        self.assertEqual(bound.as_dict(), json.loads(snapshot_path.read_text(encoding="utf-8")))

    def test_metadata_probe_uses_kingbase_safe_text_concatenation(self):
        self.assertNotIn("||", METADATA_PROBE_SQL)
        self.assertIn("concat(", METADATA_PROBE_SQL)
        self.assertNotIn("'[]'::json", METADATA_PROBE_SQL)
        self.assertIn("json_build_array()", METADATA_PROBE_SQL)

    def test_valid_metadata_and_date(self):
        metadata = valid_metadata()
        validate_live_metadata(metadata)
        self.assertEqual(parse_bus_date("20260811"), "2026-08-11")

    def test_exact_three_private_columns_are_accepted(self):
        metadata = valid_metadata()
        validate_live_metadata(metadata)
        for table in metadata["tables"]:
            business = {name for name, _ in TABLE_COLUMNS[table["table"]]}
            actual = {column["name"] for column in table["columns"]}
            self.assertEqual(actual - business, set(PRIVATE_COLUMNS))

    def test_float_temporal_binary_json_array_domain_enum_are_rejected(self):
        forbidden = (
            ("double precision", "float8"),
            ("timestamp without time zone", "timestamp"),
            ("bytea", "bytea"),
            ("jsonb", "jsonb"),
            ("ARRAY", "_text"),
            ("DOMAIN:custom_id", "varchar"),
            ("USER-DEFINED", "custom_enum"),
        )
        for data_type, udt_name in forbidden:
            metadata = valid_metadata()
            target = metadata["tables"][0]["columns"][0]
            target["dataType"] = data_type
            target["udtName"] = udt_name
            with self.subTest(data_type=data_type), self.assertRaises(
                MetadataMismatch
            ):
                validate_live_metadata(metadata)

    def test_missing_unknown_fourth_and_case_folded_column_are_rejected(self):
        mutations = []
        missing = valid_metadata()
        missing["tables"][0]["columns"].pop()
        mutations.append(missing)
        extra = valid_metadata()
        next_ordinal = len(extra["tables"][0]["columns"]) + 1
        extra["tables"][0]["columns"].append(
            column("UNREVIEWED_EXTRA", next_ordinal, "private_note")
        )
        mutations.append(extra)
        folded = valid_metadata()
        folded["tables"][0]["columns"][-1]["name"] = "memo"
        mutations.append(folded)
        for metadata in mutations:
            with self.subTest(columns=metadata["tables"][0]["columns"]), self.assertRaises(
                MetadataMismatch
            ):
                validate_live_metadata(metadata)

    def test_nullable_stable_id_nonlocal_partition_inheritance_and_key_drift_are_rejected(self):
        mutations = []
        nullable = valid_metadata()
        nullable["tables"][0]["columns"][0]["isNullable"] = "YES"
        mutations.append(nullable)
        view = valid_metadata()
        view["tables"][0]["relkind"] = "v"
        mutations.append(view)
        partition = valid_metadata()
        partition["tables"][0]["isPartition"] = True
        mutations.append(partition)
        inherited = valid_metadata()
        inherited["tables"][0]["inherits"] = True
        mutations.append(inherited)
        key = valid_metadata()
        key["tables"][0]["keyColumns"] = ["YC11_PD_CD"]
        mutations.append(key)
        for metadata in mutations:
            with self.subTest(metadata=metadata["tables"][0]), self.assertRaises(
                MetadataMismatch
            ):
                validate_live_metadata(metadata)

    def test_duplicate_empty_bad_watermark_and_orphan_are_rejected(self):
        mutations = []
        duplicate = valid_metadata()
        duplicate["observations"]["uniqueKeyCounts"]["T_EDW_VAR_PD_INFO_Q"] = 2
        mutations.append(duplicate)
        empty = valid_metadata()
        empty["observations"]["emptyKeyCounts"]["T_EDW_VAR_PD_INFO_Q"] = 1
        mutations.append(empty)
        bad_date = valid_metadata()
        bad_date["observations"]["busDates"]["T_EDW_VAR_PD_INFO_Q"] = ["2026-08-11"]
        mutations.append(bad_date)
        cross_date = valid_metadata()
        cross_date["observations"]["busDates"]["T_EDW_VAR_PD_INFO_Q"] = ["20260810"]
        mutations.append(cross_date)
        orphan = valid_metadata()
        orphan["observations"]["orphanCounts"]["relationToIndustry"] = 1
        mutations.append(orphan)
        for metadata in mutations:
            with self.subTest(observations=metadata["observations"]), self.assertRaises(
                MetadataMismatch
            ):
                validate_live_metadata(metadata)

    def test_snapshot_is_exact_but_row_counts_are_observations(self):
        metadata = valid_metadata()
        snapshot = freeze_snapshot(metadata)
        changed_count = copy.deepcopy(metadata)
        changed_count["observations"]["rowCounts"]["T_EDW_VAR_PD_INFO_Q"] = 99
        changed_count["observations"]["uniqueKeyCounts"]["T_EDW_VAR_PD_INFO_Q"] = 99
        validate_snapshot(changed_count, snapshot)
        changed_type = copy.deepcopy(metadata)
        changed_type["tables"][0]["columns"][0]["characterMaximumLength"] = 32
        with self.assertRaises(MetadataMismatch):
            validate_snapshot(changed_type, snapshot)

    def test_any_private_snapshot_tuple_drift_is_rejected(self):
        metadata = valid_metadata()
        snapshot = freeze_snapshot(metadata)
        changes = (
            ("name", "MEMO_RENAMED"),
            ("ordinalPosition", 99),
            ("dataType", "text"),
            ("udtName", "text"),
            ("characterMaximumLength", 1),
            ("numericPrecision", 1),
            ("numericScale", 1),
            ("isNullable", "NO"),
        )
        for field, replacement in changes:
            changed = copy.deepcopy(metadata)
            changed["tables"][0]["columns"][-1][field] = replacement
            with self.subTest(field=field), self.assertRaises(MetadataMismatch):
                validate_snapshot(changed, snapshot)

    def test_snapshot_table_order_drift_is_rejected(self):
        metadata = valid_metadata()
        snapshot = freeze_snapshot(metadata)
        changed = copy.deepcopy(metadata)
        changed["tables"][0], changed["tables"][1] = (
            changed["tables"][1],
            changed["tables"][0],
        )
        with self.assertRaises(MetadataMismatch):
            validate_snapshot(changed, snapshot)

    def test_bound_snapshot_hash_and_closed_shape(self):
        self.assertTrue(hasattr(metadata_contract_module, "BoundSnapshot"))
        self.assertTrue(hasattr(metadata_contract_module, "load_bound_snapshot"))
        snapshot = freeze_snapshot(valid_metadata())
        raw = (json.dumps(snapshot, ensure_ascii=False, sort_keys=True) + "\n").encode()
        expected_sha = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata_contract.json"
            path.write_bytes(raw)
            bound = metadata_contract_module.load_bound_snapshot(path, expected_sha)
            self.assertEqual(bound.as_dict(), snapshot)
            with self.assertRaises(MetadataMismatch):
                metadata_contract_module.load_bound_snapshot(path, "0" * 64)
            path.write_bytes(raw + b" ")
            with self.assertRaises(MetadataMismatch):
                metadata_contract_module.load_bound_snapshot(path, expected_sha)

    def test_snapshot_shape_rejects_observations_and_private_values(self):
        self.assertTrue(hasattr(metadata_contract_module, "validate_snapshot_shape"))
        snapshot = freeze_snapshot(valid_metadata())
        metadata_contract_module.validate_snapshot_shape(snapshot)
        for field, value in (
            ("observations", {}),
            ("MEMO", "private value"),
            ("endpoint", "host"),
        ):
            changed = copy.deepcopy(snapshot)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(MetadataMismatch):
                metadata_contract_module.validate_snapshot_shape(changed)

    def test_metadata_probe_uses_one_secret_and_one_psql_call(self):
        metadata = valid_metadata()
        password_calls = []
        psql_calls = []

        def password_reader():
            password_calls.append(True)
            return Secret("x")

        def executor(plan, secret):
            psql_calls.append((plan, secret))
            return PsqlResult(metadata, None, None)

        actual = collect_metadata(
            password_reader=password_reader,
            executor=executor,
        )
        self.assertEqual(actual, metadata)
        self.assertEqual(len(password_calls), 1)
        self.assertEqual(len(psql_calls), 1)


if __name__ == "__main__":
    unittest.main()
