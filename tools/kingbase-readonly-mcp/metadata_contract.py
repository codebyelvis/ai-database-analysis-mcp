import copy
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from contracts import PROFILE, SCHEMA


SNAPSHOT_PATH = Path(__file__).with_name("metadata_contract.json")
BOUND_SNAPSHOT_SHA256 = "74b15e86094d6b16429f861867f72bedf3c0d2a0536abd1c96119804739d105f"


TYPE_ROLES = {
    "identifier": frozenset(
        {"varchar", "bpchar", "text", "int2", "int4", "int8", "numeric_scale_0"}
    ),
    "name": frozenset({"varchar", "bpchar", "text"}),
    "status": frozenset(
        {
            "varchar",
            "bpchar",
            "text",
            "int2",
            "int4",
            "int8",
            "numeric_scale_0",
            "bool",
        }
    ),
    "bus_date": frozenset(
        {"varchar", "bpchar", "text", "int2", "int4", "int8", "numeric_scale_0"}
    ),
}

TABLE_COLUMNS = {
    "T_EDW_VAR_PD_INFO_Q": {
        "PD_ID": "identifier",
        "YC11_PD_CD": "identifier",
        "PD_NAME": "name",
        "IS_EFF": "status",
        "BUS_DATE": "bus_date",
    },
    "T_EDW_VAR_PD_IDTY_RELA_Q": {
        "PD_ID": "identifier",
        "TERT_IDTY_ID": "identifier",
        "IS_EFF": "status",
        "BUS_DATE": "bus_date",
    },
    "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": {
        "IDTY_CLAS": "name",
        "PRI_IDTY_ID": "identifier",
        "PRI_IDTY_NAME": "name",
        "SCD_IDTY_ID": "identifier",
        "SCD_IDTY_NAME": "name",
        "TERT_IDTY_ID": "identifier",
        "TERT_IDTY_NAME": "name",
        "IS_EFF": "status",
        "BUS_DATE": "bus_date",
    },
}

TABLE_KEYS = {
    "T_EDW_VAR_PD_INFO_Q": ["PD_ID"],
    "T_EDW_VAR_PD_IDTY_RELA_Q": ["PD_ID", "TERT_IDTY_ID"],
    "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": ["TERT_IDTY_ID"],
}

PRIVATE_PHYSICAL_COLUMNS = frozenset({"CRT_TIME", "UPDT_TIME", "MEMO"})

TABLE_FIELDS = {
    "table",
    "relkind",
    "isPartition",
    "inherits",
    "keyColumns",
    "columns",
}
COLUMN_FIELDS = {
    "name",
    "ordinalPosition",
    "dataType",
    "udtName",
    "characterMaximumLength",
    "numericPrecision",
    "numericScale",
    "isNullable",
}


class MetadataMismatch(RuntimeError):
    def __str__(self) -> str:
        return "data contract mismatch"


def _fail() -> None:
    raise MetadataMismatch()


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_safe_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F for character in value)
    )


def _normalized_type(column: dict[str, Any]) -> str:
    data_type = column.get("dataType")
    udt_name = column.get("udtName")
    if (
        not isinstance(data_type, str)
        or not isinstance(udt_name, str)
        or data_type.startswith("DOMAIN:")
        or data_type in {"ARRAY", "USER-DEFINED"}
        or udt_name.startswith("_")
    ):
        _fail()
    if udt_name == "numeric":
        if column.get("numericScale") != 0:
            _fail()
        return "numeric_scale_0"
    return udt_name


def parse_bus_date(value: Any) -> str:
    if not isinstance(value, str) or len(value) != 8 or not value.isascii() or not value.isdigit():
        _fail()
    try:
        parsed = datetime.strptime(value, "%Y%m%d")
    except ValueError:
        _fail()
    if parsed.strftime("%Y%m%d") != value:
        _fail()
    return parsed.strftime("%Y-%m-%d")


def _validate_tables(tables: Any) -> None:
    if not isinstance(tables, list) or len(tables) != 3:
        _fail()
    by_name = {}
    for table in tables:
        if not isinstance(table, dict) or set(table) != TABLE_FIELDS:
            _fail()
        name = table.get("table")
        if name in by_name or name not in TABLE_COLUMNS:
            _fail()
        by_name[name] = table
        if (
            table.get("relkind") != "r"
            or table.get("isPartition") is not False
            or table.get("inherits") is not False
            or table.get("keyColumns") != TABLE_KEYS[name]
        ):
            _fail()

        columns = table.get("columns")
        if not isinstance(columns, list):
            _fail()
        expected = TABLE_COLUMNS[name]
        allowed_names = set(expected) | PRIVATE_PHYSICAL_COLUMNS
        actual_names = [column.get("name") for column in columns if isinstance(column, dict)]
        if set(actual_names) != allowed_names or len(actual_names) != len(allowed_names):
            _fail()
        ordinals = []
        for column in columns:
            if not isinstance(column, dict) or set(column) != COLUMN_FIELDS:
                _fail()
            column_name = column.get("name")
            ordinal = column.get("ordinalPosition")
            if (
                not isinstance(ordinal, int)
                or isinstance(ordinal, bool)
                or ordinal <= 0
                or column.get("isNullable") not in {"YES", "NO"}
            ):
                _fail()
            ordinals.append(ordinal)
            if column_name in expected:
                token = _normalized_type(column)
                if token not in TYPE_ROLES[expected[column_name]]:
                    _fail()
            elif not (
                _is_safe_text(column.get("dataType"))
                and _is_safe_text(column.get("udtName"))
            ):
                _fail()
            if column_name in {
                "PD_ID",
                "PRI_IDTY_ID",
                "SCD_IDTY_ID",
                "TERT_IDTY_ID",
            } and column.get("isNullable") != "NO":
                _fail()
            for field in (
                "characterMaximumLength",
                "numericPrecision",
                "numericScale",
            ):
                value = column.get(field)
                if value is not None and (
                    not isinstance(value, int) or isinstance(value, bool) or value < 0
                ):
                    _fail()
        if ordinals != sorted(ordinals) or len(ordinals) != len(set(ordinals)):
            _fail()
    if set(by_name) != set(TABLE_COLUMNS):
        _fail()


def _validate_observations(observations: Any) -> None:
    if not isinstance(observations, dict) or set(observations) != {
        "rowCounts",
        "uniqueKeyCounts",
        "emptyKeyCounts",
        "busDates",
        "orphanCounts",
    }:
        _fail()
    table_names = set(TABLE_COLUMNS)
    for field in ("rowCounts", "uniqueKeyCounts", "emptyKeyCounts", "busDates"):
        value = observations.get(field)
        if not isinstance(value, dict) or set(value) != table_names:
            _fail()
    for table in table_names:
        row_count = observations["rowCounts"][table]
        unique_count = observations["uniqueKeyCounts"][table]
        empty_count = observations["emptyKeyCounts"][table]
        if (
            not _is_nonnegative_integer(row_count)
            or not _is_nonnegative_integer(unique_count)
            or not _is_nonnegative_integer(empty_count)
            or unique_count != row_count
            or empty_count != 0
        ):
            _fail()
    dates = []
    for table in table_names:
        table_dates = observations["busDates"][table]
        if not isinstance(table_dates, list) or len(table_dates) != 1:
            _fail()
        dates.append(table_dates[0])
    normalized_dates = [parse_bus_date(value) for value in dates]
    if len(set(normalized_dates)) != 1:
        _fail()
    orphans = observations.get("orphanCounts")
    if (
        not isinstance(orphans, dict)
        or set(orphans) != {"relationToProduct", "relationToIndustry"}
        or any(value != 0 for value in orphans.values())
    ):
        _fail()


def validate_live_metadata(metadata: Any) -> None:
    if not isinstance(metadata, dict) or set(metadata) != {
        "profile",
        "schema",
        "capturedAt",
        "tables",
        "observations",
    }:
        _fail()
    if (
        metadata.get("profile") != PROFILE
        or metadata.get("schema") != SCHEMA
        or not isinstance(metadata.get("capturedAt"), str)
        or not metadata["capturedAt"]
    ):
        _fail()
    _validate_tables(metadata.get("tables"))
    _validate_observations(metadata.get("observations"))


def validate_snapshot_shape(snapshot: Any) -> None:
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "profile",
        "schema",
        "capturedAt",
        "tables",
    }:
        _fail()
    if (
        snapshot.get("profile") != PROFILE
        or snapshot.get("schema") != SCHEMA
        or not _is_safe_text(snapshot.get("capturedAt"))
    ):
        _fail()
    _validate_tables(snapshot.get("tables"))


def freeze_snapshot(metadata: Any) -> dict[str, Any]:
    validate_live_metadata(metadata)
    snapshot = copy.deepcopy(
        {
            "profile": metadata["profile"],
            "schema": metadata["schema"],
            "capturedAt": metadata["capturedAt"],
            "tables": metadata["tables"],
        }
    )
    validate_snapshot_shape(snapshot)
    return snapshot


def validate_snapshot(metadata: Any, snapshot: Any) -> None:
    validate_live_metadata(metadata)
    validate_snapshot_shape(snapshot)
    if (
        metadata["profile"] != snapshot["profile"]
        or metadata["schema"] != snapshot["schema"]
        or metadata["tables"] != snapshot["tables"]
    ):
        _fail()


def _closed_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail()
        value[key] = item
    return value


@dataclass(frozen=True)
class BoundSnapshot:
    _canonical: bytes

    @classmethod
    def from_value(cls, value: Any) -> "BoundSnapshot":
        validate_snapshot_shape(value)
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return cls(canonical)

    def as_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical)


def load_bound_snapshot(
    path: Path = SNAPSHOT_PATH,
    expected_sha256: str = BOUND_SNAPSHOT_SHA256,
) -> BoundSnapshot:
    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        _fail()
    try:
        raw = Path(path).read_bytes()
    except OSError:
        _fail()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        _fail()
    try:
        value = json.loads(raw, object_pairs_hook=_closed_json_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail()
    return BoundSnapshot.from_value(value)
