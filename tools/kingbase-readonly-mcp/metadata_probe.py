import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from contracts import PROFILE
from credentials import AuthUnavailable, read_password
from metadata_contract import (
    BoundSnapshot,
    MetadataMismatch,
    SNAPSHOT_PATH,
    load_bound_snapshot,
    validate_live_metadata,
    validate_snapshot,
)
from psql_runner import PsqlResult, QueryFailed, ResultTooLarge, run_psql
from sql_templates import PSQL_PREAMBLE, SqlPlan, build_preflight_plan


OUTPUT_PATH = Path("/tmp/kingbase-readonly-metadata.json")

METADATA_PROBE_SQL = r"""
\set QUIET 1
\pset tuples_only on
\pset format unaligned
\pset pager off
SELECT (
    pg_catalog.current_setting('transaction_read_only') = 'on'
    AND pg_catalog.current_setting('search_path') = 'ai_dw'
    AND pg_catalog.current_setting('standard_conforming_strings') = 'on'
    AND pg_catalog.current_schema() = 'ai_dw'
    AND pg_catalog.current_schemas(false) = ARRAY['ai_dw']::name[]
    AND pg_catalog.current_schemas(true) = ARRAY['sys','pg_catalog','sys_catalog','ai_dw']::name[]
    AND NOT pg_catalog.has_schema_privilege(current_user, 'sys', 'CREATE')
    AND NOT pg_catalog.has_schema_privilege(current_user, 'pg_catalog', 'CREATE')
    AND NOT pg_catalog.has_schema_privilege(current_user, 'sys_catalog', 'CREATE')
    AND pg_catalog.current_database() IS NOT NULL
    AND pg_catalog.btrim(current_user::text) <> ''
) AS ok
\gset kb_session_
\if :kb_session_ok
SELECT (
    SELECT count(*) = 3
        AND bool_and(c.relkind = 'r')
        AND bool_and(NOT c.relispartition)
        AND bool_and(NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_inherits i
            WHERE i.inhrelid = c.oid
        ))
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'ai_dw'
      AND c.relname IN (
          'T_EDW_VAR_PD_INFO_Q',
          'T_EDW_VAR_PD_IDTY_RELA_Q',
          'T_EDW_VAR_HCZQ_IDTY_CLAS_Q'
      )
) AS ok
\gset kb_contract_
\if :kb_contract_ok
BEGIN READ ONLY;
SELECT concat('KBRM1_PREFLIGHT_OK|', json_build_object(
    'profile', 'ai_app_industry_test_ro',
    'schema', 'ai_dw',
    'capturedAt', to_char(
        clock_timestamp() AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS"Z"'
    ),
    'tables', json_build_array(
        json_build_object(
            'table', 'T_EDW_VAR_PD_INFO_Q',
            'relkind', 'r',
            'isPartition', false,
            'inherits', false,
            'keyColumns', (
                SELECT coalesce(
                    json_agg(attribute.attname::text ORDER BY key_position.key_ordinal),
                    json_build_array()
                )
                FROM pg_catalog.pg_index index_row
                JOIN pg_catalog.pg_class table_row
                  ON table_row.oid = index_row.indrelid
                JOIN pg_catalog.pg_namespace namespace_row
                  ON namespace_row.oid = table_row.relnamespace
                CROSS JOIN LATERAL pg_catalog.unnest(index_row.indkey)
                  WITH ORDINALITY AS key_position(attnum, key_ordinal)
                JOIN pg_catalog.pg_attribute attribute
                  ON attribute.attrelid = table_row.oid
                 AND attribute.attnum = key_position.attnum
                WHERE namespace_row.nspname = 'ai_dw'
                  AND table_row.relname = 'T_EDW_VAR_PD_INFO_Q'
                  AND index_row.indisprimary
            ),
            'columns', (
                SELECT json_agg(json_build_object(
                    'name', column_name,
                    'ordinalPosition', ordinal_position,
                    'dataType', CASE
                        WHEN domain_name IS NULL THEN data_type::text
                        ELSE concat('DOMAIN:', domain_name::text)
                    END,
                    'udtName', udt_name,
                    'characterMaximumLength', character_maximum_length,
                    'numericPrecision', numeric_precision,
                    'numericScale', numeric_scale,
                    'isNullable', is_nullable
                ) ORDER BY ordinal_position)
                FROM information_schema.columns
                WHERE table_schema = 'ai_dw'
                  AND table_name = 'T_EDW_VAR_PD_INFO_Q'
            )
        ),
        json_build_object(
            'table', 'T_EDW_VAR_PD_IDTY_RELA_Q',
            'relkind', 'r',
            'isPartition', false,
            'inherits', false,
            'keyColumns', (
                SELECT coalesce(
                    json_agg(attribute.attname::text ORDER BY key_position.key_ordinal),
                    json_build_array()
                )
                FROM pg_catalog.pg_index index_row
                JOIN pg_catalog.pg_class table_row
                  ON table_row.oid = index_row.indrelid
                JOIN pg_catalog.pg_namespace namespace_row
                  ON namespace_row.oid = table_row.relnamespace
                CROSS JOIN LATERAL pg_catalog.unnest(index_row.indkey)
                  WITH ORDINALITY AS key_position(attnum, key_ordinal)
                JOIN pg_catalog.pg_attribute attribute
                  ON attribute.attrelid = table_row.oid
                 AND attribute.attnum = key_position.attnum
                WHERE namespace_row.nspname = 'ai_dw'
                  AND table_row.relname = 'T_EDW_VAR_PD_IDTY_RELA_Q'
                  AND index_row.indisprimary
            ),
            'columns', (
                SELECT json_agg(json_build_object(
                    'name', column_name,
                    'ordinalPosition', ordinal_position,
                    'dataType', CASE
                        WHEN domain_name IS NULL THEN data_type::text
                        ELSE concat('DOMAIN:', domain_name::text)
                    END,
                    'udtName', udt_name,
                    'characterMaximumLength', character_maximum_length,
                    'numericPrecision', numeric_precision,
                    'numericScale', numeric_scale,
                    'isNullable', is_nullable
                ) ORDER BY ordinal_position)
                FROM information_schema.columns
                WHERE table_schema = 'ai_dw'
                  AND table_name = 'T_EDW_VAR_PD_IDTY_RELA_Q'
            )
        ),
        json_build_object(
            'table', 'T_EDW_VAR_HCZQ_IDTY_CLAS_Q',
            'relkind', 'r',
            'isPartition', false,
            'inherits', false,
            'keyColumns', (
                SELECT coalesce(
                    json_agg(attribute.attname::text ORDER BY key_position.key_ordinal),
                    json_build_array()
                )
                FROM pg_catalog.pg_index index_row
                JOIN pg_catalog.pg_class table_row
                  ON table_row.oid = index_row.indrelid
                JOIN pg_catalog.pg_namespace namespace_row
                  ON namespace_row.oid = table_row.relnamespace
                CROSS JOIN LATERAL pg_catalog.unnest(index_row.indkey)
                  WITH ORDINALITY AS key_position(attnum, key_ordinal)
                JOIN pg_catalog.pg_attribute attribute
                  ON attribute.attrelid = table_row.oid
                 AND attribute.attnum = key_position.attnum
                WHERE namespace_row.nspname = 'ai_dw'
                  AND table_row.relname = 'T_EDW_VAR_HCZQ_IDTY_CLAS_Q'
                  AND index_row.indisprimary
            ),
            'columns', (
                SELECT json_agg(json_build_object(
                    'name', column_name,
                    'ordinalPosition', ordinal_position,
                    'dataType', CASE
                        WHEN domain_name IS NULL THEN data_type::text
                        ELSE concat('DOMAIN:', domain_name::text)
                    END,
                    'udtName', udt_name,
                    'characterMaximumLength', character_maximum_length,
                    'numericPrecision', numeric_precision,
                    'numericScale', numeric_scale,
                    'isNullable', is_nullable
                ) ORDER BY ordinal_position)
                FROM information_schema.columns
                WHERE table_schema = 'ai_dw'
                  AND table_name = 'T_EDW_VAR_HCZQ_IDTY_CLAS_Q'
            )
        )
    ),
    'observations', json_build_object(
        'rowCounts', json_build_object(
            'T_EDW_VAR_PD_INFO_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
                WHERE "IS_EFF"::text = '1'
            ),
            'T_EDW_VAR_PD_IDTY_RELA_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
                WHERE "IS_EFF"::text = '1'
            ),
            'T_EDW_VAR_HCZQ_IDTY_CLAS_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
                WHERE "IS_EFF"::text = '1'
            )
        ),
        'uniqueKeyCounts', json_build_object(
            'T_EDW_VAR_PD_INFO_Q', (
                SELECT count(DISTINCT "PD_ID"::text)
                FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
                WHERE "IS_EFF"::text = '1'
            ),
            'T_EDW_VAR_PD_IDTY_RELA_Q', (
                SELECT count(DISTINCT ("PD_ID"::text, "TERT_IDTY_ID"::text))
                FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
                WHERE "IS_EFF"::text = '1'
            ),
            'T_EDW_VAR_HCZQ_IDTY_CLAS_Q', (
                SELECT count(DISTINCT "TERT_IDTY_ID"::text)
                FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
                WHERE "IS_EFF"::text = '1'
            )
        ),
        'emptyKeyCounts', json_build_object(
            'T_EDW_VAR_PD_INFO_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
                WHERE "IS_EFF"::text = '1'
                  AND btrim(coalesce("PD_ID"::text, '')) = ''
            ),
            'T_EDW_VAR_PD_IDTY_RELA_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
                WHERE "IS_EFF"::text = '1'
                  AND (
                      btrim(coalesce("PD_ID"::text, '')) = ''
                      OR btrim(coalesce("TERT_IDTY_ID"::text, '')) = ''
                  )
            ),
            'T_EDW_VAR_HCZQ_IDTY_CLAS_Q', (
                SELECT count(*) FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
                WHERE "IS_EFF"::text = '1'
                  AND (
                      btrim(coalesce("IDTY_CLAS"::text, '')) = ''
                      OR btrim(coalesce("PRI_IDTY_ID"::text, '')) = ''
                      OR btrim(coalesce("SCD_IDTY_ID"::text, '')) = ''
                      OR btrim(coalesce("TERT_IDTY_ID"::text, '')) = ''
                  )
            )
        ),
        'busDates', json_build_object(
            'T_EDW_VAR_PD_INFO_Q', (
                SELECT coalesce(json_agg(value ORDER BY value), json_build_array())
                FROM (
                    SELECT DISTINCT "BUS_DATE"::text AS value
                    FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
                    WHERE "IS_EFF"::text = '1'
                ) d
            ),
            'T_EDW_VAR_PD_IDTY_RELA_Q', (
                SELECT coalesce(json_agg(value ORDER BY value), json_build_array())
                FROM (
                    SELECT DISTINCT "BUS_DATE"::text AS value
                    FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
                    WHERE "IS_EFF"::text = '1'
                ) d
            ),
            'T_EDW_VAR_HCZQ_IDTY_CLAS_Q', (
                SELECT coalesce(json_agg(value ORDER BY value), json_build_array())
                FROM (
                    SELECT DISTINCT "BUS_DATE"::text AS value
                    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
                    WHERE "IS_EFF"::text = '1'
                ) d
            )
        ),
        'orphanCounts', json_build_object(
            'relationToProduct', (
                SELECT count(*)
                FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q" r
                LEFT JOIN ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
                  ON p."PD_ID"::text = r."PD_ID"::text
                 AND p."IS_EFF"::text = '1'
                WHERE r."IS_EFF"::text = '1'
                  AND p."PD_ID" IS NULL
            ),
            'relationToIndustry', (
                SELECT count(*)
                FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q" r
                LEFT JOIN ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
                  ON c."TERT_IDTY_ID"::text = r."TERT_IDTY_ID"::text
                 AND c."IS_EFF"::text = '1'
                WHERE r."IS_EFF"::text = '1'
                  AND c."TERT_IDTY_ID" IS NULL
            )
        )
    )
)::text);
\else
SELECT 'KBRM1_DATA_CONTRACT_MISMATCH';
\endif
\else
SELECT 'KBRM1_READ_ONLY_REQUIRED';
\endif
"""

METADATA_PROBE_V1 = SqlPlan(
    operation="kingbase_readonly_preflight",
    version="METADATA_PROBE_V1",
    sql=METADATA_PROBE_SQL,
    variables={},
)

DECODER_CAPABILITY_SQL = PSQL_PREAMBLE + r"""
BEGIN READ ONLY;
WITH function_candidates AS (
    SELECT
        n.nspname::text AS schema_name,
        p.proname::text AS function_name,
        COALESCE((
            SELECT json_agg(json_build_object(
                'schema', argument_type_namespace.nspname::text,
                'name', argument_type.typname::text
            ) ORDER BY argument_position.ordinality)
            FROM pg_catalog.unnest(p.proargtypes)
                WITH ORDINALITY AS argument_position(type_oid, ordinality)
            JOIN pg_catalog.pg_type argument_type
              ON argument_type.oid = argument_position.type_oid
            JOIN pg_catalog.pg_namespace argument_type_namespace
              ON argument_type_namespace.oid = argument_type.typnamespace
        ), json_build_array()) AS argument_types,
        json_build_object(
            'schema', result_type_namespace.nspname::text,
            'name', result_type.typname::text
        ) AS result_type,
        p.prokind::text AS routine_kind,
        p.proretset::boolean AS returns_set
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_type result_type ON result_type.oid = p.prorettype
    JOIN pg_catalog.pg_namespace result_type_namespace
      ON result_type_namespace.oid = result_type.typnamespace
    WHERE p.proname IN ('decode', 'decoding', 'convert_from')
      AND n.nspname IN ('sys', 'pg_catalog', 'sys_catalog', 'ai_dw')
)
SELECT concat('KBRM1_PREFLIGHT_OK|', json_build_object(
    'functionCandidates', COALESCE((
        SELECT json_agg(json_build_object(
            'schema', schema_name,
            'name', function_name,
            'argumentTypes', argument_types,
            'resultType', result_type,
            'routineKind', routine_kind,
            'returnsSet', returns_set
        ) ORDER BY schema_name, function_name, argument_types::text,
                   result_type::text, routine_kind, returns_set)
        FROM function_candidates
    ), json_build_array())
)::text);
\else
SELECT 'KBRM1_READ_ONLY_REQUIRED';
\endif
"""

DECODER_CAPABILITY_V1 = SqlPlan(
    operation="kingbase_readonly_preflight",
    version="DECODER_CAPABILITY_V1",
    sql=DECODER_CAPABILITY_SQL,
    variables={},
)

PROTECTED_SYSTEM_SCHEMAS = frozenset({"sys", "pg_catalog", "sys_catalog"})
VISIBLE_FUNCTION_SCHEMAS = PROTECTED_SYSTEM_SCHEMAS | {"ai_dw"}
CAPABILITY_CANDIDATE_KEYS = frozenset(
    {
        "schema",
        "name",
        "argumentTypes",
        "resultType",
        "routineKind",
        "returnsSet",
    }
)
TYPE_IDENTITY_KEYS = frozenset({"schema", "name"})


@dataclass(frozen=True)
class DecoderCapability:
    decoder_schema: str
    convert_from_schema: str


def _safe_catalog_identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 63
        or not value.isascii()
        or not (value[0].isalpha() or value[0] == "_")
        or any(not (character.isalnum() or character == "_") for character in value)
    ):
        raise MetadataMismatch()
    return value


def _type_identity(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != TYPE_IDENTITY_KEYS:
        raise MetadataMismatch()
    return (
        _safe_catalog_identifier(value["schema"]),
        _safe_catalog_identifier(value["name"]),
    )


def validate_decoder_capability(candidates: Any) -> DecoderCapability:
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= 32:
        raise MetadataMismatch()

    normalized = []
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != CAPABILITY_CANDIDATE_KEYS:
            raise MetadataMismatch()
        schema = _safe_catalog_identifier(candidate["schema"])
        name = _safe_catalog_identifier(candidate["name"])
        argument_types = candidate["argumentTypes"]
        routine_kind = candidate["routineKind"]
        returns_set = candidate["returnsSet"]
        if (
            schema not in VISIBLE_FUNCTION_SCHEMAS
            or name not in {"decode", "decoding", "convert_from"}
            or not isinstance(argument_types, list)
            or len(argument_types) != 2
            or not isinstance(routine_kind, str)
            or routine_kind not in {"f", "p", "a", "w", "P"}
            or type(returns_set) is not bool
        ):
            raise MetadataMismatch()
        arguments = tuple(_type_identity(value) for value in argument_types)
        result = _type_identity(candidate["resultType"])
        if (
            schema not in PROTECTED_SYSTEM_SCHEMAS
            or any(type_schema not in PROTECTED_SYSTEM_SCHEMAS for type_schema, _ in arguments)
            or result[0] not in PROTECTED_SYSTEM_SCHEMAS
            or routine_kind != "f"
            or returns_set
        ):
            raise MetadataMismatch()
        normalized.append((schema, name, arguments, result))

    def has_type_names(
        candidate: tuple[
            str,
            str,
            tuple[tuple[str, str], ...],
            tuple[str, str],
        ],
        function_name: str,
        argument_names: tuple[str, str],
        result_name: str,
    ) -> bool:
        _, name, arguments, result = candidate
        return (
            name == function_name
            and tuple(type_name for _, type_name in arguments) == argument_names
            and result[1] == result_name
        )

    decoder_rows = [
        candidate
        for candidate in normalized
        if has_type_names(candidate, "decoding", ("text", "text"), "bytea")
    ]
    convert_from_rows = [
        candidate
        for candidate in normalized
        if has_type_names(candidate, "convert_from", ("bytea", "name"), "text")
    ]
    legacy_decode_rows = [
        candidate
        for candidate in normalized
        if has_type_names(candidate, "decode", ("text", "text"), "bytea")
    ]
    if (
        len(normalized) != 2
        or len(decoder_rows) != 1
        or len(convert_from_rows) != 1
        or legacy_decode_rows
    ):
        raise MetadataMismatch()
    return DecoderCapability(
        decoder_schema=decoder_rows[0][0],
        convert_from_schema=convert_from_rows[0][0],
    )


class ReadOnlyRequired(RuntimeError):
    def __str__(self) -> str:
        return "read-only boundary unavailable"


def collect_metadata(
    *,
    password_reader: Callable[[], Any] = read_password,
    executor: Callable[[SqlPlan, Any], PsqlResult] = run_psql,
) -> dict[str, Any]:
    secret = password_reader()
    result = executor(METADATA_PROBE_V1, secret)
    if result.error_code == "READ_ONLY_REQUIRED":
        raise ReadOnlyRequired()
    if result.error_code is not None or result.preflight is None:
        raise MetadataMismatch()
    validate_live_metadata(result.preflight)
    return result.preflight


def collect_decoder_capability(
    *,
    password_reader: Callable[[], Any] = read_password,
    executor: Callable[[SqlPlan, Any], PsqlResult] = run_psql,
) -> DecoderCapability:
    secret = password_reader()
    result = executor(DECODER_CAPABILITY_V1, secret)
    if result.error_code == "READ_ONLY_REQUIRED":
        raise ReadOnlyRequired()
    if (
        result.error_code is not None
        or result.preflight is None
        or result.business is not None
        or set(result.preflight) != {"functionCandidates"}
    ):
        raise MetadataMismatch()
    return validate_decoder_capability(result.preflight["functionCandidates"])


def run_runtime_guard(
    bound_snapshot: BoundSnapshot,
    *,
    password_reader: Callable[[], Any] = read_password,
    executor: Callable[[SqlPlan, Any], PsqlResult] = run_psql,
) -> None:
    plan = build_preflight_plan(bound_snapshot)
    required_fragments = (
        "live_tables EXCEPT ALL SELECT * FROM expected_tables",
        "expected_tables EXCEPT ALL SELECT * FROM live_tables",
        "live_keys EXCEPT ALL SELECT * FROM expected_keys",
        "expected_keys EXCEPT ALL SELECT * FROM live_keys",
        "live_columns EXCEPT ALL SELECT * FROM expected_columns",
        "expected_columns EXCEPT ALL SELECT * FROM live_columns",
    )
    if "KBRM1_BUSINESS_V1" in plan.sql or any(
        fragment not in plan.sql for fragment in required_fragments
    ):
        raise MetadataMismatch()
    secret = password_reader()
    result = executor(plan, secret)
    if result.error_code == "READ_ONLY_REQUIRED":
        raise ReadOnlyRequired()
    if (
        result.error_code is not None
        or result.preflight is None
        or result.business is not None
    ):
        raise MetadataMismatch()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output")
    group.add_argument("--check")
    group.add_argument("--runtime-guard")
    group.add_argument("--decoder-capability", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    runtime_snapshot_loader: Callable[[Path], BoundSnapshot] = load_bound_snapshot,
    password_reader: Callable[[], Any] = read_password,
    executor: Callable[[SqlPlan, Any], PsqlResult] = run_psql,
) -> int:
    args = _parser().parse_args(argv)
    if args.profile != PROFILE:
        print("POLICY_DENIED", file=sys.stderr)
        return 2
    try:
        if args.decoder_capability:
            capability = collect_decoder_capability(
                password_reader=password_reader,
                executor=executor,
            )
            print(
                "DECODER_CAPABILITY_OK "
                f"decoderSchema={capability.decoder_schema} "
                f"convertFromSchema={capability.convert_from_schema} "
                "legacyDecodeTextTextBytea=0"
            )
            return 0

        if args.runtime_guard is not None:
            if (
                Path(args.runtime_guard).resolve() != SNAPSHOT_PATH.resolve()
            ):
                raise MetadataMismatch()
            bound_snapshot = runtime_snapshot_loader(SNAPSHOT_PATH)
            run_runtime_guard(
                bound_snapshot,
                password_reader=password_reader,
                executor=executor,
            )
            print("METADATA_RUNTIME_GUARD_OK")
            return 0

        metadata = collect_metadata(
            password_reader=password_reader,
            executor=executor,
        )
        if args.output is not None:
            if Path(args.output) != OUTPUT_PATH:
                print("POLICY_DENIED", file=sys.stderr)
                return 2
            OUTPUT_PATH.write_text(
                json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.check is not None:
            if Path(args.check).resolve() != SNAPSHOT_PATH.resolve():
                print("POLICY_DENIED", file=sys.stderr)
                return 2
            snapshot = json.loads(SNAPSHOT_PATH.read_text(encoding="utf-8"))
            validate_snapshot(metadata, snapshot)
    except AuthUnavailable:
        print("AUTH_UNAVAILABLE", file=sys.stderr)
        return 3
    except ReadOnlyRequired:
        print("READ_ONLY_REQUIRED", file=sys.stderr)
        return 4
    except MetadataMismatch:
        print("DATA_CONTRACT_MISMATCH", file=sys.stderr)
        return 5
    except ResultTooLarge:
        print("RESULT_TOO_LARGE", file=sys.stderr)
        return 6
    except QueryFailed:
        print("QUERY_FAILED", file=sys.stderr)
        return 7
    print("METADATA_CONTRACT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
