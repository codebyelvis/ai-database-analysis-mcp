from dataclasses import dataclass
from typing import Any

from contracts import validate_catalog_request
from metadata_contract import BoundSnapshot, MetadataMismatch


@dataclass(frozen=True)
class SqlPlan:
    operation: str
    version: str
    sql: str
    variables: dict[str, Any]


SNAPSHOT_SQL_TYPES = {
    "table_name": "text",
    "relkind": "text",
    "is_partition": "boolean",
    "inherits": "boolean",
    "key_ordinal": "bigint",
    "column_name": "text",
    "ordinal_position": "bigint",
    "data_type": "text",
    "udt_name": "text",
    "character_maximum_length": "bigint",
    "numeric_precision": "bigint",
    "numeric_scale": "bigint",
    "is_nullable": "text",
}


def _has_c0_c1(value: str) -> bool:
    return any(ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F for character in value)


def snapshot_sql_literal(field: str, value: str | int | bool | None) -> str:
    sql_type = SNAPSHOT_SQL_TYPES.get(field)
    if sql_type is None:
        raise MetadataMismatch()
    if value is None:
        return f"NULL::{sql_type}"
    if sql_type == "boolean":
        if type(value) is not bool:
            raise MetadataMismatch()
        return ("TRUE" if value else "FALSE") + "::boolean"
    if sql_type == "bigint":
        if type(value) is not int or value < 0:
            raise MetadataMismatch()
        return f"{value}::bigint"
    if not isinstance(value, str) or not value or _has_c0_c1(value):
        raise MetadataMismatch()
    encoded = value.encode("utf-8").hex()
    return (
        "pg_catalog.convert_from("
        f"pg_catalog.decoding('{encoded}', 'hex'), 'UTF8')::text"
    )


def _sql_values(fields: tuple[str, ...], rows: list[tuple[Any, ...]]) -> str:
    if not rows:
        raise MetadataMismatch()
    rendered = []
    for row in rows:
        if len(row) != len(fields):
            raise MetadataMismatch()
        rendered.append(
            "(" + ", ".join(
                snapshot_sql_literal(field, value)
                for field, value in zip(fields, row, strict=True)
            ) + ")"
        )
    return ",\n        ".join(rendered)


def _snapshot_guard_sql(bound_snapshot: BoundSnapshot) -> str:
    if not isinstance(bound_snapshot, BoundSnapshot):
        raise MetadataMismatch()
    snapshot = bound_snapshot.as_dict()
    table_rows = []
    key_rows = []
    column_rows = []
    for table in snapshot["tables"]:
        table_name = table["table"]
        table_rows.append(
            (table_name, table["relkind"], table["isPartition"], table["inherits"])
        )
        key_rows.extend(
            (table_name, ordinal, column_name)
            for ordinal, column_name in enumerate(table["keyColumns"], 1)
        )
        column_rows.extend(
            (
                table_name,
                column["name"],
                column["ordinalPosition"],
                column["dataType"],
                column["udtName"],
                column["characterMaximumLength"],
                column["numericPrecision"],
                column["numericScale"],
                column["isNullable"],
            )
            for column in table["columns"]
        )

    tables = _sql_values(
        ("table_name", "relkind", "is_partition", "inherits"),
        table_rows,
    )
    keys = _sql_values(
        ("table_name", "key_ordinal", "column_name"),
        key_rows,
    )
    columns = _sql_values(
        (
            "table_name",
            "column_name",
            "ordinal_position",
            "data_type",
            "udt_name",
            "character_maximum_length",
            "numeric_precision",
            "numeric_scale",
            "is_nullable",
        ),
        column_rows,
    )
    return f"""
WITH expected_tables(table_name, relkind, is_partition, inherits) AS (
    VALUES
        {tables}
),
expected_keys(table_name, key_ordinal, column_name) AS (
    VALUES
        {keys}
),
expected_columns(
    table_name, column_name, ordinal_position, data_type, udt_name,
    character_maximum_length, numeric_precision, numeric_scale, is_nullable
) AS (
    VALUES
        {columns}
),
live_tables AS (
    SELECT
        c.relname::text AS table_name,
        c.relkind::text AS relkind,
        c.relispartition::boolean AS is_partition,
        EXISTS (
            SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid = c.oid
        )::boolean AS inherits
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN expected_tables e ON e.table_name = c.relname::text
    WHERE n.nspname = 'ai_dw'
),
live_keys AS (
    SELECT
        c.relname::text AS table_name,
        key_position.key_ordinal::bigint AS key_ordinal,
        attribute.attname::text AS column_name
    FROM pg_catalog.pg_index index_row
    JOIN pg_catalog.pg_class c ON c.oid = index_row.indrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN expected_tables e ON e.table_name = c.relname::text
    CROSS JOIN LATERAL pg_catalog.unnest(index_row.indkey)
        WITH ORDINALITY AS key_position(attnum, key_ordinal)
    JOIN pg_catalog.pg_attribute attribute
      ON attribute.attrelid = c.oid AND attribute.attnum = key_position.attnum
    WHERE n.nspname = 'ai_dw' AND index_row.indisprimary
),
live_columns AS (
    SELECT
        column_row.table_name::text AS table_name,
        column_row.column_name::text AS column_name,
        column_row.ordinal_position::bigint AS ordinal_position,
        CASE
            WHEN column_row.domain_name IS NULL THEN column_row.data_type::text
            ELSE concat('DOMAIN:', column_row.domain_name::text)
        END::text AS data_type,
        column_row.udt_name::text AS udt_name,
        column_row.character_maximum_length::bigint AS character_maximum_length,
        column_row.numeric_precision::bigint AS numeric_precision,
        column_row.numeric_scale::bigint AS numeric_scale,
        column_row.is_nullable::text AS is_nullable
    FROM information_schema.columns column_row
    JOIN expected_tables e ON e.table_name = column_row.table_name::text
    WHERE column_row.table_schema = 'ai_dw'
)
SELECT (
    NOT EXISTS (SELECT * FROM live_tables EXCEPT ALL SELECT * FROM expected_tables)
    AND NOT EXISTS (SELECT * FROM expected_tables EXCEPT ALL SELECT * FROM live_tables)
    AND NOT EXISTS (SELECT * FROM live_keys EXCEPT ALL SELECT * FROM expected_keys)
    AND NOT EXISTS (SELECT * FROM expected_keys EXCEPT ALL SELECT * FROM live_keys)
    AND NOT EXISTS (SELECT * FROM live_columns EXCEPT ALL SELECT * FROM expected_columns)
    AND NOT EXISTS (SELECT * FROM expected_columns EXCEPT ALL SELECT * FROM live_columns)
) AS ok
\\gset kb_snapshot_
\\if :kb_snapshot_ok
"""


ROOT_ID_SQL = (
    "concat('INDUSTRY_ROOT:', "
    "rtrim(translate(replace(encode(convert_to(\"IDTY_CLAS\"::text, "
    "'UTF8'), 'base64'), chr(10), ''), '+/', '-_'), '='))"
)

PSQL_PREAMBLE = r"""
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
"""

CONTRACT_GUARD_SQL = r"""
SELECT (
    (
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
    )
    AND (
        SELECT array_agg(column_name::text ORDER BY column_name) =
            ARRAY[
                'BUS_DATE','CRT_TIME','IS_EFF','MEMO','PD_ID','PD_NAME',
                'UPDT_TIME','YC11_PD_CD'
            ]::text[]
        FROM information_schema.columns
        WHERE table_schema = 'ai_dw'
          AND table_name = 'T_EDW_VAR_PD_INFO_Q'
    )
    AND (
        SELECT array_agg(column_name::text ORDER BY column_name) =
            ARRAY[
                'BUS_DATE','CRT_TIME','IS_EFF','MEMO','PD_ID',
                'TERT_IDTY_ID','UPDT_TIME'
            ]::text[]
        FROM information_schema.columns
        WHERE table_schema = 'ai_dw'
          AND table_name = 'T_EDW_VAR_PD_IDTY_RELA_Q'
    )
    AND (
        SELECT array_agg(column_name::text ORDER BY column_name) =
            ARRAY[
                'BUS_DATE','CRT_TIME','IDTY_CLAS','IS_EFF','MEMO','PRI_IDTY_ID',
                'PRI_IDTY_NAME','SCD_IDTY_ID','SCD_IDTY_NAME',
                'TERT_IDTY_ID','TERT_IDTY_NAME','UPDT_TIME'
            ]::text[]
        FROM information_schema.columns
        WHERE table_schema = 'ai_dw'
          AND table_name = 'T_EDW_VAR_HCZQ_IDTY_CLAS_Q'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns c
        WHERE c.table_schema = 'ai_dw'
          AND c.table_name IN (
              'T_EDW_VAR_PD_INFO_Q',
              'T_EDW_VAR_PD_IDTY_RELA_Q',
              'T_EDW_VAR_HCZQ_IDTY_CLAS_Q'
          )
          AND (
              (
                  c.column_name IN (
                      'PD_ID','YC11_PD_CD','PRI_IDTY_ID','SCD_IDTY_ID',
                      'TERT_IDTY_ID'
                  )
                  AND NOT (
                      c.udt_name IN (
                          'varchar','bpchar','text','int2','int4','int8'
                      )
                      OR (c.udt_name = 'numeric' AND c.numeric_scale = 0)
                  )
              )
              OR (
                  c.column_name IN (
                      'PD_NAME','IDTY_CLAS','PRI_IDTY_NAME',
                      'SCD_IDTY_NAME','TERT_IDTY_NAME'
                  )
                  AND c.udt_name NOT IN ('varchar','bpchar','text')
              )
              OR (
                  c.column_name = 'IS_EFF'
                  AND NOT (
                      c.udt_name IN (
                          'varchar','bpchar','text','int2','int4','int8','bool'
                      )
                      OR (c.udt_name = 'numeric' AND c.numeric_scale = 0)
                  )
              )
              OR (
                  c.column_name = 'BUS_DATE'
                  AND NOT (
                      c.udt_name IN (
                          'varchar','bpchar','text','int2','int4','int8'
                      )
                      OR (c.udt_name = 'numeric' AND c.numeric_scale = 0)
                  )
              )
          )
    )
    AND (
        SELECT count(*) = count(DISTINCT "PD_ID"::text)
            AND bool_and(btrim("PD_ID"::text) <> '')
            AND count(DISTINCT "BUS_DATE"::text) = 1
            AND bool_and("BUS_DATE"::text ~ '^[0-9]{8}$')
        FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
        WHERE "IS_EFF"::text = '1'
    )
    AND (
        SELECT count(*) = count(DISTINCT ("PD_ID"::text, "TERT_IDTY_ID"::text))
            AND bool_and(btrim("PD_ID"::text) <> '')
            AND bool_and(btrim("TERT_IDTY_ID"::text) <> '')
            AND count(DISTINCT "BUS_DATE"::text) = 1
            AND bool_and("BUS_DATE"::text ~ '^[0-9]{8}$')
        FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
        WHERE "IS_EFF"::text = '1'
    )
    AND (
        SELECT count(*) = count(DISTINCT "TERT_IDTY_ID"::text)
            AND bool_and(btrim("IDTY_CLAS"::text) <> '')
            AND bool_and(btrim("PRI_IDTY_ID"::text) <> '')
            AND bool_and(btrim("SCD_IDTY_ID"::text) <> '')
            AND bool_and(btrim("TERT_IDTY_ID"::text) <> '')
            AND count(DISTINCT "BUS_DATE"::text) = 1
            AND bool_and("BUS_DATE"::text ~ '^[0-9]{8}$')
        FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
        WHERE "IS_EFF"::text = '1'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
        WHERE c."IS_EFF"::text = '1'
        GROUP BY c."PRI_IDTY_ID"::text
        HAVING count(DISTINCT (
            c."IDTY_CLAS"::text,
            c."PRI_IDTY_NAME"::text
        )) > 1
    )
    AND NOT EXISTS (
        SELECT 1
        FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
        WHERE c."IS_EFF"::text = '1'
        GROUP BY c."SCD_IDTY_ID"::text
        HAVING count(DISTINCT (
            c."PRI_IDTY_ID"::text,
            c."SCD_IDTY_NAME"::text
        )) > 1
    )
    AND (
        SELECT min("BUS_DATE"::text)
        FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
        WHERE "IS_EFF"::text = '1'
    ) = (
        SELECT min("BUS_DATE"::text)
        FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
        WHERE "IS_EFF"::text = '1'
    )
    AND (
        SELECT min("BUS_DATE"::text)
        FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
        WHERE "IS_EFF"::text = '1'
    ) = (
        SELECT min("BUS_DATE"::text)
        FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
        WHERE "IS_EFF"::text = '1'
    )
    AND NOT EXISTS (
        SELECT 1
        FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q" r
        LEFT JOIN ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
          ON p."PD_ID"::text = r."PD_ID"::text
         AND p."IS_EFF"::text = '1'
        WHERE r."IS_EFF"::text = '1'
          AND p."PD_ID" IS NULL
    )
    AND NOT EXISTS (
        SELECT 1
        FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q" r
        LEFT JOIN ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
          ON c."TERT_IDTY_ID"::text = r."TERT_IDTY_ID"::text
         AND c."IS_EFF"::text = '1'
        WHERE r."IS_EFF"::text = '1'
          AND c."TERT_IDTY_ID" IS NULL
    )
) AS ok
\gset kb_contract_
\if :kb_contract_ok
BEGIN READ ONLY;
SELECT concat('KBRM1_PREFLIGHT_OK|', json_build_object(
    'dataAsOfRaw', (
        SELECT min("BUS_DATE"::text)
        FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
        WHERE "IS_EFF"::text = '1'
    ),
    'productCount', (
        SELECT count(*)
        FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"
        WHERE "IS_EFF"::text = '1'
    ),
    'relationCount', (
        SELECT count(*)
        FROM ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"
        WHERE "IS_EFF"::text = '1'
    ),
    'industryCount', (
        SELECT count(*)
        FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"
        WHERE "IS_EFF"::text = '1'
    ),
    'privilegeMode', 'CLIENT_ENFORCED_READ_ONLY',
    'databasePrivilegeRisk', 'WRITE_CAPABLE_ACCOUNT'
)::text);
"""

PSQL_POSTAMBLE = r"""
\else
SELECT 'KBRM1_DATA_CONTRACT_MISMATCH';
\endif
\else
SELECT 'KBRM1_DATA_CONTRACT_MISMATCH';
\endif
\else
SELECT 'KBRM1_READ_ONLY_REQUIRED';
\endif
"""

RESOLVE_SQL = """
WITH candidates AS (
    SELECT
        concat('PRODUCT:', p."PD_ID"::text) AS entity_id,
        'PRODUCT'::text AS entity_kind,
        p."PD_NAME"::text AS canonical_name,
        CASE
            WHEN lower(p."YC11_PD_CD"::text) = lower(:'request_text') THEN 'YC11_PD_CD'
            WHEN lower(p."PD_NAME"::text) = lower(:'request_text') THEN 'PD_NAME'
            WHEN p."YC11_PD_CD"::text ILIKE concat(:'request_text', '%') THEN 'YC11_PD_CD'
            WHEN p."PD_NAME"::text ILIKE concat(:'request_text', '%') THEN 'PD_NAME'
            WHEN p."YC11_PD_CD"::text ILIKE concat('%', :'request_text', '%') THEN 'YC11_PD_CD'
            ELSE 'PD_NAME'
        END AS matched_field,
        CASE
            WHEN lower(p."YC11_PD_CD"::text) = lower(:'request_text')
              OR lower(p."PD_NAME"::text) = lower(:'request_text')
            THEN 'EXACT'
            WHEN p."YC11_PD_CD"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            WHEN p."PD_NAME"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            ELSE 'CONTAINS'
        END AS match_kind,
        CASE
            WHEN lower(p."YC11_PD_CD"::text) = lower(:'request_text')
              OR lower(p."PD_NAME"::text) = lower(:'request_text')
            THEN 0 ELSE 1
        END AS match_rank,
        0 AS entity_level_rank
    FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
    WHERE p."IS_EFF"::text = '1'
      AND :'expected_entity_type' IN ('PRODUCT', 'ANY')
      AND (
          p."PD_NAME"::text ILIKE concat('%', :'request_text', '%')
          OR p."YC11_PD_CD"::text ILIKE concat('%', :'request_text', '%')
      )
    UNION ALL
    SELECT DISTINCT
        {root_id} AS entity_id,
        'INDUSTRY_ROOT'::text AS entity_kind,
        c."IDTY_CLAS"::text AS canonical_name,
        'IDTY_CLAS'::text AS matched_field,
        CASE
            WHEN lower(c."IDTY_CLAS"::text) = lower(:'request_text') THEN 'EXACT'
            WHEN c."IDTY_CLAS"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            ELSE 'CONTAINS'
        END AS match_kind,
        CASE WHEN lower(c."IDTY_CLAS"::text) = lower(:'request_text') THEN 0 ELSE 1 END AS match_rank,
        1
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND :'expected_entity_type' IN ('INDUSTRY', 'ANY')
      AND c."IDTY_CLAS"::text ILIKE concat('%', :'request_text', '%')
    UNION ALL
    SELECT DISTINCT
        concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text),
        'INDUSTRY_L1'::text,
        c."PRI_IDTY_NAME"::text,
        'PRI_IDTY_NAME'::text,
        CASE
            WHEN lower(c."PRI_IDTY_NAME"::text) = lower(:'request_text') THEN 'EXACT'
            WHEN c."PRI_IDTY_NAME"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            ELSE 'CONTAINS'
        END AS match_kind,
        CASE WHEN lower(c."PRI_IDTY_NAME"::text) = lower(:'request_text') THEN 0 ELSE 1 END AS match_rank,
        2
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND :'expected_entity_type' IN ('INDUSTRY', 'ANY')
      AND c."PRI_IDTY_NAME"::text ILIKE concat('%', :'request_text', '%')
    UNION ALL
    SELECT DISTINCT
        concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text),
        'INDUSTRY_L2'::text,
        c."SCD_IDTY_NAME"::text,
        'SCD_IDTY_NAME'::text,
        CASE
            WHEN lower(c."SCD_IDTY_NAME"::text) = lower(:'request_text') THEN 'EXACT'
            WHEN c."SCD_IDTY_NAME"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            ELSE 'CONTAINS'
        END AS match_kind,
        CASE WHEN lower(c."SCD_IDTY_NAME"::text) = lower(:'request_text') THEN 0 ELSE 1 END AS match_rank,
        3
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND :'expected_entity_type' IN ('INDUSTRY', 'ANY')
      AND c."SCD_IDTY_NAME"::text ILIKE concat('%', :'request_text', '%')
    UNION ALL
    SELECT DISTINCT
        concat('INDUSTRY_L3:', c."TERT_IDTY_ID"::text),
        'INDUSTRY_L3'::text,
        c."TERT_IDTY_NAME"::text,
        'TERT_IDTY_NAME'::text,
        CASE
            WHEN lower(c."TERT_IDTY_NAME"::text) = lower(:'request_text') THEN 'EXACT'
            WHEN c."TERT_IDTY_NAME"::text ILIKE concat(:'request_text', '%') THEN 'PREFIX'
            ELSE 'CONTAINS'
        END AS match_kind,
        CASE WHEN lower(c."TERT_IDTY_NAME"::text) = lower(:'request_text') THEN 0 ELSE 1 END AS match_rank,
        4
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND :'expected_entity_type' IN ('INDUSTRY', 'ANY')
      AND c."TERT_IDTY_NAME"::text ILIKE concat('%', :'request_text', '%')
),
limited AS (
    SELECT *
    FROM candidates
    ORDER BY match_rank ASC, entity_level_rank ASC, entity_id ASC
    LIMIT :request_limit
)
SELECT concat('KBRM1_BUSINESS_V1|', json_build_object(
    'operation', 'RESOLVE_CATALOG',
    'totalCount', (SELECT count(*) FROM candidates),
    'rows', COALESCE((
        SELECT json_agg(json_build_object(
            'entityId', entity_id,
            'entityKind', entity_kind,
            'canonicalName', canonical_name,
            'matchedField', matched_field,
            'matchKind', match_kind
        ) ORDER BY match_rank ASC, entity_level_rank ASC, entity_id ASC)
        FROM limited
    ), json_build_array()),
    'directEdges', json_build_array()
)::text);
""".format(root_id=ROOT_ID_SQL)

SEARCH_PRODUCTS_SQL = """
WITH candidates AS (
    SELECT
        p."PD_ID"::text AS pd_id,
        p."YC11_PD_CD"::text AS yc11_pd_cd,
        p."PD_NAME"::text AS pd_name,
        p."IS_EFF"::text AS is_eff,
        CASE
            WHEN (
                (:'match_field' IN ('ANY', 'NAME')
                 AND lower(p."PD_NAME"::text) = lower(:'search_text'))
                OR (:'match_field' IN ('ANY', 'CODE')
                    AND lower(p."YC11_PD_CD"::text) = lower(:'search_text'))
            )
            THEN 0 ELSE 1
        END AS match_rank
    FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
    WHERE p."IS_EFF"::text = '1'
      AND (
          (:'match_field' IN ('ANY', 'NAME') AND p."PD_NAME"::text ILIKE concat('%', :'search_text', '%'))
          OR (:'match_field' IN ('ANY', 'CODE') AND p."YC11_PD_CD"::text ILIKE concat('%', :'search_text', '%'))
      )
),
limited AS (
    SELECT *
    FROM candidates
    ORDER BY match_rank ASC, pd_name ASC, pd_id ASC
    LIMIT :request_limit
)
SELECT concat('KBRM1_BUSINESS_V1|', json_build_object(
    'operation', 'SEARCH_PRODUCTS',
    'totalCount', (SELECT count(*) FROM candidates),
    'rows', COALESCE((
        SELECT json_agg(json_build_object(
            'pdId', pd_id,
            'yc11PdCd', yc11_pd_cd,
            'pdName', pd_name,
            'isEff', is_eff
        ) ORDER BY match_rank ASC, pd_name ASC, pd_id ASC)
        FROM limited
    ), json_build_array()),
    'directEdges', json_build_array()
)::text);
"""

PRODUCT_INDUSTRIES_SQL = """
WITH product_context AS (
    SELECT
        concat('PRODUCT:', p."PD_ID"::text) AS entity_id,
        p."PD_ID"::text AS pd_id,
        p."YC11_PD_CD"::text AS yc11_pd_cd,
        p."PD_NAME"::text AS pd_name,
        p."IS_EFF"::text AS is_eff
    FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
    WHERE p."IS_EFF"::text = '1'
      AND concat('PRODUCT:', p."PD_ID"::text) = :'product_entity_id'
),
paths AS (
    SELECT
        p."PD_ID"::text AS pd_id,
        p."YC11_PD_CD"::text AS yc11_pd_cd,
        p."PD_NAME"::text AS pd_name,
        p."IS_EFF"::text AS is_eff,
        {root_id} AS root_id,
        c."IDTY_CLAS"::text AS root_name,
        c."PRI_IDTY_ID"::text AS l1_id,
        c."PRI_IDTY_NAME"::text AS l1_name,
        c."SCD_IDTY_ID"::text AS l2_id,
        c."SCD_IDTY_NAME"::text AS l2_name,
        c."TERT_IDTY_ID"::text AS l3_id,
        c."TERT_IDTY_NAME"::text AS l3_name
    FROM ONLY ai_dw."T_EDW_VAR_PD_INFO_Q" p
    JOIN ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q" r
      ON r."PD_ID"::text = p."PD_ID"::text
     AND r."IS_EFF"::text = '1'
    JOIN ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
      ON c."TERT_IDTY_ID"::text = r."TERT_IDTY_ID"::text
     AND c."IS_EFF"::text = '1'
    WHERE p."IS_EFF"::text = '1'
      AND concat('PRODUCT:', p."PD_ID"::text) = :'product_entity_id'
),
limited AS (
    SELECT *
    FROM paths
    ORDER BY root_id ASC, l1_id ASC, l2_id ASC, l3_id ASC
    LIMIT :request_limit
),
edge_rows AS (
    SELECT
        root_id AS parent_entity_id,
        'ROOT'::text AS parent_level,
        concat('INDUSTRY_L1:', l1_id) AS child_entity_id,
        'L1'::text AS child_level
    FROM limited
    UNION ALL
    SELECT
        concat('INDUSTRY_L1:', l1_id),
        'L1'::text,
        concat('INDUSTRY_L2:', l2_id),
        'L2'::text
    FROM limited
    UNION ALL
    SELECT
        concat('INDUSTRY_L2:', l2_id),
        'L2'::text,
        concat('INDUSTRY_L3:', l3_id),
        'L3'::text
    FROM limited
),
edges AS (
    SELECT DISTINCT
        parent_entity_id,
        parent_level,
        child_entity_id,
        child_level
    FROM edge_rows
)
SELECT concat('KBRM1_BUSINESS_V1|', json_build_object(
    'operation', 'PRODUCT_INDUSTRIES',
    'product', (
        SELECT json_build_object(
            'entityId', entity_id,
            'pdId', pd_id,
            'yc11PdCd', yc11_pd_cd,
            'pdName', pd_name,
            'isEff', is_eff
        )
        FROM product_context
    ),
    'totalCount', (SELECT count(*) FROM paths),
    'rows', COALESCE((
        SELECT json_agg(json_build_object(
            'pdId', pd_id,
            'yc11PdCd', yc11_pd_cd,
            'pdName', pd_name,
            'isEff', is_eff,
            'rootId', root_id,
            'rootName', root_name,
            'l1Id', l1_id,
            'l1Name', l1_name,
            'l2Id', l2_id,
            'l2Name', l2_name,
            'l3Id', l3_id,
            'l3Name', l3_name
        ) ORDER BY root_id ASC, l1_id ASC, l2_id ASC, l3_id ASC)
        FROM limited
    ), json_build_array()),
    'directEdges', COALESCE((
        SELECT json_agg(json_build_object(
            'parentEntityId', parent_entity_id,
            'parentLevel', parent_level,
            'childEntityId', child_entity_id,
            'childLevel', child_level
        ) ORDER BY parent_entity_id ASC, parent_level ASC,
                     child_entity_id ASC, child_level ASC)
        FROM edges
    ), json_build_array())
)::text);
""".format(root_id=ROOT_ID_SQL)

INDUSTRY_CHILDREN_SQL = """
WITH parent_context AS (
    SELECT DISTINCT
        {root_id} AS entity_id,
        'ROOT'::text AS node_level,
        c."IDTY_CLAS"::text AS canonical_name,
        NULL::text AS source_id
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND {root_id} = :'parent_entity_id'
    UNION ALL
    SELECT DISTINCT
        concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text),
        'L1'::text,
        c."PRI_IDTY_NAME"::text,
        c."PRI_IDTY_ID"::text
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text) = :'parent_entity_id'
    UNION ALL
    SELECT DISTINCT
        concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text),
        'L2'::text,
        c."SCD_IDTY_NAME"::text,
        c."SCD_IDTY_ID"::text
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text) = :'parent_entity_id'
),
children AS (
    SELECT DISTINCT
        c."PRI_IDTY_ID"::text AS source_id,
        c."PRI_IDTY_NAME"::text AS canonical_name,
        'L1'::text AS child_level
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND {root_id} = :'parent_entity_id'
    UNION ALL
    SELECT DISTINCT
        c."SCD_IDTY_ID"::text,
        c."SCD_IDTY_NAME"::text,
        'L2'::text
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text) = :'parent_entity_id'
    UNION ALL
    SELECT DISTINCT
        c."TERT_IDTY_ID"::text,
        c."TERT_IDTY_NAME"::text,
        'L3'::text
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text) = :'parent_entity_id'
),
limited AS (
    SELECT *
    FROM children
    ORDER BY source_id ASC, canonical_name ASC
    LIMIT :request_limit
),
edges AS (
    SELECT DISTINCT
        parent.entity_id AS parent_entity_id,
        parent.node_level AS parent_level,
        CASE limited.child_level
            WHEN 'L1' THEN concat('INDUSTRY_L1:', limited.source_id)
            WHEN 'L2' THEN concat('INDUSTRY_L2:', limited.source_id)
            WHEN 'L3' THEN concat('INDUSTRY_L3:', limited.source_id)
        END AS child_entity_id,
        limited.child_level AS child_level
    FROM limited
    CROSS JOIN parent_context parent
)
SELECT concat('KBRM1_BUSINESS_V1|', json_build_object(
    'operation', 'INDUSTRY_CHILDREN',
    'parent', (
        SELECT CASE
            WHEN node_level = 'ROOT' THEN json_build_object(
                'entityId', entity_id,
                'level', node_level,
                'canonicalName', canonical_name
            )
            ELSE json_build_object(
                'entityId', entity_id,
                'level', node_level,
                'canonicalName', canonical_name,
                'sourceId', source_id
            )
        END
        FROM parent_context
    ),
    'totalCount', (SELECT count(*) FROM children),
    'rows', COALESCE((
        SELECT json_agg(json_build_object(
            'sourceId', source_id,
            'canonicalName', canonical_name,
            'level', child_level
        ) ORDER BY source_id ASC, canonical_name ASC)
        FROM limited
    ), json_build_array()),
    'directEdges', COALESCE((
        SELECT json_agg(json_build_object(
            'parentEntityId', parent_entity_id,
            'parentLevel', parent_level,
            'childEntityId', child_entity_id,
            'childLevel', child_level
        ) ORDER BY parent_entity_id ASC, parent_level ASC,
                     child_entity_id ASC, child_level ASC)
        FROM edges
    ), json_build_array())
)::text);
""".format(root_id=ROOT_ID_SQL)

INDUSTRY_PARENT_PATH_SQL = """
WITH matching_paths AS (
    SELECT
        {root_id} AS root_id,
        c."IDTY_CLAS"::text AS root_name,
        c."PRI_IDTY_ID"::text AS l1_id,
        c."PRI_IDTY_NAME"::text AS l1_name,
        c."SCD_IDTY_ID"::text AS l2_id,
        c."SCD_IDTY_NAME"::text AS l2_name,
        c."TERT_IDTY_ID"::text AS l3_id,
        c."TERT_IDTY_NAME"::text AS l3_name,
        CASE
            WHEN {root_id} = :'industry_entity_id' THEN 1
            WHEN concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text) = :'industry_entity_id' THEN 2
            WHEN concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text) = :'industry_entity_id' THEN 3
            WHEN concat('INDUSTRY_L3:', c."TERT_IDTY_ID"::text) = :'industry_entity_id' THEN 4
        END AS path_position
    FROM ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q" c
    WHERE c."IS_EFF"::text = '1'
      AND (
          {root_id} = :'industry_entity_id'
          OR concat('INDUSTRY_L1:', c."PRI_IDTY_ID"::text) = :'industry_entity_id'
          OR concat('INDUSTRY_L2:', c."SCD_IDTY_ID"::text) = :'industry_entity_id'
          OR concat('INDUSTRY_L3:', c."TERT_IDTY_ID"::text) = :'industry_entity_id'
      )
),
selected AS (
    SELECT *
    FROM matching_paths
    ORDER BY path_position ASC, root_id ASC, l1_id ASC, l2_id ASC, l3_id ASC
    LIMIT 1
),
node_context AS (
    SELECT CASE path_position
        WHEN 1 THEN json_build_object(
            'entityId', root_id,
            'level', 'ROOT',
            'canonicalName', root_name
        )
        WHEN 2 THEN json_build_object(
            'entityId', concat('INDUSTRY_L1:', l1_id),
            'level', 'L1',
            'canonicalName', l1_name,
            'sourceId', l1_id
        )
        WHEN 3 THEN json_build_object(
            'entityId', concat('INDUSTRY_L2:', l2_id),
            'level', 'L2',
            'canonicalName', l2_name,
            'sourceId', l2_id
        )
        WHEN 4 THEN json_build_object(
            'entityId', concat('INDUSTRY_L3:', l3_id),
            'level', 'L3',
            'canonicalName', l3_name,
            'sourceId', l3_id
        )
    END AS node_json
    FROM selected
),
edge_rows AS (
    SELECT
        root_id AS parent_entity_id,
        'ROOT'::text AS parent_level,
        concat('INDUSTRY_L1:', l1_id) AS child_entity_id,
        'L1'::text AS child_level
    FROM selected
    WHERE path_position >= 2
    UNION ALL
    SELECT
        concat('INDUSTRY_L1:', l1_id),
        'L1'::text,
        concat('INDUSTRY_L2:', l2_id),
        'L2'::text
    FROM selected
    WHERE path_position >= 3
    UNION ALL
    SELECT
        concat('INDUSTRY_L2:', l2_id),
        'L2'::text,
        concat('INDUSTRY_L3:', l3_id),
        'L3'::text
    FROM selected
    WHERE path_position >= 4
),
edges AS (
    SELECT DISTINCT
        parent_entity_id,
        parent_level,
        child_entity_id,
        child_level
    FROM edge_rows
)
SELECT concat('KBRM1_BUSINESS_V1|', json_build_object(
    'operation', 'INDUSTRY_PARENT_PATH',
    'node', (SELECT node_json FROM node_context),
    'totalCount', (SELECT count(*) FROM selected),
    'rows', COALESCE((
        SELECT json_agg(json_build_object(
            'rootId', root_id,
            'rootName', root_name,
            'l1Id', l1_id,
            'l1Name', l1_name,
            'l2Id', l2_id,
            'l2Name', l2_name,
            'l3Id', l3_id,
            'l3Name', l3_name,
            'pathPosition', path_position
        ) ORDER BY path_position ASC)
        FROM selected
    ), json_build_array()),
    'directEdges', COALESCE((
        SELECT json_agg(json_build_object(
            'parentEntityId', parent_entity_id,
            'parentLevel', parent_level,
            'childEntityId', child_entity_id,
            'childLevel', child_level
        ) ORDER BY parent_entity_id ASC, parent_level ASC,
                     child_entity_id ASC, child_level ASC)
        FROM edges
    ), json_build_array())
)::text);
""".format(root_id=ROOT_ID_SQL)

BUSINESS_SQL = {
    "RESOLVE_CATALOG": RESOLVE_SQL,
    "SEARCH_PRODUCTS": SEARCH_PRODUCTS_SQL,
    "PRODUCT_INDUSTRIES": PRODUCT_INDUSTRIES_SQL,
    "INDUSTRY_CHILDREN": INDUSTRY_CHILDREN_SQL,
    "INDUSTRY_PARENT_PATH": INDUSTRY_PARENT_PATH_SQL,
}


def _assemble(operation: str | None, bound_snapshot: BoundSnapshot) -> str:
    business = "" if operation is None else BUSINESS_SQL[operation]
    return (
        PSQL_PREAMBLE
        + _snapshot_guard_sql(bound_snapshot)
        + CONTRACT_GUARD_SQL
        + business
        + PSQL_POSTAMBLE
    )


def build_preflight_plan(bound_snapshot: BoundSnapshot) -> SqlPlan:
    return SqlPlan(
        operation="kingbase_readonly_preflight",
        version="PREFLIGHT_V1",
        sql=_assemble(None, bound_snapshot),
        variables={},
    )


def build_sql_plan(request: dict[str, Any], bound_snapshot: BoundSnapshot) -> SqlPlan:
    request = validate_catalog_request(request)
    operation = request["operation"]
    if operation == "RESOLVE_CATALOG":
        variables = {
            "request_text": request["text"],
            "expected_entity_type": request["expectedEntityType"],
            "request_limit": request["limit"],
        }
    elif operation == "SEARCH_PRODUCTS":
        variables = {
            "search_text": request["searchText"],
            "match_field": request["matchField"],
            "request_limit": request["limit"],
        }
    elif operation == "PRODUCT_INDUSTRIES":
        variables = {
            "product_entity_id": request["productEntityId"],
            "request_limit": request["limit"],
        }
    elif operation == "INDUSTRY_CHILDREN":
        variables = {
            "parent_entity_id": request["parentEntityId"],
            "request_limit": request["limit"],
        }
    else:
        variables = {"industry_entity_id": request["industryEntityId"]}
    return SqlPlan(
        operation=operation,
        version=operation + "_V1",
        sql=_assemble(operation, bound_snapshot),
        variables=variables,
    )


def all_plans_for_static_validation(
    bound_snapshot: BoundSnapshot,
) -> tuple[SqlPlan, ...]:
    requests = (
        {
            "operation": "RESOLVE_CATALOG",
            "text": "x",
            "expectedEntityType": "ANY",
            "limit": 1,
        },
        {
            "operation": "SEARCH_PRODUCTS",
            "searchText": "x",
            "matchField": "ANY",
            "limit": 1,
        },
        {
            "operation": "PRODUCT_INDUSTRIES",
            "productEntityId": "PRODUCT:X",
            "limit": 1,
        },
        {
            "operation": "INDUSTRY_CHILDREN",
            "parentEntityId": "INDUSTRY_L1:X",
            "limit": 1,
        },
        {
            "operation": "INDUSTRY_PARENT_PATH",
            "industryEntityId": "INDUSTRY_L1:X",
        },
    )
    return (
        build_preflight_plan(bound_snapshot),
        *(build_sql_plan(request, bound_snapshot) for request in requests),
    )
