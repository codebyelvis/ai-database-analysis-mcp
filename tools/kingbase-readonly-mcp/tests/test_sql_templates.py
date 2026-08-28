import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import metadata_contract  # noqa: E402
import sql_templates  # noqa: E402
from test_contracts import VALID_REQUESTS  # noqa: E402
from test_metadata_contract import valid_metadata  # noqa: E402


TABLES = (
    'ONLY ai_dw."T_EDW_VAR_PD_INFO_Q"',
    'ONLY ai_dw."T_EDW_VAR_PD_IDTY_RELA_Q"',
    'ONLY ai_dw."T_EDW_VAR_HCZQ_IDTY_CLAS_Q"',
)

EXPECTED_VARIABLES = {
    "RESOLVE_CATALOG": {"request_text", "expected_entity_type", "request_limit"},
    "SEARCH_PRODUCTS": {"search_text", "match_field", "request_limit"},
    "PRODUCT_INDUSTRIES": {"product_entity_id", "request_limit"},
    "INDUSTRY_CHILDREN": {"parent_entity_id", "request_limit"},
    "INDUSTRY_PARENT_PATH": {"industry_entity_id"},
}

PRIVATE_COLUMNS = ("CRT_TIME", "UPDT_TIME", "MEMO")


def bound_snapshot():
    cls = getattr(metadata_contract, "BoundSnapshot", None)
    if cls is None:
        raise AssertionError("BoundSnapshot is not implemented")
    return cls.from_value(metadata_contract.freeze_snapshot(valid_metadata()))


def preflight_plan():
    builder = getattr(sql_templates, "build_preflight_plan", None)
    if builder is None:
        raise AssertionError("build_preflight_plan is not implemented")
    return builder(bound_snapshot())


class SqlTemplateTest(unittest.TestCase):
    def test_every_preflight_and_catalog_plan_contains_exact_snapshot_guard(self):
        snapshot = metadata_contract.load_bound_snapshot()
        plans = [
            sql_templates.build_preflight_plan(snapshot),
            *(sql_templates.build_sql_plan(request, snapshot) for request in VALID_REQUESTS),
        ]
        expected_rows = sum(
            len(table["columns"])
            for table in snapshot.as_dict()["tables"]
        )
        self.assertEqual(expected_rows, 27)
        for plan in plans:
            with self.subTest(operation=plan.operation):
                for fragment in (
                    "live_tables EXCEPT ALL SELECT * FROM expected_tables",
                    "expected_tables EXCEPT ALL SELECT * FROM live_tables",
                    "live_keys EXCEPT ALL SELECT * FROM expected_keys",
                    "expected_keys EXCEPT ALL SELECT * FROM live_keys",
                    "live_columns EXCEPT ALL SELECT * FROM expected_columns",
                    "expected_columns EXCEPT ALL SELECT * FROM live_columns",
                ):
                    self.assertIn(fragment, plan.sql)
                for private_name in PRIVATE_COLUMNS:
                    rendered = sql_templates.snapshot_sql_literal(
                        "column_name",
                        private_name,
                    )
                    self.assertIn(rendered, plan.sql)

    def test_preflight_has_no_business_section(self):
        plan = preflight_plan()
        self.assertNotIn("KBRM1_BUSINESS_V1", plan.sql)
        self.assertEqual(plan.variables, {})

    def test_every_operation_uses_fixed_tables_and_exact_variables(self):
        for request in VALID_REQUESTS:
            plan = sql_templates.build_sql_plan(request, bound_snapshot())
            with self.subTest(operation=request["operation"]):
                self.assertEqual(set(plan.variables), EXPECTED_VARIABLES[request["operation"]])
                self.assertEqual(plan.sql.count("KBRM1_BUSINESS_V1"), 1)
                for table in TABLES:
                    self.assertIn(table, plan.sql)

    def test_all_plans_use_kingbase_safe_text_concatenation(self):
        plans = [
            preflight_plan(),
            *(sql_templates.build_sql_plan(request, bound_snapshot()) for request in VALID_REQUESTS),
        ]
        for plan in plans:
            with self.subTest(operation=plan.operation):
                self.assertNotIn("||", plan.sql)
                self.assertIn("concat(", plan.sql)
                self.assertNotIn("'[]'::json", plan.sql)
                if plan.operation != "kingbase_readonly_preflight":
                    self.assertIn("json_build_array()", plan.sql)

    def test_request_values_never_enter_sql_text(self):
        request = {
            "operation": "RESOLVE_CATALOG",
            "text": "UNIQUE_USER_VALUE_9f3a",
            "expectedEntityType": "ANY",
            "limit": 7,
        }
        plan = sql_templates.build_sql_plan(request, bound_snapshot())
        self.assertNotIn(request["text"], plan.sql)
        self.assertIn(request["text"], plan.variables.values())
        self.assertIn(":'request_text'", plan.sql)
        self.assertIn(":request_limit", plan.sql)

    def test_fixed_sort_and_limit_contracts_are_present(self):
        expected = {
            "RESOLVE_CATALOG": ("match_rank ASC", "entity_level_rank ASC", "entity_id ASC"),
            "SEARCH_PRODUCTS": ("match_rank ASC", "pd_name ASC", "pd_id ASC"),
            "PRODUCT_INDUSTRIES": ("root_id ASC", "l1_id ASC", "l2_id ASC", "l3_id ASC"),
            "INDUSTRY_CHILDREN": ("source_id ASC", "canonical_name ASC"),
            "INDUSTRY_PARENT_PATH": ("path_position ASC",),
        }
        for request in VALID_REQUESTS:
            plan = sql_templates.build_sql_plan(request, bound_snapshot())
            with self.subTest(operation=request["operation"]):
                for fragment in expected[request["operation"]]:
                    self.assertIn(fragment, plan.sql)
                if "limit" in request:
                    self.assertIn(":request_limit", plan.sql)
                else:
                    self.assertNotIn(":request_limit", plan.sql)

    def test_snapshot_guard_is_bidirectional_and_precedes_every_business_marker(self):
        plans = [
            preflight_plan(),
            *(sql_templates.build_sql_plan(request, bound_snapshot()) for request in VALID_REQUESTS),
        ]
        for plan in plans:
            with self.subTest(operation=plan.operation):
                self.assertIn("live_tables EXCEPT ALL SELECT * FROM expected_tables", plan.sql)
                self.assertIn("expected_tables EXCEPT ALL SELECT * FROM live_tables", plan.sql)
                self.assertIn("live_keys EXCEPT ALL SELECT * FROM expected_keys", plan.sql)
                self.assertIn("expected_keys EXCEPT ALL SELECT * FROM live_keys", plan.sql)
                self.assertIn("live_columns EXCEPT ALL SELECT * FROM expected_columns", plan.sql)
                self.assertIn("expected_columns EXCEPT ALL SELECT * FROM live_columns", plan.sql)
                guard = plan.sql.index("expected_tables")
                marker = plan.sql.find("KBRM1_BUSINESS_V1")
                if marker >= 0:
                    self.assertLess(guard, marker)

    def test_snapshot_guard_does_not_union_different_tuple_shapes(self):
        sql = preflight_plan().sql
        guard = sql[
            sql.index("WITH expected_tables") : sql.index("\\gset kb_snapshot_")
        ]
        self.assertNotIn("UNION ALL", guard)
        for live, expected in (
            ("live_tables", "expected_tables"),
            ("live_keys", "expected_keys"),
            ("live_columns", "expected_columns"),
        ):
            self.assertIn(
                f"NOT EXISTS (SELECT * FROM {live} EXCEPT ALL SELECT * FROM {expected})",
                guard,
            )
            self.assertIn(
                f"NOT EXISTS (SELECT * FROM {expected} EXCEPT ALL SELECT * FROM {live})",
                guard,
            )

    def test_snapshot_renderer_types_and_hex_encodes_values(self):
        renderer = getattr(sql_templates, "snapshot_sql_literal", None)
        self.assertIsNotNone(renderer)
        self.assertEqual(renderer("numeric_scale", None), "NULL::bigint")
        self.assertEqual(renderer("is_partition", True), "TRUE::boolean")
        self.assertEqual(renderer("ordinal_position", 7), "7::bigint")
        rendered = renderer("column_name", "quote'\\产业")
        self.assertIn("pg_catalog.convert_from", rendered)
        self.assertIn("pg_catalog.decoding", rendered)
        self.assertNotIn("pg_catalog.decode(", rendered)
        self.assertNotIn("quote", rendered)
        self.assertNotIn("产业", rendered)
        for value in ("a\u0000b", "a\u001fb", "a\u007fb", "a\u0085b"):
            with self.subTest(value=repr(value)), self.assertRaises(
                metadata_contract.MetadataMismatch
            ):
                renderer("column_name", value)

    def test_snapshot_renderer_uses_observed_pg_catalog_decoder_signatures(self):
        value = "quote'\\产业"
        encoded = value.encode("utf-8").hex()
        rendered = sql_templates.snapshot_sql_literal("column_name", value)
        self.assertEqual(
            rendered,
            "pg_catalog.convert_from("
            f"pg_catalog.decoding('{encoded}', 'hex'), 'UTF8')::text",
        )
        self.assertNotIn("pg_catalog.decode(", rendered)

    def test_all_null_numeric_metadata_dimensions_are_explicitly_typed(self):
        sql = preflight_plan().sql
        self.assertGreaterEqual(sql.count("NULL::bigint"), 3)
        self.assertNotIn("VALUES (NULL,", sql)

    def test_business_sql_does_not_project_private_physical_columns(self):
        self.assertTrue(hasattr(sql_templates, "BUSINESS_SQL"))
        operation_bodies = "\n".join(sql_templates.BUSINESS_SQL.values())
        for name in PRIVATE_COLUMNS:
            self.assertNotIn(name, operation_bodies)

    def test_session_guard_requires_target_kingbase_path_and_system_schema_safety(self):
        sql = preflight_plan().sql
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
        self.assertLess(sql.index("current_schemas(true)"), sql.index("live_columns"))

    def test_resolve_and_search_payloads_include_closed_internal_envelope_and_empty_edges(self):
        requests = {
            "RESOLVE_CATALOG": VALID_REQUESTS[0],
            "SEARCH_PRODUCTS": VALID_REQUESTS[1],
        }
        for operation, request in requests.items():
            sql = sql_templates.build_sql_plan(request, bound_snapshot()).sql
            with self.subTest(operation=operation):
                for field in ("operation", "totalCount", "rows", "directEdges"):
                    self.assertIn(f"'{field}'", sql)
                self.assertRegex(sql, r"'directEdges'\s*,\s*json_build_array\(\)")
                self.assertEqual(sql.count("KBRM1_BUSINESS_V1"), 1)

    def test_product_industries_has_independent_product_context_flat_rows_and_limited_edges(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[2], bound_snapshot()).sql
        for field in ("product", "operation", "totalCount", "rows", "directEdges"):
            self.assertIn(f"'{field}'", sql)
        self.assertIn("product_context AS", sql)
        self.assertIn("FROM ONLY ai_dw.\"T_EDW_VAR_PD_INFO_Q\" p", sql)
        self.assertIn("FROM limited", sql)
        self.assertIn("'parentEntityId'", sql)
        self.assertIn("'childEntityId'", sql)
        self.assertIn("'parentLevel'", sql)
        self.assertIn("'childLevel'", sql)
        self.assertIn("json_build_array()", sql)
        self.assertEqual(sql.count("KBRM1_BUSINESS_V1"), 1)

    def test_industry_children_has_public_parent_context_and_direct_child_edges(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[3], bound_snapshot()).sql
        for field in ("parent", "operation", "totalCount", "rows", "directEdges"):
            self.assertIn(f"'{field}'", sql)
        for field in ("entityId", "level", "canonicalName"):
            self.assertIn(f"'{field}'", sql)
        self.assertIn("parent_context AS", sql)
        self.assertIn("FROM limited", sql)
        self.assertIn("'parentEntityId'", sql)
        self.assertIn("'childEntityId'", sql)
        self.assertIn("'parentLevel'", sql)
        self.assertIn("'childLevel'", sql)
        self.assertEqual(sql.count("KBRM1_BUSINESS_V1"), 1)

    def test_industry_parent_path_has_target_context_flat_path_rows_and_adjacent_edges(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[4], bound_snapshot()).sql
        for field in ("node", "operation", "totalCount", "rows", "directEdges"):
            self.assertIn(f"'{field}'", sql)
        for field in ("entityId", "level", "canonicalName"):
            self.assertIn(f"'{field}'", sql)
        self.assertIn("node_context AS", sql)
        self.assertIn("pathPosition", sql)
        self.assertIn("FROM selected", sql)
        self.assertIn("'parentEntityId'", sql)
        self.assertIn("'childEntityId'", sql)
        self.assertIn("'parentLevel'", sql)
        self.assertIn("'childLevel'", sql)
        self.assertEqual(sql.count("KBRM1_BUSINESS_V1"), 1)

    def test_resolve_product_match_field_and_kind_follow_the_actual_match_branch(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[0], bound_snapshot()).sql
        code_exact = "WHEN lower(p.\"YC11_PD_CD\"::text) = lower(:'request_text')"
        name_exact = "WHEN lower(p.\"PD_NAME\"::text) = lower(:'request_text')"
        self.assertIn(code_exact, sql)
        self.assertIn(name_exact, sql)
        self.assertLess(sql.index(code_exact), sql.index(name_exact))
        self.assertIn("ILIKE concat(:'request_text', '%')", sql)
        self.assertIn("'PREFIX'", sql)
        self.assertIn("'CONTAINS'", sql)
        self.assertRegex(sql, r"END AS matched_field,\s*CASE")
        self.assertRegex(sql, r"END AS match_kind,\s*CASE")
        self.assertRegex(sql, r"'matchKind'\s*,\s*match_kind")

    def test_search_exact_match_rank_is_constrained_by_match_field(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[1], bound_snapshot()).sql
        self.assertRegex(
            sql,
            r"CASE\s+WHEN\s+\(\s*\(:'match_field' IN \('ANY', 'NAME'\)\s+"
            r"AND lower\(p\.\"PD_NAME\"::text\) = lower\(:'search_text'\)\)\s+"
            r"OR\s+\(:'match_field' IN \('ANY', 'CODE'\)\s+"
            r"AND lower\(p\.\"YC11_PD_CD\"::text\) = lower\(:'search_text'\)\)\s+\)\s+"
            r"THEN 0\s+ELSE 1\s+END AS match_rank",
        )

    def test_resolve_all_candidate_branches_have_exact_prefix_contains_kind_and_rank(self):
        sql = sql_templates.build_sql_plan(VALID_REQUESTS[0], bound_snapshot()).sql
        fields = (
            ('c', 'IDTY_CLAS'),
            ('c', 'PRI_IDTY_NAME'),
            ('c', 'SCD_IDTY_NAME'),
            ('c', 'TERT_IDTY_NAME'),
        )
        for alias, field in fields:
            exact = f'{alias}."{field}"::text'
            with self.subTest(field=field):
                self.assertIn(
                    f"WHEN lower({exact}) = lower(:'request_text') THEN 'EXACT'",
                    sql,
                )
                self.assertIn(
                    f"WHEN {exact} ILIKE concat(:'request_text', '%') THEN 'PREFIX'",
                    sql,
                )
        self.assertEqual(sql.count("END AS match_kind"), 5)
        self.assertEqual(sql.count("END AS match_rank"), 5)
        self.assertIn("THEN 0 ELSE 1", sql)
        self.assertIn("ORDER BY match_rank ASC, entity_level_rank ASC, entity_id ASC", sql)

    def test_business_context_and_edges_stay_in_one_guarded_statement_and_exclude_private_values(self):
        for request in VALID_REQUESTS:
            plan = sql_templates.build_sql_plan(request, bound_snapshot())
            with self.subTest(operation=plan.operation):
                self.assertEqual(plan.sql.count("KBRM1_BUSINESS_V1"), 1)
                self.assertEqual(plan.sql.count("BEGIN READ ONLY;"), 1)
                self.assertEqual(plan.sql.count("\\gset kb_session_"), 1)
                self.assertEqual(plan.sql.count("\\gset kb_contract_"), 1)
                body = sql_templates.BUSINESS_SQL[plan.operation]
                for private_name in PRIVATE_COLUMNS:
                    self.assertNotIn(f"'{private_name}'", body)
                    self.assertNotIn(f'"{private_name}"', body)
                self.assertNotIn("CRT_TIME", body)
                self.assertNotIn("UPDT_TIME", body)
                self.assertNotIn("MEMO", body)

    def test_contract_guard_rejects_same_level_id_mapping_conflicts_before_business_marker(self):
        sql = preflight_plan().sql
        marker = sql.index("KBRM1_BUSINESS_V1") if "KBRM1_BUSINESS_V1" in sql else len(sql)
        guard = sql[:marker]
        self.assertIn('GROUP BY c."PRI_IDTY_ID"', guard)
        self.assertRegex(
            guard,
            r'count\(DISTINCT \(\s*c\."IDTY_CLAS"::text,\s*'
            r'c\."PRI_IDTY_NAME"::text\s*\)\) > 1',
        )
        self.assertIn('GROUP BY c."SCD_IDTY_ID"', guard)
        self.assertRegex(
            guard,
            r'count\(DISTINCT \(\s*c\."PRI_IDTY_ID"::text,\s*'
            r'c\."SCD_IDTY_NAME"::text\s*\)\) > 1',
        )
        self.assertIn("SELECT 'KBRM1_DATA_CONTRACT_MISMATCH';", sql)


if __name__ == "__main__":
    unittest.main()
