import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import metadata_contract  # noqa: E402
import sql_templates  # noqa: E402
from test_metadata_contract import valid_metadata  # noqa: E402


ALLOWED_META = {"set", "pset", "gset", "if", "else", "endif"}


def meta_commands(sql):
    return tuple(
        match.group(1).lower()
        for match in re.finditer(r"(?m)^[ \t]*\\([A-Za-z!]+)", sql)
    )


def all_plans():
    cls = getattr(metadata_contract, "BoundSnapshot", None)
    if cls is None:
        raise AssertionError("BoundSnapshot is not implemented")
    snapshot = cls.from_value(metadata_contract.freeze_snapshot(valid_metadata()))
    return sql_templates.all_plans_for_static_validation(snapshot)


class SqlControlFlowTest(unittest.TestCase):
    def test_session_failure_branch_has_no_business_marker(self):
        for plan in all_plans():
            outer_else = plan.sql.rfind("\\else")
            self.assertGreater(outer_else, 0)
            self.assertNotIn("KBRM1_BUSINESS_V1", plan.sql[outer_else:])

    def test_metadata_failure_branch_has_no_business_marker(self):
        for plan in all_plans():
            first_else = plan.sql.find("\\else")
            self.assertGreater(first_else, 0)
            self.assertNotIn("KBRM1_BUSINESS_V1", plan.sql[first_else:])

    def test_success_branch_begins_read_only_before_business_marker(self):
        for plan in all_plans():
            if plan.operation == "kingbase_readonly_preflight":
                continue
            self.assertLess(plan.sql.index("BEGIN READ ONLY"), plan.sql.index("KBRM1_BUSINESS_V1"))

    def test_only_one_business_marker_exists(self):
        for plan in all_plans():
            expected = 0 if plan.operation == "kingbase_readonly_preflight" else 1
            self.assertEqual(plan.sql.count("KBRM1_BUSINESS_V1"), expected)

    def test_meta_commands_are_closed_allowlist(self):
        for plan in all_plans():
            commands = set(meta_commands(plan.sql))
            self.assertTrue(commands)
            self.assertLessEqual(commands, ALLOWED_META)
            self.assertIn("if", commands)
            self.assertIn("gset", commands)

    def test_connect_include_shell_copy_output_and_gexec_are_forbidden(self):
        forbidden = {
            "connect", "c", "include", "i", "ir", "copy", "!", "o",
            "gexec", "watch", "q",
        }
        for plan in all_plans():
            self.assertTrue(forbidden.isdisjoint(meta_commands(plan.sql)))

    def test_guard_order_is_session_then_metadata_then_transaction(self):
        for plan in all_plans():
            sql = plan.sql
            self.assertLess(sql.index("\\gset kb_session_"), sql.index("\\if :kb_session_ok"))
            self.assertLess(sql.index("\\if :kb_session_ok"), sql.index("\\gset kb_contract_"))
            self.assertLess(sql.index("\\gset kb_contract_"), sql.index("\\if :kb_contract_ok"))
            self.assertLess(sql.index("\\if :kb_contract_ok"), sql.index("BEGIN READ ONLY"))

    def test_session_path_failure_precedes_metadata_and_business(self):
        for plan in all_plans():
            sql = plan.sql
            path_guard = sql.index("pg_catalog.current_setting('search_path')")
            metadata = sql.index("live_columns")
            self.assertLess(path_guard, metadata)
            outer_else = sql.rfind("\\else")
            self.assertIn("KBRM1_READ_ONLY_REQUIRED", sql[outer_else:])
            self.assertNotIn("live_columns", sql[outer_else:])
            self.assertNotIn("KBRM1_BUSINESS_V1", sql[outer_else:])


if __name__ == "__main__":
    unittest.main()
