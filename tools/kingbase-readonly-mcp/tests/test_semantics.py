import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical import canonical_sha256, industry_root_id  # noqa: E402
from semantics import validate_catalog_semantics  # noqa: E402


FIXTURES = json.loads((ROOT / "schemas" / "strict-negative-fixtures.json").read_text())
SEMANTIC_CASES = tuple(
    case for case in FIXTURES["examples"] if "semanticRule" in case
)


class CanonicalTest(unittest.TestCase):
    def test_canonical_sha256_uses_recursive_sorted_utf8_json(self):
        expected = hashlib.sha256('{"a":"产业","b":1}'.encode()).hexdigest()
        self.assertEqual(canonical_sha256({"b": 1, "a": "产业"}), expected)

    def test_root_id_is_reversible_nfc_base64url(self):
        self.assertEqual(industry_root_id("人工智能"), "INDUSTRY_ROOT:5Lq65bel5pm66IO9")
        self.assertEqual(industry_root_id("e\u0301"), "INDUSTRY_ROOT:w6k")

    def test_root_id_rejects_control_characters(self):
        for value in ("", "a\u0000b", "a\u0085b", "a\u007fb"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(ValueError):
                    industry_root_id(value)


class SemanticFixtureTest(unittest.TestCase):
    def test_fixture_count_is_frozen(self):
        self.assertEqual(len(SEMANTIC_CASES), 18)

    def test_each_semantic_fixture_fails_only_its_declared_rule(self):
        for case in SEMANTIC_CASES:
            with self.subTest(caseId=case["caseId"]):
                result = validate_catalog_semantics(
                    case["request"],
                    case["payload"],
                    case.get("queryContext"),
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.failed_rules, (case["semanticRule"],))


if __name__ == "__main__":
    unittest.main()
