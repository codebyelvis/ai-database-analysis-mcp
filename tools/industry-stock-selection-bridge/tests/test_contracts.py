"""Verify the public bridge contracts stay identical to the Skill source."""

import json
import unittest
from pathlib import Path


BRIDGE_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = BRIDGE_ROOT / "contracts"
SKILL_ROOT = Path(
    "/Users/elvis/file/develop/workspace/ai-app/ai_app/ai_app_skill_package/"
    "domains/stock-selection/docs/models/产业选股"
)
CONTRACT_NAMES = (
    "entity-resolve.request.schema.json",
    "entity-resolve.response.schema.json",
    "business-query.request.schema.json",
    "business-query.response.schema.json",
)


class PublicContractTest(unittest.TestCase):
    def test_runtime_contracts_are_byte_identical_to_skill_source(self):
        for name in CONTRACT_NAMES:
            with self.subTest(name=name):
                runtime = CONTRACT_ROOT / name
                self.assertTrue(runtime.is_file())
                self.assertFalse(runtime.is_symlink())
                self.assertEqual(runtime.read_bytes(), (SKILL_ROOT / name).read_bytes())

    def test_real_catalog_path_fields_are_formally_expressible(self):
        schema = json.loads(
            (SKILL_ROOT / "business-query.response.schema.json").read_text(
                encoding="utf-8"
            )
        )
        definitions = schema["$defs"]
        self.assertIn("sourceEntityId", definitions["pathResultData"]["properties"])
        self.assertEqual(
            definitions["entity"]["properties"]["nodeLevel"]["enum"],
            ["ROOT", "L1", "L2", "L3"],
        )
        self.assertEqual(
            definitions["dataEntity"]["properties"]["nodeLevel"]["enum"],
            ["ROOT", "L1", "L2", "L3"],
        )
        self.assertIn("mockData", definitions["entity"]["properties"])
        step = definitions["stepResult"]
        self.assertIn("dataAsOf", step["required"])
        self.assertEqual(
            step["properties"]["dataAsOf"]["oneOf"],
            [{"$ref": "#/$defs/date"}, {"type": "null"}],
        )
        ok_branch = step["allOf"][0]["then"]["properties"]
        self.assertEqual(ok_branch["dataAsOf"], {"$ref": "#/$defs/date"})
        self.assertIn("truncated", definitions["pathResultData"]["required"])

    def test_supported_steps_accept_prior_node_set_results(self):
        schema = json.loads(
            (SKILL_ROOT / "business-query.request.schema.json").read_text(
                encoding="utf-8"
            )
        )
        branches = schema["$defs"]["step"]["allOf"]
        by_relation = {
            branch["if"]["properties"]["relation"].get("const"): branch
            for branch in branches
            if "const" in branch["if"]["properties"]["relation"]
        }
        for relation in ("CHILDREN", "PARENT_PATH"):
            choices = by_relation[relation]["then"]["properties"]["input"]["oneOf"]
            self.assertEqual(
                [choice["$ref"] for choice in choices],
                ["#/$defs/catalogEntityInput", "#/$defs/nodeSetInput"],
            )


if __name__ == "__main__":
    unittest.main()
