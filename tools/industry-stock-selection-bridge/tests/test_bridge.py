"""Deterministic public projection tests for the real catalog bridge."""

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from industry_selection_bridge import IndustrySelectionBridge  # noqa: E402


FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "private_responses.json").read_text(
        encoding="utf-8"
    )
)


class FakePrivate:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []
        self.closed = False

    def call_catalog(self, arguments):
        self.calls.append(copy.deepcopy(arguments))
        if not self.responses:
            raise AssertionError("unexpected private call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)

    def close(self):
        self.closed = True


def unresolved_request(*, text="产品一", relation="PARENT_PATH"):
    output_type = "PATH_RESULT" if relation == "PARENT_PATH" else "NODE_SET"
    return {
        "operation": "entity_resolve",
        "mentions": [
            {
                "mentionId": "m1",
                "text": text,
                "expectedEntityTypes": ["CATALOG_NODE"],
            }
        ],
        "queryPlan": {
            "planId": "plan1",
            "steps": [
                {
                    "stepId": "s1",
                    "relation": relation,
                    "input": {"sourceType": "MENTION", "mentionId": "m1"},
                    "outputType": output_type,
                    "presentation": {"visibility": "VISIBLE"},
                }
            ],
        },
    }


def entity(entity_id, name):
    return {
        "entityId": entity_id,
        "entityType": "CATALOG_NODE",
        "canonicalName": name,
    }


class EntityResolveTest(unittest.TestCase):
    def test_private_client_is_created_lazily_on_first_valid_catalog_call(self):
        private = FakePrivate([FIXTURES["resolveProduct"]])
        created = []

        def factory():
            created.append(True)
            return private

        bridge = IndustrySelectionBridge(private_factory=factory)
        self.assertEqual(created, [])
        result = bridge.entity_resolve(unresolved_request())
        self.assertTrue(result["success"])
        self.assertEqual(created, [True])
        bridge.close()
        self.assertTrue(private.closed)

    def test_catalog_mention_maps_once_and_compiles_canonical_plan(self):
        private = FakePrivate([FIXTURES["resolveProduct"]])
        bridge = IndustrySelectionBridge(private_client=private)
        result = bridge.entity_resolve(unresolved_request())
        self.assertEqual(
            private.calls,
            [
                {
                    "operation": "RESOLVE_CATALOG",
                    "text": "产品一",
                    "expectedEntityType": "ANY",
                    "limit": 10,
                }
            ],
        )
        self.assertTrue(result["success"])
        self.assertFalse(result["mockData"])
        resolved = result["resolutionResults"][0]
        self.assertEqual(resolved["resolutionStatus"], "RESOLVED")
        self.assertEqual(resolved["resolved"], entity("PRODUCT:P1", "产品一"))
        self.assertEqual(
            result["resolvedPlan"]["steps"][0]["input"],
            {"sourceType": "ENTITY", "entity": entity("PRODUCT:P1", "产品一")},
        )

    def test_ambiguous_not_found_and_private_error_never_guess(self):
        private = FakePrivate(
            [FIXTURES["resolveAmbiguous"], {**FIXTURES["resolveProduct"], "dataStatus": "EMPTY", "totalCount": 0, "returnedCount": 0, "data": {"rows": []}}, FIXTURES["error"]]
        )
        bridge = IndustrySelectionBridge(private_client=private)
        ambiguous = bridge.entity_resolve(unresolved_request(text="同名对象"))
        not_found = bridge.entity_resolve(unresolved_request(text="不存在"))
        failed = bridge.entity_resolve(unresolved_request(text="失败"))
        self.assertEqual(ambiguous["resolutionResults"][0]["resolutionStatus"], "AMBIGUOUS")
        self.assertEqual(
            [item["entityId"] for item in ambiguous["resolutionResults"][0]["candidates"]],
            ["PRODUCT:P1", "INDUSTRY_L2:L2"],
        )
        self.assertIsNone(ambiguous["resolvedPlan"])
        self.assertEqual(not_found["resolutionResults"][0]["resolutionStatus"], "NOT_FOUND")
        self.assertFalse(failed["success"])
        self.assertEqual(failed["resolutionResults"][0]["resolutionStatus"], "ERROR")
        self.assertEqual(len(private.calls), 3)

    def test_company_or_invalid_plan_fails_before_private_call(self):
        private = FakePrivate()
        bridge = IndustrySelectionBridge(private_client=private)
        request = unresolved_request()
        request["mentions"][0]["expectedEntityTypes"] = ["COMPANY"]
        unavailable = bridge.entity_resolve(request)
        self.assertFalse(unavailable["success"])
        self.assertEqual(unavailable["errorCode"], "RESOLUTION_UNAVAILABLE")
        invalid = unresolved_request()
        invalid["mentions"].append(copy.deepcopy(invalid["mentions"][0]))
        rejected = bridge.entity_resolve(invalid)
        self.assertFalse(rejected["success"])
        self.assertEqual(rejected["errorCode"], "INVALID_REQUEST")
        self.assertEqual(private.calls, [])


class BusinessQueryTest(unittest.TestCase):
    def test_children_and_both_parent_path_mappings_are_exact(self):
        private = FakePrivate(
            [FIXTURES["children"], FIXTURES["productIndustries"], FIXTURES["parentPath"]]
        )
        bridge = IndustrySelectionBridge(private_client=private)
        request = {
            "operation": "business_query",
            "resolvedPlan": {
                "planId": "plan1",
                "steps": [
                    {
                        "stepId": "children",
                        "relation": "CHILDREN",
                        "input": {"sourceType": "ENTITY", "entity": entity("INDUSTRY_L1:L1", "一级产业")},
                        "outputType": "NODE_SET",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                    {
                        "stepId": "product_path",
                        "relation": "PARENT_PATH",
                        "input": {"sourceType": "ENTITY", "entity": entity("PRODUCT:P1", "产品一")},
                        "outputType": "PATH_RESULT",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                    {
                        "stepId": "industry_path",
                        "relation": "PARENT_PATH",
                        "input": {"sourceType": "ENTITY", "entity": entity("INDUSTRY_L2:L2", "二级产业")},
                        "outputType": "PATH_RESULT",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                ],
            },
        }
        result = bridge.business_query(request)
        self.assertEqual(
            private.calls,
            [
                {"operation": "INDUSTRY_CHILDREN", "parentEntityId": "INDUSTRY_L1:L1", "limit": 50},
                {"operation": "PRODUCT_INDUSTRIES", "productEntityId": "PRODUCT:P1", "limit": 50},
                {"operation": "INDUSTRY_PARENT_PATH", "industryEntityId": "INDUSTRY_L2:L2"},
            ],
        )
        self.assertEqual(result["executionStatus"], "OK")
        self.assertFalse(result["mockData"])
        self.assertEqual(result["stepResults"][0]["data"]["nodes"][0]["nodeLevel"], "L2")
        self.assertEqual(result["stepResults"][1]["data"]["sourceEntityId"], "PRODUCT:P1")
        self.assertTrue(
            all(
                node["mockData"] is False
                for step in result["stepResults"][1:]
                for path in step["data"]["paths"]
                for node in path["nodes"]
            )
        )
        projected_text = json.dumps(result, ensure_ascii=False)
        for private_name in (
            "INDUSTRY_CHILDREN",
            "PRODUCT_INDUSTRIES",
            "INDUSTRY_PARENT_PATH",
        ):
            self.assertNotIn(private_name, projected_text)

    def test_step_result_uses_prior_success_and_unsupported_is_zero_call(self):
        private = FakePrivate([FIXTURES["children"], FIXTURES["parentPath"]])
        bridge = IndustrySelectionBridge(private_client=private)
        request = {
            "operation": "business_query",
            "resolvedPlan": {
                "planId": "plan2",
                "steps": [
                    {
                        "stepId": "children",
                        "relation": "CHILDREN",
                        "input": {"sourceType": "ENTITY", "entity": entity("INDUSTRY_L1:L1", "一级产业")},
                        "outputType": "NODE_SET",
                        "presentation": {"visibility": "INTERMEDIATE"},
                    },
                    {
                        "stepId": "paths",
                        "relation": "PARENT_PATH",
                        "input": {"sourceType": "STEP_RESULT", "sourceStepId": "children", "resultType": "NODE_SET", "selector": "ALL"},
                        "outputType": "PATH_RESULT",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                    {
                        "stepId": "unsupported",
                        "relation": "UPSTREAM",
                        "input": {"sourceType": "ENTITY", "entity": entity("INDUSTRY_L1:L1", "一级产业")},
                        "outputType": "NODE_SET",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                ],
            },
        }
        result = bridge.business_query(request)
        self.assertEqual(len(private.calls), 2)
        self.assertEqual(private.calls[1]["industryEntityId"], "INDUSTRY_L2:L2")
        self.assertEqual(result["executionStatus"], "PARTIAL")
        self.assertEqual(result["stepResults"][2]["executionStatus"], "ERROR")
        self.assertEqual(result["stepResults"][2]["reasonCode"], "STEP_EXECUTION_ERROR")


if __name__ == "__main__":
    unittest.main()
