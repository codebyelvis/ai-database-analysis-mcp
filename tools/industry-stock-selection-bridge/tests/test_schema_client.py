"""Real public Ajv worker boundary tests; no private MCP or database is used."""

import copy
import importlib
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = Path(__file__).resolve().parent
sys.path[:0] = [str(ROOT), str(TEST_ROOT)]
NODE = Path("/opt/homebrew/Cellar/node@20/20.20.2/bin/node")
WORKER = ROOT / "schema_worker.mjs"
CONTRACTS = {
    "entityResolveRequest",
    "entityResolveResponse",
    "businessQueryRequest",
    "businessQueryResponse",
}


def entity_request():
    return {
        "operation": "entity_resolve",
        "mentions": [
            {
                "mentionId": "m1",
                "text": "产品一",
                "expectedEntityTypes": ["CATALOG_NODE"],
            }
        ],
        "queryPlan": {
            "planId": "plan1",
            "steps": [
                {
                    "stepId": "s1",
                    "relation": "PARENT_PATH",
                    "input": {"sourceType": "MENTION", "mentionId": "m1"},
                    "outputType": "PATH_RESULT",
                    "presentation": {"visibility": "VISIBLE"},
                }
            ],
        },
    }


def business_request():
    return {
        "operation": "business_query",
        "resolvedPlan": {
            "planId": "plan1",
            "steps": [
                {
                    "stepId": "s1",
                    "relation": "PARENT_PATH",
                    "input": {
                        "sourceType": "ENTITY",
                        "entity": {
                            "entityId": "PRODUCT:P1",
                            "entityType": "CATALOG_NODE",
                            "canonicalName": "产品一",
                        },
                    },
                    "outputType": "PATH_RESULT",
                    "presentation": {"visibility": "VISIBLE"},
                }
            ],
        },
    }


VALID = {
    "entityResolveRequest": entity_request(),
    "entityResolveResponse": {
        "success": False,
        "operation": "entity_resolve",
        "mockData": False,
        "resolutionResults": [],
        "resolvedPlan": None,
        "errorCode": "INTERNAL_ERROR",
        "message": "catalog resolution is unavailable",
        "retryable": False,
    },
    "businessQueryRequest": business_request(),
    "businessQueryResponse": {
        "success": False,
        "operation": "business_query",
        "planId": "plan1",
        "executionStatus": "FAILED",
        "mockData": False,
        "stepResults": [],
        "errorCode": "INTERNAL_ERROR",
        "message": "catalog query is unavailable",
        "retryable": False,
    },
}


class PublicSchemaClientTest(unittest.TestCase):
    def test_shared_module_load_is_isolated_and_real_worker_checks_all_contracts(self):
        before = list(sys.path)
        server = importlib.import_module("industry_selection_bridge_server")
        self.assertEqual(sys.path, before)
        with server.SchemaClient(
            node_binary=str(NODE),
            worker_path=WORKER,
            contracts=CONTRACTS,
            startup_probe=("entityResolveResponse", VALID["entityResolveResponse"]),
        ) as client:
            for contract in sorted(CONTRACTS):
                with self.subTest(contract=contract):
                    self.assertTrue(client.validate(contract, VALID[contract]))
                    self.assertFalse(client.validate(contract, {"invalid": True}))

    def test_missing_presentation_visibility_is_rejected(self):
        server = importlib.import_module("industry_selection_bridge_server")
        invalid = business_request()
        invalid["resolvedPlan"]["steps"][0]["presentation"] = {}
        with server.SchemaClient(
            node_binary=str(NODE),
            worker_path=WORKER,
            contracts=CONTRACTS,
            startup_probe=("entityResolveResponse", VALID["entityResolveResponse"]),
        ) as client:
            self.assertFalse(client.validate("businessQueryRequest", invalid))

    def test_real_bridge_projection_branches_satisfy_response_contracts(self):
        from industry_selection_bridge import IndustrySelectionBridge
        from test_bridge import FakePrivate, FIXTURES, entity, unresolved_request

        cases = []
        for name, private_response in (
            ("resolved", FIXTURES["resolveProduct"]),
            ("ambiguous", FIXTURES["resolveAmbiguous"]),
            (
                "not-found",
                {
                    **copy.deepcopy(FIXTURES["resolveProduct"]),
                    "dataStatus": "EMPTY",
                    "totalCount": 0,
                    "returnedCount": 0,
                    "data": {"rows": []},
                },
            ),
            ("private-error", FIXTURES["error"]),
        ):
            request = unresolved_request(text=name)
            bridge = IndustrySelectionBridge(
                private_client=FakePrivate([private_response])
            )
            cases.append(
                (
                    name,
                    "entityResolveRequest",
                    request,
                    "entityResolveResponse",
                    bridge.entity_resolve(request),
                )
            )

        business = {
            "operation": "business_query",
            "resolvedPlan": {
                "planId": "plan1",
                "steps": [
                    {
                        "stepId": "children",
                        "relation": "CHILDREN",
                        "input": {
                            "sourceType": "ENTITY",
                            "entity": entity("INDUSTRY_L1:L1", "一级产业"),
                        },
                        "outputType": "NODE_SET",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                    {
                        "stepId": "productPath",
                        "relation": "PARENT_PATH",
                        "input": {
                            "sourceType": "ENTITY",
                            "entity": entity("PRODUCT:P1", "产品一"),
                        },
                        "outputType": "PATH_RESULT",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                    {
                        "stepId": "industryPath",
                        "relation": "PARENT_PATH",
                        "input": {
                            "sourceType": "ENTITY",
                            "entity": entity("INDUSTRY_L2:L2", "二级产业"),
                        },
                        "outputType": "PATH_RESULT",
                        "presentation": {"visibility": "VISIBLE"},
                    },
                ],
            },
        }
        bridge = IndustrySelectionBridge(
            private_client=FakePrivate(
                [
                    FIXTURES["children"],
                    FIXTURES["productIndustries"],
                    FIXTURES["parentPath"],
                ]
            )
        )
        cases.append(
            (
                "business-ok",
                "businessQueryRequest",
                business,
                "businessQueryResponse",
                bridge.business_query(business),
            )
        )
        partial = copy.deepcopy(business)
        partial["resolvedPlan"]["planId"] = "plan2"
        partial["resolvedPlan"]["steps"] = [
            {
                "stepId": "unsupported",
                "relation": "UPSTREAM",
                "input": {
                    "sourceType": "ENTITY",
                    "entity": entity("INDUSTRY_L1:L1", "一级产业"),
                },
                "outputType": "NODE_SET",
                "presentation": {"visibility": "VISIBLE"},
            }
        ]
        bridge = IndustrySelectionBridge(private_client=FakePrivate([]))
        cases.append(
            (
                "business-partial",
                "businessQueryRequest",
                partial,
                "businessQueryResponse",
                bridge.business_query(partial),
            )
        )
        invalid_plan = copy.deepcopy(business)
        invalid_plan["resolvedPlan"]["planId"] = "plan3"
        duplicate_step = copy.deepcopy(invalid_plan["resolvedPlan"]["steps"][0])
        invalid_plan["resolvedPlan"]["steps"] = [
            duplicate_step,
            copy.deepcopy(duplicate_step),
        ]
        bridge = IndustrySelectionBridge(private_client=FakePrivate([]))
        cases.append(
            (
                "business-failed",
                "businessQueryRequest",
                invalid_plan,
                "businessQueryResponse",
                bridge.business_query(invalid_plan),
            )
        )

        server = importlib.import_module("industry_selection_bridge_server")
        with server.SchemaClient(
            node_binary=str(NODE),
            worker_path=WORKER,
            contracts=CONTRACTS,
            startup_probe=("entityResolveResponse", VALID["entityResolveResponse"]),
        ) as client:
            for name, request_contract, request, response_contract, response in cases:
                with self.subTest(name=name):
                    self.assertTrue(client.validate(request_contract, request))
                    self.assertTrue(client.validate(response_contract, response))


if __name__ == "__main__":
    unittest.main()
