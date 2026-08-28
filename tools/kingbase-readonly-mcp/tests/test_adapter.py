import copy
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import metadata_contract  # noqa: E402
from canonical import canonical_sha256, industry_root_id  # noqa: E402
from credentials import AuthUnavailable, Secret  # noqa: E402
from metadata_probe import ReadOnlyRequired  # noqa: E402
from psql_runner import PsqlResult, QueryFailed, ResultTooLarge  # noqa: E402
from schema_client import SchemaClient  # noqa: E402

import adapter  # noqa: E402


QUERY_ID = "0123456789abcdef"
DATA_AS_OF = "2026-08-11"
READ_BOUNDARY = {
    "transactionReadOnly": True,
    "privilegeMode": "CLIENT_ENFORCED_READ_ONLY",
    "databasePrivilegeRisk": "WRITE_CAPABLE_ACCOUNT",
}

RESOLVE_REQUEST = {
    "operation": "RESOLVE_CATALOG",
    "text": "P1",
    "expectedEntityType": "ANY",
    "limit": 10,
}
SEARCH_REQUEST = {
    "operation": "SEARCH_PRODUCTS",
    "searchText": "P",
    "matchField": "ANY",
    "limit": 20,
}
PRODUCT_REQUEST = {
    "operation": "PRODUCT_INDUSTRIES",
    "productEntityId": "PRODUCT:P1",
    "limit": 50,
}
ROOT_ID = industry_root_id("Root")
CHILDREN_REQUEST = {
    "operation": "INDUSTRY_CHILDREN",
    "parentEntityId": ROOT_ID,
    "limit": 50,
}
PATH_REQUEST = {
    "operation": "INDUSTRY_PARENT_PATH",
    "industryEntityId": "INDUSTRY_L3:L3",
}


def _snapshot():
    return metadata_contract.load_bound_snapshot()


def _preflight_raw(**overrides):
    value = {
        "dataAsOfRaw": "20260811",
        "productCount": 3,
        "relationCount": 4,
        "industryCount": 2,
        "privilegeMode": "CLIENT_ENFORCED_READ_ONLY",
        "databasePrivilegeRisk": "WRITE_CAPABLE_ACCOUNT",
    }
    value.update(overrides)
    return value


def _edge(parent_id, parent_level, child_id, child_level):
    return {
        "parentEntityId": parent_id,
        "parentLevel": parent_level,
        "childEntityId": child_id,
        "childLevel": child_level,
    }


def _product_raw(total=1, rows=None, direct_edges=None, product=None):
    if product is None:
        product = {
            "entityId": "PRODUCT:P1",
            "pdId": "P1",
            "yc11PdCd": "C1",
            "pdName": "Product 1",
            "isEff": "1",
        }
    if rows is None:
        rows = [
            {
                "pdId": "P1",
                "yc11PdCd": "C1",
                "pdName": "Product 1",
                "isEff": "1",
                "rootId": ROOT_ID,
                "rootName": "Root",
                "l1Id": "L1",
                "l1Name": "Level 1",
                "l2Id": "L2",
                "l2Name": "Level 2",
                "l3Id": "L3",
                "l3Name": "Level 3",
            }
        ]
    if direct_edges is None:
        direct_edges = [
            _edge("INDUSTRY_L1:L1", "L1", "INDUSTRY_L2:L2", "L2"),
            _edge("INDUSTRY_L2:L2", "L2", "INDUSTRY_L3:L3", "L3"),
            _edge(ROOT_ID, "ROOT", "INDUSTRY_L1:L1", "L1"),
        ]
    return {
        "operation": "PRODUCT_INDUSTRIES",
        "totalCount": total,
        "rows": rows,
        "directEdges": direct_edges,
        "product": product,
    }


def _children_raw(total=1, rows=None, direct_edges=None, parent=None):
    if parent is None:
        parent = {
            "entityId": ROOT_ID,
            "level": "ROOT",
            "canonicalName": "Root",
        }
    if rows is None:
        rows = [
            {
                "sourceId": "L1",
                "canonicalName": "Level 1",
                "level": "L1",
            }
        ]
    if direct_edges is None:
        direct_edges = [_edge(ROOT_ID, "ROOT", "INDUSTRY_L1:L1", "L1")]
    return {
        "operation": "INDUSTRY_CHILDREN",
        "totalCount": total,
        "rows": rows,
        "directEdges": direct_edges,
        "parent": parent,
    }


def _path_raw(path_position=4, total=1, direct_edges=None, node=None):
    nodes = [
        {"entityId": ROOT_ID, "level": "ROOT", "canonicalName": "Root"},
        {"entityId": "INDUSTRY_L1:L1", "level": "L1", "canonicalName": "Level 1", "sourceId": "L1"},
        {"entityId": "INDUSTRY_L2:L2", "level": "L2", "canonicalName": "Level 2", "sourceId": "L2"},
        {"entityId": "INDUSTRY_L3:L3", "level": "L3", "canonicalName": "Level 3", "sourceId": "L3"},
    ]
    if node is None:
        node = nodes[path_position - 1]
    if direct_edges is None:
        hierarchy_edges = [
            _edge(ROOT_ID, "ROOT", "INDUSTRY_L1:L1", "L1"),
            _edge("INDUSTRY_L1:L1", "L1", "INDUSTRY_L2:L2", "L2"),
            _edge("INDUSTRY_L2:L2", "L2", "INDUSTRY_L3:L3", "L3"),
        ]
        direct_edges = sorted(
            hierarchy_edges[: max(path_position - 1, 0)],
            key=lambda edge: tuple(
                edge[field]
                for field in ("parentEntityId", "parentLevel", "childEntityId", "childLevel")
            ),
        )
    flat = {
        "rootId": ROOT_ID,
        "rootName": "Root",
        "l1Id": "L1",
        "l1Name": "Level 1",
        "l2Id": "L2",
        "l2Name": "Level 2",
        "l3Id": "L3",
        "l3Name": "Level 3",
        "pathPosition": path_position,
    }
    return {
        "operation": "INDUSTRY_PARENT_PATH",
        "totalCount": total,
        "rows": [flat] if total else [],
        "directEdges": direct_edges,
        "node": node if total else None,
    }


def _raw_for(request):
    operation = request["operation"]
    if operation == "RESOLVE_CATALOG":
        return {
            "operation": operation,
            "totalCount": 1,
            "rows": [
                {
                    "entityId": "PRODUCT:P1",
                    "entityKind": "PRODUCT",
                    "canonicalName": "Product 1",
                    "matchedField": "PD_NAME",
                    "matchKind": "EXACT",
                }
            ],
            "directEdges": [],
        }
    if operation == "SEARCH_PRODUCTS":
        return {
            "operation": operation,
            "totalCount": 1,
            "rows": [
                {
                    "pdId": "P1",
                    "yc11PdCd": "C1",
                    "pdName": "Product 1",
                    "isEff": "1",
                }
            ],
            "directEdges": [],
        }
    if operation == "PRODUCT_INDUSTRIES":
        return _product_raw()
    if operation == "INDUSTRY_CHILDREN":
        return _children_raw()
    return _path_raw()


class FakeSchema:
    def __init__(self, *, request_valid=True, response_valid=True, events=None, failure=None):
        self.request_valid = request_valid
        self.response_valid = response_valid
        self.events = events if events is not None else []
        self.failure = failure
        self.calls = []

    def validate(self, contract, instance):
        self.calls.append((contract, copy.deepcopy(instance)))
        self.events.append("schema:" + contract)
        if self.failure is not None:
            raise self.failure
        if contract in {"preflightRequest", "catalogRequest"}:
            return self.request_valid
        return self.response_valid


class DelegatingSchema:
    def __init__(self, delegate):
        self.delegate = delegate
        self.calls = []

    def validate(self, contract, instance):
        self.calls.append((contract, copy.deepcopy(instance)))
        return self.delegate.validate(contract, instance)


class SchemaFactory:
    def __init__(self, schema):
        self.schema = schema
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.schema


class FixtureRunner:
    def __init__(self, result_factory, events=None):
        self.result_factory = result_factory
        self.events = events if events is not None else []
        self.calls = []

    def __call__(self, plan, secret):
        self.calls.append((plan, secret))
        self.events.append("runner")
        return self.result_factory(plan)


class FixtureCredentials:
    def __init__(self, events=None, result=None, error=None):
        self.events = events if events is not None else []
        self.result = result if result is not None else Secret("fixture-secret")
        self.error = error
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.events.append("credentials")
        if self.error is not None:
            raise self.error
        return self.result


class FixtureSnapshot:
    def __init__(self, events=None, result=None, error=None):
        self.events = events if events is not None else []
        self.result = result if result is not None else _snapshot()
        self.error = error
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.events.append("snapshot")
        if self.error is not None:
            raise self.error
        return self.result


def make_adapter(*, raw_factory=None, snapshot=None, credentials=None, schema=None, query_ids=None, events=None, runner_error=None):
    events = events if events is not None else []
    snapshot_loader = snapshot if snapshot is not None else FixtureSnapshot(events=events)
    credential_reader = credentials if credentials is not None else FixtureCredentials(events=events)
    schema_client = schema if schema is not None else FakeSchema(events=events)
    schema_factory = SchemaFactory(schema_client)

    def result_factory(plan):
        if runner_error is not None:
            raise runner_error
        raw = raw_factory(plan) if raw_factory is not None else _raw_for(SEARCH_REQUEST)
        if plan.operation == "kingbase_readonly_preflight":
            return PsqlResult(_preflight_raw(), None, None)
        return PsqlResult(_preflight_raw(), raw, None)

    runner = FixtureRunner(result_factory, events=events)
    query_id_factory = (lambda: QUERY_ID) if query_ids is None else query_ids
    instance = adapter.KingbaseReadonlyAdapter(
        snapshot_loader=snapshot_loader,
        credential_reader=credential_reader,
        runner=runner,
        schema_factory=schema_factory,
        query_id_factory=query_id_factory,
    )
    return instance, snapshot_loader, credential_reader, runner, schema_client


class AdapterPipelineTest(unittest.TestCase):
    def test_each_call_fresh_loads_sha_bound_snapshot_before_credentials_and_runner(self):
        events = []
        snapshot = FixtureSnapshot(events=events)
        credentials = FixtureCredentials(events=events)
        instance, _, _, runner, _ = make_adapter(snapshot=snapshot, credentials=credentials, events=events)
        first = instance.catalog(SEARCH_REQUEST)
        second = instance.catalog(SEARCH_REQUEST)
        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.assertEqual(snapshot.calls, 2)
        self.assertEqual(credentials.calls, 2)
        self.assertEqual(len(runner.calls), 2)
        first_run = [event for event in events if not event.startswith("schema:")]
        self.assertEqual(first_run[:3], ["snapshot", "credentials", "runner"])
        self.assertEqual(first_run[3:6], ["snapshot", "credentials", "runner"])

    def test_snapshot_failure_prevents_credentials_and_psql_for_preflight_and_catalog(self):
        for failure in (metadata_contract.MetadataMismatch(), ValueError("tampered")):
            for method, request in (("preflight", {}), ("catalog", SEARCH_REQUEST)):
                events = []
                snapshot = FixtureSnapshot(events=events, error=failure)
                credentials = FixtureCredentials(events=events)
                instance, _, _, runner, _ = make_adapter(snapshot=snapshot, credentials=credentials, events=events)
                response = getattr(instance, method)(request)
                with self.subTest(method=method, failure=type(failure).__name__):
                    self.assertFalse(response["success"])
                    self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
                    self.assertEqual(credentials.calls, 0)
                    self.assertEqual(len(runner.calls), 0)

    def test_invalid_extra_sql_pagination_and_unknown_requests_fail_before_credentials(self):
        invalid = [
            dict(RESOLVE_REQUEST, sql="select 1"),
            dict(RESOLVE_REQUEST, offset=0),
            dict(RESOLVE_REQUEST, page=1),
            dict(RESOLVE_REQUEST, cursor="x"),
            dict(RESOLVE_REQUEST, orderBy="x"),
        ]
        for request in invalid:
            events = []
            schema = FakeSchema(events=events)
            instance, snapshot, credentials, runner, _ = make_adapter(schema=schema, events=events)
            response = instance.catalog(request)
            with self.subTest(request=request):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], "POLICY_DENIED")
                self.assertEqual(snapshot.calls, 0)
                self.assertEqual(credentials.calls, 0)
                self.assertEqual(len(runner.calls), 0)

        events = []
        schema = FakeSchema(request_valid=True, events=events)
        instance, snapshot, credentials, runner, _ = make_adapter(schema=schema, events=events)
        response = instance.catalog({"operation": "DROP_ALL", "sql": "select 1"})
        self.assertFalse(response["success"])
        self.assertEqual(response["operation"], "UNKNOWN_OPERATION")
        self.assertEqual(response["errorCode"], "POLICY_DENIED")
        self.assertEqual(snapshot.calls, 0)
        self.assertEqual(credentials.calls, 0)
        self.assertEqual(len(runner.calls), 0)

    def test_one_credential_one_plan_one_runner_result_and_no_retry(self):
        instance, snapshot, credentials, runner, _ = make_adapter()
        response = instance.catalog(SEARCH_REQUEST)
        self.assertTrue(response["success"])
        self.assertEqual(snapshot.calls, 1)
        self.assertEqual(credentials.calls, 1)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0][0].operation, "SEARCH_PRODUCTS")

    def test_psql_result_and_runtime_failures_map_to_frozen_messages_without_diagnostics(self):
        cases = (
            ("AUTH_UNAVAILABLE", AuthUnavailable()),
            ("READ_ONLY_REQUIRED", ReadOnlyRequired()),
            ("DATA_CONTRACT_MISMATCH", PsqlResult(None, None, "DATA_CONTRACT_MISMATCH")),
            ("QUERY_FAILED", QueryFailed()),
            ("RESULT_TOO_LARGE", ResultTooLarge()),
        )
        messages = {
            "AUTH_UNAVAILABLE": "credential unavailable",
            "READ_ONLY_REQUIRED": "read-only boundary unavailable",
            "DATA_CONTRACT_MISMATCH": "data contract mismatch",
            "QUERY_FAILED": "query failed",
            "RESULT_TOO_LARGE": "result exceeds limit",
        }
        for code, failure in cases:
            def result_factory(plan, failure=failure):
                if isinstance(failure, PsqlResult):
                    return failure
                raise failure

            events = []
            schema = FakeSchema(events=events)
            snapshot = FixtureSnapshot(events=events)
            credentials = FixtureCredentials(events=events)
            runner = FixtureRunner(result_factory, events=events)
            instance = adapter.KingbaseReadonlyAdapter(
                snapshot_loader=snapshot,
                credential_reader=credentials,
                runner=runner,
                schema_factory=SchemaFactory(schema),
                query_id_factory=lambda: QUERY_ID,
            )
            response = instance.catalog(SEARCH_REQUEST)
            with self.subTest(code=code):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], code)
                self.assertEqual(response["message"], messages[code])
                self.assertEqual(response["data"], None)
                self.assertNotIn("fixture", repr(response))
                self.assertEqual(len(runner.calls), 1)


class PreflightNormalizationTest(unittest.TestCase):
    def test_preflight_has_exact_three_public_objects_and_unified_date(self):
        instance, _, _, _, _ = make_adapter()
        response = instance.preflight({})
        self.assertTrue(response["success"])
        self.assertEqual(response["dataAsOf"], DATA_AS_OF)
        self.assertEqual(response["readBoundary"], READ_BOUNDARY)
        self.assertEqual([obj["table"] for obj in response["objects"]], [
            "T_EDW_VAR_PD_INFO_Q",
            "T_EDW_VAR_PD_IDTY_RELA_Q",
            "T_EDW_VAR_HCZQ_IDTY_CLAS_Q",
        ])
        for obj in response["objects"]:
            self.assertEqual(obj["rowCount"], obj["uniqueKeyCount"])
            self.assertNotIn("CRT_TIME", obj["columns"])
            self.assertNotIn("UPDT_TIME", obj["columns"])
            self.assertNotIn("MEMO", obj["columns"])

    def test_preflight_bad_date_or_privilege_is_contract_mismatch_without_public_private_values(self):
        for overrides in (
            {"dataAsOfRaw": "20260230"},
            {"privilegeMode": "WRITE_CAPABLE"},
            {"databasePrivilegeRisk": "secret diagnostic"},
        ):
            def raw_factory(plan, overrides=overrides):
                return _raw_for(SEARCH_REQUEST)

            events = []
            snapshot = FixtureSnapshot(events=events)
            credentials = FixtureCredentials(events=events)
            schema = FakeSchema(events=events)

            def result_factory(plan, overrides=overrides):
                return PsqlResult(_preflight_raw(**overrides), None, None)

            runner = FixtureRunner(result_factory, events=events)
            instance = adapter.KingbaseReadonlyAdapter(
                snapshot_loader=snapshot,
                credential_reader=credentials,
                runner=runner,
                schema_factory=SchemaFactory(schema),
                query_id_factory=lambda: QUERY_ID,
            )
            response = instance.preflight({})
            with self.subTest(overrides=overrides):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
                self.assertEqual(response["objects"], [])
                self.assertIsNone(response["readBoundary"])
                self.assertIsNone(response["dataAsOf"])


class CatalogNormalizationTest(unittest.TestCase):
    def _catalog(self, request, raw):
        def raw_factory(plan):
            return raw

        instance, _, _, _, schema = make_adapter(raw_factory=raw_factory)
        response = instance.catalog(request)
        self.assertTrue(schema.calls)
        return response, schema

    def test_all_five_operations_normalize_empty_and_available_payloads(self):
        cases = (
            (RESOLVE_REQUEST, _raw_for(RESOLVE_REQUEST)),
            (SEARCH_REQUEST, _raw_for(SEARCH_REQUEST)),
            (PRODUCT_REQUEST, _product_raw()),
            (CHILDREN_REQUEST, _children_raw()),
            (PATH_REQUEST, _path_raw()),
        )
        for request, raw in cases:
            response, schema = self._catalog(request, raw)
            with self.subTest(operation=request["operation"]):
                self.assertTrue(response["success"])
                self.assertEqual(response["operation"], request["operation"])
                self.assertEqual(response["dataStatus"], "AVAILABLE")
                self.assertEqual(response["returnedCount"], len(response["data"]["rows"]))
                self.assertEqual(response["truncated"], False)
                self.assertEqual(response["queryId"], QUERY_ID)
                self.assertEqual(response["readBoundary"], READ_BOUNDARY)
                self.assertEqual(schema.calls[-1][0], "catalogResponse")
                self.assertNotIn("directEdges", response["data"])

        empty_cases = (
            (RESOLVE_REQUEST, dict(_raw_for(RESOLVE_REQUEST), totalCount=0, rows=[])),
            (SEARCH_REQUEST, dict(_raw_for(SEARCH_REQUEST), totalCount=0, rows=[])),
            (PRODUCT_REQUEST, _product_raw(total=0, rows=[], direct_edges=[])),
            (CHILDREN_REQUEST, _children_raw(total=0, rows=[], direct_edges=[])),
            (PATH_REQUEST, _path_raw(total=0, direct_edges=[])),
        )
        for request, raw in empty_cases:
            response, _ = self._catalog(request, raw)
            with self.subTest(empty=request["operation"]):
                if request["operation"] == "INDUSTRY_PARENT_PATH":
                    self.assertFalse(response["success"])
                    self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
                else:
                    self.assertTrue(response["success"])
                    self.assertEqual(response["dataStatus"], "EMPTY")
                    self.assertEqual(response["totalCount"], 0)
                    self.assertEqual(response["returnedCount"], 0)
                    self.assertFalse(response["truncated"])

    def test_search_normalizes_product_ids_and_product_industries_nodes_canonically(self):
        response, _ = self._catalog(SEARCH_REQUEST, _raw_for(SEARCH_REQUEST))
        self.assertEqual(response["data"]["rows"][0]["entityId"], "PRODUCT:P1")

        response, _ = self._catalog(PRODUCT_REQUEST, _product_raw())
        self.assertEqual(response["data"]["product"]["entityId"], "PRODUCT:P1")
        nodes = response["data"]["rows"][0]["nodes"]
        self.assertEqual([node["level"] for node in nodes], ["ROOT", "L1", "L2", "L3"])
        self.assertEqual(nodes[0]["entityId"], industry_root_id("Root"))
        self.assertNotIn("sourceId", nodes[0])
        self.assertEqual(nodes[1]["entityId"], "INDUSTRY_L1:L1")

    def test_children_parent_root_l1_l2_and_parent_path_root_l1_l2_l3_are_public_shaped(self):
        for parent_id, level, source_id, name in (
            (ROOT_ID, "ROOT", None, "Root"),
            ("INDUSTRY_L1:L1", "L1", "L1", "Level 1"),
            ("INDUSTRY_L2:L2", "L2", "L2", "Level 2"),
        ):
            request = dict(CHILDREN_REQUEST, parentEntityId=parent_id)
            parent = {"entityId": parent_id, "level": level, "canonicalName": name}
            if source_id is not None:
                parent["sourceId"] = source_id
            raw = _children_raw(parent=parent, rows=[], total=0, direct_edges=[])
            response, _ = self._catalog(request, raw)
            with self.subTest(parent=parent_id):
                self.assertTrue(response["success"])
                self.assertEqual(response["data"]["parent"], parent)

        for path_position, request_id in enumerate((ROOT_ID, "INDUSTRY_L1:L1", "INDUSTRY_L2:L2", "INDUSTRY_L3:L3"), 1):
            request = dict(PATH_REQUEST, industryEntityId=request_id)
            response, _ = self._catalog(request, _path_raw(path_position=path_position))
            with self.subTest(path=request_id):
                self.assertTrue(response["success"])
                self.assertEqual(response["data"]["node"]["entityId"], request_id)
                self.assertEqual(len(response["data"]["rows"][0]["nodes"]), path_position)

    def test_null_conflicting_malformed_and_operation_mismatched_internal_context_fail_closed(self):
        cases = (
            (PRODUCT_REQUEST, dict(_product_raw(), product=None), "DATA_CONTRACT_MISMATCH"),
            (
                PRODUCT_REQUEST,
                dict(
                    _product_raw(),
                    product={
                        "pdId": "P1",
                        "yc11PdCd": "C1",
                        "pdName": "Product 1",
                        "isEff": "1",
                    },
                ),
                "DATA_CONTRACT_MISMATCH",
            ),
            (PRODUCT_REQUEST, dict(_product_raw(), operation="SEARCH_PRODUCTS"), "DATA_CONTRACT_MISMATCH"),
            (SEARCH_REQUEST, dict(_raw_for(SEARCH_REQUEST), directEdges=[{"bad": True}]), "DATA_CONTRACT_MISMATCH"),
            (CHILDREN_REQUEST, _children_raw(parent={"entityId": "INDUSTRY_ROOT:Other", "level": "ROOT", "canonicalName": "Other"}), "DATA_CONTRACT_MISMATCH"),
        )
        for request, raw, expected in cases:
            response, _ = self._catalog(request, raw)
            with self.subTest(operation=request["operation"], raw=raw):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], expected)
                self.assertIsNone(response["data"])

    def test_success_is_semantically_validated_before_publication(self):
        raw = _children_raw(
            direct_edges=[_edge(ROOT_ID, "ROOT", "INDUSTRY_L1:OTHER", "L1")],
            rows=[{"sourceId": "L1", "canonicalName": "Level 1", "level": "L1"}],
        )
        response, _ = self._catalog(CHILDREN_REQUEST, raw)
        self.assertFalse(response["success"])
        self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
        self.assertIsNone(response["data"])

    def test_children_reject_duplicate_canonical_child_entity_ids_without_retry(self):
        for names in (("Level 1", "Level 1"), ("Level 1", "Conflicting Name")):
            raw = _children_raw(
                total=2,
                rows=[
                    {"sourceId": "L1", "canonicalName": name, "level": "L1"}
                    for name in names
                ],
                direct_edges=[_edge(ROOT_ID, "ROOT", "INDUSTRY_L1:L1", "L1")],
            )
            instance, _, _, runner, _ = make_adapter(raw_factory=lambda plan, raw=raw: raw)
            response = instance.catalog(CHILDREN_REQUEST)
            with self.subTest(names=names):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
                self.assertIsNone(response["data"])
                self.assertEqual(len(runner.calls), 1)

    def test_catalog_rejects_unrelated_extra_direct_edges_without_retry(self):
        cases = (
            (
                PRODUCT_REQUEST,
                dict(
                    _product_raw(),
                    directEdges=_product_raw()["directEdges"]
                    + [_edge("INDUSTRY_ROOT:Other", "ROOT", "INDUSTRY_L1:Other", "L1")],
                ),
            ),
            (
                CHILDREN_REQUEST,
                dict(
                    _children_raw(),
                    directEdges=_children_raw()["directEdges"]
                    + [_edge("INDUSTRY_ROOT:Other", "ROOT", "INDUSTRY_L1:Other", "L1")],
                ),
            ),
            (
                PATH_REQUEST,
                dict(
                    _path_raw(),
                    directEdges=_path_raw()["directEdges"]
                    + [_edge("INDUSTRY_L2:Other", "L2", "INDUSTRY_L3:Other", "L3")],
                ),
            ),
        )
        for request, raw in cases:
            instance, _, _, runner, _ = make_adapter(raw_factory=lambda plan, raw=raw: raw)
            response = instance.catalog(request)
            with self.subTest(operation=request["operation"]):
                self.assertFalse(response["success"])
                self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
                self.assertIsNone(response["data"])
                self.assertEqual(len(runner.calls), 1)

    def test_total_count_binding_limit_and_parent_path_nontruncation(self):
        limited_request = dict(SEARCH_REQUEST, limit=1)
        raw = _raw_for(limited_request)
        raw["totalCount"] = 2
        response, _ = self._catalog(limited_request, raw)
        self.assertTrue(response["success"])
        self.assertEqual(response["returnedCount"], 1)
        self.assertTrue(response["truncated"])

        raw = _raw_for(SEARCH_REQUEST)
        raw["totalCount"] = 3
        raw["rows"] = [raw["rows"][0], copy.deepcopy(raw["rows"][0])]
        raw["rows"][1]["pdId"] = "P2"
        raw["rows"][1]["yc11PdCd"] = "C2"
        response, _ = self._catalog(SEARCH_REQUEST, raw)
        self.assertFalse(response["success"])

        raw = _path_raw(path_position=4)
        raw["totalCount"] = 2
        response, _ = self._catalog(PATH_REQUEST, raw)
        self.assertFalse(response["success"])


class SchemaBoundaryTest(unittest.TestCase):
    def test_preflight_shape_passes_real_injected_ajv_worker(self):
        with SchemaClient() as schema:
            recorder = DelegatingSchema(schema)
            instance, _, _, _, _ = make_adapter(schema=recorder)
            response = instance.preflight({})
            self.assertTrue(response["success"], {"response": response, "calls": recorder.calls})

    def test_successful_catalog_shapes_pass_the_real_injected_ajv_worker(self):
        with SchemaClient() as schema:
            recorder = DelegatingSchema(schema)
            raw_by_operation = {
                request["operation"]: _raw_for(request)
                for request in (
                    RESOLVE_REQUEST,
                    SEARCH_REQUEST,
                    PRODUCT_REQUEST,
                    CHILDREN_REQUEST,
                    PATH_REQUEST,
                )
            }
            for request in (
                RESOLVE_REQUEST,
                SEARCH_REQUEST,
                PRODUCT_REQUEST,
                CHILDREN_REQUEST,
                PATH_REQUEST,
            ):
                instance, _, _, _, _ = make_adapter(
                    schema=recorder,
                    raw_factory=lambda plan, raw_by_operation=raw_by_operation: raw_by_operation[plan.operation],
                )
                response = instance.catalog(request)
                with self.subTest(operation=request["operation"]):
                    self.assertTrue(response["success"], {"response": response, "calls": recorder.calls})

    def test_response_schema_is_called_before_semantics_and_rejected_output_is_not_published(self):
        events = []
        schema = FakeSchema(events=events, response_valid=True)
        instance, _, _, _, _ = make_adapter(schema=schema, events=events)
        raw = _children_raw(
            direct_edges=[_edge(ROOT_ID, "ROOT", "INDUSTRY_L1:OTHER", "L1")],
            rows=[{"sourceId": "L1", "canonicalName": "Level 1", "level": "L1"}],
        )
        instance, _, _, _, schema = make_adapter(
            schema=schema,
            events=events,
            raw_factory=lambda plan: raw,
        )
        response = instance.catalog(CHILDREN_REQUEST)
        self.assertFalse(response["success"])
        self.assertEqual(response["errorCode"], "DATA_CONTRACT_MISMATCH")
        self.assertIsNone(response["data"])
        self.assertEqual(
            [contract for contract, _ in schema.calls],
            ["catalogRequest", "catalogResponse", "catalogResponse"],
        )

    def test_schema_worker_unavailable_crash_or_reject_fails_closed_without_manual_publication(self):
        for failure in (adapter.SchemaUnavailable("down"), EOFError("crash")):
            schema = FakeSchema(events=[], failure=failure)
            instance, _, _, _, _ = make_adapter(schema=schema)
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(adapter.AdapterUnavailable):
                    instance.catalog(SEARCH_REQUEST)

        schema = FakeSchema(events=[], response_valid=False)
        instance, _, _, _, _ = make_adapter(schema=schema)
        with self.assertRaises(adapter.AdapterUnavailable):
            instance.catalog(SEARCH_REQUEST)

    def test_query_id_is_lowercase_hex_and_only_unified_date_drives_public_data_as_of(self):
        ids = iter(("ABC", "a" * 16, "f" * 64))
        instance, _, _, _, _ = make_adapter(query_ids=lambda: next(ids))
        response = instance.catalog(SEARCH_REQUEST)
        self.assertFalse(response["success"])

        instance, _, _, _, _ = make_adapter(query_ids=lambda: "a" * 16)
        response = instance.catalog(SEARCH_REQUEST)
        self.assertTrue(response["success"])
        self.assertRegex(response["queryId"], re.compile(r"^[a-f0-9]{16,64}$"))
        self.assertEqual(response["dataAsOf"], DATA_AS_OF)

    def test_catalog_public_response_cap_is_enforced(self):
        huge = _raw_for(SEARCH_REQUEST)
        huge["rows"][0]["pdName"] = "x" * (1024 * 1024)
        response, _ = self._catalog_with_raw(SEARCH_REQUEST, huge)
        self.assertFalse(response["success"])
        self.assertEqual(response["errorCode"], "RESULT_TOO_LARGE")
        self.assertIsNone(response["data"])

    def _catalog_with_raw(self, request, raw):
        instance, _, _, _, schema = make_adapter(raw_factory=lambda plan: raw)
        return instance.catalog(request), schema


if __name__ == "__main__":
    unittest.main()
