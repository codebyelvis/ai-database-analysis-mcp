"""Deterministic public projection from Skill tools to the private catalog MCP."""

from __future__ import annotations

import copy
import re
from typing import Any, Callable

from private_mcp_client import PrivateMcpClient, PrivateMcpUnavailable


_LOCAL_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_CATALOG_PREFIXES = (
    "PRODUCT:",
    "INDUSTRY_ROOT:",
    "INDUSTRY_L1:",
    "INDUSTRY_L2:",
    "INDUSTRY_L3:",
)
_CHILDREN_PREFIXES = ("INDUSTRY_ROOT:", "INDUSTRY_L1:", "INDUSTRY_L2:")
_INDUSTRY_PREFIXES = _CATALOG_PREFIXES[1:]
_SUPPORTED_RELATIONS = frozenset({"CHILDREN", "PARENT_PATH"})
_RELATION_OUTPUT = {"CHILDREN": "NODE_SET", "PARENT_PATH": "PATH_RESULT"}
_KNOWN_RELATIONS = frozenset(
    {
        "CHILDREN",
        "PARENT_PATH",
        "UPSTREAM",
        "COMPONENTS",
        "DOWNSTREAM",
        "APPLICATIONS",
        "RELATED_COMPANIES",
        "COMPANY_PRODUCTS",
        "RANK_COMPANIES",
        "GET_NODE_METRICS",
        "EVIDENCE",
        "COMPANY_PROFILE",
        "COMPANY_INDUSTRY_POSITIONS",
    }
)


class _BridgeRequestError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise _BridgeRequestError(code, message)


def _is_local_id(value: Any) -> bool:
    return isinstance(value, str) and _LOCAL_ID.fullmatch(value) is not None


def _is_catalog_id(value: Any) -> bool:
    return isinstance(value, str) and any(value.startswith(prefix) for prefix in _CATALOG_PREFIXES)


def _catalog_entity(value: Any) -> dict[str, str]:
    _require(isinstance(value, dict), "INVALID_ENTITY_SOURCE", "catalog entity is required")
    _require(
        set(value) == {"entityId", "entityType", "canonicalName"},
        "INVALID_ENTITY_SOURCE",
        "catalog entity shape is invalid",
    )
    _require(value.get("entityType") == "CATALOG_NODE", "INPUT_TYPE_MISMATCH", "catalog entity type is required")
    _require(_is_catalog_id(value.get("entityId")), "INVALID_ENTITY_SOURCE", "catalog entity id is invalid")
    _require(
        isinstance(value.get("canonicalName"), str) and 1 <= len(value["canonicalName"]) <= 200,
        "INVALID_ENTITY_SOURCE",
        "catalog canonical name is invalid",
    )
    return copy.deepcopy(value)


def _private_success(response: Any, operation: str) -> tuple[list[dict[str, Any]], str, int, bool]:
    if not isinstance(response, dict) or response.get("operation") != operation:
        raise PrivateMcpUnavailable()
    if response.get("success") is not True:
        raise PrivateMcpUnavailable()
    rows = (response.get("data") or {}).get("rows")
    data_as_of = response.get("dataAsOf")
    total_count = response.get("totalCount")
    truncated = response.get("truncated")
    if (
        not isinstance(rows, list)
        or not isinstance(data_as_of, str)
        or _DATE.fullmatch(data_as_of) is None
        or not isinstance(total_count, int)
        or isinstance(total_count, bool)
        or total_count < 0
        or not isinstance(truncated, bool)
        or response.get("returnedCount") != len(rows)
    ):
        raise PrivateMcpUnavailable()
    return rows, data_as_of, total_count, truncated


def _public_entity(row: Any) -> dict[str, str]:
    if not isinstance(row, dict):
        raise PrivateMcpUnavailable()
    entity_id = row.get("entityId")
    canonical_name = row.get("canonicalName")
    if not _is_catalog_id(entity_id) or not isinstance(canonical_name, str) or not canonical_name:
        raise PrivateMcpUnavailable()
    return {
        "entityId": entity_id,
        "entityType": "CATALOG_NODE",
        "canonicalName": canonical_name,
    }


def _public_node(row: Any, *, with_status: bool) -> dict[str, Any]:
    entity = _public_entity(row)
    level = row.get("level") if isinstance(row, dict) else None
    if level not in {"ROOT", "L1", "L2", "L3"}:
        raise PrivateMcpUnavailable()
    entity["nodeLevel"] = level
    entity["mockData"] = False
    if with_status:
        entity["dataStatus"] = "AVAILABLE"
    return entity


class IndustrySelectionBridge:
    def __init__(
        self,
        *,
        private_client: Any | None = None,
        private_factory: Callable[[], Any] = PrivateMcpClient,
    ) -> None:
        self._private = private_client if private_client is not None else private_factory()
        self._closed = False

    def _entity_failure(
        self,
        code: str,
        message: str,
        results: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        return {
            "success": False,
            "operation": "entity_resolve",
            "mockData": False,
            "resolutionResults": results or [],
            "resolvedPlan": None,
            "errorCode": code,
            "message": message,
            "retryable": False,
        }

    def _validate_entity_request(
        self, request: Any
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        _require(
            isinstance(request, dict)
            and set(request) == {"operation", "mentions", "queryPlan"}
            and request.get("operation") == "entity_resolve",
            "INVALID_REQUEST",
            "entity request is invalid",
        )
        mentions = request.get("mentions")
        _require(isinstance(mentions, list) and 1 <= len(mentions) <= 8, "INVALID_REQUEST", "mention count is invalid")
        mention_ids: list[str] = []
        for mention in mentions:
            _require(
                isinstance(mention, dict)
                and set(mention) <= {"mentionId", "text", "searchText", "expectedEntityTypes"}
                and {"mentionId", "text", "expectedEntityTypes"} <= set(mention),
                "INVALID_REQUEST",
                "mention shape is invalid",
            )
            mention_id = mention.get("mentionId")
            expected = mention.get("expectedEntityTypes")
            _require(_is_local_id(mention_id), "INVALID_REQUEST", "mention id is invalid")
            _require(
                isinstance(mention.get("text"), str) and 1 <= len(mention["text"]) <= 200,
                "INVALID_REQUEST",
                "mention text is invalid",
            )
            if "searchText" in mention:
                _require(
                    isinstance(mention["searchText"], str) and 1 <= len(mention["searchText"]) <= 200,
                    "INVALID_REQUEST",
                    "mention search text is invalid",
                )
            _require(
                isinstance(expected, list)
                and 1 <= len(expected) <= 2
                and len(expected) == len(set(expected))
                and set(expected) <= {"CATALOG_NODE", "COMPANY"},
                "INVALID_REQUEST",
                "mention entity types are invalid",
            )
            mention_ids.append(mention_id)
        _require(len(mention_ids) == len(set(mention_ids)), "INVALID_REQUEST", "mention ids must be unique")

        plan = request.get("queryPlan")
        _require(isinstance(plan, dict) and set(plan) == {"planId", "steps"}, "INVALID_REQUEST", "query plan is invalid")
        _require(_is_local_id(plan.get("planId")), "INVALID_REQUEST", "plan id is invalid")
        steps = plan.get("steps")
        _require(isinstance(steps, list) and 1 <= len(steps) <= 20, "PLAN_LIMIT_EXCEEDED", "step count is invalid")
        step_ids: list[str] = []
        referenced_mentions: set[str] = set()
        seen_steps: set[str] = set()
        for step in steps:
            _require(isinstance(step, dict), "INVALID_REQUEST", "plan step is invalid")
            step_id = step.get("stepId")
            _require(_is_local_id(step_id) and step_id not in seen_steps, "INVALID_PLAN_DEPENDENCY", "step id is invalid")
            seen_steps.add(step_id)
            step_ids.append(step_id)
            _require(step.get("relation") in _KNOWN_RELATIONS, "INVALID_REQUEST", "relation is invalid")
            _require(isinstance(step.get("presentation"), dict), "INVALID_REQUEST", "presentation is invalid")
            source = step.get("input")
            _require(isinstance(source, dict), "INVALID_REQUEST", "step input is invalid")
            if source.get("sourceType") == "MENTION":
                _require(set(source) == {"sourceType", "mentionId"}, "INVALID_REQUEST", "mention input is invalid")
                _require(source.get("mentionId") in mention_ids, "INVALID_REQUEST", "unknown mention reference")
                referenced_mentions.add(source["mentionId"])
            elif source.get("sourceType") == "STEP_RESULT":
                _require(
                    source.get("sourceStepId") in seen_steps - {step_id},
                    "INVALID_PLAN_DEPENDENCY",
                    "step dependency must precede its consumer",
                )
            else:
                raise _BridgeRequestError("INVALID_REQUEST", "unresolved plan source is invalid")
        _require(referenced_mentions == set(mention_ids), "INVALID_REQUEST", "mentions and plan references differ")
        return copy.deepcopy(mentions), copy.deepcopy(plan)

    @staticmethod
    def _compile_plan(
        plan: dict[str, Any], resolved: dict[str, dict[str, str]]
    ) -> dict[str, Any]:
        compiled = copy.deepcopy(plan)
        for step in compiled["steps"]:
            source = step["input"]
            if source.get("sourceType") == "MENTION":
                step["input"] = {
                    "sourceType": "ENTITY",
                    "entity": copy.deepcopy(resolved[source["mentionId"]]),
                }
            if "references" in step:
                references = []
                for reference in step["references"]:
                    if reference.get("sourceType") == "MENTION":
                        references.append(
                            {
                                "role": reference["role"],
                                "sourceType": "ENTITY",
                                "entity": copy.deepcopy(resolved[reference["mentionId"]]),
                            }
                        )
                    else:
                        references.append(copy.deepcopy(reference))
                step["references"] = references
        return compiled

    def entity_resolve(self, request: Any) -> dict[str, Any]:
        try:
            mentions, plan = self._validate_entity_request(request)
        except _BridgeRequestError as error:
            return self._entity_failure(error.code, str(error))

        if any("COMPANY" in mention["expectedEntityTypes"] for mention in mentions):
            results = [
                {
                    "mentionId": mention["mentionId"],
                    "resolutionStatus": "ERROR",
                    "mockData": False,
                    "message": "company resolution is unavailable",
                }
                for mention in mentions
            ]
            return self._entity_failure(
                "RESOLUTION_UNAVAILABLE", "company resolution is unavailable", results
            )

        results: list[dict[str, Any]] = []
        resolved: dict[str, dict[str, str]] = {}
        for mention in mentions:
            query_text = mention.get("searchText") or mention["text"]
            try:
                response = self._private.call_catalog(
                    {
                        "operation": "RESOLVE_CATALOG",
                        "text": query_text,
                        "expectedEntityType": "ANY",
                        "limit": 10,
                    }
                )
                rows, _date, _total, _truncated = _private_success(
                    response, "RESOLVE_CATALOG"
                )
                if not rows:
                    result = {
                        "mentionId": mention["mentionId"],
                        "resolutionStatus": "NOT_FOUND",
                        "mockData": False,
                        "searchedText": query_text,
                        "candidates": [],
                    }
                elif len(rows) == 1:
                    public = _public_entity(rows[0])
                    result = {
                        "mentionId": mention["mentionId"],
                        "resolutionStatus": "RESOLVED",
                        "mockData": False,
                        "resolved": public,
                    }
                    resolved[mention["mentionId"]] = public
                else:
                    result = {
                        "mentionId": mention["mentionId"],
                        "resolutionStatus": "AMBIGUOUS",
                        "mockData": False,
                        "candidates": [_public_entity(row) for row in rows],
                    }
                results.append(result)
            except Exception:
                results.append(
                    {
                        "mentionId": mention["mentionId"],
                        "resolutionStatus": "ERROR",
                        "mockData": False,
                        "message": "catalog resolution is unavailable",
                    }
                )
                return self._entity_failure(
                    "INTERNAL_ERROR", "catalog resolution is unavailable", results
                )

        compiled = (
            self._compile_plan(plan, resolved)
            if len(resolved) == len(mentions)
            else None
        )
        return {
            "success": True,
            "operation": "entity_resolve",
            "mockData": False,
            "resolutionResults": results,
            "resolvedPlan": compiled,
        }

    def _validate_business_request(self, request: Any) -> dict[str, Any]:
        _require(
            isinstance(request, dict)
            and set(request) == {"operation", "resolvedPlan"}
            and request.get("operation") == "business_query",
            "INVALID_REQUEST",
            "business request is invalid",
        )
        plan = request.get("resolvedPlan")
        _require(isinstance(plan, dict) and set(plan) == {"planId", "steps"}, "INVALID_REQUEST", "resolved plan is invalid")
        _require(_is_local_id(plan.get("planId")), "INVALID_REQUEST", "plan id is invalid")
        steps = plan.get("steps")
        _require(isinstance(steps, list) and 1 <= len(steps) <= 20, "PLAN_LIMIT_EXCEEDED", "step count is invalid")
        seen: dict[str, str] = {}
        for step in steps:
            _require(isinstance(step, dict), "INVALID_REQUEST", "step is invalid")
            step_id = step.get("stepId")
            _require(_is_local_id(step_id) and step_id not in seen, "INVALID_PLAN_DEPENDENCY", "step id is invalid")
            relation = step.get("relation")
            _require(relation in _KNOWN_RELATIONS, "UNKNOWN_RELATION", "relation is invalid")
            _require(isinstance(step.get("presentation"), dict), "INVALID_REQUEST", "presentation is invalid")
            source = step.get("input")
            _require(isinstance(source, dict), "INPUT_TYPE_MISMATCH", "step input is invalid")
            if source.get("sourceType") == "ENTITY":
                _catalog_entity(source.get("entity"))
            elif source.get("sourceType") == "STEP_RESULT":
                source_id = source.get("sourceStepId")
                _require(source_id in seen, "INVALID_PLAN_DEPENDENCY", "step dependency must precede its consumer")
                _require(source.get("resultType") == seen[source_id], "INPUT_TYPE_MISMATCH", "dependency result type differs")
                _require(source.get("selector") == "ALL", "INVALID_SELECTOR", "only ALL is supported")
            else:
                raise _BridgeRequestError("INPUT_TYPE_MISMATCH", "step source is invalid")
            expected_output = _RELATION_OUTPUT.get(relation)
            if expected_output is not None:
                _require(step.get("outputType") == expected_output, "OUTPUT_TYPE_MISMATCH", "step output type differs")
            seen[step_id] = step.get("outputType")
        return copy.deepcopy(plan)

    @staticmethod
    def _depends_on(step: dict[str, Any]) -> list[str]:
        source = step["input"]
        return [source["sourceStepId"]] if source.get("sourceType") == "STEP_RESULT" else []

    @staticmethod
    def _step_failure(
        plan_id: str,
        step: dict[str, Any],
        *,
        status: str,
        reason: str,
        message: str | None = None,
        data_as_of: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "planId": plan_id,
            "stepId": step["stepId"],
            "relation": step["relation"],
            "dependsOn": IndustrySelectionBridge._depends_on(step),
            "executionStatus": status,
            "resultType": step["outputType"],
            "dataAsOf": data_as_of,
            "presentation": copy.deepcopy(step["presentation"]),
            "mockData": False,
            "data": None,
            "reasonCode": reason,
        }
        if message is not None:
            result["message"] = message
        return result

    @staticmethod
    def _source_entities(
        step: dict[str, Any], runtime: dict[str, dict[str, Any]]
    ) -> tuple[list[dict[str, str]], str | None]:
        source = step["input"]
        if source["sourceType"] == "ENTITY":
            return [_catalog_entity(source["entity"])], None
        prior = runtime[source["sourceStepId"]]
        if prior["executionStatus"] in {"EMPTY", "SKIPPED_EMPTY_DEPENDENCY"}:
            return [], "EMPTY_DEPENDENCY"
        if prior["executionStatus"] != "OK":
            return [], "ERROR_DEPENDENCY"
        data = prior.get("data") or {}
        nodes = data.get("nodes")
        if not isinstance(nodes, list):
            return [], "ERROR_DEPENDENCY"
        entities: list[dict[str, str]] = []
        seen: set[str] = set()
        for node in nodes:
            entity = {
                "entityId": node.get("entityId"),
                "entityType": node.get("entityType"),
                "canonicalName": node.get("canonicalName"),
            }
            entity = _catalog_entity(entity)
            if entity["entityId"] not in seen:
                seen.add(entity["entityId"])
                entities.append(entity)
        if len(entities) > 20:
            raise _BridgeRequestError("PLAN_LIMIT_EXCEEDED", "source entity count exceeded")
        return entities, None

    def _execute_supported(
        self,
        plan_id: str,
        step: dict[str, Any],
        sources: list[dict[str, str]],
    ) -> dict[str, Any]:
        responses: list[tuple[list[dict[str, Any]], str, int, bool]] = []
        for source in sources:
            entity_id = source["entityId"]
            if step["relation"] == "CHILDREN":
                if not entity_id.startswith(_CHILDREN_PREFIXES):
                    return self._step_failure(
                        plan_id,
                        step,
                        status="ERROR",
                        reason="STEP_EXECUTION_ERROR",
                        message="catalog relation is unavailable",
                    )
                operation = "INDUSTRY_CHILDREN"
                arguments = {
                    "operation": operation,
                    "parentEntityId": entity_id,
                    "limit": 50,
                }
            else:
                if entity_id.startswith("PRODUCT:"):
                    operation = "PRODUCT_INDUSTRIES"
                    arguments = {
                        "operation": operation,
                        "productEntityId": entity_id,
                        "limit": 50,
                    }
                elif entity_id.startswith(_INDUSTRY_PREFIXES):
                    operation = "INDUSTRY_PARENT_PATH"
                    arguments = {"operation": operation, "industryEntityId": entity_id}
                else:
                    return self._step_failure(
                        plan_id,
                        step,
                        status="ERROR",
                        reason="STEP_EXECUTION_ERROR",
                        message="catalog relation is unavailable",
                    )
            response = self._private.call_catalog(arguments)
            responses.append(_private_success(response, operation))

        data_as_of_values = {item[1] for item in responses}
        if len(data_as_of_values) != 1:
            raise PrivateMcpUnavailable()
        data_as_of = next(iter(data_as_of_values))
        rows = [row for response in responses for row in response[0]]
        if not rows:
            return self._step_failure(
                plan_id,
                step,
                status="EMPTY",
                reason="NO_DATA",
                data_as_of=data_as_of,
            )

        if step["relation"] == "CHILDREN":
            nodes: list[dict[str, Any]] = []
            seen: set[str] = set()
            for row in rows:
                node = _public_node(row, with_status=True)
                if node["entityId"] not in seen:
                    seen.add(node["entityId"])
                    nodes.append(node)
            data: dict[str, Any] = {
                "mockData": False,
                "totalCount": sum(item[2] for item in responses),
                "returnedCount": len(nodes),
                "truncated": any(item[3] for item in responses),
                "nodes": nodes,
            }
            if len(sources) == 1:
                data["sourceEntityId"] = sources[0]["entityId"]
        else:
            paths: list[dict[str, Any]] = []
            seen_paths: set[tuple[str, ...]] = set()
            for row in rows:
                private_nodes = row.get("nodes") if isinstance(row, dict) else None
                if not isinstance(private_nodes, list) or not private_nodes:
                    raise PrivateMcpUnavailable()
                public_nodes = [_public_node(node, with_status=False) for node in private_nodes]
                identity = tuple(node["entityId"] for node in public_nodes)
                if identity not in seen_paths:
                    seen_paths.add(identity)
                    paths.append({"nodes": public_nodes})
            data = {
                "mockData": False,
                "totalCount": sum(item[2] for item in responses),
                "returnedCount": len(paths),
                "truncated": any(item[3] for item in responses),
                "paths": paths,
            }
            if len(sources) == 1:
                data["sourceEntityId"] = sources[0]["entityId"]

        return {
            "planId": plan_id,
            "stepId": step["stepId"],
            "relation": step["relation"],
            "dependsOn": self._depends_on(step),
            "executionStatus": "OK",
            "resultType": step["outputType"],
            "dataAsOf": data_as_of,
            "presentation": copy.deepcopy(step["presentation"]),
            "mockData": False,
            "data": data,
        }

    def business_query(self, request: Any) -> dict[str, Any]:
        try:
            plan = self._validate_business_request(request)
        except _BridgeRequestError as error:
            plan_id = (
                ((request or {}).get("resolvedPlan") or {}).get("planId")
                if isinstance(request, dict)
                else None
            )
            return {
                "success": False,
                "operation": "business_query",
                "planId": plan_id if _is_local_id(plan_id) else "invalidPlan",
                "executionStatus": "FAILED",
                "mockData": False,
                "stepResults": [],
                "errorCode": error.code,
                "message": str(error),
                "retryable": False,
            }

        runtime: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        for step in plan["steps"]:
            if step["relation"] not in _SUPPORTED_RELATIONS:
                result = self._step_failure(
                    plan["planId"],
                    step,
                    status="ERROR",
                    reason="STEP_EXECUTION_ERROR",
                    message="relation is outside the current data domain",
                )
            else:
                try:
                    sources, dependency = self._source_entities(step, runtime)
                    if dependency is not None:
                        status = (
                            "SKIPPED_EMPTY_DEPENDENCY"
                            if dependency == "EMPTY_DEPENDENCY"
                            else "SKIPPED_ERROR_DEPENDENCY"
                        )
                        result = self._step_failure(
                            plan["planId"],
                            step,
                            status=status,
                            reason=dependency,
                        )
                    else:
                        result = self._execute_supported(plan["planId"], step, sources)
                except (_BridgeRequestError, PrivateMcpUnavailable, OSError, ValueError):
                    result = self._step_failure(
                        plan["planId"],
                        step,
                        status="ERROR",
                        reason="STEP_EXECUTION_ERROR",
                        message="catalog query is unavailable",
                    )
            runtime[step["stepId"]] = copy.deepcopy(result)
            results.append(result)

        status = "OK" if all(item["executionStatus"] == "OK" for item in results) else "PARTIAL"
        return {
            "success": True,
            "operation": "business_query",
            "planId": plan["planId"],
            "executionStatus": status,
            "mockData": False,
            "stepResults": results,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._private, "close", None)
        if callable(close):
            close()

    def __enter__(self) -> "IndustrySelectionBridge":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
