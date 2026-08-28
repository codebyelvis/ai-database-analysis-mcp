from dataclasses import dataclass
from typing import Any

from canonical import canonical_sha256


RESPONSE_OPERATION_BINDING = "RESPONSE_OPERATION_BINDING"
CONTEXT_OPERATION_BINDING = "CONTEXT_OPERATION_BINDING"
CONTEXT_REQUEST_DIGEST = "CONTEXT_REQUEST_DIGEST"
CONTEXT_DATA_AS_OF = "CONTEXT_DATA_AS_OF"
CONTEXT_EDGE_UNIQUE = "CONTEXT_EDGE_UNIQUE"
CONTEXT_REQUIRED_BINDING = "CONTEXT_REQUIRED_BINDING"
REQUEST_LIMIT_BINDING = "REQUEST_LIMIT_BINDING"
PRODUCT_ID_BINDING = "PRODUCT_ID_BINDING"
PRODUCT_REQUEST_BINDING = "PRODUCT_REQUEST_BINDING"
CHILD_PARENT_BINDING = "CHILD_PARENT_BINDING"
CHILD_DIRECT_PARENT = "CHILD_DIRECT_PARENT"
PRODUCT_PATH_DIRECT_PARENT = "PRODUCT_PATH_DIRECT_PARENT"
PATH_TARGET_BINDING = "PATH_TARGET_BINDING"
PATH_DIRECT_PARENT = "PATH_DIRECT_PARENT"
RESOLVE_MATCH_FIELD = "RESOLVE_MATCH_FIELD"

BASE_CONTEXT_FIELDS = {
    "requestCanonicalSha256",
    "operation",
    "dataAsOf",
    "directEdges",
}


@dataclass(frozen=True)
class SemanticResult:
    ok: bool
    failed_rules: tuple[str, ...]


def _result(failures: list[str]) -> SemanticResult:
    unique = tuple(dict.fromkeys(failures))
    return SemanticResult(not unique, unique)


def _edge_tuple(edge: Any) -> tuple[Any, Any, Any, Any] | None:
    if not isinstance(edge, dict):
        return None
    required = (
        "parentEntityId",
        "parentLevel",
        "childEntityId",
        "childLevel",
    )
    if set(edge) != set(required):
        return None
    return tuple(edge[key] for key in required)


def _path_edges(nodes: Any) -> tuple[tuple[Any, Any, Any, Any], ...] | None:
    if not isinstance(nodes, list):
        return None
    edges = []
    for parent, child in zip(nodes, nodes[1:]):
        if not isinstance(parent, dict) or not isinstance(child, dict):
            return None
        edges.append(
            (
                parent.get("entityId"),
                parent.get("level"),
                child.get("entityId"),
                child.get("level"),
            )
        )
    return tuple(edges)


def _product_id_matches(product: Any) -> bool:
    return (
        isinstance(product, dict)
        and isinstance(product.get("pdId"), str)
        and product.get("entityId") == f"PRODUCT:{product['pdId']}"
    )


def _matched_field_is_valid(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    allowed = {
        "PRODUCT": {"PD_NAME", "YC11_PD_CD"},
        "INDUSTRY_ROOT": {"IDTY_CLAS"},
        "INDUSTRY_L1": {"PRI_IDTY_NAME"},
        "INDUSTRY_L2": {"SCD_IDTY_NAME"},
        "INDUSTRY_L3": {"TERT_IDTY_NAME"},
    }
    return row.get("matchedField") in allowed.get(row.get("entityKind"), set())


def validate_catalog_semantics(
    request: dict[str, Any],
    response: dict[str, Any],
    query_context: dict[str, Any] | None,
) -> SemanticResult:
    request_operation = request.get("operation")
    if response.get("operation") != request_operation:
        return _result([RESPONSE_OPERATION_BINDING])

    if response.get("success") is not True:
        return _result([])

    operation = request_operation
    expected_context_fields = set(BASE_CONTEXT_FIELDS)
    if operation == "PRODUCT_INDUSTRIES":
        expected_context_fields.update({"productEntityId", "canonicalProductId"})
    elif operation == "INDUSTRY_CHILDREN":
        expected_context_fields.add("parentEntityId")

    if not isinstance(query_context, dict) or set(query_context) != expected_context_fields:
        return _result([CONTEXT_REQUIRED_BINDING])
    if query_context.get("operation") != operation:
        return _result([CONTEXT_OPERATION_BINDING])

    edges = tuple(_edge_tuple(edge) for edge in query_context.get("directEdges", ()))
    if any(edge is None for edge in edges):
        return _result([CONTEXT_REQUIRED_BINDING])

    if operation == "PRODUCT_INDUSTRIES":
        requested = request.get("productEntityId")
        if (
            query_context.get("productEntityId") != requested
            or query_context.get("canonicalProductId") != requested
        ):
            return _result([CONTEXT_REQUIRED_BINDING])
    elif operation == "INDUSTRY_CHILDREN":
        if query_context.get("parentEntityId") != request.get("parentEntityId"):
            return _result([CONTEXT_REQUIRED_BINDING])

    failures: list[str] = []
    if query_context.get("requestCanonicalSha256") != canonical_sha256(request):
        failures.append(CONTEXT_REQUEST_DIGEST)
    if query_context.get("dataAsOf") != response.get("dataAsOf"):
        failures.append(CONTEXT_DATA_AS_OF)
    if len(edges) != len(set(edges)):
        failures.append(CONTEXT_EDGE_UNIQUE)

    total = response.get("totalCount")
    returned = response.get("returnedCount")
    limit = request.get("limit")
    if (
        isinstance(limit, int)
        and not isinstance(limit, bool)
        and isinstance(total, int)
        and isinstance(returned, int)
    ):
        if (
            returned != min(total, limit)
            or response.get("truncated") is not (total > limit)
        ):
            failures.append(REQUEST_LIMIT_BINDING)

    data = response.get("data")
    data = data if isinstance(data, dict) else {}
    rows = data.get("rows")
    rows = rows if isinstance(rows, list) else []

    if operation == "SEARCH_PRODUCTS":
        if any(not _product_id_matches(row) for row in rows):
            failures.append(PRODUCT_ID_BINDING)

    if operation == "PRODUCT_INDUSTRIES":
        product = data.get("product")
        if not _product_id_matches(product):
            failures.append(PRODUCT_ID_BINDING)
        if not isinstance(product, dict) or product.get("entityId") != request.get(
            "productEntityId"
        ):
            failures.append(PRODUCT_REQUEST_BINDING)
        edge_set = set(edges)
        if any(
            path is None or any(edge not in edge_set for edge in path)
            for path in (
                _path_edges(row.get("nodes")) if isinstance(row, dict) else None
                for row in rows
            )
        ):
            failures.append(PRODUCT_PATH_DIRECT_PARENT)

    if operation == "INDUSTRY_CHILDREN":
        parent = data.get("parent")
        if not isinstance(parent, dict) or parent.get("entityId") != request.get(
            "parentEntityId"
        ):
            failures.append(CHILD_PARENT_BINDING)
        edge_set = set(edges)
        parent_id = parent.get("entityId") if isinstance(parent, dict) else None
        parent_level = parent.get("level") if isinstance(parent, dict) else None
        if any(
            not isinstance(row, dict)
            or (
                parent_id,
                parent_level,
                row.get("entityId"),
                row.get("level"),
            )
            not in edge_set
            for row in rows
        ):
            failures.append(CHILD_DIRECT_PARENT)

    if operation == "INDUSTRY_PARENT_PATH":
        target = request.get("industryEntityId")
        node = data.get("node")
        terminal_matches = isinstance(node, dict) and node.get("entityId") == target
        for row in rows:
            nodes = row.get("nodes") if isinstance(row, dict) else None
            terminal_matches = (
                terminal_matches
                and isinstance(nodes, list)
                and bool(nodes)
                and isinstance(nodes[-1], dict)
                and nodes[-1].get("entityId") == target
            )
        if not terminal_matches:
            failures.append(PATH_TARGET_BINDING)
        edge_set = set(edges)
        if any(
            path is None or any(edge not in edge_set for edge in path)
            for path in (
                _path_edges(row.get("nodes")) if isinstance(row, dict) else None
                for row in rows
            )
        ):
            failures.append(PATH_DIRECT_PARENT)

    if operation == "RESOLVE_CATALOG":
        if any(not _matched_field_is_valid(row) for row in rows):
            failures.append(RESOLVE_MATCH_FIELD)

    return _result(failures)
