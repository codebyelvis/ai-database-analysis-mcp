import re
import secrets
from typing import Any, Callable

from canonical import canonical_sha256, industry_root_id
from contracts import (
    PROFILE,
    SCHEMA,
    PolicyDenied,
    normalize_operation,
    validate_catalog_request,
)
from credentials import AuthUnavailable, read_password
from metadata_contract import (
    BoundSnapshot,
    MetadataMismatch,
    load_bound_snapshot,
    parse_bus_date,
)
from metadata_probe import ReadOnlyRequired
from psql_runner import (
    PsqlResult,
    QueryFailed,
    ResultTooLarge,
    enforce_public_response_cap,
    run_psql,
)
from schema_client import SchemaClient, SchemaUnavailable
from semantics import validate_catalog_semantics
from sql_templates import SqlPlan, build_preflight_plan, build_sql_plan


ERROR_MESSAGES = {
    "POLICY_DENIED": "request rejected by policy",
    "AUTH_UNAVAILABLE": "credential unavailable",
    "READ_ONLY_REQUIRED": "read-only boundary unavailable",
    "DATA_CONTRACT_MISMATCH": "data contract mismatch",
    "QUERY_FAILED": "query failed",
    "RESULT_TOO_LARGE": "result exceeds limit",
}

_QUERY_ID_RE = re.compile(r"^[a-f0-9]{16,64}$")
_PRIVATE_COLUMNS = frozenset({"CRT_TIME", "UPDT_TIME", "MEMO"})
_LIMITED_OPERATIONS = frozenset(
    {
        "RESOLVE_CATALOG",
        "SEARCH_PRODUCTS",
        "PRODUCT_INDUSTRIES",
        "INDUSTRY_CHILDREN",
    }
)
_EDGE_FIELDS = frozenset(
    {"parentEntityId", "parentLevel", "childEntityId", "childLevel"}
)
_EDGE_ORDER_FIELDS = (
    "parentEntityId",
    "parentLevel",
    "childEntityId",
    "childLevel",
)
_RAW_COMMON_FIELDS = frozenset({"operation", "totalCount", "rows", "directEdges"})
_PRODUCT_FIELDS = frozenset({"entityId", "pdId", "yc11PdCd", "pdName", "isEff"})
_PATH_FIELDS = frozenset(
    {
        "rootId",
        "rootName",
        "l1Id",
        "l1Name",
        "l2Id",
        "l2Name",
        "l3Id",
        "l3Name",
        "pathPosition",
    }
)
_PRODUCT_PATH_FIELDS = _PATH_FIELDS - {"pathPosition"}


class AdapterUnavailable(RuntimeError):
    """The adapter cannot safely publish an unvalidated response."""

    def __str__(self) -> str:
        return "contract validation unavailable"


class _ContractMismatch(RuntimeError):
    pass


class _ResponseSchemaRejected(RuntimeError):
    pass


class _InvalidQueryId(RuntimeError):
    pass


def _raise_mismatch() -> None:
    raise _ContractMismatch()


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_safe_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(
            ord(character) <= 0x1F or 0x7F <= ord(character) <= 0x9F
            for character in value
        )
    )


def _entity_id(level: str, source_id: str) -> str:
    if not isinstance(source_id, str) or not source_id:
        _raise_mismatch()
    prefixes = {"ROOT": "INDUSTRY_ROOT", "L1": "INDUSTRY_L1", "L2": "INDUSTRY_L2", "L3": "INDUSTRY_L3"}
    prefix = prefixes.get(level)
    if prefix is None:
        _raise_mismatch()
    return f"{prefix}:{source_id}"


def _check_closed(value: Any, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _raise_mismatch()
    return value


def _check_raw_count_and_rows(
    raw: dict[str, Any],
    request: dict[str, Any],
) -> tuple[int, list[Any], bool]:
    if not _is_nonnegative_int(raw.get("totalCount")):
        _raise_mismatch()
    rows = raw.get("rows")
    if not isinstance(rows, list):
        _raise_mismatch()
    total = raw["totalCount"]
    operation = request["operation"]
    if operation in _LIMITED_OPERATIONS:
        limit = request.get("limit")
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            _raise_mismatch()
        expected = min(total, limit)
        truncated = total > limit
    else:
        if total not in (0, 1):
            _raise_mismatch()
        expected = total
        truncated = False
    if len(rows) != expected:
        _raise_mismatch()
    return total, rows, truncated


def _validate_edges(raw_edges: Any) -> list[dict[str, Any]]:
    if not isinstance(raw_edges, list):
        _raise_mismatch()
    normalized = []
    for edge in raw_edges:
        _check_closed(edge, _EDGE_FIELDS)
        if (
            not _is_safe_text(edge["parentEntityId"])
            or not _is_safe_text(edge["childEntityId"])
            or edge["parentLevel"] not in {"ROOT", "L1", "L2"}
            or edge["childLevel"] not in {"L1", "L2", "L3"}
        ):
            _raise_mismatch()
        normalized.append(dict(edge))
    return normalized


def _edge_from_nodes(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    return {
        "parentEntityId": parent["entityId"],
        "parentLevel": parent["level"],
        "childEntityId": child["entityId"],
        "childLevel": child["level"],
    }


def _expected_edges(paths: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for nodes in paths:
        if not isinstance(nodes, list):
            _raise_mismatch()
        for parent, child in zip(nodes, nodes[1:]):
            edge = _edge_from_nodes(parent, child)
            key = tuple(edge[field] for field in _EDGE_ORDER_FIELDS)
            unique[key] = edge
    return [unique[key] for key in sorted(unique)]


def _require_exact_edges(
    raw_edges: list[dict[str, Any]],
    paths: list[list[dict[str, Any]]],
) -> None:
    if raw_edges != _expected_edges(paths):
        _raise_mismatch()


def _public_product(value: Any, *, allow_missing_entity_id: bool = True) -> dict[str, Any]:
    if not isinstance(value, dict):
        _raise_mismatch()
    if set(value) - set(_PRODUCT_FIELDS):
        _raise_mismatch()
    missing = set(_PRODUCT_FIELDS) - set(value)
    if missing - {"entityId"} or (missing and not allow_missing_entity_id):
        _raise_mismatch()
    for key in ("pdId", "yc11PdCd", "pdName"):
        if not _is_safe_text(value.get(key)):
            _raise_mismatch()
    if value.get("isEff") != "1":
        _raise_mismatch()
    computed = f"PRODUCT:{value['pdId']}"
    if "entityId" in value and value["entityId"] != computed:
        _raise_mismatch()
    result = {
        "entityId": computed,
        "pdId": value["pdId"],
        "yc11PdCd": value["yc11PdCd"],
        "pdName": value["pdName"],
        "isEff": "1",
    }
    return result


def _public_node(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        _raise_mismatch()
    if set(value) - {"entityId", "level", "canonicalName", "sourceId"}:
        _raise_mismatch()
    if set(value) < {"entityId", "level", "canonicalName"}:
        _raise_mismatch()
    level = value.get("level")
    entity_id = value.get("entityId")
    canonical_name = value.get("canonicalName")
    if level not in {"ROOT", "L1", "L2", "L3"} or not _is_safe_text(canonical_name):
        _raise_mismatch()
    if not isinstance(entity_id, str) or not entity_id:
        _raise_mismatch()
    if level == "ROOT":
        if "sourceId" in value:
            _raise_mismatch()
        try:
            expected_root_id = industry_root_id(canonical_name)
        except ValueError:
            _raise_mismatch()
        if entity_id != expected_root_id:
            _raise_mismatch()
    else:
        if not _is_safe_text(value.get("sourceId")):
            _raise_mismatch()
        if entity_id != _entity_id(level, value["sourceId"]):
            _raise_mismatch()
    return dict(value)


def _path_nodes(raw: dict[str, Any]) -> list[dict[str, Any]]:
    required = (
        ("ROOT", "rootId", "rootName"),
        ("L1", "l1Id", "l1Name"),
        ("L2", "l2Id", "l2Name"),
        ("L3", "l3Id", "l3Name"),
    )
    nodes = []
    for level, id_key, name_key in required:
        source = raw.get(id_key)
        name = raw.get(name_key)
        if not _is_safe_text(source) or not _is_safe_text(name):
            _raise_mismatch()
        if level == "ROOT":
            try:
                canonical_root = industry_root_id(name)
            except ValueError:
                _raise_mismatch()
            if "rootId" in raw and raw["rootId"] != canonical_root:
                _raise_mismatch()
            nodes.append(
                {
                    "entityId": canonical_root,
                    "level": "ROOT",
                    "canonicalName": name,
                }
            )
        else:
            nodes.append(
                {
                    "entityId": _entity_id(level, source),
                    "level": level,
                    "canonicalName": name,
                    "sourceId": source,
                }
            )
    return nodes


class KingbaseReadonlyAdapter:
    """Closed, schema-first adapter around one fixed Kingbase SQL plan."""

    def __init__(
        self,
        *,
        snapshot_loader: Callable[[], BoundSnapshot] = load_bound_snapshot,
        credential_reader: Callable[[], Any] = read_password,
        runner: Callable[[SqlPlan, Any], PsqlResult] = run_psql,
        schema_factory: Callable[[], Any] = SchemaClient,
        query_id_factory: Callable[[], str] | None = None,
        preflight_plan_factory: Callable[[BoundSnapshot], SqlPlan] = build_preflight_plan,
        catalog_plan_factory: Callable[[dict[str, Any], BoundSnapshot], SqlPlan] = build_sql_plan,
    ) -> None:
        self._snapshot_loader = snapshot_loader
        self._credential_reader = credential_reader
        self._runner = runner
        self._query_id_factory = query_id_factory or (lambda: secrets.token_hex(16))
        self._preflight_plan_factory = preflight_plan_factory
        self._catalog_plan_factory = catalog_plan_factory
        self._schema = None
        self._schema_failed = False
        try:
            self._schema = schema_factory()
        except Exception:
            self._schema_failed = True

    def _schema_validate(self, contract: str, instance: Any) -> bool:
        if self._schema_failed or self._schema is None:
            raise AdapterUnavailable()
        try:
            valid = self._schema.validate(contract, instance)
        except Exception:
            raise AdapterUnavailable() from None
        if type(valid) is not bool:
            raise AdapterUnavailable()
        return valid

    def _query_id(self) -> str:
        try:
            value = self._query_id_factory()
        except Exception:
            raise _InvalidQueryId() from None
        if not isinstance(value, str) or _QUERY_ID_RE.fullmatch(value) is None:
            raise _InvalidQueryId()
        return value

    def _snapshot(self) -> BoundSnapshot:
        try:
            snapshot = self._snapshot_loader()
        except MetadataMismatch:
            raise
        except Exception:
            raise MetadataMismatch() from None
        if isinstance(snapshot, BoundSnapshot):
            return snapshot
        if isinstance(snapshot, dict):
            return BoundSnapshot.from_value(snapshot)
        raise MetadataMismatch()

    @staticmethod
    def _raw_error_code(result: Any) -> str | None:
        if not isinstance(result, PsqlResult):
            raise _ContractMismatch()
        if result.error_code is None:
            return None
        if result.error_code not in ERROR_MESSAGES:
            raise _ContractMismatch()
        return result.error_code

    @staticmethod
    def _read_boundary(raw: dict[str, Any]) -> dict[str, Any]:
        _check_closed(
            raw,
            frozenset(
                {
                    "dataAsOfRaw",
                    "productCount",
                    "relationCount",
                    "industryCount",
                    "privilegeMode",
                    "databasePrivilegeRisk",
                }
            ),
        )
        if raw["privilegeMode"] not in {"DATABASE_READ_ONLY", "CLIENT_ENFORCED_READ_ONLY"}:
            _raise_mismatch()
        if raw["databasePrivilegeRisk"] not in {"NONE_OBSERVED", "WRITE_CAPABLE_ACCOUNT"}:
            _raise_mismatch()
        for key in ("productCount", "relationCount", "industryCount"):
            if not _is_nonnegative_int(raw[key]):
                _raise_mismatch()
        return {
            "transactionReadOnly": True,
            "privilegeMode": raw["privilegeMode"],
            "databasePrivilegeRisk": raw["databasePrivilegeRisk"],
        }

    @classmethod
    def _normalize_preflight_raw(cls, raw: Any, snapshot: BoundSnapshot) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
        if not isinstance(raw, dict):
            _raise_mismatch()
        boundary = cls._read_boundary(raw)
        try:
            data_as_of = parse_bus_date(raw["dataAsOfRaw"])
        except Exception:
            raise _ContractMismatch() from None
        snapshot_value = snapshot.as_dict()
        objects = []
        counts = {
            "T_EDW_VAR_PD_INFO_Q": raw["productCount"],
            "T_EDW_VAR_PD_IDTY_RELA_Q": raw["relationCount"],
            "T_EDW_VAR_HCZQ_IDTY_CLAS_Q": raw["industryCount"],
        }
        for table in snapshot_value["tables"]:
            name = table["table"]
            columns = [
                column["name"]
                for column in table["columns"]
                if column["name"] not in _PRIVATE_COLUMNS
            ]
            if not columns or name not in counts:
                _raise_mismatch()
            objects.append(
                {
                    "table": name,
                    "rowCount": counts[name],
                    "uniqueKeyCount": counts[name],
                    "columns": columns,
                }
            )
        if len(objects) != 3 or {item["table"] for item in objects} != {
            "T_EDW_VAR_PD_INFO_Q",
            "T_EDW_VAR_PD_IDTY_RELA_Q",
            "T_EDW_VAR_HCZQ_IDTY_CLAS_Q",
        }:
            _raise_mismatch()
        return data_as_of, boundary, objects

    @classmethod
    def _normalize_business(
        cls,
        request: dict[str, Any],
        raw: Any,
        data_as_of: str,
    ) -> tuple[dict[str, Any], dict[str, Any], int, bool]:
        if not isinstance(raw, dict) or not _RAW_COMMON_FIELDS <= set(raw):
            _raise_mismatch()
        operation = request["operation"]
        if raw.get("operation") != operation:
            _raise_mismatch()
        direct_edges = _validate_edges(raw.get("directEdges"))
        total, rows, truncated = _check_raw_count_and_rows(raw, request)
        context = {
            "requestCanonicalSha256": canonical_sha256(request),
            "operation": operation,
            "dataAsOf": data_as_of,
            "directEdges": direct_edges,
        }
        if operation in {"RESOLVE_CATALOG", "SEARCH_PRODUCTS"} and direct_edges:
            _raise_mismatch()

        if operation == "RESOLVE_CATALOG":
            if set(raw) != _RAW_COMMON_FIELDS:
                _raise_mismatch()
            normalized_rows = []
            expected_fields = frozenset(
                {"entityId", "entityKind", "canonicalName", "matchedField", "matchKind"}
            )
            for row in rows:
                item = _check_closed(row, expected_fields)
                if not _is_safe_text(item.get("canonicalName")):
                    _raise_mismatch()
                if item.get("entityKind") == "INDUSTRY_ROOT":
                    try:
                        expected_root_id = industry_root_id(item["canonicalName"])
                    except ValueError:
                        _raise_mismatch()
                    if item.get("entityId") != expected_root_id:
                        _raise_mismatch()
                normalized_rows.append(dict(item))
            data = {"rows": normalized_rows}
        elif operation == "SEARCH_PRODUCTS":
            if set(raw) != _RAW_COMMON_FIELDS:
                _raise_mismatch()
            normalized_rows = []
            expected_fields = frozenset({"pdId", "yc11PdCd", "pdName", "isEff"})
            for row in rows:
                item = _check_closed(row, expected_fields)
                product = _public_product(item, allow_missing_entity_id=True)
                normalized_rows.append(product)
            data = {"rows": normalized_rows}
        elif operation == "PRODUCT_INDUSTRIES":
            if set(raw) != _RAW_COMMON_FIELDS | {"product"}:
                _raise_mismatch()
            product = _public_product(raw.get("product"), allow_missing_entity_id=False)
            if product["entityId"] != request["productEntityId"]:
                _raise_mismatch()
            context.update(
                {
                    "productEntityId": request["productEntityId"],
                    "canonicalProductId": product["entityId"],
                }
            )
            expected_fields = _PRODUCT_PATH_FIELDS | frozenset(
                {"pdId", "yc11PdCd", "pdName", "isEff"}
            )
            normalized_rows = []
            for row in rows:
                item = _check_closed(row, expected_fields)
                nodes = _path_nodes(item)
                for key in ("pdId", "yc11PdCd", "pdName", "isEff"):
                    if item[key] != product[key]:
                        _raise_mismatch()
                normalized_rows.append({"nodes": nodes})
            data = {"product": product, "rows": normalized_rows}
        elif operation == "INDUSTRY_CHILDREN":
            if set(raw) != _RAW_COMMON_FIELDS | {"parent"}:
                _raise_mismatch()
            parent = _public_node(raw.get("parent"))
            context["parentEntityId"] = request["parentEntityId"]
            normalized_rows = []
            child_entity_ids = set()
            expected_fields = frozenset({"sourceId", "canonicalName", "level"})
            for row in rows:
                item = _check_closed(row, expected_fields | {"entityId"}) if "entityId" in row else _check_closed(row, expected_fields)
                level = item.get("level")
                if level not in {"L1", "L2", "L3"} or not _is_safe_text(item.get("sourceId")) or not _is_safe_text(item.get("canonicalName")):
                    _raise_mismatch()
                entity_id = _entity_id(level, item["sourceId"])
                if "entityId" in item and item["entityId"] != entity_id:
                    _raise_mismatch()
                if entity_id in child_entity_ids:
                    _raise_mismatch()
                child_entity_ids.add(entity_id)
                normalized_rows.append(
                    {
                        "entityId": entity_id,
                        "level": level,
                        "canonicalName": item["canonicalName"],
                        "sourceId": item["sourceId"],
                    }
                )
            data = {"parent": parent, "rows": normalized_rows}
        else:
            if set(raw) != _RAW_COMMON_FIELDS | {"node"}:
                _raise_mismatch()
            if raw.get("node") is None:
                _raise_mismatch()
            node = _public_node(raw.get("node"))
            normalized_rows = []
            for row in rows:
                item = _check_closed(row, _PATH_FIELDS)
                path_position = item.get("pathPosition")
                if not isinstance(path_position, int) or isinstance(path_position, bool) or not 1 <= path_position <= 4:
                    _raise_mismatch()
                nodes = _path_nodes(item)[:path_position]
                if nodes[-1] != node:
                    _raise_mismatch()
                normalized_rows.append({"nodes": nodes})
            if rows and node is None:
                _raise_mismatch()
            data = {"node": node, "rows": normalized_rows}

        return data, context, total, truncated

    @staticmethod
    def _success_response(
        request: dict[str, Any],
        data: dict[str, Any],
        total: int,
        truncated: bool,
        data_as_of: str,
        query_id: str,
        read_boundary: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "success": True,
            "operation": request["operation"],
            "dataStatus": "EMPTY" if total == 0 else "AVAILABLE",
            "totalCount": total,
            "returnedCount": len(data.get("rows", [])),
            "truncated": truncated,
            "dataAsOf": data_as_of,
            "queryId": query_id,
            "readBoundary": read_boundary,
            "data": data,
        }

    @staticmethod
    def _validate_business_edges(
        operation: str,
        data: dict[str, Any],
        direct_edges: list[dict[str, Any]],
    ) -> None:
        if operation == "PRODUCT_INDUSTRIES":
            paths = [row["nodes"] for row in data["rows"]]
        elif operation == "INDUSTRY_CHILDREN":
            parent = data["parent"]
            paths = [[parent, row] for row in data["rows"]]
        elif operation == "INDUSTRY_PARENT_PATH":
            paths = [row["nodes"] for row in data["rows"]]
        else:
            return
        _require_exact_edges(direct_edges, paths)

    def _publish_catalog_error(self, operation: Any, query_id: str, code: str) -> dict[str, Any]:
        response = {
            "success": False,
            "operation": normalize_operation(operation),
            "dataStatus": "REJECTED" if code == "POLICY_DENIED" else "FAILED",
            "totalCount": 0,
            "returnedCount": 0,
            "truncated": False,
            "dataAsOf": None,
            "queryId": query_id,
            "errorCode": code,
            "message": ERROR_MESSAGES[code],
            "data": None,
        }
        if not self._schema_validate("catalogResponse", response):
            raise AdapterUnavailable()
        return response

    def _publish_preflight_error(self, query_id: str, code: str) -> dict[str, Any]:
        response = {
            "success": False,
            "operation": "kingbase_readonly_preflight",
            "profile": PROFILE,
            "schema": SCHEMA,
            "readBoundary": None,
            "objects": [],
            "dataAsOf": None,
            "queryId": query_id,
            "errorCode": code,
            "message": ERROR_MESSAGES[code],
        }
        if not self._schema_validate("preflightResponse", response):
            raise AdapterUnavailable()
        return response

    @staticmethod
    def _map_exception(exc: Exception) -> str:
        if isinstance(exc, PolicyDenied):
            return "POLICY_DENIED"
        if isinstance(exc, AuthUnavailable):
            return "AUTH_UNAVAILABLE"
        if isinstance(exc, ReadOnlyRequired):
            return "READ_ONLY_REQUIRED"
        if isinstance(exc, ResultTooLarge):
            return "RESULT_TOO_LARGE"
        if isinstance(exc, QueryFailed):
            return "QUERY_FAILED"
        if isinstance(exc, MetadataMismatch) or isinstance(exc, _ContractMismatch):
            return "DATA_CONTRACT_MISMATCH"
        if isinstance(exc, _InvalidQueryId):
            return "DATA_CONTRACT_MISMATCH"
        return "QUERY_FAILED"

    def preflight(self, request: Any) -> dict[str, Any]:
        operation = "kingbase_readonly_preflight"
        try:
            if not self._schema_validate("preflightRequest", request):
                raise _ContractMismatch()
            if not isinstance(request, dict) or request:
                raise _ContractMismatch()
            query_id = self._query_id()
            snapshot = self._snapshot()
            plan = self._preflight_plan_factory(snapshot)
            secret = self._credential_reader()
            result = self._runner(plan, secret)
            code = self._raw_error_code(result)
            if code is not None:
                raise RuntimeError(code)
            if result.preflight is None or result.business is not None:
                raise _ContractMismatch()
            data_as_of, boundary, objects = self._normalize_preflight_raw(result.preflight, snapshot)
            response = {
                "success": True,
                "operation": operation,
                "profile": PROFILE,
                "schema": SCHEMA,
                "readBoundary": boundary,
                "objects": objects,
                "dataAsOf": data_as_of,
                "queryId": query_id,
            }
            if not self._schema_validate("preflightResponse", response):
                raise _ResponseSchemaRejected()
            enforce_public_response_cap(response)
            return response
        except AdapterUnavailable:
            raise
        except _ResponseSchemaRejected:
            raise AdapterUnavailable()
        except RuntimeError as exc:
            if str(exc) in ERROR_MESSAGES:
                code = str(exc)
            else:
                code = self._map_exception(exc)
            try:
                query_id = query_id
            except UnboundLocalError:
                query_id = secrets.token_hex(16)
            return self._publish_preflight_error(query_id, code)
        except Exception as exc:
            try:
                query_id = query_id
            except UnboundLocalError:
                query_id = secrets.token_hex(16)
            return self._publish_preflight_error(query_id, self._map_exception(exc))

    def catalog(self, request: Any) -> dict[str, Any]:
        operation = request.get("operation") if isinstance(request, dict) else None
        query_id = None
        try:
            if not self._schema_validate("catalogRequest", request):
                raise PolicyDenied(normalize_operation(operation))
            request = validate_catalog_request(request)
            query_id = self._query_id()
            snapshot = self._snapshot()
            plan = self._catalog_plan_factory(request, snapshot)
            secret = self._credential_reader()
            result = self._runner(plan, secret)
            code = self._raw_error_code(result)
            if code is not None:
                raise RuntimeError(code)
            if result.preflight is None or result.business is None:
                raise _ContractMismatch()
            data_as_of, boundary, _ = self._normalize_preflight_raw(result.preflight, snapshot)
            data, query_context, total, truncated = self._normalize_business(
                request,
                result.business,
                data_as_of,
            )
            response = self._success_response(
                request,
                data,
                total,
                truncated,
                data_as_of,
                query_id,
                boundary,
            )
            if not self._schema_validate("catalogResponse", response):
                raise _ResponseSchemaRejected()
            self._validate_business_edges(
                request["operation"],
                data,
                query_context["directEdges"],
            )
            semantic = validate_catalog_semantics(request, response, query_context)
            if not semantic.ok:
                raise _ContractMismatch()
            enforce_public_response_cap(response)
            return response
        except AdapterUnavailable:
            raise
        except _ResponseSchemaRejected:
            raise AdapterUnavailable()
        except RuntimeError as exc:
            if str(exc) in ERROR_MESSAGES:
                code = str(exc)
            else:
                code = self._map_exception(exc)
            if query_id is None:
                query_id = secrets.token_hex(16)
            return self._publish_catalog_error(operation, query_id, code)
        except Exception as exc:
            if query_id is None:
                query_id = secrets.token_hex(16)
            return self._publish_catalog_error(operation, query_id, self._map_exception(exc))


ReadonlyAdapter = KingbaseReadonlyAdapter
Adapter = KingbaseReadonlyAdapter


__all__ = [
    "Adapter",
    "AdapterUnavailable",
    "KingbaseReadonlyAdapter",
    "ReadonlyAdapter",
    "SchemaUnavailable",
]
