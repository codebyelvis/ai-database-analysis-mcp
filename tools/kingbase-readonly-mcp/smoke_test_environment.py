"""Deterministic read-only acceptance smoke for the fixed test profile.

The real smoke deliberately projects only aggregate, contract-level facts.  It
never writes raw Adapter responses, query identifiers, SQL, credentials, or
business rows to the evidence artifact.
"""

from __future__ import annotations

import argparse
import copy
import datetime as _datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from contracts import PROFILE, SCHEMA
from metadata_contract import BOUND_SNAPSHOT_SHA256, load_bound_snapshot


OUTPUT_PATH = Path("/tmp/kingbase-readonly-smoke.json")
PRIVATE_COLUMNS = ["CRT_TIME", "MEMO", "UPDT_TIME"]
NEGATIVE_FIELDS = ["sql", "statement", "offset", "page", "cursor"]
SNAPSHOT_SHA256 = BOUND_SNAPSHOT_SHA256

RESOLVE_REQUEST = {
    "operation": "RESOLVE_CATALOG",
    "text": "AI产业模型",
    "expectedEntityType": "INDUSTRY",
    "limit": 10,
}
SEARCH_REQUEST = {
    "operation": "SEARCH_PRODUCTS",
    "searchText": "电",
    "matchField": "NAME",
    "limit": 20,
}

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RFC3339_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIVATE_UPPER = frozenset(PRIVATE_COLUMNS)
_FORBIDDEN_KEY_WORDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "credentials",
        "endpoint",
        "host",
        "hostname",
        "port",
        "account",
        "username",
        "dsn",
        "uri",
        "url",
        "connectionstring",
        "connection_string",
        "sql",
        "statement",
        "stderr",
        "stdout",
        "traceback",
        "queryid",
        "query_id",
        "row",
        "rows",
    }
)
_FORBIDDEN_VALUE_RE = re.compile(
    r"(?:PGPASSWORD|postgres(?:ql)?://|kingbase://|jdbc:|\bdsn\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bcreate\b|traceback|password\s*=)",
    re.IGNORECASE,
)
_SAFE_FAILURE_PHASES = frozenset(
    {
        "ARGS",
        "SNAPSHOT",
        "POLICY",
        "SCHEMA_STARTUP",
        "PREFLIGHT",
        "RESOLVE_CATALOG",
        "SEARCH_PRODUCTS",
        "PRODUCT_INDUSTRIES",
        "INDUSTRY_CHILDREN",
        "INDUSTRY_PARENT_PATH",
        "EVIDENCE",
        "OUTPUT",
        "INTERNAL",
    }
)
_SAFE_ERROR_CODES = frozenset(
    {
        "AUTH_UNAVAILABLE",
        "DATA_CONTRACT_MISMATCH",
        "POLICY_DENIED",
        "QUERY_FAILED",
        "READ_ONLY_REQUIRED",
        "RESULT_TOO_LARGE",
    }
)


class _ResponseFailure(ValueError):
    def __init__(self, code: Any) -> None:
        super().__init__("smoke response rejected")
        self.code = code if code in _SAFE_ERROR_CODES else None


class _PhaseFailure(ValueError):
    def __init__(self, phase: str, code: str | None = None) -> None:
        super().__init__("smoke contract failed")
        self.phase = phase if phase in _SAFE_FAILURE_PHASES else "INTERNAL"
        self.code = code if code in _SAFE_ERROR_CODES else None


def safe_failure_marker(phase: Any, code: Any = None) -> str:
    """Return a frozen, non-diagnostic stderr marker for a failure phase."""

    normalized = phase if isinstance(phase, str) and phase in _SAFE_FAILURE_PHASES else "INTERNAL"
    if isinstance(code, str) and code in _SAFE_ERROR_CODES:
        return f"TASK7_SMOKE_BLOCKED|phase={normalized}|code={code}"
    return f"TASK7_SMOKE_BLOCKED|phase={normalized}"


def _phase_call(phase: str, callback: Any) -> Any:
    try:
        return callback()
    except _ResponseFailure as failure:
        raise _PhaseFailure(phase, failure.code) from None
    except _PhaseFailure:
        raise
    except SystemExit:
        raise
    except Exception:
        raise _PhaseFailure(phase) from None


def _fail(message: str = "smoke contract failed") -> None:
    raise ValueError(message)


def _require(condition: bool, message: str = "smoke contract failed") -> None:
    if not condition:
        _fail(message)


def _require_success(response: Any, operation: str | None = None) -> dict[str, Any]:
    _require(isinstance(response, dict))
    if response.get("success") is not True:
        raise _ResponseFailure(response.get("errorCode"))
    if operation is not None:
        _require(response.get("operation") == operation)
    _require(isinstance(response.get("dataAsOf"), str))
    _require(_DATE_RE.fullmatch(response["dataAsOf"]) is not None)
    boundary = response.get("readBoundary")
    _require(isinstance(boundary, dict))
    _require(
        set(boundary)
        == {"transactionReadOnly", "privilegeMode", "databasePrivilegeRisk"}
    )
    _require(boundary.get("transactionReadOnly") is True)
    _require(
        boundary.get("privilegeMode")
        in {"DATABASE_READ_ONLY", "CLIENT_ENFORCED_READ_ONLY"}
    )
    _require(
        boundary.get("databasePrivilegeRisk")
        in {"NONE_OBSERVED", "WRITE_CAPABLE_ACCOUNT"}
    )
    if operation is not None:
        _require(response.get("dataStatus") in {"AVAILABLE", "EMPTY"})
    return response


def _first_rows(response: dict[str, Any]) -> list[Any]:
    data = response.get("data")
    _require(isinstance(data, dict))
    rows = data.get("rows")
    _require(isinstance(rows, list))
    return rows


def _operation_projection(
    response: dict[str, Any],
    sequence: int,
    operation: str,
    preflight: dict[str, Any],
) -> dict[str, Any]:
    _require_success(response, operation)
    _require(response.get("readBoundary") == preflight["readBoundary"])
    _require(response.get("totalCount") is not None)
    _require(
        isinstance(response["totalCount"], int)
        and not isinstance(response["totalCount"], bool)
        and response["totalCount"] >= 0
    )
    _require(
        isinstance(response.get("returnedCount"), int)
        and not isinstance(response["returnedCount"], bool)
        and response["returnedCount"] >= 0
    )
    _require(isinstance(response.get("truncated"), bool))
    _require(response["dataAsOf"] == preflight["dataAsOf"])
    return {
        "sequence": sequence,
        "operation": operation,
        "success": True,
        "dataStatus": response.get("dataStatus"),
        "totalCount": response["totalCount"],
        "returnedCount": response["returnedCount"],
        "truncated": response["truncated"],
        "dataAsOf": response["dataAsOf"],
    }


def _run_fixed_chain(adapter: Any) -> dict[str, Any]:
    """Run exactly one preflight and five fixed catalog calls.

    IDs selected from the successful responses remain in this return value only
    long enough for the next call.  Callers must not persist the raw responses.
    """

    # The Adapter's preflight contract carries a fixed operation name in the
    # production response; the injected dry-run fake intentionally keeps only
    # the fields needed by the chain, so validate the name when present.
    preflight = _phase_call("PREFLIGHT", lambda: _require_success(adapter.preflight({})))
    if "operation" in preflight:
        _phase_call(
            "PREFLIGHT",
            lambda: _require(preflight["operation"] == "kingbase_readonly_preflight"),
        )
    resolve = _phase_call(
        "RESOLVE_CATALOG",
        lambda: _require_success(adapter.catalog(copy.deepcopy(RESOLVE_REQUEST)), "RESOLVE_CATALOG"),
    )
    search = _phase_call(
        "SEARCH_PRODUCTS",
        lambda: _require_success(adapter.catalog(copy.deepcopy(SEARCH_REQUEST)), "SEARCH_PRODUCTS"),
    )

    search_rows = _phase_call("SEARCH_PRODUCTS", lambda: _first_rows(search))
    _phase_call("SEARCH_PRODUCTS", lambda: _require(search_rows, "search returned no product"))
    product_id = _phase_call("SEARCH_PRODUCTS", lambda: search_rows[0].get("entityId"))
    _phase_call("SEARCH_PRODUCTS", lambda: _require(isinstance(product_id, str) and product_id))

    product_request = {
        "operation": "PRODUCT_INDUSTRIES",
        "productEntityId": product_id,
        "limit": 50,
    }
    product_industries = _phase_call(
        "PRODUCT_INDUSTRIES",
        lambda: _require_success(
            adapter.catalog(product_request), "PRODUCT_INDUSTRIES"
        ),
    )
    product_rows = _phase_call("PRODUCT_INDUSTRIES", lambda: _first_rows(product_industries))
    _phase_call(
        "PRODUCT_INDUSTRIES",
        lambda: _require(product_rows, "product has no industry path"),
    )
    nodes = product_rows[0].get("nodes") if isinstance(product_rows[0], dict) else None
    _phase_call("PRODUCT_INDUSTRIES", lambda: _require(isinstance(nodes, list)))
    l2_nodes = [node for node in nodes if isinstance(node, dict) and node.get("level") == "L2"]
    l3_nodes = [node for node in nodes if isinstance(node, dict) and node.get("level") == "L3"]
    _phase_call(
        "PRODUCT_INDUSTRIES",
        lambda: _require(len(l2_nodes) == 1 and len(l3_nodes) == 1),
    )
    parent_id = l2_nodes[0].get("entityId")
    industry_id = l3_nodes[0].get("entityId")
    _phase_call(
        "PRODUCT_INDUSTRIES",
        lambda: _require(isinstance(parent_id, str) and parent_id),
    )
    _phase_call(
        "PRODUCT_INDUSTRIES",
        lambda: _require(isinstance(industry_id, str) and industry_id),
    )

    children_request = {
        "operation": "INDUSTRY_CHILDREN",
        "parentEntityId": parent_id,
        "limit": 50,
    }
    children = _phase_call(
        "INDUSTRY_CHILDREN",
        lambda: _require_success(
            adapter.catalog(children_request), "INDUSTRY_CHILDREN"
        ),
    )
    path_request = {
        "operation": "INDUSTRY_PARENT_PATH",
        "industryEntityId": industry_id,
    }
    parent_path = _phase_call(
        "INDUSTRY_PARENT_PATH",
        lambda: _require_success(
            adapter.catalog(path_request), "INDUSTRY_PARENT_PATH"
        ),
    )

    responses = [resolve, search, product_industries, children, parent_path]
    operation_names = [
        "RESOLVE_CATALOG",
        "SEARCH_PRODUCTS",
        "PRODUCT_INDUSTRIES",
        "INDUSTRY_CHILDREN",
        "INDUSTRY_PARENT_PATH",
    ]
    operations = _phase_call(
        "EVIDENCE",
        lambda: [
            _operation_projection(response, index, name, preflight)
            for index, (response, name) in enumerate(zip(responses, operation_names), 1)
        ],
    )
    return {
        "preflight": preflight,
        "resolve": resolve,
        "operations": operations,
    }


def run_fixed_chain(adapter: Any) -> dict[str, Any]:
    """Public dry-run helper exposing only the deterministic call sequence."""

    details = _run_fixed_chain(adapter)
    return {
        "operations": [
            {"sequence": item["sequence"], "operation": item["operation"]}
            for item in details["operations"]
        ]
    }


def run_negative_policy(adapter: Any) -> list[dict[str, Any]]:
    """Exercise policy rejection without crossing credentials or psql."""

    records = []
    for field in NEGATIVE_FIELDS:
        request = copy.deepcopy(RESOLVE_REQUEST)
        request[field] = "forbidden"
        response = adapter.catalog(request)
        _require(isinstance(response, dict))
        _require(response.get("success") is False)
        _require(response.get("errorCode") == "POLICY_DENIED")
        records.append(
            {"field": field, "errorCode": "POLICY_DENIED", "psqlStarted": False}
        )
    return records


def _key_is_forbidden(key: Any) -> bool:
    if not isinstance(key, str):
        return True
    normalized = key.replace("-", "_").lower()
    return normalized in _FORBIDDEN_KEY_WORDS or normalized.upper() in _PRIVATE_UPPER


def assert_sanitized(value: Any) -> None:
    """Reject secret-bearing, raw-query, row-bearing, or diagnostic values."""

    if isinstance(value, dict):
        for key, child in value.items():
            if _key_is_forbidden(key):
                raise ValueError("unsafe evidence field")
            assert_sanitized(child)
        return
    if isinstance(value, list):
        for child in value:
            assert_sanitized(child)
        return
    if isinstance(value, str) and _FORBIDDEN_VALUE_RE.search(value):
        raise ValueError("unsafe evidence value")


def _object_records(preflight: dict[str, Any], snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    source_objects = preflight.get("objects")
    _require(isinstance(source_objects, list) and len(source_objects) == 3)
    snapshot_tables = snapshot.get("tables")
    _require(isinstance(snapshot_tables, list) and len(snapshot_tables) == 3)
    expected_names = [table.get("table") for table in snapshot_tables]
    _require(all(isinstance(name, str) for name in expected_names))
    by_name = {}
    for source in source_objects:
        _require(isinstance(source, dict))
        _require(set(source) == {"table", "rowCount", "uniqueKeyCount", "columns"})
        _require(source["table"] not in by_name)
        by_name[source["table"]] = source
    _require(set(by_name) == set(expected_names))
    return [
        {
            "table": name,
            "rowCount": _nonnegative_int(by_name[name].get("rowCount")),
            "uniqueKeyCount": _nonnegative_int(by_name[name].get("uniqueKeyCount")),
            "emptyStableKeyCount": 0,
            "localBaseTable": True,
            "metadataExact": True,
            "evidenceSource": "preflightResponse+successfulLiveGuard",
        }
        for name in expected_names
    ]


def _nonnegative_int(value: Any) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0)
    return value


class _PolicyOnlyAdapter:
    def catalog(self, request: dict[str, Any]) -> dict[str, Any]:
        extra = set(request) - set(RESOLVE_REQUEST)
        _require(len(extra) == 1)
        field = next(iter(extra))
        _require(field in NEGATIVE_FIELDS)
        _require(set(request) == set(RESOLVE_REQUEST) | {field})
        return {"success": False, "errorCode": "POLICY_DENIED"}


class _PolicyProbeSchema:
    def validate(self, _contract: str, _instance: Any) -> bool:
        return True


def make_policy_probe_adapter() -> Any:
    """Build a real Adapter whose post-policy boundaries fail if reached."""

    from adapter import Adapter

    def bomb(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("policy probe crossed a later boundary")

    return Adapter(
        snapshot_loader=bomb,
        credential_reader=bomb,
        runner=bomb,
        schema_factory=_PolicyProbeSchema,
    )


def build_evidence(adapter: Any) -> dict[str, Any]:
    snapshot = _phase_call("SNAPSHOT", lambda: load_bound_snapshot().as_dict())
    negative = _phase_call(
        "POLICY",
        lambda: run_negative_policy(make_policy_probe_adapter()),
    )
    details = _phase_call("PREFLIGHT", lambda: _run_fixed_chain(adapter))
    preflight = details["preflight"]
    _phase_call("PREFLIGHT", lambda: _require(preflight.get("profile") == PROFILE))
    _phase_call("PREFLIGHT", lambda: _require(preflight.get("schema") == SCHEMA))
    _phase_call("PREFLIGHT", lambda: _require(isinstance(preflight.get("dataAsOf"), str)))
    _phase_call(
        "PREFLIGHT",
        lambda: _require(_DATE_RE.fullmatch(preflight["dataAsOf"]) is not None),
    )

    evidence = {
        "schemaVersion": "kingbase-readonly-smoke-v1",
        "observedAt": _datetime.datetime.now(_datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "profile": PROFILE,
        "schema": SCHEMA,
        "snapshotSha256": SNAPSHOT_SHA256,
        "identityPresence": {"database": True, "user": True},
        "readBoundary": copy.deepcopy(preflight["readBoundary"]),
        "dataAsOf": preflight["dataAsOf"],
        "privateColumns": list(PRIVATE_COLUMNS),
        "metadataTables": copy.deepcopy(snapshot["tables"]),
        "objects": _phase_call("EVIDENCE", lambda: _object_records(preflight, snapshot)),
        "orphanCounts": {
            "productIndustry": 0,
            "industryHierarchy": 0,
            "evidenceSource": "successfulLiveGuard",
        },
        "operations": details["operations"],
        "negativePolicy": negative,
    }
    _phase_call("EVIDENCE", lambda: _validate_evidence(evidence))
    return evidence


def _validate_evidence(evidence: dict[str, Any]) -> None:
    expected = {
        "schemaVersion",
        "observedAt",
        "profile",
        "schema",
        "snapshotSha256",
        "identityPresence",
        "readBoundary",
        "dataAsOf",
        "privateColumns",
        "metadataTables",
        "objects",
        "orphanCounts",
        "operations",
        "negativePolicy",
    }
    _require(set(evidence) == expected)
    _require(evidence["schemaVersion"] == "kingbase-readonly-smoke-v1")
    _require(_RFC3339_Z_RE.fullmatch(evidence["observedAt"]) is not None)
    _require(evidence["profile"] == PROFILE and evidence["schema"] == SCHEMA)
    _require(_HEX64_RE.fullmatch(evidence["snapshotSha256"]) is not None)
    _require(evidence["snapshotSha256"] == SNAPSHOT_SHA256)
    _require(evidence["identityPresence"] == {"database": True, "user": True})
    _require(isinstance(evidence["readBoundary"], dict))
    _require(
        set(evidence["readBoundary"])
        == {"transactionReadOnly", "privilegeMode", "databasePrivilegeRisk"}
    )
    _require(evidence["readBoundary"]["transactionReadOnly"] is True)
    _require(
        evidence["readBoundary"]["privilegeMode"]
        in {"DATABASE_READ_ONLY", "CLIENT_ENFORCED_READ_ONLY"}
    )
    _require(
        evidence["readBoundary"]["databasePrivilegeRisk"]
        in {"NONE_OBSERVED", "WRITE_CAPABLE_ACCOUNT"}
    )
    _require(_DATE_RE.fullmatch(evidence["dataAsOf"]) is not None)
    _require(evidence["privateColumns"] == PRIVATE_COLUMNS)
    snapshot = load_bound_snapshot().as_dict()
    _require(evidence["metadataTables"] == snapshot["tables"])
    _require(isinstance(evidence["objects"], list) and len(evidence["objects"]) == 3)
    object_names = [item.get("table") for item in evidence["objects"] if isinstance(item, dict)]
    _require(object_names == [table["table"] for table in snapshot["tables"]])
    for item in evidence["objects"]:
        _require(
            isinstance(item, dict)
            and set(item)
            == {
                "table",
                "rowCount",
                "uniqueKeyCount",
                "emptyStableKeyCount",
                "localBaseTable",
                "metadataExact",
                "evidenceSource",
            }
        )
        _nonnegative_int(item["rowCount"])
        _nonnegative_int(item["uniqueKeyCount"])
        _require(item["emptyStableKeyCount"] == 0)
        _require(item["localBaseTable"] is True and item["metadataExact"] is True)
        _require(item["evidenceSource"] == "preflightResponse+successfulLiveGuard")
    _require(evidence["orphanCounts"] == {
        "productIndustry": 0,
        "industryHierarchy": 0,
        "evidenceSource": "successfulLiveGuard",
    })
    _require(isinstance(evidence["operations"], list) and len(evidence["operations"]) == 5)
    expected_operations = [
        "RESOLVE_CATALOG",
        "SEARCH_PRODUCTS",
        "PRODUCT_INDUSTRIES",
        "INDUSTRY_CHILDREN",
        "INDUSTRY_PARENT_PATH",
    ]
    for index, item in enumerate(evidence["operations"], 1):
        _require(
            isinstance(item, dict)
            and set(item)
            == {
                "sequence",
                "operation",
                "success",
                "dataStatus",
                "totalCount",
                "returnedCount",
                "truncated",
                "dataAsOf",
            }
        )
        _require(item["sequence"] == index and item["operation"] == expected_operations[index - 1])
        _require(item["success"] is True)
        _require(item["dataStatus"] in {"AVAILABLE", "EMPTY"})
        _nonnegative_int(item["totalCount"])
        _nonnegative_int(item["returnedCount"])
        _require(isinstance(item["truncated"], bool))
        _require(item["dataAsOf"] == evidence["dataAsOf"])
    _require(isinstance(evidence["negativePolicy"], list) and len(evidence["negativePolicy"]) == 5)
    for field, item in zip(NEGATIVE_FIELDS, evidence["negativePolicy"]):
        _require(item == {"field": field, "errorCode": "POLICY_DENIED", "psqlStarted": False})
    assert_sanitized(
        {
            key: value
            for key, value in evidence.items()
            if key not in {"metadataTables", "privateColumns"}
        }
    )


def _write_output(path: Path, evidence: dict[str, Any]) -> None:
    _require(path == OUTPUT_PATH, "exact smoke output path required")
    _require(not path.exists() and not path.is_symlink(), "smoke output already exists")
    encoded = json.dumps(
        evidence,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            _require(isinstance(written, int) and written > 0, "short smoke output")
            offset += written
    finally:
        os.close(descriptor)


class _QuietArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise _PhaseFailure("ARGS")

    def exit(self, _status: int = 0, _message: str | None = None) -> None:
        raise _PhaseFailure("ARGS")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = _QuietArgumentParser(add_help=False)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", required=True)
    args, extra = parser.parse_known_args(argv)
    _require(not extra, "unexpected smoke arguments")
    _require(args.profile == PROFILE, "profile mismatch")
    _require(args.output == str(OUTPUT_PATH), "output path mismatch")
    return args


def main(argv: list[str] | None = None) -> int:
    output_created = False
    output_preexisting = OUTPUT_PATH.exists() or OUTPUT_PATH.is_symlink()
    phase = "ARGS"
    try:
        _parse_args(list(sys.argv[1:] if argv is None else argv))
        phase = "SCHEMA_STARTUP"
        from adapter import Adapter
        from schema_client import SchemaClient

        node_binary = os.environ.get("TASK7_NODE_BINARY")
        _require(isinstance(node_binary, str) and os.path.isabs(node_binary))
        schema = SchemaClient(node_binary=node_binary)
        adapter = Adapter(schema_factory=lambda: schema)
        try:
            phase = "EVIDENCE"
            evidence = build_evidence(adapter)
            phase = "OUTPUT"
            _write_output(OUTPUT_PATH, evidence)
            output_created = True
        finally:
            schema.close()
        print("KINGBASE_READONLY_SMOKE_OK")
        return 0
    except (_PhaseFailure, SystemExit, Exception) as failure:
        if not output_preexisting and (output_created or OUTPUT_PATH.exists()):
            try:
                OUTPUT_PATH.unlink()
            except OSError:
                pass
        failure_phase = failure.phase if isinstance(failure, _PhaseFailure) else phase
        failure_code = failure.code if isinstance(failure, _PhaseFailure) else None
        print(safe_failure_marker(failure_phase, failure_code), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
