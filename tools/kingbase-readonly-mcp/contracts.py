import re
from dataclasses import dataclass
from typing import Any

from canonical import decode_industry_root_id, has_control


PROFILE = "ai_app_industry_test_ro"
SCHEMA = "ai_dw"
KEYCHAIN_SERVICE = "ai-app-industry-kingbase-test"
TABLES = (
    "T_EDW_VAR_PD_INFO_Q",
    "T_EDW_VAR_PD_IDTY_RELA_Q",
    "T_EDW_VAR_HCZQ_IDTY_CLAS_Q",
)
OPERATIONS = frozenset(
    {
        "RESOLVE_CATALOG",
        "SEARCH_PRODUCTS",
        "PRODUCT_INDUSTRIES",
        "INDUSTRY_CHILDREN",
        "INDUSTRY_PARENT_PATH",
    }
)

_ENTITY_PATTERNS = {
    "productEntityId": re.compile(r"^PRODUCT:[A-Za-z0-9._-]+$"),
    "parentEntityId": re.compile(r"^INDUSTRY_(?:ROOT:[A-Za-z0-9_-]+|L[12]:[A-Za-z0-9._-]+)$"),
    "industryEntityId": re.compile(r"^INDUSTRY_(?:ROOT:[A-Za-z0-9_-]+|L[123]:[A-Za-z0-9._-]+)$"),
}


@dataclass(frozen=True)
class PolicyDenied(ValueError):
    operation: str

    def __str__(self) -> str:
        return "request rejected by policy"


def normalize_operation(value: Any) -> str:
    return value if isinstance(value, str) and value in OPERATIONS else "UNKNOWN_OPERATION"


def _deny(operation: Any) -> None:
    raise PolicyDenied(normalize_operation(operation))


def _safe_text(value: Any, maximum: int = 200) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= maximum
        and not has_control(value)
    )


def _safe_limit(value: Any, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= maximum
    )


def _safe_entity(field: str, value: Any) -> bool:
    if not isinstance(value, str) or not 3 <= len(value) <= 128:
        return False
    if _ENTITY_PATTERNS[field].fullmatch(value) is None:
        return False
    if value.startswith("INDUSTRY_ROOT:"):
        try:
            decode_industry_root_id(value)
        except ValueError:
            return False
    return True


def validate_catalog_request(request: Any) -> dict[str, Any]:
    if not isinstance(request, dict):
        _deny(None)
    operation = request.get("operation")
    if operation not in OPERATIONS:
        _deny(operation)

    if operation == "RESOLVE_CATALOG":
        valid = (
            set(request) == {"operation", "text", "expectedEntityType", "limit"}
            and _safe_text(request.get("text"))
            and request.get("expectedEntityType") in {"PRODUCT", "INDUSTRY", "ANY"}
            and _safe_limit(request.get("limit"), 10)
        )
    elif operation == "SEARCH_PRODUCTS":
        valid = (
            set(request) == {"operation", "searchText", "matchField", "limit"}
            and _safe_text(request.get("searchText"))
            and request.get("matchField") in {"ANY", "NAME", "CODE"}
            and _safe_limit(request.get("limit"), 20)
        )
    elif operation == "PRODUCT_INDUSTRIES":
        valid = (
            set(request) == {"operation", "productEntityId", "limit"}
            and _safe_entity("productEntityId", request.get("productEntityId"))
            and _safe_limit(request.get("limit"), 50)
        )
    elif operation == "INDUSTRY_CHILDREN":
        valid = (
            set(request) == {"operation", "parentEntityId", "limit"}
            and _safe_entity("parentEntityId", request.get("parentEntityId"))
            and _safe_limit(request.get("limit"), 50)
        )
    else:
        valid = (
            set(request) == {"operation", "industryEntityId"}
            and _safe_entity("industryEntityId", request.get("industryEntityId"))
        )

    if not valid:
        _deny(operation)
    return dict(request)
