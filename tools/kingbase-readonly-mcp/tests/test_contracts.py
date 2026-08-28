import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from contracts import PolicyDenied, normalize_operation, validate_catalog_request  # noqa: E402


VALID_REQUESTS = (
    {
        "operation": "RESOLVE_CATALOG",
        "text": "人工智能",
        "expectedEntityType": "ANY",
        "limit": 10,
    },
    {
        "operation": "SEARCH_PRODUCTS",
        "searchText": "产品",
        "matchField": "ANY",
        "limit": 20,
    },
    {
        "operation": "PRODUCT_INDUSTRIES",
        "productEntityId": "PRODUCT:P1",
        "limit": 50,
    },
    {
        "operation": "INDUSTRY_CHILDREN",
        "parentEntityId": "INDUSTRY_ROOT:5Lqn5Lia",
        "limit": 50,
    },
    {
        "operation": "INDUSTRY_PARENT_PATH",
        "industryEntityId": "INDUSTRY_L3:L3",
    },
)


class RequestPolicyTest(unittest.TestCase):
    def test_all_five_closed_requests_are_accepted(self):
        for request in VALID_REQUESTS:
            with self.subTest(operation=request["operation"]):
                self.assertEqual(validate_catalog_request(request), request)

    def test_unknown_operation_is_normalized_without_echo(self):
        self.assertEqual(normalize_operation("DROP_ALL"), "UNKNOWN_OPERATION")
        with self.assertRaises(PolicyDenied) as caught:
            validate_catalog_request({"operation": "DROP_ALL", "sql": "select 1"})
        self.assertEqual(caught.exception.operation, "UNKNOWN_OPERATION")

    def test_forbidden_sql_and_pagination_fields_are_rejected(self):
        for field in ("sql", "statement", "offset", "page", "cursor", "orderBy"):
            request = dict(VALID_REQUESTS[0])
            request[field] = "x"
            with self.subTest(field=field), self.assertRaises(PolicyDenied):
                validate_catalog_request(request)

    def test_control_characters_and_empty_text_are_rejected(self):
        for value in ("", "a\u0000b", "a\u007fb", "a\u0085b"):
            request = dict(VALID_REQUESTS[0], text=value)
            with self.subTest(value=repr(value)), self.assertRaises(PolicyDenied):
                validate_catalog_request(request)

    def test_limit_bool_and_out_of_range_are_rejected(self):
        for value in (True, 0, 11, 1.0):
            request = dict(VALID_REQUESTS[0], limit=value)
            with self.subTest(value=value), self.assertRaises(PolicyDenied):
                validate_catalog_request(request)

    def test_entity_prefixes_and_l3_children_are_rejected(self):
        invalid = (
            dict(VALID_REQUESTS[2], productEntityId="INDUSTRY_L1:X"),
            dict(VALID_REQUESTS[3], parentEntityId="INDUSTRY_L3:X"),
            dict(VALID_REQUESTS[4], industryEntityId="PRODUCT:P1"),
        )
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(PolicyDenied):
                validate_catalog_request(request)


if __name__ == "__main__":
    unittest.main()
