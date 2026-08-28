"""
作者：elvis
日期：2026-08-18
作用：验证 compact evidence.scope 与响应字节上限
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from envelope import (
    MAX_RESPONSE_BYTES,
    EnvelopeTooLarge,
    build_result_too_large,
    compact_scope,
    response_bytes,
    validate_response_size,
)


def _max_scope():
    schema = "模式" * 64
    table = "表名" * 64
    column = "字段" * 64
    return {
        "businessCatalogSchemas": [schema] * 3,
        "dataObjects": [
            {"schema": schema, "object": table, "objectKind": "LOCAL_BASE_TABLE"}
            for _ in range(50)
        ],
        "valueColumns": [
            {"schema": schema, "object": table, "column": column}
            for _ in range(100)
        ],
        "sampleColumns": [
            {"schema": schema, "object": table, "column": column}
            for _ in range(100)
        ],
        "sqlColumns": [
            {"schema": schema, "object": table, "column": column}
            for _ in range(100)
        ],
        "statsGrants": [
            {"schema": schema, "object": table, "metrics": ["ROW_COUNT"]}
            for _ in range(100)
        ],
        "metadataOnly": False,
    }


class EnvelopeTest(unittest.TestCase):
    def test_compact_result_too_large_fits_limit(self):
        scope = _max_scope()
        response = build_result_too_large(scope)
        self.assertEqual(response["status"], "RESULT_TOO_LARGE")
        self.assertFalse(response["truncated"])
        self.assertIsNone(response["data"])
        self.assertIsNone(response["page"])
        self.assertEqual(response["evidence"]["scope"], compact_scope(scope))
        self.assertLess(response_bytes(response), MAX_RESPONSE_BYTES)

    def test_full_scope_echo_is_not_legal_response(self):
        scope = _max_scope()
        response = build_result_too_large(scope)
        response["evidence"]["scope"] = scope
        with self.assertRaises(EnvelopeTooLarge):
            validate_response_size(response)

    def test_serialized_bytes_must_match_canonical_response_size(self):
        response = build_result_too_large(_max_scope())
        response["evidence"]["serializedBytes"] = 0
        with self.assertRaises(EnvelopeTooLarge):
            validate_response_size(response)

    def test_compact_preview_rejects_extra_fields_and_unbounded_text(self):
        for preview in (
            [{"schema": "ai_dw", "object": "t", "column": "x", "secret": "leak"}],
            [{"schema": "ai_dw", "object": "t", "column": "x" * 33}],
        ):
            response = build_result_too_large(_max_scope())
            response["evidence"]["scope"]["preview"]["valueColumns"] = preview
            response["evidence"]["serializedBytes"] = response_bytes(response)
            with self.assertRaises(EnvelopeTooLarge):
                validate_response_size(response)

    def test_compact_scope_rejects_non_string_preview_sources(self):
        scope = _max_scope()
        scope["dataObjects"][0]["schema"] = 123
        with self.assertRaises(EnvelopeTooLarge):
            compact_scope(scope)


if __name__ == "__main__":
    unittest.main()
