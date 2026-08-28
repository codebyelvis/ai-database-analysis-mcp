"""
作者：elvis
日期：2026-08-19
作用：验证无库 stdio MCP 协议与 Slice 1 工具适配边界
"""

import io
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from mcp_server import PROTOCOL_VERSION, serve


SERVER_ENTRYPOINT = Path(__file__).resolve().parents[1] / "run_mcp_server.sh"


class McpServerTest(unittest.TestCase):
    def request(self, method, params=None, request_id=1):
        request = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request["params"] = params
        input_stream = io.StringIO(json.dumps(request) + "\n")
        output_stream = io.StringIO()
        serve(input_stream, output_stream)
        return json.loads(output_stream.getvalue())

    def call_tool(self, name, arguments):
        response = self.request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        return response["result"]

    def process_request(self, request):
        """通过真实 stdio 入口发送一条请求并返回进程结果。"""
        return self.process_raw(json.dumps(request, ensure_ascii=False) + "\n")

    def process_raw(self, raw_request):
        """通过真实 stdio 入口发送原始 JSON 行。"""
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        return subprocess.run(
            [str(SERVER_ENTRYPOINT)],
            input=raw_request,
            text=True,
            capture_output=True,
            env=environment,
        )

    def test_initialize_advertises_tools_without_external_capability(self):
        response = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "fixture-test", "version": "1"},
            },
        )
        self.assertEqual(response["result"]["protocolVersion"], PROTOCOL_VERSION)
        self.assertEqual(response["result"]["capabilities"], {"tools": {}})

    def test_tools_list_is_fixed_and_contains_only_fixture_tools(self):
        response = self.request("tools/list", {})
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertEqual(
            names,
            {
                "canonicalize",
                "scan_dbar1",
                "validate_append_only",
                "scan_v1_fixture",
                "ledger_probe",
                "build_result_too_large",
            },
        )

    def test_tools_list_accepts_codex_optional_null_params(self):
        completed = self.process_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": None}
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        response = json.loads(completed.stdout)
        self.assertNotIn("error", response)
        self.assertEqual(len(response["result"]["tools"]), 6)

    def test_tools_list_accepts_codex_request_metadata(self):
        completed = self.process_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {"_meta": {"progressToken": 0}},
            }
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        response = json.loads(completed.stdout)
        self.assertNotIn("error", response)
        self.assertEqual(len(response["result"]["tools"]), 6)

    def test_request_metadata_is_transport_only_for_other_methods(self):
        metadata = {"_meta": {"progressToken": 1, "threadId": "thread-1"}}
        initialized = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "codex", "version": "1"},
                **metadata,
            },
        )
        pinged = self.request("ping", metadata)
        called = self.request(
            "tools/call",
            {
                "name": "canonicalize",
                "arguments": {"value": {"b": 2, "a": 1}},
                **metadata,
            },
        )
        self.assertNotIn("error", initialized)
        self.assertEqual(pinged["result"], {})
        self.assertEqual(called["result"]["content"][0]["text"], '{"a":1,"b":2}')

    def test_tool_schemas_are_closed_objects(self):
        response = self.request("tools/list", {})

        def assert_closed(node, path="schema"):
            if isinstance(node, dict):
                if node.get("type") == "object" or "properties" in node:
                    self.assertFalse(
                        node.get("additionalProperties", True),
                        path,
                    )
                for key, value in node.get("properties", {}).items():
                    assert_closed(value, f"{path}.properties.{key}")
                for key in ("items", "additionalProperties"):
                    if key in node and isinstance(node[key], dict):
                        assert_closed(node[key], f"{path}.{key}")
                for key in ("anyOf", "oneOf", "allOf"):
                    for index, value in enumerate(node.get(key, [])):
                        assert_closed(value, f"{path}.{key}[{index}]")

        for tool in response["result"]["tools"]:
            with self.subTest(tool=tool["name"]):
                self.assertFalse(tool["inputSchema"].get("additionalProperties", True))
                assert_closed(tool["inputSchema"], tool["name"])

    def test_canonicalize_returns_stable_json_text(self):
        result = self.call_tool("canonicalize", {"value": {"b": 2, "a": "中文"}})
        self.assertFalse(result.get("isError", False))
        self.assertEqual(result["content"][0]["text"], '{"a":"中文","b":2}')

    def test_dbar1_rejection_is_tool_error_without_traceback(self):
        result = self.call_tool("scan_dbar1", {"raw": "DBAR1 rec-1 " + "a" * 64 + "\n"})
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"]), {"error": "syntax"})
        self.assertNotIn("Traceback", result["content"][0]["text"])

    def test_dbar1_success_returns_record_keys(self):
        result = self.call_tool(
            "scan_dbar1",
            {"raw": "DBAR1\trec-1\t" + "a" * 64 + "\n"},
        )
        self.assertFalse(result.get("isError", False))
        self.assertEqual(
            json.loads(result["content"][0]["text"]),
            {"recordKeys": ["rec-1"]},
        )

    def test_v1_runtime_rejects_schema_invalid_pid_and_sha(self):
        base = {
            "fd": {
                "canonicalPath": "/fixture/toolbox",
                "device": "1",
                "inode": "2",
                "sha256": "a" * 64,
            },
            "procs": [
                {"pid": 4, "device": "9", "inode": "9", "sha256": "a" * 64}
            ],
        }
        invalid_fixtures = []
        invalid_pid = {**base, "procs": [{**base["procs"][0], "pid": 0}]}
        invalid_negative_pid = {
            **base,
            "procs": [{**base["procs"][0], "pid": -1}],
        }
        invalid_bool_pid = {
            **base,
            "procs": [{**base["procs"][0], "pid": True}],
        }
        invalid_proc_sha = {
            **base,
            "procs": [{**base["procs"][0], "sha256": "not-hex"}],
        }
        invalid_fd_sha = {
            **base,
            "fd": {**base["fd"], "sha256": "A" * 64},
        }
        invalid_fixtures.extend(
            [
                invalid_pid,
                invalid_negative_pid,
                invalid_bool_pid,
                invalid_proc_sha,
                invalid_fd_sha,
            ]
        )
        for arguments in invalid_fixtures:
            with self.subTest(arguments=arguments):
                result = self.call_tool("scan_v1_fixture", arguments)
                self.assertTrue(result["isError"])

    def test_each_tool_rejection_is_an_error_result(self):
        rejected_calls = [
            ("canonicalize", {"value": float("nan")}),
            (
                "validate_append_only",
                {"preimage": "", "postimage": "", "recordKey": ""},
            ),
            (
                "scan_v1_fixture",
                {
                    "fd": {
                        "canonicalPath": "/fixture/toolbox",
                        "device": "1",
                        "inode": "2",
                        "sha256": "a" * 64,
                    },
                    "procs": "not-an-array",
                },
            ),
            (
                "ledger_probe",
                {"events": [{"op": "refusePermit", "reason": "not-verified"}]},
            ),
            ("build_result_too_large", {"scope": {"dataObjects": [{}]}}),
        ]
        for tool_name, arguments in rejected_calls:
            with self.subTest(tool_name=tool_name):
                result = self.call_tool(tool_name, arguments)
                self.assertTrue(result["isError"])
                self.assertNotIn("Traceback", result["content"][0]["text"])

    def test_tool_and_nested_arguments_reject_extra_fields(self):
        cases = [
            ("scan_dbar1", {"raw": "", "extra": 1}),
            (
                "validate_append_only",
                {"preimage": "", "postimage": "", "recordKey": "r", "extra": 1},
            ),
            (
                "scan_v1_fixture",
                {
                    "fd": {
                        "canonicalPath": "/fixture/toolbox",
                        "device": "1",
                        "inode": "2",
                        "sha256": "a" * 64,
                        "extra": 1,
                    },
                    "procs": [],
                },
            ),
            (
                "ledger_probe",
                {"events": [{"op": "reserve", "extra": 1}]},
            ),
            (
                "build_result_too_large",
                {
                    "scope": {
                        "businessCatalogSchemas": [],
                        "dataObjects": [],
                        "valueColumns": [],
                        "sampleColumns": [],
                        "sqlColumns": [],
                        "statsGrants": [],
                        "metadataOnly": True,
                        "extra": 1,
                    }
                },
            ),
            (
                "build_result_too_large",
                {
                    "scope": {
                        "businessCatalogSchemas": [],
                        "dataObjects": [
                            {
                                "schema": "s",
                                "object": "t",
                                "objectKind": "LOCAL_BASE_TABLE",
                                "extra": 1,
                            }
                        ],
                        "valueColumns": [],
                        "sampleColumns": [],
                        "sqlColumns": [],
                        "statsGrants": [],
                        "metadataOnly": True,
                    }
                },
            ),
        ]
        for tool_name, arguments in cases:
            with self.subTest(tool_name=tool_name):
                self.assertTrue(self.call_tool(tool_name, arguments)["isError"])

    def test_lifecycle_methods_reject_non_object_params(self):
        for method in ("initialize", "ping", "tools/list"):
            with self.subTest(method=method):
                response = self.request(method, [])
                self.assertEqual(response["error"]["code"], -32602)

    def test_invalid_ledger_state_does_not_kill_stdio_process(self):
        completed = self.process_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "ledger_probe",
                    "arguments": {
                        "events": [{"op": "refusePermit", "reason": "not-verified"}]
                    },
                },
            }
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        response = json.loads(completed.stdout)
        self.assertTrue(response["result"]["isError"])

    def test_non_string_method_is_invalid_request_not_process_failure(self):
        completed = self.process_request(
            {"jsonrpc": "2.0", "id": 12, "method": [], "params": {}}
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(json.loads(completed.stdout)["error"]["code"], -32600)

    def test_invalid_method_and_id_types_return_null_id(self):
        completed = self.process_raw(
            '{"jsonrpc":"2.0","id":{"bad":1},"method":{}}\n'
            '{"jsonrpc":"2.0","id":13,"method":null}\n'
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(responses), 2)
        for response in responses:
            self.assertIsNone(response["id"])
            self.assertEqual(response["error"]["code"], -32600)

    def test_invalid_id_and_deep_json_do_not_kill_stdio_process(self):
        invalid_id = self.process_raw(
            '{"jsonrpc":"2.0","id":"\\ud800","method":"ping"}\n'
        )
        self.assertEqual(invalid_id.returncode, 0)
        self.assertEqual(invalid_id.stderr, "")
        invalid_id_response = json.loads(invalid_id.stdout)
        self.assertIsNone(invalid_id_response["id"])
        self.assertEqual(invalid_id_response["error"]["code"], -32600)

        deeply_nested = "{" + '"jsonrpc":"2.0","id":1,"method":"ping","params":' + (
            "[" * 1200 + "]" * 1200
        ) + "}\n"
        deep_response = self.process_raw(deeply_nested)
        self.assertEqual(deep_response.returncode, 0)
        self.assertEqual(deep_response.stderr, "")
        self.assertEqual(json.loads(deep_response.stdout)["error"]["code"], -32700)

    def test_initialize_notification_has_no_response(self):
        input_stream = io.StringIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {},
                }
            )
            + "\n"
        )
        output_stream = io.StringIO()
        serve(input_stream, output_stream)
        self.assertEqual(output_stream.getvalue(), "")

    def test_tools_call_notification_has_no_response(self):
        input_stream = io.StringIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "canonicalize",
                        "arguments": {"value": {"a": 1}},
                    },
                }
            )
            + "\n"
        )
        output_stream = io.StringIO()
        serve(input_stream, output_stream)
        self.assertEqual(output_stream.getvalue(), "")

    def test_protocol_error_does_not_stop_following_requests(self):
        completed = self.process_raw(
            '{"jsonrpc":"2.0",\n'
            '{"jsonrpc":"2.0","id":14,"method":"ping"}\n'
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, "")
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([response["error"]["code"] for response in responses[:1]], [-32700])
        self.assertEqual(responses[1], {"jsonrpc": "2.0", "id": 14, "result": {}})

    def test_append_only_and_v1_tools_return_structured_fixture_results(self):
        preimage = "<!-- local-database-analysis-records:v1 -->\n"
        postimage = preimage + "DBAR1\trec-1\t" + "a" * 64 + "\n"
        append_result = self.call_tool(
            "validate_append_only",
            {
                "preimage": preimage,
                "postimage": postimage,
                "recordKey": "rec-1",
            },
        )
        self.assertFalse(append_result.get("isError", False))
        self.assertEqual(json.loads(append_result["content"][0]["text"]), {"valid": True})

        scan_result = self.call_tool(
            "scan_v1_fixture",
            {
                "fd": {
                    "canonicalPath": "/fixture/toolbox",
                    "device": "1",
                    "inode": "2",
                    "sha256": "a" * 64,
                },
                "procs": [
                    {"pid": 4, "device": "9", "inode": "9", "sha256": "a" * 64},
                    {"pid": 5, "device": "9", "inode": "9", "sha256": "b" * 64},
                ],
            },
        )
        self.assertEqual(
            json.loads(scan_result["content"][0]["text"]),
            {"scanComplete": True, "matchedPids": [4]},
        )

    def test_ledger_and_envelope_tools_are_no_side_effect_fixtures(self):
        ledger_result = self.call_tool(
            "ledger_probe",
            {
                "events": [
                    {"op": "reserve", "nowMs": 1000},
                    {
                        "op": "reportSpawnOk",
                        "pid": 4,
                        "audit": "a" * 64,
                        "nowMs": 1001,
                    },
                    {
                        "op": "reportSpawnOk",
                        "pid": 9,
                        "audit": "b" * 64,
                        "nowMs": 1002,
                    },
                ]
            },
        )
        ledger_payload = json.loads(ledger_result["content"][0]["text"])
        self.assertFalse(ledger_result.get("isError", False))
        self.assertFalse(ledger_payload["events"][2]["result"])
        self.assertEqual(ledger_payload["snapshot"]["spawned"]["pid"], 4)
        self.assertIsNone(ledger_payload["snapshot"]["cleanupChildPid"])

        envelope_result = self.call_tool(
            "build_result_too_large",
            {
                "scope": {
                    "businessCatalogSchemas": [],
                    "dataObjects": [],
                    "valueColumns": [],
                    "sampleColumns": [],
                    "sqlColumns": [],
                    "statsGrants": [],
                    "metadataOnly": True,
                }
            },
        )
        envelope_payload = json.loads(envelope_result["content"][0]["text"])
        self.assertEqual(envelope_payload["status"], "RESULT_TOO_LARGE")
        self.assertLessEqual(envelope_payload["evidence"]["serializedBytes"], 32768)

    def test_unknown_method_and_tool_fail_closed(self):
        method_response = self.request("filesystem/read", {})
        self.assertEqual(method_response["error"]["code"], -32601)

        tool_result = self.call_tool("shell", {})
        self.assertTrue(tool_result["isError"])
        self.assertEqual(json.loads(tool_result["content"][0]["text"]), {"error": "unknown_tool"})

    def test_stdio_stream_ignores_initialized_notification_and_writes_only_json(self):
        input_stream = io.StringIO(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                }
            )
            + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"})
            + "\n"
        )
        output_stream = io.StringIO()
        serve(input_stream, output_stream)
        lines = output_stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {"jsonrpc": "2.0", "id": 2, "result": {}})
        self.assertNotIn("diagnostic", output_stream.getvalue())


if __name__ == "__main__":
    unittest.main()
