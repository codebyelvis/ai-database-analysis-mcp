"""Exact public MCP stdio protocol tests."""

import importlib
import io
import json
import math
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


PROTOCOL_VERSION = "2024-11-05"


def load_server():
    return importlib.import_module("industry_selection_bridge_server")


class FakeBridge:
    def __init__(self, result=None):
        self.result = result or {
            "success": True,
            "operation": "entity_resolve",
            "mockData": False,
            "resolutionResults": [],
            "resolvedPlan": None,
        }
        self.calls = []
        self.closed = False

    def entity_resolve(self, arguments):
        self.calls.append(("entity_resolve", arguments))
        return self.result

    def business_query(self, arguments):
        self.calls.append(("business_query", arguments))
        return self.result

    def close(self):
        self.closed = True


def run_protocol(requests, bridge=None):
    server = load_server()
    input_bytes = b"".join(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        for value in requests
    )
    output = io.BytesIO()
    target = bridge or FakeBridge()
    status = server.serve(io.BytesIO(input_bytes), output, bridge=target)
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    return status, lines, target


class ShortWrite(io.BytesIO):
    def write(self, value):
        super().write(value)
        return max(0, len(value) - 1)


class PublicServerTest(unittest.TestCase):
    def test_tools_list_accepts_codex_optional_null_params(self):
        status, lines, bridge = run_protocol(
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": None}]
        )
        self.assertEqual(status, 0)
        self.assertEqual([tool["name"] for tool in lines[0]["result"]["tools"]], [
            "entity_resolve",
            "business_query",
        ])
        self.assertEqual(bridge.calls, [])

    def test_exact_initialize_list_and_two_tool_calls(self):
        status, lines, bridge = run_protocol(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {},
                    },
                },
                {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "entity_resolve", "arguments": {"x": 1}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "business_query", "arguments": {"y": 2}},
                },
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            lines[0]["result"],
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "industry-stock-selection-local",
                    "version": "1.0.0",
                },
            },
        )
        self.assertEqual(lines[1]["result"], {})
        tools = lines[2]["result"]["tools"]
        self.assertEqual([tool["name"] for tool in tools], ["entity_resolve", "business_query"])
        self.assertTrue(all(tool["annotations"] == {"readOnlyHint": True, "destructiveHint": False} for tool in tools))
        tools[0]["inputSchema"]["properties"].clear()
        fresh_tools = load_server().tool_definitions()
        self.assertIn("operation", fresh_tools[0]["inputSchema"]["properties"])
        self.assertEqual(
            bridge.calls,
            [("entity_resolve", {"x": 1}), ("business_query", {"y": 2})],
        )
        self.assertEqual(
            json.loads(lines[3]["result"]["content"][0]["text"]), bridge.result
        )
        self.assertTrue(bridge.closed)

    def test_notification_is_silent_and_never_invokes_bridge(self):
        bridge = FakeBridge()
        status, lines, _ = run_protocol(
            [
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "entity_resolve", "arguments": {}},
                }
            ],
            bridge,
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines, [])
        self.assertEqual(bridge.calls, [])

    def test_cursor_unknown_tool_and_invalid_id_are_frozen_errors(self):
        status, lines, bridge = run_protocol(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"cursor": "x"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "other", "arguments": {}}},
                {"jsonrpc": "2.0", "id": True, "method": "ping", "params": {}},
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines[0]["error"], {"code": -32602, "message": "invalid_params"})
        self.assertEqual(lines[1]["error"], {"code": -32602, "message": "invalid_params"})
        self.assertEqual(lines[2]["error"], {"code": -32600, "message": "invalid_request"})
        self.assertEqual(bridge.calls, [])

    def test_strict_json_depth_line_limit_and_continue(self):
        server = load_server()
        invalid = [
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":NaN}\n',
            b"\xff\n",
            b"[" * 65 + b"0" + b"]" * 65 + b"\n",
            b"x" * (server.MAX_JSON_LINE_BYTES + 1) + b"\n",
            b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n',
        ]
        output = io.BytesIO()
        status = server.serve(io.BytesIO(b"".join(invalid)), output, bridge=FakeBridge())
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(status, 0)
        self.assertEqual(lines[-1]["result"], {})
        self.assertTrue(all(math.isfinite(value["error"]["code"]) for value in lines[:-1]))

    def test_short_write_returns_nonzero_without_raw_diagnostic(self):
        server = load_server()
        status = server.serve(
            io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n'),
            ShortWrite(),
            bridge=FakeBridge(),
        )
        self.assertEqual(status, 1)

    def test_startup_failure_is_one_safe_line_and_no_protocol_output(self):
        server = load_server()
        stdin = type("Input", (), {"buffer": io.BytesIO()})()
        stdout_buffer = io.BytesIO()
        stdout = type("Output", (), {"buffer": stdout_buffer})()
        stderr = io.StringIO()
        with patch.object(server, "create_bridge", side_effect=RuntimeError("secret path")):
            with patch.object(server.sys, "stdin", stdin), patch.object(server.sys, "stdout", stdout), patch.object(server.sys, "stderr", stderr):
                self.assertEqual(server.main(), 1)
        self.assertEqual(stdout_buffer.getvalue(), b"")
        self.assertEqual(stderr.getvalue(), "INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        self.assertNotIn("secret", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
