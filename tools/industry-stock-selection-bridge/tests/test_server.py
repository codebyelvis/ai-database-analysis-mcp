"""Exact public MCP stdio protocol tests."""

import importlib
import io
import json
import math
import signal
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
    def __init__(self, result=None, events=None):
        self.result = result or {
            "success": True,
            "operation": "entity_resolve",
            "mockData": False,
            "resolutionResults": [],
            "resolvedPlan": None,
        }
        self.calls = []
        self.closed = False
        self.events = events

    def entity_resolve(self, arguments):
        self.calls.append(("entity_resolve", arguments))
        return self.result

    def business_query(self, arguments):
        self.calls.append(("business_query", arguments))
        return self.result

    def close(self):
        self.closed = True
        if self.events is not None:
            self.events.append("bridge.close")


class FakeSchemaClient:
    def __init__(self, responses=None, events=None):
        self.responses = list(responses or [])
        self.calls = []
        self.closed = False
        self.events = events

    def validate(self, contract, instance):
        self.calls.append((contract, instance))
        if not self.responses:
            return True
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        self.closed = True
        if self.events is not None:
            self.events.append("schema.close")


def run_protocol(requests, bridge=None, schema_client=None):
    server = load_server()
    input_bytes = b"".join(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
        for value in requests
    )
    output = io.BytesIO()
    target = bridge or FakeBridge()
    contracts = schema_client or FakeSchemaClient()
    status = server.serve(
        io.BytesIO(input_bytes),
        output,
        bridge=target,
        schema_client=contracts,
    )
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    return status, lines, target


class ShortWrite(io.BytesIO):
    def write(self, value):
        super().write(value)
        return max(0, len(value) - 1)


class FlushFailure(io.BytesIO):
    def flush(self):
        raise OSError("private flush detail")


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

    def test_tools_list_accepts_codex_request_metadata(self):
        status, lines, bridge = run_protocol(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {"_meta": {"progressToken": 0}},
                }
            ]
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            [tool["name"] for tool in lines[0]["result"]["tools"]],
            ["entity_resolve", "business_query"],
        )
        self.assertEqual(bridge.calls, [])

    def test_request_metadata_is_transport_only_for_other_methods(self):
        metadata = {"_meta": {"progressToken": 1, "threadId": "thread-1"}}
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
                        **metadata,
                    },
                },
                {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": metadata},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "entity_resolve",
                        "arguments": {"x": 1},
                        **metadata,
                    },
                },
            ]
        )
        self.assertEqual(status, 0)
        self.assertNotIn("error", lines[0])
        self.assertEqual(lines[1]["result"], {})
        self.assertNotIn("error", lines[2])
        self.assertEqual(bridge.calls, [("entity_resolve", {"x": 1})])

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
        schema = FakeSchemaClient()
        status, lines, _ = run_protocol(
            [
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "entity_resolve", "arguments": {}},
                }
            ],
            bridge,
            schema,
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines, [])
        self.assertEqual(bridge.calls, [])
        self.assertEqual(schema.calls, [])

    def test_request_schema_rejection_is_invalid_params_before_bridge(self):
        bridge = FakeBridge()
        schema = FakeSchemaClient([False])
        status, lines, _ = run_protocol(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "entity_resolve",
                        "arguments": {"operation": "entity_resolve"},
                    },
                }
            ],
            bridge,
            schema,
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            lines[0]["error"],
            {"code": -32602, "message": "invalid_params"},
        )
        self.assertEqual(
            [contract for contract, _ in schema.calls],
            ["entityResolveRequest"],
        )
        self.assertEqual(bridge.calls, [])

    def test_each_tool_uses_its_exact_request_and_response_contracts(self):
        cases = (
            (
                "entity_resolve",
                "entityResolveRequest",
                "entityResolveResponse",
            ),
            (
                "business_query",
                "businessQueryRequest",
                "businessQueryResponse",
            ),
        )
        for tool_name, request_contract, response_contract in cases:
            with self.subTest(tool_name=tool_name):
                bridge = FakeBridge(
                    {
                        "success": True,
                        "operation": tool_name,
                        "mockData": False,
                    }
                )
                schema = FakeSchemaClient()
                status, lines, _ = run_protocol(
                    [
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": tool_name,
                                "arguments": {"operation": tool_name},
                            },
                        }
                    ],
                    bridge,
                    schema,
                )
                self.assertEqual(status, 0)
                self.assertNotIn("error", lines[0])
                self.assertEqual(
                    [contract for contract, _ in schema.calls],
                    [request_contract, response_contract],
                )
                self.assertEqual(
                    bridge.calls,
                    [(tool_name, {"operation": tool_name})],
                )

    def test_invalid_or_unavailable_response_is_internal_error_and_not_published(self):
        for response in (False, RuntimeError("private validator detail"), "true"):
            with self.subTest(response=response):
                bridge = FakeBridge(
                    {
                        "success": True,
                        "operation": "entity_resolve",
                        "privateMarker": "MUST_NOT_PUBLISH",
                    }
                )
                schema = FakeSchemaClient([True, response])
                status, lines, _ = run_protocol(
                    [
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "entity_resolve",
                                "arguments": {"operation": "entity_resolve"},
                            },
                        }
                    ],
                    bridge,
                    schema,
                )
                self.assertEqual(status, 0)
                self.assertEqual(
                    lines[0]["error"],
                    {"code": -32603, "message": "internal_error"},
                )
                self.assertNotIn("MUST_NOT_PUBLISH", repr(lines))
                self.assertEqual(len(bridge.calls), 1)

    def test_unavailable_or_nonboolean_request_validator_is_internal_error_before_bridge(self):
        for response in (RuntimeError("private validator detail"), "true"):
            with self.subTest(response=response):
                bridge = FakeBridge()
                schema = FakeSchemaClient([response])
                status, lines, _ = run_protocol(
                    [
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "business_query",
                                "arguments": {"operation": "business_query"},
                            },
                        }
                    ],
                    bridge,
                    schema,
                )
                self.assertEqual(status, 0)
                self.assertEqual(
                    lines[0]["error"],
                    {"code": -32603, "message": "internal_error"},
                )
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
        status = server.serve(
            io.BytesIO(b"".join(invalid)),
            output,
            bridge=FakeBridge(),
            schema_client=FakeSchemaClient(),
        )
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(status, 0)
        self.assertEqual(lines[-1]["result"], {})
        self.assertTrue(all(math.isfinite(value["error"]["code"]) for value in lines[:-1]))

    def test_1200_depth_notification_returns_parse_error_then_ping_without_bridge_call(self):
        server = load_server()
        bridge = FakeBridge()
        deep = (
            b'{"jsonrpc":"2.0","method":"tools/call","params":'
            b'{"name":"entity_resolve","arguments":{"deep":'
            + b"[" * 1200
            + b"0"
            + b"]" * 1200
            + b"}}}\n"
        )
        ping = b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n'
        output = io.BytesIO()

        status = server.serve(
            io.BytesIO(deep + ping),
            output,
            bridge=bridge,
            schema_client=FakeSchemaClient(),
        )
        lines = [json.loads(line) for line in output.getvalue().splitlines()]

        self.assertEqual(status, 0)
        self.assertEqual(
            lines,
            [
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "parse_error"},
                },
                {"jsonrpc": "2.0", "id": 2, "result": {}},
            ],
        )
        self.assertEqual(bridge.calls, [])
        self.assertTrue(bridge.closed)

    def test_short_write_returns_nonzero_without_raw_diagnostic(self):
        server = load_server()
        events = []
        status = server.serve(
            io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n'),
            ShortWrite(),
            bridge=FakeBridge(events=events),
            schema_client=FakeSchemaClient(events=events),
        )
        self.assertEqual(status, 1)
        self.assertEqual(events, ["bridge.close", "schema.close"])

    def test_serve_owns_resources_and_closes_bridge_before_schema_on_eof_and_read_failure(self):
        server = load_server()

        class BadInput:
            def readline(self, _cap):
                raise OSError("private read detail")

        for input_stream in (io.BytesIO(), BadInput()):
            with self.subTest(input_stream=type(input_stream).__name__):
                events = []
                bridge = FakeBridge(events=events)
                schema = FakeSchemaClient(events=events)
                status = server.serve(
                    input_stream,
                    io.BytesIO(),
                    bridge=bridge,
                    schema_client=schema,
                )
                self.assertIn(status, {0, 1})
                self.assertEqual(events, ["bridge.close", "schema.close"])

    def test_flush_and_internal_error_paths_close_bridge_before_schema(self):
        server = load_server()
        ping = io.BytesIO(
            b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n'
        )
        events = []
        self.assertEqual(
            server.serve(
                ping,
                FlushFailure(),
                bridge=FakeBridge(events=events),
                schema_client=FakeSchemaClient(events=events),
            ),
            1,
        )
        self.assertEqual(events, ["bridge.close", "schema.close"])

        request = io.BytesIO(
            b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
            b'"params":{"name":"entity_resolve","arguments":{}}}\n'
        )
        events = []
        output = io.BytesIO()
        self.assertEqual(
            server.serve(
                request,
                output,
                bridge=FakeBridge(events=events),
                schema_client=FakeSchemaClient([True, "not-a-bool"], events=events),
            ),
            0,
        )
        self.assertEqual(
            json.loads(output.getvalue())["error"],
            {"code": -32603, "message": "internal_error"},
        )
        self.assertEqual(events, ["bridge.close", "schema.close"])

    def test_main_constructs_schema_before_bridge_and_closes_in_owner_order(self):
        server = load_server()
        events = []
        schema = FakeSchemaClient(events=events)
        bridge = FakeBridge(events=events)
        stdin = type("Input", (), {"buffer": io.BytesIO()})()
        stdout = type("Output", (), {"buffer": io.BytesIO()})()
        stderr = io.StringIO()

        def create_schema():
            events.append("schema.create")
            return schema

        def create_bridge():
            events.append("bridge.create")
            return bridge

        with patch.object(server, "create_schema_client", side_effect=create_schema):
            with patch.object(server, "create_bridge", side_effect=create_bridge):
                with patch.object(server.sys, "stdin", stdin), patch.object(
                    server.sys, "stdout", stdout
                ), patch.object(server.sys, "stderr", stderr):
                    self.assertEqual(server.main(), 0)
        self.assertEqual(
            events,
            ["schema.create", "bridge.create", "bridge.close", "schema.close"],
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_term_handler_closes_owned_resources_then_restores_handlers(self):
        server = load_server()
        events = []
        installed = {}
        previous = {
            signal.SIGHUP: object(),
            signal.SIGINT: object(),
            signal.SIGTERM: object(),
        }

        def record_signal(signum, handler):
            if callable(handler):
                events.append(("install", signum))
                installed[signum] = handler
                return previous[signum]
            events.append(("restore", signum))
            self.assertIs(handler, previous[signum])
            return None

        class SignalInput:
            def readline(self, _cap):
                events.append(("read", signal.SIGTERM))
                installed[signal.SIGTERM](signal.SIGTERM, None)

        bridge = FakeBridge(events=events)
        schema = FakeSchemaClient(events=events)
        with patch.object(server.signal, "signal", side_effect=record_signal):
            with self.assertRaises(SystemExit) as caught:
                server._serve_with_signal_handlers(
                    SignalInput(),
                    io.BytesIO(),
                    bridge=bridge,
                    schema_client=schema,
                )
        self.assertEqual(caught.exception.code, 143)
        self.assertEqual(events[:3], [
            ("install", signal.SIGHUP),
            ("install", signal.SIGINT),
            ("install", signal.SIGTERM),
        ])
        self.assertEqual(
            events[3:],
            [
                ("read", signal.SIGTERM),
                "bridge.close",
                "schema.close",
                ("restore", signal.SIGTERM),
                ("restore", signal.SIGINT),
                ("restore", signal.SIGHUP),
            ],
        )

    def test_startup_failure_is_one_safe_line_and_no_protocol_output(self):
        server = load_server()
        stdin = type("Input", (), {"buffer": io.BytesIO()})()
        stdout_buffer = io.BytesIO()
        stdout = type("Output", (), {"buffer": stdout_buffer})()
        stderr = io.StringIO()
        schema = FakeSchemaClient()
        with patch.object(server, "create_schema_client", return_value=schema):
            with patch.object(server, "create_bridge", side_effect=RuntimeError("secret path")):
                with patch.object(server.sys, "stdin", stdin), patch.object(server.sys, "stdout", stdout), patch.object(server.sys, "stderr", stderr):
                    self.assertEqual(server.main(), 1)
        self.assertEqual(stdout_buffer.getvalue(), b"")
        self.assertEqual(stderr.getvalue(), "INDUSTRY_SELECTION_BRIDGE_FAILED\n")
        self.assertNotIn("secret", stderr.getvalue())
        self.assertTrue(schema.closed)

    def test_schema_startup_failure_never_constructs_bridge(self):
        server = load_server()
        stdin = type("Input", (), {"buffer": io.BytesIO()})()
        stdout_buffer = io.BytesIO()
        stdout = type("Output", (), {"buffer": stdout_buffer})()
        stderr = io.StringIO()
        with patch.object(
            server,
            "create_schema_client",
            side_effect=RuntimeError("secret validator path"),
        ):
            with patch.object(server, "create_bridge") as create_bridge:
                with patch.object(server.sys, "stdin", stdin), patch.object(
                    server.sys, "stdout", stdout
                ), patch.object(server.sys, "stderr", stderr):
                    self.assertEqual(server.main(), 1)
        create_bridge.assert_not_called()
        self.assertEqual(stdout_buffer.getvalue(), b"")
        self.assertEqual(stderr.getvalue(), "INDUSTRY_SELECTION_BRIDGE_FAILED\n")


if __name__ == "__main__":
    unittest.main()
