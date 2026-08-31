"""
作者：liyan
日期：2026-08-26
作用：验证私有 Kingbase 只读 MCP server、隔离 seam 与离线 smoke 合同。
"""

import importlib
import contextlib
import inspect
import io
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import schema_client  # noqa: E402
from schema_client import SchemaClient, SchemaUnavailable  # noqa: E402


PROTOCOL_VERSION = "2024-11-05"
TOOL_ANNOTATIONS = {"readOnlyHint": True, "destructiveHint": False}
PREFLIGHT_REQUEST = {
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


def load_server():
    try:
        return importlib.import_module("kingbase_readonly_server")
    except ModuleNotFoundError as exc:
        raise AssertionError("private server target is absent; A2 behavior RED") from exc


def load_smoke():
    try:
        return importlib.import_module("smoke_test_environment")
    except ModuleNotFoundError as exc:
        raise AssertionError("smoke target is absent; B1 behavior RED") from exc


class FakeProcess:
    def __init__(self):
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO()
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def wait(self, timeout=None):
        self.returncode = self.returncode or 0
        return self.returncode

    def kill(self):
        self.returncode = -9


class FakeSelector:
    def register(self, *_args):
        return None

    def close(self):
        return None


class ShortWriteBuffer(io.BytesIO):
    def __init__(self, result):
        super().__init__()
        self.result = result

    def write(self, value):
        super().write(value)
        return self.result


class RecordingTransport:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.writes = []
        self.closed = False

    def write_line(self, payload):
        self.writes.append(payload)

    def read_line(self, _timeout, _cap):
        if not self.responses:
            raise EOFError("closed")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    def terminate(self):
        self.closed = True


class SchemaClientSeamTest(unittest.TestCase):
    def test_constructor_exposes_node_binary_and_injected_factory(self):
        signature = inspect.signature(SchemaClient)
        self.assertIn("node_binary", signature.parameters)
        self.assertIn("transport_factory", signature.parameters)
        transport = RecordingTransport([
            b'{"id":0,"valid":true}',
            b'{"id":1,"valid":true}',
        ])
        client = SchemaClient(
            node_binary="/opt/homebrew/bin/node",
            transport_factory=lambda: transport,
        )
        self.assertTrue(client.validate("preflightRequest", {}))
        client.close()
        self.assertTrue(transport.closed)

    def test_process_transport_passes_absolute_node_and_empty_environment(self):
        process = FakeProcess()
        node_binary = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        with patch.object(schema_client.subprocess, "Popen", return_value=process) as popen:
            with patch.object(schema_client.selectors, "DefaultSelector", return_value=FakeSelector()):
                transport = schema_client._ProcessTransport(node_binary)
                transport.terminate()
        args, kwargs = popen.call_args
        self.assertTrue(Path(args[0][0]).is_absolute())
        self.assertEqual(args[0][0], node_binary)
        self.assertEqual(kwargs["env"], {})

    def test_process_transport_rejects_short_and_none_writes(self):
        node_binary = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        for result in (1, None):
            with self.subTest(result=result):
                process = FakeProcess()
                process.stdin = ShortWriteBuffer(result)
                with patch.object(schema_client.subprocess, "Popen", return_value=process):
                    with patch.object(schema_client.selectors, "DefaultSelector", return_value=FakeSelector()):
                        transport = schema_client._ProcessTransport(node_binary)
                        with self.assertRaises(OSError):
                            transport.write_line(b'{"id":1}')
                        transport.terminate()

    def test_relative_or_missing_node_is_rejected_without_spawn(self):
        with patch.object(schema_client.subprocess, "Popen") as popen:
            with self.assertRaises((ValueError, FileNotFoundError, RuntimeError)):
                schema_client._ProcessTransport("node")
            popen.assert_not_called()

    def test_default_factory_resolves_once_and_final_argv_is_absolute(self):
        transport = RecordingTransport([b'{"id":0,"valid":true}'])
        node_binary = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        with patch.object(schema_client.shutil, "which", return_value=node_binary) as which:
            with patch.object(schema_client, "_ProcessTransport", return_value=transport) as factory:
                client = SchemaClient()
                client.close()
        which.assert_called_once_with("node")
        factory.assert_called_once_with(node_binary)

    def test_bootstrap_failure_closes_transport_without_diagnostics(self):
        transport = RecordingTransport([TimeoutError("private")])
        with self.assertRaises(SchemaUnavailable) as caught:
            SchemaClient(transport_factory=lambda: transport)
        self.assertEqual(str(caught.exception), "contract validation unavailable")
        self.assertTrue(transport.closed)
        self.assertNotIn("private", str(caught.exception))


class FakeAdapter:
    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def preflight(self, arguments):
        self.calls.append(("preflight", arguments))
        return self.responses.get("preflight", {"success": True})

    def catalog(self, arguments):
        self.calls.append(("catalog", arguments))
        return self.responses[arguments["operation"]]


def protocol_response(success=True, operation="kingbase_readonly_preflight"):
    response = {
        "success": success,
        "operation": operation,
        "dataStatus": "AVAILABLE" if success else "FAILED",
        "totalCount": 0,
        "returnedCount": 0,
        "truncated": False,
        "dataAsOf": "2026-08-11",
        "queryId": "0123456789abcdef",
        "data": {},
    }
    if not success:
        response.update({"errorCode": "QUERY_FAILED", "message": "query failed"})
    return response


def run_protocol(server, payloads, adapter):
    source = b"".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for item in payloads)
    output = io.BytesIO()
    status = server.serve(io.BytesIO(source), output, adapter=adapter)
    lines = [json.loads(line) for line in output.getvalue().splitlines()]
    return status, lines, adapter.calls


class ProtocolContractTest(unittest.TestCase):
    def test_tool_definitions_are_private_exact_and_schema_isolation_is_fresh(self):
        server = load_server()
        first = server.tool_definitions()
        second = server.tool_definitions()
        self.assertEqual(
            [tool["name"] for tool in first],
            ["kingbase_readonly_preflight", "kingbase_catalog_query"],
        )
        self.assertEqual(first[0]["annotations"], TOOL_ANNOTATIONS)
        self.assertEqual(first[0]["description"], "Validate the fixed test-environment read-only Kingbase contract.")
        self.assertEqual(first[1]["description"], "Query the fixed test-environment industry catalog.")
        self.assertEqual(first[0]["inputSchema"], second[0]["inputSchema"])
        self.assertIsNot(first[0]["inputSchema"], second[0]["inputSchema"])
        first[0]["inputSchema"]["x-injected"] = True
        self.assertNotIn("x-injected", second[0]["inputSchema"])
        self.assertEqual(
            second[0]["inputSchema"],
            json.loads((ROOT / "schemas" / "kingbase-readonly-preflight.request.schema.json").read_text()),
        )
        self.assertEqual(
            second[1]["inputSchema"],
            json.loads((ROOT / "schemas" / "kingbase-catalog.request.schema.json").read_text()),
        )

    def test_server_bootstrap_failure_has_no_success_output(self):
        server = load_server()
        with patch.object(server, "_startup_adapter", side_effect=RuntimeError("private")):
            output = io.BytesIO()
            status = server.serve(io.BytesIO(b"{}\n"), output, adapter=None)
        self.assertEqual(status, 1)
        self.assertEqual(output.getvalue(), b"")

    def test_short_none_write_read_and_flush_fail_with_safe_status(self):
        server = load_server()
        adapter = FakeAdapter()

        class ShortOutput(io.BytesIO):
            def write(self, value):
                return 0

        class NoneOutput(io.BytesIO):
            def write(self, value):
                return None

        class BadInput:
            def readline(self, _cap):
                raise RuntimeError("private read")

        class BadFlush(io.BytesIO):
            def flush(self):
                raise RuntimeError("private flush")

        request = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}\n'
        for output in (ShortOutput(), NoneOutput(), BadFlush()):
            with self.subTest(output=type(output).__name__):
                self.assertEqual(server.serve(io.BytesIO(request), output, adapter=adapter), 1)
        self.assertEqual(server.serve(BadInput(), io.BytesIO(), adapter=adapter), 1)

    def test_main_passes_exact_node_binary_to_ready_adapter(self):
        server = load_server()
        node = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        input_stream = type("Input", (), {"buffer": io.BytesIO()})()
        output_stream = type("Output", (), {"buffer": io.BytesIO()})()
        adapter = FakeAdapter()
        with patch.object(server, "_startup_adapter", return_value=adapter) as startup:
            with patch.object(server.sys, "stdin", input_stream), patch.object(server.sys, "stdout", output_stream):
                self.assertEqual(server.main(node), 0)
        startup.assert_called_once_with(node)

    def test_initialize_ping_list_and_calls_are_exact_and_notifications_are_silent(self):
        responses = {
            "preflight": protocol_response(),
            "RESOLVE_CATALOG": protocol_response(operation="RESOLVE_CATALOG"),
        }
        adapter = FakeAdapter(responses)
        status, lines, calls = run_protocol(
            load_server(),
            [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "kingbase_readonly_preflight", "arguments": {}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "kingbase_readonly_preflight", "arguments": {}}},
            ],
            adapter,
        )
        self.assertEqual(status, 0)
        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0]["result"], {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": "kingbase-readonly-private", "version": "1.0.0"}})
        self.assertEqual(lines[1]["result"], {})
        self.assertEqual([tool["name"] for tool in lines[2]["result"]["tools"]], ["kingbase_readonly_preflight", "kingbase_catalog_query"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "preflight")

    def test_tools_list_rejects_cursor_for_non_paginated_v1_contract(self):
        status, lines, calls = run_protocol(
            load_server(),
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {"cursor": "unexpected"},
                }
            ],
            FakeAdapter(),
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines[0]["error"], {"code": -32602, "message": "invalid_params"})
        self.assertEqual(calls, [])

    def test_tool_call_notification_does_not_invoke_adapter(self):
        adapter = FakeAdapter({"preflight": protocol_response()})
        status, lines, calls = run_protocol(
            load_server(),
            [
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "kingbase_readonly_preflight",
                        "arguments": {},
                    },
                }
            ],
            adapter,
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines, [])
        self.assertEqual(calls, [])

    def test_errors_are_frozen_and_adapter_failure_is_sanitized(self):
        adapter = FakeAdapter({"preflight": protocol_response(False)})
        status, lines, _ = run_protocol(
            load_server(),
            [
                {"jsonrpc": "2.0", "id": 1, "method": "unknown", "params": {}},
                {"jsonrpc": "2.0", "id": True, "method": "ping", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "unknown"}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "kingbase_readonly_preflight"}},
            ],
            adapter,
        )
        self.assertEqual(status, 0)
        self.assertEqual(lines[0]["error"], {"code": -32601, "message": "method_not_found"})
        self.assertIsNone(lines[1]["id"])
        self.assertEqual(lines[2]["error"], {"code": -32602, "message": "invalid_params"})
        self.assertTrue(lines[3]["result"]["isError"])
        self.assertNotIn("traceback", repr(lines[3]))
        self.assertNotIn("private", repr(lines[3]))

    def test_binary_utf8_json_depth_and_line_limits_fail_closed_then_ping(self):
        server = load_server()
        adapter = FakeAdapter({"preflight": protocol_response()})
        values = [
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":NaN}\n",
            b"\xff\n",
            (b"{" + b"\"x\":[" * 65 + b"0" + b"]" * 65 + b"}\n"),
            b"x" * (server.MAX_JSON_LINE_BYTES + 1) + b"\n",
            b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n',
        ]
        output = io.BytesIO()
        status = server.serve(io.BytesIO(b"".join(values)), output, adapter=adapter)
        lines = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(status, 0)
        self.assertEqual(lines[-1]["result"], {})
        self.assertEqual(adapter.calls, [])
        self.assertTrue(all("Traceback" not in line.decode("utf-8", "replace") for line in output.getvalue().splitlines()))

    def test_1200_depth_notification_returns_parse_error_then_ping_without_adapter_call(self):
        server = load_server()
        adapter = FakeAdapter({"preflight": protocol_response()})
        deep = (
            b'{"jsonrpc":"2.0","method":"tools/call","params":'
            b'{"name":"kingbase_readonly_preflight","arguments":{"deep":'
            + b"[" * 1200
            + b"0"
            + b"]" * 1200
            + b"}}}\n"
        )
        ping = b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}\n'
        output = io.BytesIO()

        status = server.serve(io.BytesIO(deep + ping), output, adapter=adapter)
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
        self.assertEqual(adapter.calls, [])

    def test_adapter_result_is_canonical_and_failed_result_is_error(self):
        success = protocol_response(operation="RESOLVE_CATALOG")
        failed = protocol_response(False)
        adapter = FakeAdapter({"preflight": success})
        status, lines, _ = run_protocol(
            load_server(),
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "kingbase_readonly_preflight"}}],
            adapter,
        )
        self.assertEqual(status, 0)
        text = lines[0]["result"]["content"][0]["text"]
        self.assertEqual(text, json.dumps(success, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
        adapter = FakeAdapter({"preflight": failed})
        _, lines, _ = run_protocol(
            load_server(),
            [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "kingbase_readonly_preflight"}}],
            adapter,
        )
        self.assertTrue(lines[0]["result"]["isError"])


class SmokeContractTest(unittest.TestCase):
    def test_smoke_failure_marker_is_phase_specific_and_sanitized(self):
        smoke = load_smoke()
        self.assertEqual(
            smoke.safe_failure_marker("PREFLIGHT"),
            "TASK7_SMOKE_BLOCKED|phase=PREFLIGHT",
        )
        self.assertEqual(
            smoke.safe_failure_marker("private/path"),
            "TASK7_SMOKE_BLOCKED|phase=INTERNAL",
        )
        self.assertNotIn("private", smoke.safe_failure_marker("private/path"))
        self.assertNotIn("/", smoke.safe_failure_marker("private/path"))

    def test_smoke_failure_marker_allows_only_known_error_code(self):
        smoke = load_smoke()
        self.assertEqual(
            smoke.safe_failure_marker("PREFLIGHT", "QUERY_FAILED"),
            "TASK7_SMOKE_BLOCKED|phase=PREFLIGHT|code=QUERY_FAILED",
        )
        self.assertEqual(
            smoke.safe_failure_marker("PREFLIGHT", "host=/private"),
            "TASK7_SMOKE_BLOCKED|phase=PREFLIGHT",
        )

    def test_smoke_response_error_code_is_propagated_only_as_safe_marker(self):
        smoke = load_smoke()
        with self.assertRaises(smoke._PhaseFailure) as context:
            smoke._phase_call(
                "PREFLIGHT",
                lambda: smoke._require_success(
                    {"success": False, "errorCode": "DATA_CONTRACT_MISMATCH"}
                ),
            )
        self.assertEqual(context.exception.phase, "PREFLIGHT")
        self.assertEqual(context.exception.code, "DATA_CONTRACT_MISMATCH")

    def test_smoke_argument_failures_emit_only_frozen_marker(self):
        smoke = load_smoke()
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = smoke.main(["--profile", smoke.PROFILE])
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "TASK7_SMOKE_BLOCKED|phase=ARGS\n")

    def _responses(self):
        root = "INDUSTRY_ROOT:Um9vdA"
        nodes = [
            {"entityId": root, "level": "ROOT", "canonicalName": "Root"},
            {"entityId": "INDUSTRY_L1:L1", "level": "L1", "canonicalName": "L1", "sourceId": "L1"},
            {"entityId": "INDUSTRY_L2:L2", "level": "L2", "canonicalName": "L2", "sourceId": "L2"},
            {"entityId": "INDUSTRY_L3:L3", "level": "L3", "canonicalName": "L3", "sourceId": "L3"},
        ]
        preflight = {"success": True, "profile": "ai_app_industry_test_ro", "schema": "ai_dw", "dataAsOf": "2026-08-11", "readBoundary": {"transactionReadOnly": True, "privilegeMode": "CLIENT_ENFORCED_READ_ONLY", "databasePrivilegeRisk": "WRITE_CAPABLE_ACCOUNT"}, "objects": []}
        return {
            "preflight": preflight,
            "RESOLVE_CATALOG": {"success": True, "operation": "RESOLVE_CATALOG", "dataStatus": "AVAILABLE", "totalCount": 1, "returnedCount": 1, "truncated": False, "dataAsOf": "2026-08-11", "readBoundary": preflight["readBoundary"], "data": {"rows": [{"entityId": "INDUSTRY_ROOT:Um9vdA"}]}},
            "SEARCH_PRODUCTS": {"success": True, "operation": "SEARCH_PRODUCTS", "dataStatus": "AVAILABLE", "totalCount": 1, "returnedCount": 1, "truncated": False, "dataAsOf": "2026-08-11", "readBoundary": preflight["readBoundary"], "data": {"rows": [{"entityId": "PRODUCT:P1"}]}},
            "PRODUCT_INDUSTRIES": {"success": True, "operation": "PRODUCT_INDUSTRIES", "dataStatus": "AVAILABLE", "totalCount": 1, "returnedCount": 1, "truncated": False, "dataAsOf": "2026-08-11", "readBoundary": preflight["readBoundary"], "data": {"rows": [{"nodes": nodes}]}},
            "INDUSTRY_CHILDREN": {"success": True, "operation": "INDUSTRY_CHILDREN", "dataStatus": "AVAILABLE", "totalCount": 1, "returnedCount": 1, "truncated": False, "dataAsOf": "2026-08-11", "readBoundary": preflight["readBoundary"], "data": {"rows": []}},
            "INDUSTRY_PARENT_PATH": {"success": True, "operation": "INDUSTRY_PARENT_PATH", "dataStatus": "AVAILABLE", "totalCount": 1, "returnedCount": 1, "truncated": False, "dataAsOf": "2026-08-11", "readBoundary": preflight["readBoundary"], "data": {"rows": []}},
        }

    def test_fixed_smoke_chain_is_one_preflight_and_five_catalog_calls(self):
        smoke = load_smoke()
        adapter = FakeAdapter(self._responses())
        result = smoke.run_fixed_chain(adapter)
        self.assertEqual([name for name, _ in adapter.calls], ["preflight", "catalog", "catalog", "catalog", "catalog", "catalog"])
        self.assertEqual([request["operation"] for kind, request in adapter.calls[1:]], ["RESOLVE_CATALOG", "SEARCH_PRODUCTS", "PRODUCT_INDUSTRIES", "INDUSTRY_CHILDREN", "INDUSTRY_PARENT_PATH"])
        self.assertEqual(result["operations"], [
            {"sequence": 1, "operation": "RESOLVE_CATALOG"},
            {"sequence": 2, "operation": "SEARCH_PRODUCTS"},
            {"sequence": 3, "operation": "PRODUCT_INDUSTRIES"},
            {"sequence": 4, "operation": "INDUSTRY_CHILDREN"},
            {"sequence": 5, "operation": "INDUSTRY_PARENT_PATH"},
        ])

    def test_negative_policy_is_injected_before_credentials_and_rejects_extra_fields(self):
        smoke = load_smoke()
        calls = []

        class PolicyAdapter:
            def catalog(self, request):
                calls.append(request)
                return {"success": False, "errorCode": "POLICY_DENIED"}

        result = smoke.run_negative_policy(PolicyAdapter())
        self.assertEqual([item["field"] for item in result], ["sql", "statement", "offset", "page", "cursor"])
        self.assertTrue(all(item["psqlStarted"] is False for item in result))
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(set(request) == {"operation", "text", "expectedEntityType", "limit", field} for request, field in zip(calls, ["sql", "statement", "offset", "page", "cursor"])))

    def test_negative_policy_probe_uses_real_adapter_with_bombed_later_boundaries(self):
        smoke = load_smoke()
        adapter = smoke.make_policy_probe_adapter()
        result = smoke.run_negative_policy(adapter)
        self.assertEqual(
            [item["field"] for item in result],
            ["sql", "statement", "offset", "page", "cursor"],
        )

    def test_sanitizer_rejects_private_and_secret_bearing_values(self):
        smoke = load_smoke()
        for value in (
            {"password": "secret"},
            {"endpoint": "https://host.example"},
            {"sql": "SELECT 1"},
            {"data": {"rows": [{"MEMO": "private"}]}},
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    smoke.assert_sanitized(value)


class LauncherContractTest(unittest.TestCase):
    def test_launcher_runner_and_readme_targets_exist_before_green(self):
        for name in ("run_kingbase_readonly_mcp.sh", "run_tests.sh", "README.md"):
            self.assertTrue((ROOT / name).is_file(), "A4 target is absent: " + name)

    def test_scripts_are_posix_syntax_and_readme_keeps_private_boundary(self):
        for name in ("run_kingbase_readonly_mcp.sh", "run_tests.sh"):
            path = ROOT / name
            self.assertTrue(path.is_file(), "A4 target is absent: " + name)
            result = subprocess.run(["/bin/sh", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        readme = ROOT / "README.md"
        self.assertTrue(readme.is_file(), "A4 target is absent: README.md")
        text = readme.read_text(encoding="utf-8")
        self.assertIn("kingbase_readonly_preflight", text)
        self.assertIn("private", text.lower())
        self.assertNotIn("PGPASSWORD=", text)

    def test_launcher_source_has_explicit_manifest_and_denylist_controls(self):
        self.assertTrue((ROOT / "run_kingbase_readonly_mcp.sh").is_file(), "A4 target is absent: launcher")
        self.assertTrue((ROOT / "run_tests.sh").is_file(), "A4 target is absent: runner")
        launcher = (ROOT / "run_kingbase_readonly_mcp.sh").read_text(encoding="utf-8")
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        for source in (launcher, runner):
            for marker in (
                "run_quiet_and_check",
                "run_and_check",
                "find",
                "-print0",
                "LC_ALL=C sort -z",
                "xargs -0 -n 1",
                "shasum",
                "DYLD_PRINT_PROTETED_MEMORY_STATUS",
                "PYTHONPATH",
                "NODE_OPTIONS",
            ):
                self.assertIn(marker, source, marker)
        self.assertIn("KINGBASE_READONLY_OFFLINE_OK", runner)
        self.assertNotIn("npm ", runner)

    def test_offline_runner_executes_launcher_protocol_fixture(self):
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        self.assertIn("run_launcher_protocol", runner)
        self.assertIn("run_child_from_file", runner)
        for method in ("initialize", "ping", "tools/list"):
            self.assertIn(method, runner)
        self.assertNotIn('"tools/call"', runner)

    def test_runner_delegates_slice_contract_to_its_official_runners(self):
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        self.assertIn("run_slice1.sh", runner)
        self.assertIn("run_slice2.sh", runner)
        self.assertNotIn("for script in test_dbar1.py", runner)

    def test_verified_wrapper_preserves_script_argv_for_smoke(self):
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        self.assertIn("sys.argv=sys.argv[1:]", runner)

    def test_runner_binds_manifest_digests_and_signal_cleanup(self):
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        for marker in (
            'manifest_verify "$ROOT/tests" 12 "$PY_TREE_BOUND"',
            'manifest_verify "$ROOT/node_modules" 538 "$NODE_TREE_BOUND"',
            'manifest_verify "$REPO_ROOT/tools/local-database-analysis" 19 "$SLICE_TREE_BOUND"',
            "trap",
            "quiesce_group",
        ):
            self.assertIn(marker, runner, marker)

    def test_runtime_mirror_gate_uses_archived_openspec_source(self):
        archived = "openspec/changes/archive/2026-08-28-add-real-kingbase-readonly-mcp-v1/schemas"
        active = "openspec/changes/add-real-kingbase-readonly-mcp-v1/schemas"
        for name in ("run_kingbase_readonly_mcp.sh", "run_tests.sh"):
            source = (ROOT / name).read_text(encoding="utf-8")
            self.assertIn(archived, source)
            self.assertNotIn(active, source)
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        self.assertIn(
            "openspec validate real-kingbase-readonly-mcp --type spec --strict",
            runner,
        )
        self.assertNotIn("openspec validate add-real-kingbase-readonly-mcp-v1", runner)


if __name__ == "__main__":
    unittest.main()
