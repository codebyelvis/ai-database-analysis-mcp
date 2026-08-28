"""Offline contract tests for the private stdio child client."""

import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from private_mcp_client import (  # noqa: E402
    MAX_PRIVATE_LINE_BYTES,
    PrivateMcpClient,
    PrivateMcpUnavailable,
    _ProcessTransport,
)


def line(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class RecordingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.writes = []
        self.closed = False

    def write_line(self, payload):
        self.writes.append(payload)

    def read_line(self, _timeout, cap):
        if not self.responses:
            raise EOFError("private child closed")
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        if len(value) > cap:
            raise OverflowError("private line too large")
        return value

    def terminate(self):
        self.closed = True


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


class PrivateMcpClientTest(unittest.TestCase):
    def test_initialize_then_monotonic_tool_call_and_exact_json_result(self):
        transport = RecordingTransport(
            [
                line(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {"tools": {}},
                            "serverInfo": {
                                "name": "kingbase-readonly-private",
                                "version": "1.0.0",
                            },
                        },
                    }
                ),
                line(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": '{"operation":"RESOLVE_CATALOG","success":true}',
                                }
                            ]
                        },
                    }
                ),
            ]
        )
        client = PrivateMcpClient(transport_factory=lambda: transport)
        result = client.call_catalog(
            {
                "operation": "RESOLVE_CATALOG",
                "text": "AI产业模型",
                "expectedEntityType": "ANY",
                "limit": 10,
            }
        )
        self.assertEqual(result, {"operation": "RESOLVE_CATALOG", "success": True})
        writes = [json.loads(item) for item in transport.writes]
        self.assertEqual([item["id"] for item in writes if "id" in item], [1, 2])
        self.assertEqual(writes[1]["method"], "notifications/initialized")
        self.assertNotIn("id", writes[1])
        self.assertEqual(writes[2]["params"]["name"], "kingbase_catalog_query")
        client.close()
        self.assertTrue(transport.closed)

    def test_wrong_id_malformed_timeout_and_oversize_fail_closed_without_retry(self):
        failures = (
            line({"jsonrpc": "2.0", "id": 99, "result": {}}),
            b"{not-json",
            TimeoutError("private endpoint"),
            b"x" * (MAX_PRIVATE_LINE_BYTES + 1),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                transport = RecordingTransport([failure])
                with self.assertRaises(PrivateMcpUnavailable) as caught:
                    PrivateMcpClient(transport_factory=lambda: transport)
                self.assertEqual(str(caught.exception), "private MCP unavailable")
                self.assertTrue(transport.closed)
                self.assertEqual(len(transport.writes), 1)
                self.assertNotIn("endpoint", str(caught.exception))

    def test_process_transport_uses_fixed_launcher_and_allowlisted_environment(self):
        process = FakeProcess()
        with patch("private_mcp_client.subprocess.Popen", return_value=process) as popen:
            with patch("private_mcp_client.selectors.DefaultSelector", return_value=FakeSelector()):
                with patch.dict(os.environ, {"HOME": "/Users/elvis", "PATH": "/attacker"}, clear=True):
                    transport = _ProcessTransport()
                    transport.terminate()
        args, kwargs = popen.call_args
        launcher = Path(args[0][0])
        self.assertTrue(launcher.is_absolute())
        self.assertEqual(
            launcher.name,
            "run_kingbase_readonly_mcp.sh",
        )
        self.assertEqual(
            kwargs["env"],
            {
                "HOME": "/Users/elvis",
                "PATH": "/opt/homebrew/opt/postgresql@17/bin:/opt/homebrew/bin:/usr/bin:/bin",
            },
        )
        self.assertTrue(kwargs["start_new_session"])


if __name__ == "__main__":
    unittest.main()
