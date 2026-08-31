import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from schema_client import (  # noqa: E402
    CLIENT_REQUEST_LINE_CAP,
    WORKER_RESPONSE_LINE_CAP,
    SchemaClient,
    SchemaUnavailable,
)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.writes = []
        self.closed = False

    def write_line(self, payload):
        if isinstance(payload, Exception):
            raise payload
        self.writes.append(payload)

    def read_line(self, timeout_seconds, cap):
        if not self.responses:
            raise EOFError("worker closed")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if len(response) > cap:
            raise OverflowError("worker response too large")
        return response

    def terminate(self):
        self.closed = True


def ready_then(*responses):
    return FakeTransport(
        [
            json.dumps({"id": 0, "valid": True}).encode(),
            *responses,
        ]
    )


class SchemaClientTest(unittest.TestCase):
    def test_custom_contract_allowlist_and_startup_probe_are_instance_scoped(self):
        transport = FakeTransport(
            [
                json.dumps({"id": 0, "valid": True}).encode(),
                json.dumps({"id": 1, "valid": False}).encode(),
            ]
        )
        client = SchemaClient(
            transport_factory=lambda: transport,
            contracts={"entityResolveRequest"},
            startup_probe=("entityResolveRequest", {"canary": True}),
        )
        self.assertFalse(client.validate("entityResolveRequest", {"bad": True}))
        requests = [json.loads(payload) for payload in transport.writes]
        self.assertEqual(
            requests,
            [
                {
                    "id": 0,
                    "contract": "entityResolveRequest",
                    "instance": {"canary": True},
                },
                {
                    "id": 1,
                    "contract": "entityResolveRequest",
                    "instance": {"bad": True},
                },
            ],
        )
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_custom_worker_path_is_absolute_regular_and_used_as_final_argv(self):
        node = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        with tempfile.TemporaryDirectory() as directory:
            canonical_directory = Path(os.path.realpath(directory))
            worker = canonical_directory / "worker.mjs"
            worker.write_text("", encoding="utf-8")
            with patch("schema_client.subprocess.Popen") as popen:
                process = popen.return_value
                process.stdin = __import__("io").BytesIO()
                process.stdout = __import__("io").BytesIO()
                process.poll.return_value = 0
                with patch("schema_client.selectors.DefaultSelector") as selector:
                    selector.return_value.register.return_value = None
                    transport = __import__("schema_client")._ProcessTransport(
                        node,
                        worker_path=worker,
                    )
                    transport.terminate()
            self.assertEqual(popen.call_args.args[0], [node, str(worker)])

            link = canonical_directory / "worker-link.mjs"
            os.symlink(worker, link)
            with self.assertRaises(ValueError):
                __import__("schema_client")._ProcessTransport(
                    node,
                    worker_path=link,
                )

            real_parent = canonical_directory / "real-parent"
            real_parent.mkdir()
            nested_worker = real_parent / "worker.mjs"
            nested_worker.write_text("", encoding="utf-8")
            linked_parent = canonical_directory / "linked-parent"
            os.symlink(real_parent, linked_parent)
            with patch("schema_client.subprocess.Popen"), patch(
                "schema_client.selectors.DefaultSelector"
            ):
                with self.assertRaises(ValueError):
                    __import__("schema_client")._ProcessTransport(
                        node,
                        worker_path=linked_parent / "worker.mjs",
                    )
        with self.assertRaises(ValueError):
            __import__("schema_client")._ProcessTransport(
                node,
                worker_path=Path("relative-worker.mjs"),
            )

    def test_selector_startup_failure_terminates_spawned_worker_and_closes_pipes(self):
        node = "/opt/homebrew/Cellar/node@20/20.20.2/bin/node"
        worker = ROOT / "schema_worker.mjs"
        process = MagicMock()
        process.stdin = io.BytesIO()
        process.stdout = io.BytesIO()
        process.poll.return_value = None
        process.wait.return_value = -15
        selector = MagicMock()
        selector.register.side_effect = OSError("selector unavailable")
        with patch("schema_client.subprocess.Popen", return_value=process), patch(
            "schema_client.selectors.DefaultSelector", return_value=selector
        ):
            with self.assertRaises(OSError):
                __import__("schema_client")._ProcessTransport(
                    node,
                    worker_path=worker,
                )
        process.terminate.assert_called_once_with()
        selector.close.assert_called_once_with()
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)

    def test_startup_timeout_fails_before_keychain(self):
        transport = FakeTransport([TimeoutError("startup")])
        keychain_calls = []
        with self.assertRaises(SchemaUnavailable):
            SchemaClient(transport_factory=lambda: transport)
        self.assertTrue(transport.closed)
        self.assertEqual(keychain_calls, [])

    def test_request_over_cap_is_not_written(self):
        transport = ready_then()
        client = SchemaClient(transport_factory=lambda: transport)
        writes_before = len(transport.writes)
        with self.assertRaises(SchemaUnavailable):
            client.validate("catalogRequest", {"x": "a" * CLIENT_REQUEST_LINE_CAP})
        self.assertEqual(len(transport.writes), writes_before)
        self.assertTrue(transport.closed)

    def test_wrong_response_id_terminates_worker(self):
        transport = ready_then(json.dumps({"id": 7, "valid": True}).encode())
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_extra_response_field_is_rejected(self):
        response = json.dumps({"id": 1, "valid": True, "errors": []}).encode()
        transport = ready_then(response)
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_malformed_json_terminates_worker(self):
        transport = ready_then(b"{not-json")
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_round_trip_timeout_terminates_worker(self):
        transport = ready_then(TimeoutError("round trip"))
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_worker_crash_fails_closed(self):
        transport = ready_then(EOFError("crashed"))
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_worker_response_over_cap_fails_closed(self):
        transport = ready_then(b"x" * (WORKER_RESPONSE_LINE_CAP + 1))
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("preflightRequest", {})
        self.assertTrue(transport.closed)

    def test_unknown_contract_fails_closed(self):
        transport = ready_then()
        client = SchemaClient(transport_factory=lambda: transport)
        with self.assertRaises(SchemaUnavailable):
            client.validate("other", {})
        self.assertTrue(transport.closed)

    def test_valid_and_invalid_instances_keep_protocol_closed(self):
        transport = ready_then(
            json.dumps({"id": 1, "valid": True}).encode(),
            json.dumps({"id": 2, "valid": False}).encode(),
        )
        client = SchemaClient(transport_factory=lambda: transport)
        self.assertTrue(client.validate("preflightRequest", {}))
        self.assertFalse(client.validate("preflightRequest", {"extra": True}))
        self.assertFalse(transport.closed)

    def test_real_worker_round_trip(self):
        with SchemaClient() as client:
            self.assertTrue(client.validate("preflightRequest", {}))
            self.assertFalse(client.validate("preflightRequest", {"extra": True}))


if __name__ == "__main__":
    unittest.main()
