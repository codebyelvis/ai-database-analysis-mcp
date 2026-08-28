import json
import sys
import unittest
from pathlib import Path


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
