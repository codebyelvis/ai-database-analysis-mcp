import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from credentials import AuthUnavailable, Secret, read_password  # noqa: E402
from psql_runner import BoundedCompleted, OutputLimitExceeded  # noqa: E402


class RecordingRun:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class CredentialTest(unittest.TestCase):
    def test_fixed_keychain_command_and_limits(self):
        run = RecordingRun(BoundedCompleted(0, b"secret\n", b""))
        secret = read_password(run=run)
        self.assertEqual(secret.reveal(), "secret")
        self.assertEqual(
            run.calls[0][0],
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                "ai-app-industry-kingbase-test",
                "-w",
            ],
        )
        self.assertEqual(run.calls[0][1]["timeout_seconds"], 5)
        self.assertEqual(run.calls[0][1]["stdout_cap"], 4096)

    def test_secret_never_renders_value(self):
        secret = Secret("s3cr3t")
        self.assertEqual(str(secret), "[REDACTED]")
        self.assertEqual(repr(secret), "[REDACTED]")

    def test_missing_empty_invalid_or_oversized_secret_is_unavailable(self):
        failures = (
            BoundedCompleted(1, b"", b"not exposed"),
            BoundedCompleted(0, b"\n", b""),
            BoundedCompleted(0, b"bad\x00value\n", b""),
            OutputLimitExceeded("stdout"),
            TimeoutError("slow"),
        )
        for failure in failures:
            run = RecordingRun(failure)
            with self.subTest(failure=type(failure).__name__), self.assertRaises(
                AuthUnavailable
            ):
                read_password(run=run)
            self.assertEqual(len(run.calls), 1)


if __name__ == "__main__":
    unittest.main()
