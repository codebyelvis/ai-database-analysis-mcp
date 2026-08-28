"""Executable public launcher tests; no Keychain or database call is made."""

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "run_industry_selection_bridge.sh"


class PublicLauncherTest(unittest.TestCase):
    def test_forbidden_preload_fails_with_one_safe_line(self):
        completed = subprocess.run(
            [str(LAUNCHER)],
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"HOME": os.environ["HOME"], "NODE_OPTIONS": "--require=/private"},
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b"")
        self.assertEqual(completed.stderr, b"INDUSTRY_SELECTION_BRIDGE_FAILED\n")

    def test_real_launcher_exposes_only_public_tools_without_database_call(self):
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {},
                },
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        input_bytes = b"".join(
            json.dumps(item, separators=(",", ":")).encode() + b"\n"
            for item in requests
        )
        completed = subprocess.run(
            [str(LAUNCHER)],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"HOME": os.environ["HOME"]},
            timeout=60,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        self.assertEqual(completed.stderr, b"")
        lines = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(
            [tool["name"] for tool in lines[1]["result"]["tools"]],
            ["entity_resolve", "business_query"],
        )
        text = completed.stdout.decode("utf-8")
        self.assertNotIn("kingbase_readonly_preflight", text)
        self.assertNotIn("kingbase_catalog_query", text)


if __name__ == "__main__":
    unittest.main()
