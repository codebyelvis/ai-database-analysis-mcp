"""Executable public launcher tests; no Keychain or database call is made."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "run_industry_selection_bridge.sh"


class PublicLauncherTest(unittest.TestCase):
    def test_runner_executes_public_schema_boundary_and_pins_node_ajv(self):
        runner = (ROOT / "run_tests.sh").read_text(encoding="utf-8")
        for marker in (
            "tests/test_schema_client.py",
            "NODE_SHA=d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4",
            "verify_ajv",
            "public_contracts.test.mjs",
        ):
            self.assertIn(marker, runner)

    def _run_gate_failure(
        self, *, wrong_node_sha=False, mismatch=None, missing_import=False
    ):
        expected_node_sha = (
            "d9944604aa99a0a4df72a3927252cfae820ba5e1749c27056fd156b82d7a09d4"
        )
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("NODE_SHA=" + expected_node_sha, source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bridge_root = root / "industry-stock-selection-bridge"
            runtime_root = root / "kingbase-readonly-mcp"
            bridge_root.mkdir()
            runtime_root.mkdir()
            launcher = bridge_root / LAUNCHER.name
            if wrong_node_sha:
                source = source.replace(
                    "NODE_SHA=" + expected_node_sha,
                    "NODE_SHA=" + "0" * 64,
                )
            launcher.write_text(source, encoding="utf-8")
            launcher.chmod(0o700)
            marker = bridge_root / "server.started"
            (bridge_root / "industry_selection_bridge_server.py").write_text(
                "from pathlib import Path\n"
                "Path(__file__).with_name('server.started').write_text('started')\n",
                encoding="utf-8",
            )

            versions = {
                "package": "8.20.0",
                "lock_root": "8.20.0",
                "lock_package": "8.20.0",
                "installed_lock": "8.20.0",
                "installed_package": "8.20.0",
            }
            if mismatch is not None:
                versions[mismatch] = "0.0.0"
            (runtime_root / "package.json").write_text(
                json.dumps({"devDependencies": {"ajv": versions["package"]}}),
                encoding="utf-8",
            )
            (runtime_root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "packages": {
                            "": {
                                "devDependencies": {"ajv": versions["lock_root"]}
                            },
                            "node_modules/ajv": {
                                "version": versions["lock_package"]
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            (runtime_root / "node_modules" / "ajv").mkdir(parents=True)
            (runtime_root / "node_modules" / ".package-lock.json").write_text(
                json.dumps(
                    {
                        "packages": {
                            "node_modules/ajv": {
                                "version": versions["installed_lock"]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            (runtime_root / "node_modules" / "ajv" / "package.json").write_text(
                json.dumps({"version": versions["installed_package"]}),
                encoding="utf-8",
            )
            if not missing_import:
                dist = runtime_root / "node_modules" / "ajv" / "dist"
                dist.mkdir()
                (dist / "2020.js").write_text(
                    "module.exports = class Ajv2020 {};\n",
                    encoding="utf-8",
                )
            completed = subprocess.run(
                [str(launcher)],
                input=b"",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": os.environ["HOME"]},
                timeout=20,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
            self.assertEqual(
                completed.stderr,
                b"INDUSTRY_SELECTION_BRIDGE_FAILED\n",
            )
            self.assertFalse(marker.exists())

    def test_wrong_node_sha_stops_before_server(self):
        self._run_gate_failure(wrong_node_sha=True)

    def test_each_ajv_metadata_mismatch_stops_before_server(self):
        for name in (
            "package",
            "lock_root",
            "lock_package",
            "installed_lock",
            "installed_package",
        ):
            with self.subTest(name=name):
                self._run_gate_failure(mismatch=name)

    def test_missing_ajv_import_stops_before_server(self):
        self._run_gate_failure(missing_import=True)

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
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": None},
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

    def test_fake_path_node_cannot_replace_verified_node(self):
        with tempfile.TemporaryDirectory() as directory:
            fake_node = Path(directory) / "node"
            fake_node.write_text(
                "#!/bin/sh\nprintf '%s\\n' FAKE_NODE_EXECUTED >&2\nexit 97\n",
                encoding="utf-8",
            )
            fake_node.chmod(0o700)
            completed = subprocess.run(
                [str(LAUNCHER)],
                input=(
                    b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}\n'
                ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "HOME": os.environ["HOME"],
                    "PATH": directory + ":/usr/bin:/bin",
                },
                timeout=60,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(b"FAKE_NODE_EXECUTED", completed.stderr)
        tools = json.loads(completed.stdout)["result"]["tools"]
        self.assertEqual(
            [tool["name"] for tool in tools],
            ["entity_resolve", "business_query"],
        )

    def test_real_launcher_rejects_invalid_public_request_then_pings(self):
        requests = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "business_query",
                    "arguments": {
                        "operation": "business_query",
                        "resolvedPlan": {
                            "planId": "plan1",
                            "steps": [
                                {
                                    "stepId": "s1",
                                    "relation": "PARENT_PATH",
                                    "input": {
                                        "sourceType": "ENTITY",
                                        "entity": {
                                            "entityId": "PRODUCT:P1",
                                            "entityType": "CATALOG_NODE",
                                            "canonicalName": "产品一",
                                        },
                                    },
                                    "outputType": "PATH_RESULT",
                                    "presentation": {},
                                }
                            ],
                        },
                    },
                },
            },
            {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}},
        ]
        completed = subprocess.run(
            [str(LAUNCHER)],
            input=b"".join(
                json.dumps(item, separators=(",", ":")).encode() + b"\n"
                for item in requests
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"HOME": os.environ["HOME"]},
            timeout=60,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        lines = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(
            lines[0]["error"],
            {"code": -32602, "message": "invalid_params"},
        )
        self.assertEqual(lines[1]["result"], {})


if __name__ == "__main__":
    unittest.main()
