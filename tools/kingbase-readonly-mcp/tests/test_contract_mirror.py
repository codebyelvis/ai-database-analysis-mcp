import hashlib
import unittest
from pathlib import Path


RUNTIME = Path(__file__).resolve().parents[1] / "schemas"

EXPECTED_SHA256 = {
    "kingbase-readonly-preflight.request.schema.json": "029845f816541ec3aeeb1d48ee74615dc9d3354e16c153b9eef33056d7c8396d",
    "kingbase-readonly-preflight.response.schema.json": "15cbb3fbac04af57dc6f2a43f176eeefab44b0f58edd0faa92d06c85076ebc2d",
    "kingbase-catalog.request.schema.json": "74f8044b898a137d2aac86be8328306a012d728ed62de002bc4ddec2d3d2fd52",
    "kingbase-catalog.response.schema.json": "771e3f9821161c868c2307066266c420df0861567c38f004a2c2481b11960743",
    "strict-negative-fixtures.json": "19938ac922db91191a1a820d7373fc92cda94a13e681949da9a734824afafec9",
}


class ContractMirrorTest(unittest.TestCase):
    def test_runtime_schema_bytes_match_reviewed_contracts(self):
        for name, expected in EXPECTED_SHA256.items():
            with self.subTest(name=name):
                actual = hashlib.sha256((RUNTIME / name).read_bytes()).hexdigest()
                self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
