"""
作者：elvis
日期：2026-08-18
作用：验证 DBAR1 记录扫描与拒绝规则
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import unittest

from dbar1 import RecordRejected, scan_dbar1, validate_append_only


MARKER = b"<!-- local-database-analysis-records:v1 -->\n"


def _record(key="rec-1", digest="a" * 64):
    return f"DBAR1\t{key}\t{digest}\n".encode("ascii")


class Dbar1Test(unittest.TestCase):
    def test_split_line_without_nl_matches(self):
        rec = "DBAR1\trec-1\t" + "a" * 64
        pre = "# head\n"
        marker = "<!-- local-database-analysis-records:v1 -->\n"
        post = pre + marker + rec + "\n"
        keys = scan_dbar1(post.encode("utf-8"))
        self.assertEqual(keys, ["rec-1"])

    def test_cr_rejected(self):
        raw = b"DBAR1\trec-1\t" + b"a" * 64 + b"\r\n"
        with self.assertRaises(RecordRejected):
            scan_dbar1(raw)

    def test_duplicate_key_rejected(self):
        rec = "DBAR1\trec-1\t" + "a" * 64 + "\n"
        raw = ("<!-- local-database-analysis-records:v1 -->\n" + rec + rec).encode()
        with self.assertRaises(RecordRejected):
            scan_dbar1(raw)

    def test_non_ascii_key_rejected(self):
        rec = "DBAR1\t记录1\t" + "a" * 64 + "\n"
        with self.assertRaises(RecordRejected):
            scan_dbar1(rec.encode())

    def test_space_separated_rejected(self):
        raw = b"DBAR1 rec-1 " + b"a" * 64 + b"\n"
        with self.assertRaises(RecordRejected):
            scan_dbar1(raw)

    def test_empty_key_rejected(self):
        raw = b"DBAR1\t\t" + b"a" * 64 + b"\n"
        with self.assertRaises(RecordRejected):
            scan_dbar1(raw)

    def test_valid_append_after_existing_marker(self):
        preimage = b"# head\n" + MARKER + _record("old")
        postimage = preimage + _record("new", "b" * 64)
        validate_append_only(preimage, postimage, "new")

    def test_valid_append_adds_marker_when_preimage_has_none(self):
        preimage = b"# head\n"
        postimage = preimage + MARKER + _record("new", "b" * 64)
        validate_append_only(preimage, postimage, "new")

    def test_missing_marker_rejected(self):
        preimage = b"# head\n"
        postimage = preimage + _record()
        with self.assertRaises(RecordRejected):
            validate_append_only(preimage, postimage, "rec-1")

    def test_duplicate_key_in_preimage_rejected(self):
        preimage = MARKER + _record("rec-1")
        postimage = preimage + _record("rec-1", "b" * 64)
        with self.assertRaises(RecordRejected):
            validate_append_only(preimage, postimage, "rec-1")

    def test_multiline_delta_rejected(self):
        preimage = MARKER + _record("old")
        postimage = preimage + _record("new") + b"extra\n"
        with self.assertRaises(RecordRejected):
            validate_append_only(preimage, postimage, "new")

    def test_middle_insert_rejected(self):
        preimage = MARKER + _record("old")
        postimage = MARKER + _record("new") + _record("old")
        with self.assertRaises(RecordRejected):
            validate_append_only(preimage, postimage, "new")

    def test_reorder_existing_records_rejected(self):
        preimage = MARKER + _record("old") + _record("older")
        postimage = MARKER + _record("older") + _record("old") + _record("new")
        with self.assertRaises(RecordRejected):
            validate_append_only(preimage, postimage, "new")


if __name__ == "__main__":
    unittest.main()
