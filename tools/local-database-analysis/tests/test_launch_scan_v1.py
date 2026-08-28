"""
作者：elvis
日期：2026-08-18
作用：验证 V1 假进程表身份匹配与扫描完成语义
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest

from launch_scan_v1 import FdId, FakeProc, scan_v1


FD = FdId(canonical_path="/bin/toolbox", device="1", inode="2", sha256="b" * 64)


class V1Test(unittest.TestCase):
    def test_orphan_same_sha_is_hit(self):
        result = scan_v1(
            FD,
            [FakeProc(9, device="9", inode="9", sha256="b" * 64)],
        )
        self.assertTrue(result.scan_complete)
        self.assertEqual(result.matched_pids, [9])

    def test_enum_fail_not_empty(self):
        result = scan_v1(FD, None)
        self.assertFalse(result.scan_complete)
        self.assertIsNone(result.matched_pids)

    def test_zero_hit_only_when_complete(self):
        result = scan_v1(
            FD,
            [FakeProc(3, device="8", inode="8", sha256="c" * 64)],
        )
        self.assertTrue(result.scan_complete)
        self.assertEqual(result.matched_pids, [])


if __name__ == "__main__":
    unittest.main()
