"""
作者：elvis
日期：2026-08-18
作用：合同规定的 UTF-8 canonical JSON 序列化
"""

import json


def canon(obj) -> bytes:
    """按合同规则序列化对象，返回无空白、稳定排序的 UTF-8 JSON 字节。"""
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
