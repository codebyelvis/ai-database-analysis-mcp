"""
作者：elvis
日期：2026-08-18
作用：SOURCE_REGISTER DBAR1 扫描与拒绝规则
"""

import re


RECORD_KEY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
RECORD = re.compile(r"^DBAR1\t[A-Za-z0-9._:-]{1,128}\t[0-9a-f]{64}$")
MARKER = b"<!-- local-database-analysis-records:v1 -->\n"


class RecordRejected(ValueError):
    """表示 SOURCE_REGISTER 中存在不符合 DBAR1 合同的记录。"""


def scan_dbar1(raw: bytes) -> list[str]:
    """扫描 UTF-8 文件中的 DBAR1 记录并返回唯一 recordKey。"""
    parts = _split_lines(raw)
    keys = []
    for line in parts:
        if line.startswith("DBAR1"):
            if RECORD.fullmatch(line) is None:
                raise RecordRejected("syntax")
            key = line.split("\t", 2)[1]
            if key in keys:
                raise RecordRejected("dup")
            keys.append(key)
    return keys


def _split_lines(raw: bytes) -> list[str]:
    """先拒绝 CR，再按 LF 分行，返回不含 LF 的行段。"""
    if b"\x0d" in raw:
        raise RecordRejected("CR")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordRejected("utf8") from exc
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    return parts


def validate_append_only(
    preimage: bytes,
    postimage: bytes,
    record_key: str,
) -> None:
    """验证 SOURCE_REGISTER 只追加一条绑定 recordKey 的 DBAR1 行。"""
    if not isinstance(record_key, str) or RECORD_KEY.fullmatch(record_key) is None:
        raise RecordRejected("record_key")

    existing_keys = scan_dbar1(preimage)
    if record_key in existing_keys:
        raise RecordRejected("dup")
    if b"\x0d" in postimage:
        raise RecordRejected("CR")
    if not postimage.startswith(preimage):
        raise RecordRejected("prefix")

    delta = postimage[len(preimage) :]
    required_prefix = b"" if MARKER in preimage else MARKER
    if not delta.startswith(required_prefix):
        raise RecordRejected("marker")
    record_bytes = delta[len(required_prefix) :]
    if not record_bytes.endswith(b"\n"):
        raise RecordRejected("lf")
    try:
        record_line = record_bytes[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecordRejected("utf8") from exc
    if RECORD.fullmatch(record_line) is None:
        raise RecordRejected("syntax")
    if record_line.split("\t", 2)[1] != record_key:
        raise RecordRejected("record_key")

    post_keys = scan_dbar1(postimage)
    if post_keys != existing_keys + [record_key]:
        raise RecordRejected("order")
