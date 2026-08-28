import base64
import hashlib
import json
import unicodedata
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def has_control(value: str) -> bool:
    return any(ord(char) <= 0x1F or 0x7F <= ord(char) <= 0x9F for char in value)


def industry_root_id(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("invalid root name")
    normalized = unicodedata.normalize("NFC", name)
    if not normalized or has_control(normalized):
        raise ValueError("invalid root name")
    token = base64.urlsafe_b64encode(normalized.encode("utf-8")).decode("ascii")
    return f"INDUSTRY_ROOT:{token.rstrip('=')}"


def decode_industry_root_id(entity_id: str) -> str:
    prefix = "INDUSTRY_ROOT:"
    if not isinstance(entity_id, str) or not entity_id.startswith(prefix):
        raise ValueError("invalid root id")
    token = entity_id[len(prefix) :]
    if not token:
        raise ValueError("invalid root id")
    padding = "=" * (-len(token) % 4)
    try:
        value = base64.b64decode(
            token + padding,
            altchars=b"-_",
            validate=True,
        ).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid root id") from exc
    if industry_root_id(value) != entity_id:
        raise ValueError("non-canonical root id")
    return value
