"""Canonical JSON and strict base64 used by packages and licenses."""

from __future__ import annotations

import base64
import json
from typing import Any

from .errors import FormatError


def canonical_json(value: Any) -> bytes:
    """UTF-8 JSON with sorted keys and no extra whitespace.

    The same value always produces the same bytes. Those bytes are the
    associated data for AES-GCM and the input of the license HMAC.
    """

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(value: object, *, expected_len: int | None = None, label: str = "필드") -> bytes:
    if not isinstance(value, str) or value == "":
        raise FormatError(f"{label} base64 값이 없습니다.")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise FormatError(f"{label} base64 값이 올바르지 않습니다.") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise FormatError(f"{label} 길이가 올바르지 않습니다.")
    return raw
