"""Offline license files (``.sdlic``).

A license holds the content key wrapped by a token, plus a recipient policy.
The HMAC and the AES-GCM associated data both cover that policy. Someone
without the token cannot extend the expiry. Someone with the token can
decrypt, which is the access the license was issued to grant.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .constants import (
    CEK_LEN,
    DEFAULT_KDF_ITERATIONS,
    GCM_TAG_LEN,
    KDF_NAME,
    LICENSE_FORMAT,
    LICENSE_WRAP_AAD_LABEL,
    MAC_ALG,
    MAC_LEN,
    NONCE_LEN,
    SALT_LEN,
)
from .crypto import (
    decrypt,
    derive_keys,
    encrypt,
    hmac_sha256,
    mac_matches,
    validate_secret,
)
from .encoding import b64d, b64e, canonical_json
from .errors import AuthenticationError, FormatError, IntegrityError
from .policy import Policy, parse_stored_instant, policy_from_dict
from .state import atomic_write_json

_LICENSE_KEYS = {
    "document_id",
    "format",
    "issued_at",
    "license_id",
    "mac",
    "policy",
    "subject",
    "wrap",
}
_WRAP_KEYS = {"iterations", "kdf", "nonce", "salt", "wrapped_cek"}
_MAC_KEYS = {"alg", "value"}


def _uuid(value: str, label: str) -> str:
    try:
        parsed = str(uuid.UUID(value))
    except (TypeError, ValueError) as exc:
        raise FormatError(f"{label}가 UUID가 아닙니다.") from exc
    if parsed != value:
        raise FormatError(f"{label}는 소문자 UUID여야 합니다.")
    return parsed


def license_wrap_aad(document_id: str, license_id: str, policy: Policy) -> bytes:
    return canonical_json(
        {
            "aad": LICENSE_WRAP_AAD_LABEL,
            "document_id": document_id,
            "license_id": license_id,
            "policy": policy.to_dict(),
        }
    )


def mac_body(document: dict[str, object]) -> dict[str, object]:
    return {
        "document_id": document["document_id"],
        "format": document["format"],
        "issued_at": document["issued_at"],
        "license_id": document["license_id"],
        "policy": document["policy"],
        "subject": document["subject"],
        "wrap": document["wrap"],
    }


def issue_license(
    path: Path,
    *,
    document_id: str,
    cek: bytes,
    token: str,
    policy: Policy,
    iterations: int = DEFAULT_KDF_ITERATIONS,
    force: bool = False,
) -> dict[str, object]:
    if len(cek) != CEK_LEN:
        raise FormatError("내용 키 길이가 올바르지 않습니다.")
    validate_secret(token, label="토큰")
    if policy.subject is None:
        raise FormatError("라이선스 주체가 없습니다.")
    if path.exists() and not force:
        raise FormatError(f"라이선스 파일이 이미 있습니다: {path}")
    document_id = _uuid(document_id, "document_id")
    license_id = str(uuid.uuid4())
    salt = os_salt()
    kek, mac_key = derive_keys(token, salt, iterations)
    nonce, wrapped = encrypt(kek, cek, license_wrap_aad(document_id, license_id, policy))
    issued_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    body: dict[str, object] = {
        "format": LICENSE_FORMAT,
        "license_id": license_id,
        "document_id": document_id,
        "subject": policy.subject,
        "issued_at": issued_at,
        "policy": policy.to_dict(),
        "wrap": {
            "kdf": KDF_NAME,
            "iterations": iterations,
            "salt": b64e(salt),
            "nonce": b64e(nonce),
            "wrapped_cek": b64e(wrapped),
        },
    }
    mac = hmac_sha256(mac_key, canonical_json(mac_body(body)))
    document = dict(body)
    document["mac"] = {"alg": MAC_ALG, "value": b64e(mac)}
    _validate_document(document)
    atomic_write_json(path, document)
    return document


def os_salt() -> bytes:
    from .crypto import generate_salt

    return generate_salt()


def read_license(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormatError(f"라이선스 파일을 읽을 수 없습니다: {path}") from exc
    _validate_document(raw)
    return raw


def _validate_document(raw: object) -> None:
    if not isinstance(raw, dict) or set(raw) != _LICENSE_KEYS:
        raise FormatError("라이선스 필드가 올바르지 않습니다.")
    if raw["format"] != LICENSE_FORMAT:
        raise FormatError("지원하지 않는 라이선스 형식입니다.")
    _uuid(raw["license_id"], "license_id")  # type: ignore[arg-type]
    _uuid(raw["document_id"], "document_id")  # type: ignore[arg-type]
    if not isinstance(raw["subject"], str):
        raise FormatError("라이선스 주체가 올바르지 않습니다.")
    if not isinstance(raw["issued_at"], str):
        raise FormatError("라이선스 발급 시각이 올바르지 않습니다.")
    parse_stored_instant(raw["issued_at"])
    policy = policy_from_dict(raw["policy"])
    if policy.subject != raw["subject"]:
        raise FormatError("라이선스 주체가 정책과 일치하지 않습니다.")
    wrap = raw["wrap"]
    if not isinstance(wrap, dict) or set(wrap) != _WRAP_KEYS:
        raise FormatError("라이선스 키 포장 필드가 올바르지 않습니다.")
    if wrap["kdf"] != KDF_NAME:
        raise FormatError("지원하지 않는 라이선스 KDF입니다.")
    iterations = wrap["iterations"]
    if type(iterations) is not int:
        raise FormatError("라이선스 KDF 반복 횟수가 올바르지 않습니다.")
    b64d(wrap["salt"], expected_len=SALT_LEN, label="라이선스 솔트")
    b64d(wrap["nonce"], expected_len=NONCE_LEN, label="라이선스 nonce")
    b64d(wrap["wrapped_cek"], expected_len=CEK_LEN + GCM_TAG_LEN, label="라이선스 포장 키")
    mac = raw["mac"]
    if not isinstance(mac, dict) or set(mac) != _MAC_KEYS or mac["alg"] != MAC_ALG:
        raise FormatError("라이선스 MAC 필드가 올바르지 않습니다.")
    b64d(mac["value"], expected_len=MAC_LEN, label="라이선스 MAC")


def unwrap_license(document: dict[str, object], token: str) -> tuple[bytes, Policy]:
    """Check the HMAC, unwrap the content key, and return ``(cek, policy)``."""

    validate_secret(token, label="토큰")
    wrap = document["wrap"]
    if not isinstance(wrap, dict):
        raise FormatError("라이선스 키 포장 필드가 올바르지 않습니다.")
    salt = b64d(wrap["salt"], expected_len=SALT_LEN, label="라이선스 솔트")
    kek, mac_key = derive_keys(token, salt, wrap["iterations"])  # type: ignore[arg-type]
    presented = b64d(document["mac"]["value"], expected_len=MAC_LEN, label="라이선스 MAC")  # type: ignore[index]
    if not mac_matches(mac_key, canonical_json(mac_body(document)), presented):
        raise AuthenticationError("토큰이 올바르지 않거나 라이선스 파일이 변경되었습니다.")
    policy = policy_from_dict(document["policy"])
    cek = decrypt(
        kek,
        b64d(wrap["nonce"], expected_len=NONCE_LEN, label="라이선스 nonce"),
        b64d(wrap["wrapped_cek"], expected_len=CEK_LEN + GCM_TAG_LEN, label="라이선스 포장 키"),
        license_wrap_aad(str(document["document_id"]), str(document["license_id"]), policy),
        failure=IntegrityError,
        message="라이선스 키 포장이 손상되었습니다.",
    )
    if len(cek) != CEK_LEN:
        raise IntegrityError("라이선스 키 포장이 손상되었습니다.")
    return cek, policy


def public_view(document: dict[str, object], *, mac_status: str) -> dict[str, object]:
    """License metadata with the wrapped key removed."""

    policy = policy_from_dict(document["policy"])
    wrap = document["wrap"]
    assert isinstance(wrap, dict)
    return {
        "format": document["format"],
        "license_id": document["license_id"],
        "document_id": document["document_id"],
        "subject": document["subject"],
        "issued_at": document["issued_at"],
        "policy": policy.to_dict(),
        "wrap": {
            "kdf": wrap["kdf"],
            "iterations": wrap["iterations"],
            "cek_wrapped": True,
        },
        "mac": {"alg": MAC_ALG, "status": mac_status},
    }
