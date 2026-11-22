"""AES-256-GCM and PBKDF2-HMAC-SHA256 key wrapping.

This module only encrypts and decrypts bytes for this educational format.
It does not talk to a license server and it does not inspect foreign DRM.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    CEK_LEN,
    MAX_KDF_ITERATIONS,
    MAX_SECRET_LENGTH,
    MIN_KDF_ITERATIONS,
    MIN_SECRET_LENGTH,
    NONCE_LEN,
)
from .errors import AuthenticationError, FormatError, IntegrityError

_COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "12345678",
        "123456789",
        "qwertyui",
        "qwerty123",
        "changeme",
        "iloveyou",
        "admin123",
        "letmein1",
    }
)


def validate_secret(secret: str, *, label: str, check_common: bool = False) -> None:
    """Reject empty, tiny, or newline-bearing secrets before any KDF work."""

    if not isinstance(secret, str) or secret.strip() == "":
        if label == "토큰":
            raise AuthenticationError("토큰이 비어 있습니다.")
        raise AuthenticationError("비밀번호가 비어 있습니다.")
    if len(secret) < MIN_SECRET_LENGTH:
        raise AuthenticationError(f"{label} 길이는 {MIN_SECRET_LENGTH}자 이상이어야 합니다.")
    if len(secret) > MAX_SECRET_LENGTH:
        raise AuthenticationError(f"{label} 길이가 너무 깁니다.")
    if "\x00" in secret or "\n" in secret or "\r" in secret:
        raise AuthenticationError(f"{label}에 줄바꿈을 넣을 수 없습니다.")
    if check_common and secret.casefold() in _COMMON_PASSWORDS:
        raise AuthenticationError(f"너무 흔한 {label}입니다. 더 긴 문구를 사용하세요.")


def generate_token() -> str:
    """Return a fresh license token. The caller stores it outside the package."""

    return secrets.token_urlsafe(24)


def generate_cek() -> bytes:
    return os.urandom(CEK_LEN)


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_keys(secret: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """Derive a 32-byte KEK and a 32-byte MAC key from one secret.

    The two halves are domain-separated only by position in the PBKDF2
    output. Callers bind them further with distinct AES-GCM associated data.
    """

    if iterations < MIN_KDF_ITERATIONS or iterations > MAX_KDF_ITERATIONS:
        raise FormatError(
            f"KDF 반복 횟수는 {MIN_KDF_ITERATIONS} 이상 {MAX_KDF_ITERATIONS} 이하여야 합니다."
        )
    if len(salt) < 16:
        raise FormatError("KDF 솔트가 너무 짧습니다.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=iterations,
    )
    material = kdf.derive(secret.encode("utf-8"))
    return material[:32], material[32:]


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Return ``(nonce, ciphertext_and_tag)``."""

    if len(key) != CEK_LEN:
        raise FormatError("암호화 키 길이가 올바르지 않습니다.")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
    *,
    failure: type[AuthenticationError | IntegrityError],
    message: str,
) -> bytes:
    if len(key) != CEK_LEN or len(nonce) != NONCE_LEN:
        raise FormatError("nonce 또는 키 길이가 올바르지 않습니다.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise failure(message) from exc


def hmac_sha256(mac_key: bytes, payload: bytes) -> bytes:
    if len(mac_key) != 32:
        raise FormatError("MAC 키 길이가 올바르지 않습니다.")
    return hmac.new(mac_key, payload, hashlib.sha256).digest()


def mac_matches(mac_key: bytes, payload: bytes, presented: bytes) -> bool:
    expected = hmac_sha256(mac_key, payload)
    if len(presented) != len(expected):
        return False
    return hmac.compare_digest(expected, presented)
