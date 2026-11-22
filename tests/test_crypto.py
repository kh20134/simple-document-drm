"""Crypto primitive tests. KDF cases stay at the library floor, not 1 iteration."""

from __future__ import annotations

import pytest

from simple_document_drm.constants import DEFAULT_KDF_ITERATIONS, MIN_KDF_ITERATIONS
from simple_document_drm.crypto import (
    decrypt,
    derive_keys,
    encrypt,
    generate_cek,
    validate_secret,
)
from simple_document_drm.errors import AuthenticationError, FormatError, IntegrityError

ITERATIONS = 20_000


def test_default_iterations_meet_the_documented_cost() -> None:
    assert DEFAULT_KDF_ITERATIONS >= 600_000
    assert MIN_KDF_ITERATIONS >= 10_000
    assert ITERATIONS >= MIN_KDF_ITERATIONS


def test_derive_keys_are_deterministic_and_split() -> None:
    salt = b"0123456789abcdef"
    kek_a, mac_a = derive_keys("owner-secret", salt, ITERATIONS)
    kek_b, mac_b = derive_keys("owner-secret", salt, ITERATIONS)
    assert kek_a == kek_b
    assert mac_a == mac_b
    assert kek_a != mac_a
    assert len(kek_a) == 32 and len(mac_a) == 32


def test_derive_keys_changes_with_secret_and_salt() -> None:
    salt = b"0123456789abcdef"
    kek, _mac = derive_keys("owner-secret", salt, ITERATIONS)
    other, _mac = derive_keys("owner-secret-2", salt, ITERATIONS)
    salted, _mac = derive_keys("owner-secret", b"abcdef0123456789", ITERATIONS)
    assert kek != other
    assert kek != salted


def test_kdf_rejects_out_of_range_iterations() -> None:
    with pytest.raises(FormatError):
        derive_keys("owner-secret", b"0123456789abcdef", MIN_KDF_ITERATIONS - 1)
    with pytest.raises(FormatError):
        derive_keys("owner-secret", b"0123456789abcdef", 10_000_000)


def test_secret_rules() -> None:
    validate_secret("owner-secret", label="비밀번호", check_common=True)
    with pytest.raises(AuthenticationError):
        validate_secret("short", label="비밀번호")
    with pytest.raises(AuthenticationError):
        validate_secret("password", label="비밀번호", check_common=True)
    with pytest.raises(AuthenticationError):
        validate_secret("has\nnewline", label="토큰")
    with pytest.raises(AuthenticationError):
        validate_secret("   ", label="비밀번호")


def test_aes_gcm_roundtrip_and_failures() -> None:
    key = generate_cek()
    aad = b"associated"
    nonce, ciphertext = encrypt(key, b"\x00\xff binary", aad)
    opened = decrypt(
        key,
        nonce,
        ciphertext,
        aad,
        failure=IntegrityError,
        message="fail",
    )
    assert opened == b"\x00\xff binary"
    with pytest.raises(IntegrityError):
        decrypt(key, nonce, ciphertext, b"other", failure=IntegrityError, message="aad")
    flipped = bytearray(ciphertext)
    flipped[-1] ^= 0x01
    with pytest.raises(AuthenticationError):
        decrypt(key, nonce, bytes(flipped), aad, failure=AuthenticationError, message="tag")
    with pytest.raises(IntegrityError):
        decrypt(generate_cek(), nonce, ciphertext, aad, failure=IntegrityError, message="key")


def test_encrypt_rejects_short_key() -> None:
    with pytest.raises(FormatError):
        encrypt(b"short", b"data", b"aad")
