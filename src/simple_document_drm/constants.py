"""Shared sizes and identifiers for the sdrm-1 / sdlic-1 formats."""

from __future__ import annotations

MAGIC = b"SDRM"
VERSION = 1
FORMAT_NAME = "sdrm-1"
LICENSE_FORMAT = "sdlic-1"

# OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
DEFAULT_KDF_ITERATIONS = 600_000
# Floor accepted in stored packages. The CLI never offers a lower setting.
# Tests may pass a value at or above this floor into the library API.
MIN_KDF_ITERATIONS = 10_000
MAX_KDF_ITERATIONS = 5_000_000

MIN_SECRET_LENGTH = 8
MAX_SECRET_LENGTH = 1024

MAX_PLAINTEXT_BYTES = 256 * 1024 * 1024
MAX_HEADER_BYTES = 65_536
MAX_TEXT_FIELD = 500

SALT_LEN = 16
NONCE_LEN = 12
CEK_LEN = 32
GCM_TAG_LEN = 16
MAC_LEN = 32

CONTENT_AAD_LABEL = "sdrm-content-v1"
PASSWORD_WRAP_AAD_LABEL = "sdrm-cek-v1"
LICENSE_WRAP_AAD_LABEL = "sdlic-cek-v1"
KDF_NAME = "PBKDF2-HMAC-SHA256"
CONTENT_ALG = "AES-256-GCM"
MAC_ALG = "HMAC-SHA256"
STATE_VERSION = 1
