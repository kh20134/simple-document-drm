"""Seal a file into an ``.sdrm`` package and open it again.

The content encryption key is random. A password, a license token, or both
wrap that key. The policy is associated data on the content ciphertext, so
changing the expiry or the open cap in the header fails authentication.
"""

from __future__ import annotations

import json
import mimetypes
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .constants import (
    CEK_LEN,
    CONTENT_AAD_LABEL,
    CONTENT_ALG,
    DEFAULT_KDF_ITERATIONS,
    FORMAT_NAME,
    GCM_TAG_LEN,
    KDF_NAME,
    MAGIC,
    MAX_HEADER_BYTES,
    MAX_PLAINTEXT_BYTES,
    NONCE_LEN,
    PASSWORD_WRAP_AAD_LABEL,
    SALT_LEN,
    VERSION,
)
from .crypto import (
    decrypt,
    derive_keys,
    encrypt,
    generate_cek,
    generate_salt,
    validate_secret,
)
from .encoding import b64d, b64e, canonical_json
from .errors import (
    AuthenticationError,
    DrmError,
    FormatError,
    IntegrityError,
    PolicyError,
    UsageError,
)
from .licensing import issue_license, read_license, unwrap_license
from .policy import (
    Policy,
    build_license_policy,
    effective_policy,
    ensure_current,
    parse_stored_instant,
    policy_from_dict,
)
from .state import atomic_write_bytes, current_opens, state_key, state_transaction

_MEDIA = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,63}$"
)
_HEADER_KEYS = {
    "created_at",
    "crypto",
    "document_id",
    "filename",
    "format",
    "media_type",
    "plaintext_size",
    "policy",
    "wrap",
}
_CRYPTO_KEYS = {"aad_alg", "alg", "nonce"}
_PASSWORD_WRAP_KEYS = {"iterations", "kdf", "method", "nonce", "salt", "wrapped_cek"}
_LICENSE_WRAP_KEYS = {"method"}


@dataclass(frozen=True)
class SealResult:
    document_id: str
    package_path: Path
    license_path: Path | None
    policy: Policy
    owner_password: bool


@dataclass(frozen=True)
class OpenResult:
    document_id: str
    filename: str
    output_path: Path
    policy: Policy
    opens_used: int
    max_opens: int | None
    authority: str
    media_type: str
    plaintext_size: int


def content_aad(
    *,
    document_id: str,
    filename: str,
    media_type: str,
    plaintext_size: int,
    policy: Policy,
) -> bytes:
    return canonical_json(
        {
            "aad": CONTENT_AAD_LABEL,
            "document_id": document_id,
            "filename": filename,
            "media_type": media_type,
            "plaintext_size": plaintext_size,
            "policy": policy.to_dict(),
        }
    )


def password_wrap_aad(document_id: str) -> bytes:
    return canonical_json({"aad": PASSWORD_WRAP_AAD_LABEL, "document_id": document_id})


def guess_media_type(filename: str) -> str:
    guessed, _encoding = mimetypes.guess_type(filename)
    if guessed and _MEDIA.fullmatch(guessed):
        return guessed
    return "application/octet-stream"


def _canonical_uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise FormatError(f"{label}가 UUID가 아닙니다.")
    try:
        parsed = str(uuid.UUID(value))
    except ValueError as exc:
        raise FormatError(f"{label}가 UUID가 아닙니다.") from exc
    if parsed != value:
        raise FormatError(f"{label}는 소문자 UUID여야 합니다.")
    return parsed


def _filename(value: object) -> str:
    if not isinstance(value, str) or value in {"", ".", ".."}:
        raise FormatError("파일 이름이 올바르지 않습니다.")
    if (
        "/" in value
        or "\\" in value
        or value != Path(value).name
        or len(value) > 200
        or any(ord(char) < 32 for char in value)
    ):
        raise FormatError("파일 이름이 올바르지 않습니다.")
    return value


def _media_type(value: object) -> str:
    if not isinstance(value, str) or _MEDIA.fullmatch(value) is None:
        raise FormatError("미디어 타입이 올바르지 않습니다.")
    return value


def _iterations(value: object) -> int:
    if type(value) is not int:
        raise FormatError("KDF 반복 횟수가 올바르지 않습니다.")
    return value


def validate_header(header: object) -> dict[str, object]:
    if not isinstance(header, dict) or set(header) != _HEADER_KEYS:
        raise FormatError("패키지 헤더 필드가 올바르지 않습니다.")
    if header["format"] != FORMAT_NAME:
        raise FormatError("지원하지 않는 패키지 형식입니다.")
    _canonical_uuid(header["document_id"], "document_id")
    _filename(header["filename"])
    _media_type(header["media_type"])
    if not isinstance(header["created_at"], str):
        raise FormatError("생성 시각이 올바르지 않습니다.")
    parse_stored_instant(header["created_at"])
    size = header["plaintext_size"]
    if type(size) is not int or size < 0 or size > MAX_PLAINTEXT_BYTES:
        raise FormatError("평문 길이가 올바르지 않습니다.")
    crypto = header["crypto"]
    if not isinstance(crypto, dict) or set(crypto) != _CRYPTO_KEYS:
        raise FormatError("암호 필드가 올바르지 않습니다.")
    if crypto["alg"] != CONTENT_ALG or crypto["aad_alg"] != "canonical-json-v1":
        raise FormatError("지원하지 않는 암호 알고리즘입니다.")
    b64d(crypto["nonce"], expected_len=NONCE_LEN, label="콘텐츠 nonce")
    policy_from_dict(header["policy"])
    wrap = header["wrap"]
    if not isinstance(wrap, dict) or "method" not in wrap:
        raise FormatError("키 포장 필드가 올바르지 않습니다.")
    if wrap["method"] == "password":
        if set(wrap) != _PASSWORD_WRAP_KEYS or wrap["kdf"] != KDF_NAME:
            raise FormatError("비밀번호 키 포장 필드가 올바르지 않습니다.")
        _iterations(wrap["iterations"])
        b64d(wrap["salt"], expected_len=SALT_LEN, label="비밀번호 솔트")
        b64d(wrap["nonce"], expected_len=NONCE_LEN, label="비밀번호 nonce")
        b64d(wrap["wrapped_cek"], expected_len=CEK_LEN + GCM_TAG_LEN, label="포장된 내용 키")
    elif wrap["method"] == "license":
        if set(wrap) != _LICENSE_WRAP_KEYS:
            raise FormatError("라이선스 전용 패키지의 키 포장 필드가 올바르지 않습니다.")
    else:
        raise FormatError("알 수 없는 키 포장 방식입니다.")
    return header


def read_container(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        data = path.read_bytes()
    except IsADirectoryError as exc:
        raise FormatError(f"패키지 경로가 디렉터리입니다: {path}") from exc
    limit = MAX_PLAINTEXT_BYTES + MAX_HEADER_BYTES + 64
    if len(data) > limit:
        raise FormatError("패키지가 너무 큽니다.")
    if len(data) < 9 or data[:4] != MAGIC:
        raise FormatError("SDRM 패키지가 아닙니다.")
    version = data[4]
    if version != VERSION:
        raise FormatError(f"지원하지 않는 패키지 버전입니다: {version}")
    header_len = int.from_bytes(data[5:9], "big")
    if header_len < 2 or header_len > MAX_HEADER_BYTES or 9 + header_len > len(data):
        raise FormatError("패키지 헤더 길이가 올바르지 않습니다.")
    try:
        header = json.loads(data[9 : 9 + header_len].decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise FormatError("패키지 헤더 JSON을 읽을 수 없습니다.") from exc
    ciphertext = data[9 + header_len :]
    if len(ciphertext) < GCM_TAG_LEN:
        raise FormatError("암호문이 너무 짧습니다.")
    return validate_header(header), ciphertext


def write_container(path: Path, header: dict[str, object], ciphertext: bytes, *, force: bool = False) -> None:
    validate_header(header)
    if len(ciphertext) < GCM_TAG_LEN:
        raise FormatError("암호문이 너무 짧습니다.")
    header_bytes = canonical_json(header)
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise FormatError("헤더가 너무 큽니다.")
    blob = MAGIC + bytes([VERSION]) + len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext
    if path.exists() and not force:
        raise UsageError(f"출력 파일이 이미 있습니다. --force 로 덮어쓰세요: {path}")
    atomic_write_bytes(path, blob)


def _read_input(src: Path) -> tuple[str, bytes]:
    if not src.is_file():
        raise DrmError(f"입력 파일이 아닙니다: {src}")
    size = src.stat().st_size
    if size > MAX_PLAINTEXT_BYTES:
        raise DrmError(f"파일이 너무 큽니다 ({size}바이트). 한도는 {MAX_PLAINTEXT_BYTES}바이트입니다.")
    payload = src.read_bytes()
    if len(payload) > MAX_PLAINTEXT_BYTES:
        raise DrmError(f"파일이 너무 큽니다 ({len(payload)}바이트). 한도는 {MAX_PLAINTEXT_BYTES}바이트입니다.")
    return _filename(src.name), payload


def seal_file(
    src: Path,
    dest: Path,
    *,
    policy: Policy,
    password: str | None = None,
    license_path: Path | None = None,
    token: str | None = None,
    license_subject: str | None = None,
    iterations: int = DEFAULT_KDF_ITERATIONS,
    force: bool = False,
) -> SealResult:
    """Encrypt ``src`` into ``dest``.

    ``iterations`` is stored in the package. The CLI always uses
    ``DEFAULT_KDF_ITERATIONS`` and has no flag to lower it. Tests pass a
    smaller value that is still at least ``MIN_KDF_ITERATIONS``.
    """

    if password is None and (license_path is None or token is None):
        raise UsageError("비밀번호 또는 라이선스 토큰이 필요합니다.")
    if (license_path is None) != (token is None):
        raise UsageError("라이선스 경로와 토큰은 함께 지정해야 합니다.")
    if dest.exists() and not force:
        raise UsageError(f"출력 파일이 이미 있습니다. --force 로 덮어쓰세요: {dest}")
    if license_path is not None and license_path.exists() and not force:
        raise UsageError(f"출력 파일이 이미 있습니다. --force 로 덮어쓰세요: {license_path}")
    if password is not None:
        validate_secret(password, label="비밀번호", check_common=True)
    filename, payload = _read_input(src)
    document_id = str(uuid.uuid4())
    media_type = guess_media_type(filename)
    cek = generate_cek()
    nonce, ciphertext = encrypt(
        cek,
        payload,
        content_aad(
            document_id=document_id,
            filename=filename,
            media_type=media_type,
            plaintext_size=len(payload),
            policy=policy,
        ),
    )
    if password is None:
        wrap: dict[str, object] = {"method": "license"}
    else:
        salt = generate_salt()
        kek, _mac_key = derive_keys(password, salt, iterations)
        wrap_nonce, wrapped = encrypt(kek, cek, password_wrap_aad(document_id))
        wrap = {
            "method": "password",
            "kdf": KDF_NAME,
            "iterations": iterations,
            "salt": b64e(salt),
            "nonce": b64e(wrap_nonce),
            "wrapped_cek": b64e(wrapped),
        }
    header: dict[str, object] = {
        "format": FORMAT_NAME,
        "document_id": document_id,
        "filename": filename,
        "media_type": media_type,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plaintext_size": len(payload),
        "crypto": {"alg": CONTENT_ALG, "nonce": b64e(nonce), "aad_alg": "canonical-json-v1"},
        "wrap": wrap,
        "policy": policy.to_dict(),
    }
    written_license: Path | None = None
    if license_path is not None and token is not None:
        if license_subject is None:
            raise UsageError("라이선스 주체(--subject)가 필요합니다.")
        license_policy = build_license_policy(policy, subject=license_subject)
        issue_license(
            license_path,
            document_id=document_id,
            cek=cek,
            token=token,
            policy=license_policy,
            iterations=iterations,
            force=force,
        )
        written_license = license_path
    write_container(dest, header, ciphertext, force=force)
    return SealResult(
        document_id=document_id,
        package_path=dest,
        license_path=written_license,
        policy=policy,
        owner_password=password is not None,
    )


def _unwrap_password(header: dict[str, object], password: str) -> bytes:
    wrap = header["wrap"]
    if not isinstance(wrap, dict) or wrap.get("method") != "password":
        raise AuthenticationError("이 패키지에는 비밀번호 포장이 없습니다. 라이선스 파일로 여세요.")
    validate_secret(password, label="비밀번호")
    kek, _mac_key = derive_keys(
        password,
        b64d(wrap["salt"], expected_len=SALT_LEN, label="비밀번호 솔트"),
        _iterations(wrap["iterations"]),
    )
    cek = decrypt(
        kek,
        b64d(wrap["nonce"], expected_len=NONCE_LEN, label="비밀번호 nonce"),
        b64d(wrap["wrapped_cek"], expected_len=CEK_LEN + GCM_TAG_LEN, label="포장된 내용 키"),
        password_wrap_aad(str(header["document_id"])),
        failure=AuthenticationError,
        message="비밀번호가 올바르지 않거나 키 포장이 손상되었습니다.",
    )
    if len(cek) != CEK_LEN:
        raise AuthenticationError("비밀번호가 올바르지 않거나 키 포장이 손상되었습니다.")
    return cek


def open_file(
    src: Path,
    dest: Path,
    *,
    state_path: Path,
    password: str | None = None,
    license_path: Path | None = None,
    token: str | None = None,
    now: datetime | None = None,
    force: bool = False,
) -> OpenResult:
    """Decrypt ``src`` into ``dest`` when the secret and the policy allow it.

    ``now`` exists so tests can move the clock. The CLI always uses the
    current UTC time and does not expose this argument.
    """

    if (password is None) == (license_path is None):
        raise UsageError("비밀번호 또는 라이선스 중 하나만 지정하세요.")
    if (license_path is None) != (token is None):
        raise UsageError("라이선스 경로와 토큰은 함께 지정해야 합니다.")
    header, ciphertext = read_container(src)
    document_id = str(header["document_id"])
    package_policy = policy_from_dict(header["policy"])
    if password is not None:
        cek = _unwrap_password(header, password)
        authority = "password"
        opened_policy = package_policy
    else:
        assert license_path is not None and token is not None
        license_document = read_license(license_path)
        if license_document["document_id"] != document_id:
            raise PolicyError("라이선스가 이 문서를 가리키지 않습니다.")
        cek, license_policy = unwrap_license(license_document, token)
        authority = f"license:{license_document['license_id']}"
        opened_policy = effective_policy(package_policy, license_policy)
    moment = now if now is not None else datetime.now(UTC)
    ensure_current(opened_policy, moment)
    aad = content_aad(
        document_id=document_id,
        filename=str(header["filename"]),
        media_type=str(header["media_type"]),
        plaintext_size=int(header["plaintext_size"]),
        policy=package_policy,
    )
    crypto = header["crypto"]
    if not isinstance(crypto, dict):
        raise FormatError("암호 필드가 올바르지 않습니다.")
    nonce = b64d(crypto["nonce"], expected_len=NONCE_LEN, label="콘텐츠 nonce")
    key = state_key(document_id, authority)

    def plaintext_of() -> bytes:
        opened = decrypt(
            cek,
            nonce,
            ciphertext,
            aad,
            failure=IntegrityError,
            message="문서 무결성 검사가 실패했습니다. 패키지가 손상되었거나 정책이 변경되었습니다.",
        )
        if len(opened) != header["plaintext_size"]:
            raise IntegrityError("평문 길이가 일치하지 않습니다.")
        return opened

    with state_transaction(state_path) as state:
        if dest.exists() and not force:
            raise UsageError(f"출력 파일이 이미 있습니다. --force 로 덮어쓰세요: {dest}")
        used = current_opens(state, key)
        if opened_policy.max_opens is not None and used >= opened_policy.max_opens:
            raise PolicyError(f"열람 횟수를 모두 사용했습니다 ({used}/{opened_policy.max_opens}).")
        payload = plaintext_of()
        atomic_write_bytes(dest, payload)
        opens = state["opens"]
        if not isinstance(opens, dict):
            raise FormatError("열람 기록 형식이 올바르지 않습니다.")
        used_now = used + 1
        opens[key] = used_now
    return OpenResult(
        document_id=document_id,
        filename=str(header["filename"]),
        output_path=dest,
        policy=opened_policy,
        opens_used=used_now,
        max_opens=opened_policy.max_opens,
        authority=authority,
        media_type=str(header["media_type"]),
        plaintext_size=len(payload),
    )


def grant_license(
    src: Path,
    dest: Path,
    *,
    password: str,
    token: str,
    subject: str,
    expires_at: datetime | None | object = ...,
    max_opens: int | None | object = ...,
    watermark: str | None | object = ...,
    iterations: int = DEFAULT_KDF_ITERATIONS,
    force: bool = False,
) -> dict[str, object]:
    """Issue another license from the owner password wrapped in the package.

    A recipient license is not accepted here. Offline, anyone who can already
    decrypt could re-wrap the content key themselves. This command does not
    add that path. It only unwraps the owner slot the publisher created.
    """

    header, _ciphertext = read_container(src)
    cek = _unwrap_password(header, password)
    ceiling = policy_from_dict(header["policy"])
    license_policy = build_license_policy(
        ceiling,
        subject=subject,
        expires_at=expires_at,
        max_opens=max_opens,
        watermark=watermark,
    )
    return issue_license(
        dest,
        document_id=str(header["document_id"]),
        cek=cek,
        token=token,
        policy=license_policy,
        iterations=iterations,
        force=force,
    )


def inspect_package(path: Path) -> dict[str, object]:
    header, ciphertext = read_container(path)
    policy = policy_from_dict(header["policy"])
    wrap = header["wrap"]
    assert isinstance(wrap, dict)
    wrap_view: dict[str, object]
    if wrap["method"] == "password":
        wrap_view = {
            "method": "password",
            "kdf": wrap["kdf"],
            "iterations": wrap["iterations"],
            "cek_wrapped": True,
        }
    else:
        wrap_view = {"method": "license", "cek_wrapped": False}
    return {
        "format": header["format"],
        "document_id": header["document_id"],
        "filename": header["filename"],
        "media_type": header["media_type"],
        "created_at": header["created_at"],
        "plaintext_size": header["plaintext_size"],
        "ciphertext_bytes": len(ciphertext),
        "crypto": {"alg": CONTENT_ALG, "aad": CONTENT_AAD_LABEL},
        "wrap": wrap_view,
        "policy": policy.to_dict(),
        "authenticated_fields": [
            "document_id",
            "filename",
            "media_type",
            "plaintext_size",
            "policy",
        ],
    }
