"""Package seal/open tests: tamper, expiry, open count, and byte fidelity."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from simple_document_drm.constants import MIN_KDF_ITERATIONS
from simple_document_drm.documents import (
    content_aad,
    inspect_package,
    open_file,
    read_container,
    seal_file,
    write_container,
)
from simple_document_drm.errors import (
    AuthenticationError,
    DrmError,
    FormatError,
    IntegrityError,
    PolicyError,
)
from simple_document_drm.policy import Policy

ITERATIONS = 20_000
assert ITERATIONS >= MIN_KDF_ITERATIONS
PASSWORD = "owner-secret"


def _seal(
    tmp_path: Path,
    payload: bytes = "한글 기밀\n".encode(),
    *,
    name: str = "note.txt",
    policy: Policy | None = None,
    password: str | None = PASSWORD,
    token: str | None = None,
    subject: str | None = None,
) -> tuple[Path, Path, Path]:
    src = tmp_path / name
    src.write_bytes(payload)
    package = tmp_path / f"{name}.sdrm"
    license_path = tmp_path / "receiver.sdlic" if token else None
    seal_file(
        src,
        package,
        policy=policy or Policy(watermark="사외반출 금지", subject="기획팀"),
        password=password,
        license_path=license_path,
        token=token,
        license_subject=subject,
        iterations=ITERATIONS,
    )
    return src, package, tmp_path / "opened.bin"


def test_content_aad_is_stable() -> None:
    aad = content_aad(
        document_id="00000000-0000-4000-8000-000000000001",
        filename="a.txt",
        media_type="text/plain",
        plaintext_size=3,
        policy=Policy(),
    )
    assert aad == (
        b'{"aad":"sdrm-content-v1","document_id":"00000000-0000-4000-8000-000000000001",'
        b'"filename":"a.txt","media_type":"text/plain","plaintext_size":3,'
        b'"policy":{"expires_at":null,"max_opens":null,"subject":null,"watermark":null}}'
    )


def test_password_roundtrip_preserves_bytes(tmp_path: Path) -> None:
    payload = bytes(range(256)) + "문서".encode()
    src, package, dest = _seal(tmp_path, payload, name="binary.bin")
    result = open_file(package, dest, state_path=tmp_path / "opens.json", password=PASSWORD)
    assert dest.read_bytes() == src.read_bytes()
    assert result.opens_used == 1
    assert result.policy.watermark == "사외반출 금지"
    assert result.filename == "binary.bin"
    assert (package.stat().st_mode & 0o777) == 0o600
    assert (dest.stat().st_mode & 0o777) == 0o600


def test_wrong_password_does_not_write_or_count(tmp_path: Path) -> None:
    _src, package, dest = _seal(tmp_path)
    state = tmp_path / "opens.json"
    with pytest.raises(AuthenticationError):
        open_file(package, dest, state_path=state, password="not-the-secret")
    assert not dest.exists()
    assert not state.exists()


def test_tampered_ciphertext_is_rejected(tmp_path: Path) -> None:
    _src, package, dest = _seal(tmp_path)
    header, ciphertext = read_container(package)
    flipped = bytearray(ciphertext)
    flipped[0] ^= 0x01
    write_container(package, header, bytes(flipped), force=True)
    with pytest.raises(IntegrityError):
        open_file(package, dest, state_path=tmp_path / "opens.json", password=PASSWORD)
    assert not dest.exists()


def test_tampered_policy_breaks_authentication(tmp_path: Path) -> None:
    _src, package, dest = _seal(tmp_path, policy=Policy(max_opens=2, watermark="원본"))
    header, ciphertext = read_container(package)
    policy = header["policy"]
    assert isinstance(policy, dict)
    policy["max_opens"] = 9
    write_container(package, header, ciphertext, force=True)
    with pytest.raises(IntegrityError):
        open_file(package, dest, state_path=tmp_path / "opens.json", password=PASSWORD)


def test_expired_document_is_not_written(tmp_path: Path) -> None:
    past = datetime.now(UTC) - timedelta(days=1)
    _src, package, dest = _seal(tmp_path, policy=Policy(expires_at=past))
    with pytest.raises(PolicyError):
        open_file(package, dest, state_path=tmp_path / "opens.json", password=PASSWORD)
    assert not dest.exists()


def test_max_opens_is_local_and_resets_only_with_a_new_state_file(tmp_path: Path) -> None:
    _src, package, dest = _seal(tmp_path, policy=Policy(max_opens=2))
    state = tmp_path / "opens.json"
    open_file(package, dest, state_path=state, password=PASSWORD)
    open_file(package, dest, state_path=state, password=PASSWORD, force=True)
    with pytest.raises(PolicyError):
        open_file(package, dest, state_path=state, password=PASSWORD, force=True)
    recorded = json.loads(state.read_text(encoding="utf-8"))
    assert list(recorded["opens"].values()) == [2]
    other = tmp_path / "other-opens.json"
    again = tmp_path / "again.bin"
    result = open_file(package, again, state_path=other, password=PASSWORD)
    assert result.opens_used == 1


def test_corrupt_state_refuses_the_open(tmp_path: Path) -> None:
    _src, package, dest = _seal(tmp_path, policy=Policy(max_opens=2))
    state = tmp_path / "opens.json"
    state.write_text("{", encoding="utf-8")
    with pytest.raises(FormatError):
        open_file(package, dest, state_path=state, password=PASSWORD)
    assert not dest.exists()


def test_empty_file_and_future_expiry(tmp_path: Path) -> None:
    future = datetime.now(UTC) + timedelta(days=2)
    src, package, dest = _seal(tmp_path, b"", name="empty.dat", policy=Policy(expires_at=future))
    result = open_file(
        package,
        dest,
        state_path=tmp_path / "opens.json",
        password=PASSWORD,
        now=datetime.now(UTC),
    )
    assert dest.read_bytes() == b""
    assert result.policy.expires_at == future.replace(microsecond=0)
    assert src.read_bytes() == b""


def test_oversize_plaintext_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("simple_document_drm.documents.MAX_PLAINTEXT_BYTES", 4)
    src = tmp_path / "big.txt"
    src.write_bytes(b"12345")
    with pytest.raises(DrmError):
        seal_file(src, tmp_path / "big.sdrm", policy=Policy(), password=PASSWORD, iterations=ITERATIONS)


def test_random_bytes_are_not_a_package(tmp_path: Path) -> None:
    bogus = tmp_path / "nope.sdrm"
    bogus.write_bytes(b"not a package")
    with pytest.raises(FormatError):
        read_container(bogus)


def test_inspect_hides_wrapped_key_material(tmp_path: Path) -> None:
    _src, package, _dest = _seal(tmp_path)
    view = inspect_package(package)
    encoded = json.dumps(view)
    assert "wrapped_cek" not in encoded
    assert view["wrap"]["cek_wrapped"] is True  # type: ignore[index]
    header, _ciphertext = read_container(package)
    wrap = header["wrap"]
    assert isinstance(wrap, dict)
    assert wrap["wrapped_cek"] not in encoded


def test_stored_filename_is_the_basename(tmp_path: Path) -> None:
    folder = tmp_path / "nested"
    folder.mkdir()
    src = folder / "report.pdf"
    src.write_bytes(b"%PDF-1.4 demo")
    package = tmp_path / "report.sdrm"
    seal_file(src, package, policy=Policy(), password=PASSWORD, iterations=ITERATIONS)
    header, _ciphertext = read_container(package)
    assert header["filename"] == "report.pdf"
    assert header["media_type"] == "application/pdf"


def test_common_password_is_rejected_at_seal(tmp_path: Path) -> None:
    src = tmp_path / "a.txt"
    src.write_bytes(b"x")
    with pytest.raises(AuthenticationError):
        seal_file(src, tmp_path / "a.sdrm", policy=Policy(), password="password", iterations=ITERATIONS)
