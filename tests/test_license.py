"""License issue, MAC, ceiling, and owner-only grant."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from simple_document_drm.crypto import derive_keys, hmac_sha256
from simple_document_drm.documents import grant_license, open_file, seal_file
from simple_document_drm.encoding import b64d, b64e, canonical_json
from simple_document_drm.errors import AuthenticationError, IntegrityError, PolicyError
from simple_document_drm.licensing import mac_body, read_license
from simple_document_drm.policy import Policy

ITERATIONS = 20_000
PASSWORD = "owner-secret"
TOKEN = "receiver-token-1"


def _package(
    tmp_path: Path,
    *,
    policy: Policy | None = None,
    password: str | None = PASSWORD,
    token: str | None = None,
    subject: str | None = None,
    payload: bytes = b"license-body",
) -> Path:
    src = tmp_path / "memo.txt"
    src.write_bytes(payload)
    package = tmp_path / "memo.sdrm"
    seal_file(
        src,
        package,
        policy=policy or Policy(max_opens=3, watermark="사외반출 금지"),
        password=password,
        license_path=tmp_path / "first.sdlic" if token else None,
        token=token,
        license_subject=subject,
        iterations=ITERATIONS,
    )
    return package


def test_license_open_matches_plaintext_and_joins_watermark(tmp_path: Path) -> None:
    package = _package(tmp_path, token=TOKEN, subject="kim")
    dest = tmp_path / "out.txt"
    result = open_file(
        package,
        dest,
        state_path=tmp_path / "opens.json",
        license_path=tmp_path / "first.sdlic",
        token=TOKEN,
    )
    assert dest.read_bytes() == b"license-body"
    assert result.authority.startswith("license:")
    assert result.policy.watermark == "사외반출 금지"
    assert result.policy.subject == "kim"
    assert (tmp_path / "first.sdlic").stat().st_mode & 0o777 == 0o600


def test_wrong_token_and_plain_tamper(tmp_path: Path) -> None:
    package = _package(tmp_path, token=TOKEN, subject="kim", policy=Policy(max_opens=2))
    license_path = tmp_path / "first.sdlic"
    with pytest.raises(AuthenticationError):
        open_file(
            package,
            tmp_path / "a.txt",
            state_path=tmp_path / "opens.json",
            license_path=license_path,
            token="another-token",
        )
    document = json.loads(license_path.read_text(encoding="utf-8"))
    document["policy"]["max_opens"] = 1
    license_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AuthenticationError):
        open_file(
            package,
            tmp_path / "b.txt",
            state_path=tmp_path / "opens.json",
            license_path=license_path,
            token=TOKEN,
        )
    assert not (tmp_path / "opens.json").exists()


def test_remac_without_rewrapping_fails(tmp_path: Path) -> None:
    package = _package(tmp_path, token=TOKEN, subject="kim", policy=Policy(max_opens=2))
    license_path = tmp_path / "first.sdlic"
    document = json.loads(license_path.read_text(encoding="utf-8"))
    document["policy"]["max_opens"] = 1
    salt = b64d(document["wrap"]["salt"])
    _kek, mac_key = derive_keys(TOKEN, salt, document["wrap"]["iterations"])
    document["mac"]["value"] = b64e(hmac_sha256(mac_key, canonical_json(mac_body(document))))
    license_path.write_text(json.dumps(document), encoding="utf-8")
    read_license(license_path)
    with pytest.raises(IntegrityError):
        open_file(
            package,
            tmp_path / "out.txt",
            state_path=tmp_path / "opens.json",
            license_path=license_path,
            token=TOKEN,
        )


def test_license_for_another_document_is_rejected(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    _package(first, token=TOKEN, subject="kim")
    other = _package(second, password=PASSWORD)
    with pytest.raises(PolicyError):
        open_file(
            other,
            second / "out.txt",
            state_path=second / "opens.json",
            license_path=first / "first.sdlic",
            token=TOKEN,
        )


def test_grant_can_narrow_and_cannot_widen(tmp_path: Path) -> None:
    package = _package(
        tmp_path,
        policy=Policy(
            max_opens=3,
            expires_at=datetime.now(UTC) + timedelta(days=10),
            watermark="사외반출 금지",
        ),
    )
    with pytest.raises(PolicyError):
        grant_license(
            package,
            tmp_path / "wide.sdlic",
            password=PASSWORD,
            token="wider-token-ok",
            subject="lee",
            max_opens=4,
            iterations=ITERATIONS,
        )
    grant_license(
        package,
        tmp_path / "kim.sdlic",
        password=PASSWORD,
        token="kim-token-value",
        subject="kim",
        max_opens=1,
        watermark="김대리",
        iterations=ITERATIONS,
    )
    state = tmp_path / "opens.json"
    result = open_file(
        package,
        tmp_path / "kim.txt",
        state_path=state,
        license_path=tmp_path / "kim.sdlic",
        token="kim-token-value",
    )
    assert result.opens_used == 1
    assert result.max_opens == 1
    assert result.policy.watermark == "사외반출 금지 · 김대리"
    with pytest.raises(PolicyError):
        open_file(
            package,
            tmp_path / "kim.txt",
            state_path=state,
            license_path=tmp_path / "kim.sdlic",
            token="kim-token-value",
            force=True,
        )
    owner = open_file(
        package,
        tmp_path / "owner.txt",
        state_path=state,
        password=PASSWORD,
    )
    assert owner.opens_used == 1
    assert owner.max_opens == 3


def test_license_only_package_has_no_owner_grant(tmp_path: Path) -> None:
    package = _package(tmp_path, password=None, token=TOKEN, subject="kim")
    with pytest.raises(AuthenticationError):
        open_file(package, tmp_path / "no.txt", state_path=tmp_path / "opens.json", password=PASSWORD)
    with pytest.raises(AuthenticationError):
        grant_license(
            package,
            tmp_path / "extra.sdlic",
            password=PASSWORD,
            token="another-token-ok",
            subject="lee",
            iterations=ITERATIONS,
        )
    opened = open_file(
        package,
        tmp_path / "yes.txt",
        state_path=tmp_path / "opens.json",
        license_path=tmp_path / "first.sdlic",
        token=TOKEN,
    )
    assert opened.plaintext_size == len(b"license-body")
