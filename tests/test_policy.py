"""Policy ceiling, expiry parsing, and the open-time intersection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from simple_document_drm.encoding import canonical_json
from simple_document_drm.errors import FormatError, PolicyError, UsageError
from simple_document_drm.policy import (
    Policy,
    assert_within_ceiling,
    build_license_policy,
    effective_policy,
    ensure_current,
    parse_expires_cli,
    parse_stored_instant,
)


def test_canonical_json_sorts_keys_and_keeps_korean() -> None:
    raw = canonical_json({"b": 1, "a": "한글"})
    assert raw == '{"a":"한글","b":1}'.encode()


def test_date_only_expires_at_the_next_utc_midnight() -> None:
    assert parse_expires_cli("2026-12-31") == datetime(2027, 1, 1, tzinfo=UTC)
    assert parse_expires_cli("2026-12-31T15:00:00Z") == datetime(2026, 12, 31, 15, 0, tzinfo=UTC)
    assert parse_expires_cli("2026-12-31T15:00:00+09:00") == datetime(2026, 12, 31, 6, 0, tzinfo=UTC)


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(UsageError):
        parse_expires_cli("2026-12-31T15:00:00")
    with pytest.raises(FormatError):
        parse_stored_instant("2026-12-31")


def test_policy_rejects_bad_fields() -> None:
    with pytest.raises(FormatError):
        Policy(expires_at=datetime(2026, 1, 1))
    with pytest.raises(FormatError):
        Policy(max_opens=0)
    with pytest.raises(FormatError):
        Policy(max_opens=True)  # type: ignore[arg-type]
    with pytest.raises(FormatError):
        Policy(watermark="x" * 501)


def test_effective_policy_takes_the_stricter_limit() -> None:
    later = datetime(2027, 1, 1, tzinfo=UTC)
    sooner = datetime(2026, 6, 1, tzinfo=UTC)
    package = Policy(expires_at=later, max_opens=5, watermark="사외반출 금지", subject="팀")
    license_policy = Policy(expires_at=sooner, max_opens=2, watermark="김대리", subject="kim")
    merged = effective_policy(package, license_policy)
    assert merged.expires_at == sooner
    assert merged.max_opens == 2
    assert merged.watermark == "사외반출 금지 · 김대리"
    assert merged.subject == "kim"
    assert effective_policy(package, None) == package


def test_license_cannot_loosen_the_package() -> None:
    ceiling = Policy(expires_at=datetime(2026, 6, 1, tzinfo=UTC), max_opens=2)
    with pytest.raises(PolicyError):
        build_license_policy(ceiling, subject="kim", expires_at=datetime(2027, 1, 1, tzinfo=UTC))
    with pytest.raises(PolicyError):
        build_license_policy(ceiling, subject="kim", max_opens=3)
    with pytest.raises(PolicyError):
        build_license_policy(ceiling, subject="kim", max_opens=None)
    inherited = build_license_policy(ceiling, subject="kim")
    assert inherited.expires_at == ceiling.expires_at
    assert inherited.max_opens == 2
    assert inherited.subject == "kim"
    stricter = build_license_policy(ceiling, subject="kim", max_opens=1)
    assert stricter.max_opens == 1
    assert_within_ceiling(ceiling, stricter)


def test_subject_is_required_for_a_license() -> None:
    with pytest.raises(UsageError):
        build_license_policy(Policy(), subject="  ")


def test_expiry_check_uses_an_inclusive_start_and_exclusive_end() -> None:
    expires = datetime(2026, 6, 1, tzinfo=UTC)
    policy = Policy(expires_at=expires)
    ensure_current(policy, expires - timedelta(seconds=1))
    with pytest.raises(PolicyError):
        ensure_current(policy, expires)
    with pytest.raises(PolicyError):
        ensure_current(Policy(), datetime(2026, 1, 1))
