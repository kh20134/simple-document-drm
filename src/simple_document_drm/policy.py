"""Expiry, open-count ceiling, watermark note, and subject.

A license may be stricter than the package. It may not be looser. The open
command also intersects the two policies, so a hand-edited license cannot
outlive the package ceiling even when its MAC was recomputed by someone who
holds the token. Holding the token still means that person can read the
plaintext. The ceiling stops a casual edit of the license file, not a copy
of the decrypted document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .constants import MAX_TEXT_FIELD
from .errors import FormatError, PolicyError, UsageError

_STORED_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_DATE_ONLY = re.compile(r"\d{4}-\d{2}-\d{2}")
_POLICY_KEYS = {"expires_at", "max_opens", "subject", "watermark"}


def format_instant(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        raise FormatError("시간대가 없는 시각입니다.")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stored_instant(value: str) -> datetime:
    if not isinstance(value, str) or _STORED_INSTANT.fullmatch(value) is None:
        raise FormatError("저장된 시각은 YYYY-MM-DDTHH:MM:SSZ 형식이어야 합니다.")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def parse_expires_cli(value: str) -> datetime:
    """Parse a CLI expiry.

    A date (``YYYY-MM-DD``) is the last UTC calendar day the document is
    valid. It is stored as the next midnight, and opening fails when
    ``now >= expires_at``. A full timestamp must include ``Z`` or an offset.
    """

    text = value.strip()
    if _DATE_ONLY.fullmatch(text):
        day = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC)
        return day + timedelta(days=1)
    raw = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise UsageError(
            "만료 형식이 올바르지 않습니다. 예: 2026-12-31 또는 2026-12-31T15:00:00Z"
        ) from exc
    if parsed.tzinfo is None:
        raise UsageError("만료 시각에 시간대가 필요합니다. 예: 2026-12-31T15:00:00Z")
    return parsed.astimezone(UTC).replace(microsecond=0)


def _clean_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FormatError(f"{field} 값이 문자열이 아닙니다.")
    cleaned = value.strip()
    if cleaned == "":
        return None
    if len(cleaned) > MAX_TEXT_FIELD:
        raise FormatError(f"{field}가 너무 깁니다.")
    if any(ord(char) < 32 for char in cleaned):
        raise FormatError(f"{field}에 제어 문자를 넣을 수 없습니다.")
    return cleaned


@dataclass(frozen=True)
class Policy:
    expires_at: datetime | None = None
    max_opens: int | None = None
    watermark: str | None = None
    subject: str | None = None

    def __post_init__(self) -> None:
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise FormatError("만료 시각에 시간대가 필요합니다.")
            normalized = self.expires_at.astimezone(UTC).replace(microsecond=0)
            object.__setattr__(self, "expires_at", normalized)
        if self.max_opens is not None and (type(self.max_opens) is not int or self.max_opens < 1):
            raise FormatError("최대 열람 횟수는 1 이상의 정수여야 합니다.")
        object.__setattr__(self, "watermark", _clean_text(self.watermark, "워터마크"))
        object.__setattr__(self, "subject", _clean_text(self.subject, "주체"))

    def to_dict(self) -> dict[str, object]:
        return {
            "expires_at": format_instant(self.expires_at),
            "max_opens": self.max_opens,
            "subject": self.subject,
            "watermark": self.watermark,
        }


def policy_from_dict(data: object) -> Policy:
    if not isinstance(data, dict) or set(data) != _POLICY_KEYS:
        raise FormatError("정책 필드가 올바르지 않습니다.")
    expires_raw = data["expires_at"]
    opens_raw = data["max_opens"]
    if expires_raw is None:
        expires_at = None
    elif isinstance(expires_raw, str):
        expires_at = parse_stored_instant(expires_raw)
    else:
        raise FormatError("만료 시각 형식이 올바르지 않습니다.")
    if opens_raw is not None and type(opens_raw) is not int:
        raise FormatError("최대 열람 횟수 형식이 올바르지 않습니다.")
    return Policy(
        expires_at=expires_at,
        max_opens=opens_raw,
        subject=data["subject"] if isinstance(data["subject"], str) or data["subject"] is None else _bad_subject(),
        watermark=data["watermark"] if isinstance(data["watermark"], str) or data["watermark"] is None else _bad_mark(),
    )


def _bad_subject() -> str:
    raise FormatError("주체 형식이 올바르지 않습니다.")


def _bad_mark() -> str:
    raise FormatError("워터마크 형식이 올바르지 않습니다.")


def earlier(left: datetime | None, right: datetime | None) -> datetime | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def tighter_opens(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def join_notes(*notes: str | None) -> str | None:
    seen: list[str] = []
    for note in notes:
        if note and note not in seen:
            seen.append(note)
    if not seen:
        return None
    return " · ".join(seen)


def effective_policy(package: Policy, license_policy: Policy | None) -> Policy:
    """Return the policy that actually gates an open.

    Password opens pass ``license_policy=None`` and use the package as-is.
    License opens take the earlier expiry, the smaller open cap, both
    watermark notes, and the license subject.
    """

    if license_policy is None:
        return package
    return Policy(
        expires_at=earlier(package.expires_at, license_policy.expires_at),
        max_opens=tighter_opens(package.max_opens, license_policy.max_opens),
        watermark=join_notes(package.watermark, license_policy.watermark),
        subject=license_policy.subject or package.subject,
    )


def assert_within_ceiling(ceiling: Policy, requested: Policy) -> None:
    """Reject a license that would outlive or out-count the package."""

    if ceiling.expires_at is not None and (
        requested.expires_at is None or requested.expires_at > ceiling.expires_at
    ):
        raise PolicyError("라이선스 만료는 패키지 만료보다 늦을 수 없습니다.")
    if ceiling.max_opens is not None and (
        requested.max_opens is None or requested.max_opens > ceiling.max_opens
    ):
        raise PolicyError("라이선스 열람 횟수는 패키지 한도보다 클 수 없습니다.")


def build_license_policy(
    ceiling: Policy,
    *,
    subject: str,
    expires_at: datetime | None | object = ...,
    max_opens: int | None | object = ...,
    watermark: str | None | object = ...,
) -> Policy:
    """Fill omitted license fields from the package, then enforce the ceiling.

    Pass ``...`` (the default) to inherit. Pass ``None`` for expiry or
    ``max_opens`` only when the package itself is unlimited. An explicit
    watermark is stored on the license in addition to the package note.
    """

    chosen_expiry = ceiling.expires_at if expires_at is ... else expires_at
    chosen_opens = ceiling.max_opens if max_opens is ... else max_opens
    chosen_mark = None if watermark is ... else watermark
    if chosen_expiry is not None and not isinstance(chosen_expiry, datetime):
        raise FormatError("만료 시각 형식이 올바르지 않습니다.")
    if chosen_opens is not None and type(chosen_opens) is not int:
        raise FormatError("최대 열람 횟수 형식이 올바르지 않습니다.")
    if chosen_mark is not None and not isinstance(chosen_mark, str):
        raise FormatError("워터마크 형식이 올바르지 않습니다.")
    policy = Policy(
        expires_at=chosen_expiry,
        max_opens=chosen_opens,
        watermark=chosen_mark,
        subject=subject,
    )
    if policy.subject is None:
        raise UsageError("라이선스 주체(--subject)가 필요합니다.")
    assert_within_ceiling(ceiling, policy)
    return policy


def ensure_current(policy: Policy, now: datetime) -> None:
    if now.tzinfo is None:
        raise PolicyError("현재 시각에 시간대가 없습니다.")
    moment = now.astimezone(UTC)
    if policy.expires_at is not None and moment >= policy.expires_at:
        raise PolicyError(f"문서가 만료되었습니다 (만료 시각 {format_instant(policy.expires_at)}).")


def describe_policy(policy: Policy) -> list[str]:
    return [
        f"만료: {format_instant(policy.expires_at) or '없음'}",
        f"최대 열람: {policy.max_opens if policy.max_opens is not None else '제한 없음'}",
        f"워터마크: {policy.watermark or '없음'}",
        f"주체: {policy.subject or '없음'}",
    ]
