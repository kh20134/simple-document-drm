"""Local open counter.

The count lives in a JSON file on the machine that opened the document.
There is no network counter in this version. Two machines do not share a
count, and removing the file starts a new one. That is a property of an
offline demo, not a hidden switch in the CLI.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .constants import STATE_VERSION
from .errors import FormatError

_KEY = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"\|(?:password|license:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


def default_state_path() -> Path:
    return Path.home() / ".local" / "share" / "simple-document-drm" / "opens.json"


def state_key(document_id: str, authority: str) -> str:
    key = f"{document_id}|{authority}"
    if _KEY.fullmatch(key) is None:
        raise FormatError("열람 기록 키가 올바르지 않습니다.")
    return key


def empty_state() -> dict[str, object]:
    return {"version": STATE_VERSION, "opens": {}}


def load_state(path: Path) -> dict[str, object]:
    if not path.exists():
        return empty_state()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FormatError(f"열람 기록 파일을 읽을 수 없습니다: {path}") from exc
    if not isinstance(raw, dict) or set(raw) != {"version", "opens"}:
        raise FormatError(f"열람 기록 형식이 올바르지 않습니다: {path}")
    if raw["version"] != STATE_VERSION:
        raise FormatError(f"지원하지 않는 열람 기록 버전입니다: {path}")
    opens = raw["opens"]
    if not isinstance(opens, dict):
        raise FormatError(f"열람 기록 형식이 올바르지 않습니다: {path}")
    for key, count in opens.items():
        if not isinstance(key, str) or _KEY.fullmatch(key) is None:
            raise FormatError(f"열람 기록 키가 올바르지 않습니다: {path}")
        if type(count) is not int or count < 0:
            raise FormatError(f"열람 횟수가 올바르지 않습니다: {path}")
    return {"version": STATE_VERSION, "opens": dict(opens)}


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(f"파일을 쓰지 못했습니다: {path}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(temporary, path)


def atomic_write_json(path: Path, payload: object, mode: int = 0o600) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, text.encode("utf-8"), mode)


@contextmanager
def state_transaction(path: Path) -> Iterator[dict[str, object]]:
    """Exclusive section around one check-and-increment of the counter.

    The JSON file is replaced only when the caller returns normally.
    """

    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        state = load_state(path)
        yield state
        atomic_write_json(path, state)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def current_opens(state: dict[str, object], key: str) -> int:
    opens = state["opens"]
    if not isinstance(opens, dict):
        raise FormatError("열람 기록 형식이 올바르지 않습니다.")
    count = opens.get(key, 0)
    if type(count) is not int or count < 0:
        raise FormatError("열람 횟수가 올바르지 않습니다.")
    return count
