"""CLI flows. These use the real KDF cost because the CLI has no iteration flag."""

from __future__ import annotations

import json
from pathlib import Path

from simple_document_drm.cli import main


def test_help_and_unknown_flag(capsys) -> None:
    assert main(["--help"]) == 0
    help_text = capsys.readouterr().out
    assert "encrypt" in help_text
    assert "iterations" not in help_text
    assert main(["open", "x.sdrm", "-o", "y", "--ignore-policy"]) == 2


def test_token_is_a_single_line(capsys) -> None:
    assert main(["token"]) == 0
    token = capsys.readouterr().out.strip()
    assert "\n" not in token
    assert len(token) >= 20


def test_encrypt_open_and_inspect(tmp_path: Path, capsys) -> None:
    src = tmp_path / "memo.txt"
    src.write_text("2026년 기밀 메모\n", encoding="utf-8")
    package = tmp_path / "memo.sdrm"
    opened = tmp_path / "memo.out.txt"
    state = tmp_path / "opens.json"
    assert (
        main(
            [
                "encrypt",
                str(src),
                "-o",
                str(package),
                "--password",
                "demo-passphrase",
                "--expires",
                "2099-01-01",
                "--max-opens",
                "2",
                "--watermark",
                "사외반출 금지",
                "--subject",
                "기획팀",
            ]
        )
        == 0
    )
    assert "wrapped_cek" not in capsys.readouterr().out
    assert main(["inspect", str(package), "--json"]) == 0
    view = json.loads(capsys.readouterr().out)
    assert view["policy"]["watermark"] == "사외반출 금지"
    assert "wrapped_cek" not in json.dumps(view)
    assert (
        main(
            [
                "open",
                str(package),
                "-o",
                str(opened),
                "--password",
                "demo-passphrase",
                "--state",
                str(state),
                "--json",
            ]
        )
        == 0
    )
    reported = json.loads(capsys.readouterr().out)
    assert "2026년 기밀 메모" not in json.dumps(reported)
    assert opened.read_text(encoding="utf-8") == "2026년 기밀 메모\n"
    assert reported["opens_used"] == 1


def test_wrong_password_and_expiry_exit_codes(tmp_path: Path, capsys) -> None:
    src = tmp_path / "memo.txt"
    src.write_bytes(b"secret")
    package = tmp_path / "memo.sdrm"
    assert main(["encrypt", str(src), "-o", str(package), "--password", "demo-passphrase", "--expires", "2000-01-01"]) == 0
    capsys.readouterr()
    assert main(["open", str(package), "-o", str(tmp_path / "a"), "--password", "wrong-password"]) == 3
    assert main(["open", str(package), "-o", str(tmp_path / "b"), "--password", "demo-passphrase"]) == 4
    assert not (tmp_path / "a").exists()
    assert not (tmp_path / "b").exists()


def test_password_file_grant_and_license_open(tmp_path: Path, capsys) -> None:
    src = tmp_path / "memo.txt"
    src.write_bytes(b"payload")
    key = tmp_path / "owner.key"
    key.write_text("demo-passphrase\n", encoding="utf-8")
    key.chmod(0o600)
    token_file = tmp_path / "kim.token"
    assert main(["token"]) == 0
    token = capsys.readouterr().out.strip()
    token_file.write_text(token + "\n", encoding="utf-8")
    package = tmp_path / "memo.sdrm"
    license_path = tmp_path / "kim.sdlic"
    assert (
        main(
            [
                "encrypt",
                str(src),
                "-o",
                str(package),
                "--password-file",
                str(key),
                "--max-opens",
                "3",
                "--watermark",
                "내부",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "grant",
                str(package),
                "-o",
                str(license_path),
                "--password-file",
                str(key),
                "--token-file",
                str(token_file),
                "--subject",
                "kim",
                "--max-opens",
                "1",
            ]
        )
        == 0
    )
    opened = tmp_path / "kim.txt"
    assert (
        main(
            [
                "open",
                str(package),
                "-o",
                str(opened),
                "--license",
                str(license_path),
                "--token-file",
                str(token_file),
                "--state",
                str(tmp_path / "opens.json"),
            ]
        )
        == 0
    )
    assert opened.read_bytes() == b"payload"
    assert (
        main(
            [
                "open",
                str(package),
                "-o",
                str(opened),
                "--password-file",
                str(key),
                "--state",
                str(tmp_path / "opens.json"),
            ]
        )
        == 2
    )


def test_refuses_to_clobber_output(tmp_path: Path) -> None:
    src = tmp_path / "memo.txt"
    src.write_bytes(b"payload")
    package = tmp_path / "memo.sdrm"
    package.write_bytes(b"already")
    assert main(["encrypt", str(src), "-o", str(package), "--password", "demo-passphrase"]) == 2
    assert package.read_bytes() == b"already"
