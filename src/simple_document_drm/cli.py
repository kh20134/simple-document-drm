"""Command line for simple-document-drm.

Messages are Korean. Secrets are read from a flag, a key file, or a prompt.
The decrypted document is written only to ``--output``, never to the terminal.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import __version__
from .crypto import generate_token, validate_secret
from .documents import grant_license, inspect_package, open_file, seal_file
from .errors import AuthenticationError, DrmError, FormatError, UsageError
from .licensing import public_view, read_license, unwrap_license
from .policy import Policy, describe_policy, parse_expires_cli, policy_from_dict
from .state import default_state_path, load_state

_EXAMPLES = """\
examples:
  sdrm encrypt memo.txt -o memo.sdrm --password-file owner.key --expires 2026-12-31 --max-opens 3 --watermark '사외반출 금지'
  sdrm open memo.sdrm -o memo.out.txt --password-file owner.key
  sdrm grant memo.sdrm -o kim.sdlic --password-file owner.key --token-file kim.token --subject kim --max-opens 1
  sdrm open memo.sdrm -o memo.kim.txt --license kim.sdlic --token-file kim.token
"""


def _positive_int(text: str) -> int:
    try:
        value = int(text, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("1 이상의 정수가 필요합니다.") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("1 이상의 정수가 필요합니다.")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sdrm",
        description="교육용 오프라인 문서 DRM. 파일을 AES-256-GCM 패키지로 포장하고, 비밀번호 또는 라이선스 파일로만 엽니다.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sdrm {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    encrypt = commands.add_parser("encrypt", help="문서를 .sdrm 패키지로 암호화합니다.")
    encrypt.add_argument("input", help="평문 파일")
    encrypt.add_argument("-o", "--output", required=True, help="쓸 .sdrm 패키지")
    encrypt.add_argument("--password", help="소유자 비밀번호 (쉘 기록에 남을 수 있습니다)")
    encrypt.add_argument("--password-file", help="비밀번호가 들어 있는 키 파일")
    encrypt.add_argument("--license-out", help="함께 발급할 .sdlic 라이선스 경로")
    encrypt.add_argument("--token", help="라이선스 토큰 (쉘 기록에 남을 수 있습니다)")
    encrypt.add_argument("--token-file", help="토큰이 들어 있는 키 파일")
    encrypt.add_argument("--subject", help="라이선스 주체. 라이선스를 만들 때 필요합니다.")
    encrypt.add_argument("--expires", help="만료. YYYY-MM-DD (해당 UTC 날짜 포함) 또는 시간대가 있는 시각")
    encrypt.add_argument("--max-opens", type=_positive_int, help="인가 수단·기기별 최대 열람 횟수")
    encrypt.add_argument("--watermark", help="열 때 표시할 워터마크 메모. 파일 바이트에는 넣지 않습니다.")
    encrypt.add_argument("--force", action="store_true", help="기존 출력 파일을 덮어씁니다.")
    encrypt.add_argument("--json", action="store_true", help="결과를 JSON으로 출력합니다.")
    encrypt.set_defaults(func=cmd_encrypt)

    open_cmd = commands.add_parser("open", help="패키지를 정책 검사 후 복호화합니다.")
    open_cmd.add_argument("package", help=".sdrm 패키지")
    open_cmd.add_argument("-o", "--output", required=True, help="평문을 쓸 경로")
    open_cmd.add_argument("--password", help="소유자 비밀번호")
    open_cmd.add_argument("--password-file", help="비밀번호 키 파일")
    open_cmd.add_argument("--license", help=".sdlic 라이선스 파일")
    open_cmd.add_argument("--token", help="라이선스 토큰")
    open_cmd.add_argument("--token-file", help="토큰 키 파일")
    open_cmd.add_argument("--state", help="열람 기록 JSON 경로")
    open_cmd.add_argument("--force", action="store_true", help="기존 출력 파일을 덮어씁니다.")
    open_cmd.add_argument("--json", action="store_true")
    open_cmd.set_defaults(func=cmd_open)

    grant = commands.add_parser("grant", help="소유자 비밀번호로 추가 라이선스를 발급합니다.")
    grant.add_argument("package", help="비밀번호 포장이 있는 .sdrm 패키지")
    grant.add_argument("-o", "--output", required=True, help="쓸 .sdlic 경로")
    grant.add_argument("--password", help="소유자 비밀번호")
    grant.add_argument("--password-file", help="비밀번호 키 파일")
    grant.add_argument("--token", help="새 수신자 토큰")
    grant.add_argument("--token-file", help="새 수신자 토큰 키 파일")
    grant.add_argument("--subject", required=True, help="라이선스 주체")
    grant.add_argument("--expires", help="패키지보다 늦을 수 없습니다. 생략하면 패키지 만료를 따릅니다.")
    grant.add_argument("--max-opens", type=_positive_int, help="패키지 한도보다 클 수 없습니다.")
    grant.add_argument("--watermark", help="라이선스에 추가할 워터마크 메모")
    grant.add_argument("--force", action="store_true")
    grant.add_argument("--json", action="store_true")
    grant.set_defaults(func=cmd_grant)

    inspect = commands.add_parser("inspect", help="패키지 헤더를 비밀 없이 보여 줍니다.")
    inspect.add_argument("package")
    inspect.add_argument("--json", action="store_true")
    inspect.set_defaults(func=cmd_inspect)

    inspect_license = commands.add_parser("inspect-license", help="라이선스 메타데이터를 보여 줍니다.")
    inspect_license.add_argument("license")
    inspect_license.add_argument("--token", help="주면 MAC과 키 포장을 확인합니다. 문서는 열지 않습니다.")
    inspect_license.add_argument("--token-file")
    inspect_license.add_argument("--json", action="store_true")
    inspect_license.set_defaults(func=cmd_inspect_license)

    state = commands.add_parser("state", help="로컬 열람 기록을 보여 줍니다.")
    state.add_argument("--state", help="열람 기록 JSON 경로")
    state.add_argument("--json", action="store_true")
    state.set_defaults(func=cmd_state)

    token = commands.add_parser("token", help="새 라이선스 토큰을 한 줄로 출력합니다.")
    token.set_defaults(func=cmd_token)
    return parser


def _warn_perms(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077:
        print(
            f"sdrm: 경고: {path} 가 다른 사용자에게 읽힐 수 있습니다 (권한 {mode & 0o777:o}).",
            file=sys.stderr,
        )


def read_secret_file(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeError as exc:
        raise FormatError(f"키 파일은 UTF-8 한 줄이어야 합니다: {path}") from exc
    text = text.removesuffix("\n")
    text = text.removesuffix("\r")
    if "\n" in text or "\r" in text:
        raise FormatError(f"키 파일은 한 줄이어야 합니다: {path}")
    return text


def resolve_secret(
    value: str | None,
    file_name: str | None,
    *,
    label: str,
    prompt: str | None,
    confirm: bool,
) -> str | None:
    if value is not None and file_name is not None:
        raise UsageError(f"{label}는 한 곳만 지정하세요.")
    if file_name is not None:
        path = Path(file_name)
        _warn_perms(path)
        return read_secret_file(path)
    if value is not None:
        return value
    if prompt is None or not sys.stdin.isatty():
        return None
    entered = getpass.getpass(prompt)
    if confirm:
        again = getpass.getpass(f"{label} 확인: ")
        if entered != again:
            raise AuthenticationError(f"{label} 확인이 일치하지 않습니다.")
    return entered


def _policy_from_flags(args: argparse.Namespace, *, subject: str | None) -> Policy:
    expires = parse_expires_cli(args.expires) if args.expires else None
    return Policy(
        expires_at=expires,
        max_opens=args.max_opens,
        watermark=args.watermark,
        subject=subject,
    )


def _emit(payload: object, *, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return
    print("\n".join(lines))


def _state_path(args: argparse.Namespace) -> Path:
    raw = getattr(args, "state", None)
    if raw:
        return Path(raw)
    return default_state_path()


def cmd_encrypt(args: argparse.Namespace) -> None:
    password = resolve_secret(
        args.password,
        args.password_file,
        label="비밀번호",
        prompt=None if args.license_out else "비밀번호: ",
        confirm=True,
    )
    token = resolve_secret(
        args.token,
        args.token_file,
        label="토큰",
        prompt="라이선스 토큰: " if args.license_out else None,
        confirm=False,
    )
    if password is None and token is None:
        raise UsageError("비밀번호 또는 --license-out 과 토큰이 필요합니다.")
    if args.license_out and token is None:
        raise UsageError("라이선스 토큰이 필요합니다. --token 또는 --token-file 을 사용하세요.")
    if args.license_out and not args.subject:
        raise UsageError("라이선스 주체(--subject)가 필요합니다.")
    if token is not None and not args.license_out:
        raise UsageError("토큰은 --license-out 과 함께 사용합니다.")
    policy = _policy_from_flags(args, subject=args.subject)
    result = seal_file(
        Path(args.input),
        Path(args.output),
        policy=policy,
        password=password,
        license_path=Path(args.license_out) if args.license_out else None,
        token=token,
        license_subject=args.subject,
        force=args.force,
    )
    if not result.owner_password:
        print(
            "sdrm: 경고: 소유자 비밀번호가 없습니다. 라이선스와 토큰을 잃으면 복구할 수 없고, "
            "grant 로 라이선스를 추가할 수도 없습니다.",
            file=sys.stderr,
        )
    payload = {
        "document_id": result.document_id,
        "package": str(result.package_path),
        "license": str(result.license_path) if result.license_path else None,
        "owner_password": result.owner_password,
        "policy": result.policy.to_dict(),
    }
    lines = [
        "패키지를 만들었습니다.",
        f"  문서 ID: {result.document_id}",
        f"  패키지: {result.package_path}",
        f"  소유자 비밀번호: {'있음' if result.owner_password else '없음'}",
        f"  라이선스: {result.license_path or '없음'}",
        *[f"  {line}" for line in describe_policy(result.policy)],
    ]
    _emit(payload, as_json=args.json, lines=lines)


def cmd_open(args: argparse.Namespace) -> None:
    password = resolve_secret(
        args.password,
        args.password_file,
        label="비밀번호",
        prompt=None if args.license else "비밀번호: ",
        confirm=False,
    )
    token = resolve_secret(
        args.token,
        args.token_file,
        label="토큰",
        prompt="라이선스 토큰: " if args.license else None,
        confirm=False,
    )
    if args.license and password is not None:
        raise UsageError("비밀번호와 라이선스를 동시에 지정할 수 없습니다.")
    if args.license and token is None:
        raise UsageError("라이선스 토큰이 필요합니다. --token 또는 --token-file 을 사용하세요.")
    if token is not None and not args.license:
        raise UsageError("토큰은 --license 와 함께 사용합니다.")
    if password is None and not args.license:
        raise UsageError("비밀번호 또는 --license 가 필요합니다.")
    result = open_file(
        Path(args.package),
        Path(args.output),
        state_path=_state_path(args),
        password=password,
        license_path=Path(args.license) if args.license else None,
        token=token,
        force=args.force,
    )
    cap = str(result.max_opens) if result.max_opens is not None else "제한 없음"
    authority = "비밀번호" if result.authority == "password" else "라이선스"
    payload = {
        "document_id": result.document_id,
        "filename": result.filename,
        "output": str(result.output_path),
        "authority": result.authority,
        "opens_used": result.opens_used,
        "max_opens": result.max_opens,
        "media_type": result.media_type,
        "plaintext_size": result.plaintext_size,
        "policy": result.policy.to_dict(),
    }
    lines = [
        "문서를 열었습니다.",
        f"  문서 ID: {result.document_id}",
        f"  원본 이름: {result.filename}",
        f"  저장: {result.output_path}",
        f"  인가: {authority}",
        f"  열람: {result.opens_used}/{cap}",
        *[f"  {line}" for line in describe_policy(result.policy)],
        "  참고: 워터마크는 안내 문구입니다. 저장한 파일 내용은 원본과 같습니다.",
    ]
    _emit(payload, as_json=args.json, lines=lines)


def cmd_grant(args: argparse.Namespace) -> None:
    password = resolve_secret(
        args.password,
        args.password_file,
        label="비밀번호",
        prompt="소유자 비밀번호: ",
        confirm=False,
    )
    token = resolve_secret(
        args.token,
        args.token_file,
        label="토큰",
        prompt="새 라이선스 토큰: ",
        confirm=False,
    )
    if password is None:
        raise UsageError("소유자 비밀번호가 필요합니다.")
    if token is None:
        raise UsageError("새 라이선스 토큰이 필요합니다.")
    validate_secret(token, label="토큰")
    document = grant_license(
        Path(args.package),
        Path(args.output),
        password=password,
        token=token,
        subject=args.subject,
        expires_at=parse_expires_cli(args.expires) if args.expires else ...,
        max_opens=args.max_opens if args.max_opens is not None else ...,
        watermark=args.watermark if args.watermark is not None else ...,
        force=args.force,
    )
    view = public_view(document, mac_status="issued")
    lines = [
        "라이선스를 발급했습니다.",
        f"  라이선스: {args.output}",
        f"  문서 ID: {view['document_id']}",
        f"  라이선스 ID: {view['license_id']}",
        f"  주체: {view['subject']}",
    ]
    _emit(view, as_json=args.json, lines=lines)


def cmd_inspect(args: argparse.Namespace) -> None:
    view = inspect_package(Path(args.package))
    policy_raw = view["policy"]
    crypto = view["crypto"]
    wrap = view["wrap"]
    fields = view["authenticated_fields"]
    if not isinstance(policy_raw, dict) or not isinstance(crypto, dict) or not isinstance(wrap, dict):
        raise FormatError("패키지 정보를 표시할 수 없습니다.")
    if not isinstance(fields, list):
        raise FormatError("패키지 정보를 표시할 수 없습니다.")
    policy = policy_from_dict(policy_raw)
    lines = [
        f"형식: {view['format']}",
        f"문서 ID: {view['document_id']}",
        f"파일 이름: {view['filename']}",
        f"미디어 타입: {view['media_type']}",
        f"생성: {view['created_at']}",
        f"평문 크기: {view['plaintext_size']}바이트",
        f"암호: {crypto['alg']}",
        f"키 포장: {wrap['method']}",
        *[f"  {line}" for line in describe_policy(policy)],
        "인증되는 필드: " + ", ".join(str(field) for field in fields),
        "포장된 내용 키와 암호문 바이트는 출력하지 않습니다.",
    ]
    _emit(view, as_json=args.json, lines=lines)


def cmd_inspect_license(args: argparse.Namespace) -> None:
    path = Path(args.license)
    document = read_license(path)
    token = resolve_secret(
        args.token,
        args.token_file,
        label="토큰",
        prompt=None,
        confirm=False,
    )
    status = "not-checked"
    if token is not None:
        unwrap_license(document, token)
        status = "valid"
    view = public_view(document, mac_status=status)
    lines = [
        f"형식: {view['format']}",
        f"라이선스 ID: {view['license_id']}",
        f"문서 ID: {view['document_id']}",
        f"주체: {view['subject']}",
        f"발급: {view['issued_at']}",
        f"MAC: {status}",
        "포장된 내용 키는 출력하지 않습니다.",
    ]
    _emit(view, as_json=args.json, lines=lines)


def cmd_state(args: argparse.Namespace) -> None:
    path = _state_path(args)
    if path.exists():
        state = load_state(path)
    else:
        state = {"version": 1, "opens": {}}
    payload = {"path": str(path), **state}
    lines = [f"열람 기록: {path}", json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)]
    _emit(payload, as_json=args.json, lines=lines)


def cmd_token(_args: argparse.Namespace) -> None:
    print(generate_token())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 0 if code is None else int(code)
    try:
        args.func(args)
    except DrmError as exc:
        print(f"sdrm: {exc}", file=sys.stderr)
        return exc.exit_code
    except FileNotFoundError as exc:
        print(f"sdrm: 파일을 찾을 수 없습니다: {exc.filename or '파일'}", file=sys.stderr)
        return 1
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        print("sdrm: 중단했습니다.", file=sys.stderr)
        return 130
    return 0
