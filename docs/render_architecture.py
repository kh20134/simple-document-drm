"""Draw docs/architecture.png.

Requires Pillow and a Korean-capable font (NanumGothic on Debian/Ubuntu).
Runtime users do not need this script. The PNG is already in the repository.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 1800
HEIGHT = 1080
BG = (244, 241, 234)
INK = (28, 25, 21)
MUTED = (90, 84, 74)
CARD = (255, 252, 247)
LINE = (196, 188, 174)
BLUE = (31, 75, 110)
BLUE_BG = (232, 240, 246)
GREEN = (24, 92, 62)
GREEN_BG = (228, 241, 232)
AMBER = (122, 78, 16)
AMBER_BG = (248, 239, 220)
RED = (122, 59, 46)
RED_BG = (247, 232, 226)

FONT = "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"


def load_font(path: str, size: int) -> ImageFont.FreeTypeFont:
    if not Path(path).is_file():
        raise SystemExit(f"Korean font not found: {path}")
    return ImageFont.truetype(path, size)


def wrap_text(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.FreeTypeFont, width: int) -> list[str]:
    """Wrap on spaces. A line that already fits is kept intact."""

    lines: list[str] = []
    for paragraph in text.split("\n"):
        if paragraph == "":
            lines.append("")
            continue
        if draw.textlength(paragraph, font=font) <= width:
            lines.append(paragraph)
            continue
        current = ""
        for token in paragraph.split(" "):
            trial = token if current == "" else f"{current} {token}"
            if draw.textlength(trial, font=font) <= width:
                current = trial
                continue
            if current:
                lines.append(current)
            current = token
        if current:
            lines.append(current)
    return lines


def card(
    draw: ImageDraw.ImageDraw,
    box: tuple[int, int, int, int],
    title: str,
    body: str,
    accent: tuple[int, int, int],
    fill: tuple[int, int, int],
    title_font: ImageFont.FreeTypeFont,
    body_font: ImageFont.FreeTypeFont,
) -> None:
    left, top, right, bottom = box
    draw.rounded_rectangle(box, radius=16, fill=fill, outline=LINE, width=2)
    draw.rounded_rectangle((left, top, right, top + 10), radius=6, fill=accent)
    draw.rectangle((left, top + 6, right, top + 10), fill=accent)
    inner = right - left - 36
    y = top + 24
    for line in wrap_text(draw, title, title_font, inner):
        draw.text((left + 18, y), line, font=title_font, fill=accent)
        y += 28
    y += 6
    for line in wrap_text(draw, body, body_font, inner):
        draw.text((left + 18, y), line, font=body_font, fill=INK)
        y += 24
    if y > bottom - 12:
        raise SystemExit(f"Text overflow in card {title!r}: {y} > {bottom - 12}")


def arrow(draw: ImageDraw.ImageDraw, start: tuple[int, int], end: tuple[int, int]) -> None:
    draw.line((start, end), fill=BLUE, width=3)
    ex, ey = end
    sx, sy = start
    if abs(ex - sx) >= abs(ey - sy):
        direction = 1 if ex >= sx else -1
        head = [
            (ex, ey),
            (ex - 12 * direction, ey - 7),
            (ex - 12 * direction, ey + 7),
        ]
    else:
        direction = 1 if ey >= sy else -1
        head = [
            (ex, ey),
            (ex - 7, ey - 12 * direction),
            (ex + 7, ey - 12 * direction),
        ]
    draw.polygon(head, fill=BLUE)


def main() -> None:
    title_font = load_font(FONT_BOLD, 36)
    subtitle_font = load_font(FONT, 20)
    lane_font = load_font(FONT_BOLD, 18)
    card_title = load_font(FONT_BOLD, 20)
    card_body = load_font(FONT, 16)
    small = load_font(FONT, 16)
    footer_title = load_font(FONT_BOLD, 18)
    footer_body = load_font(FONT, 16)

    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.text((48, 32), "simple-document-drm", font=title_font, fill=INK)
    draw.text(
        (48, 82),
        "오프라인 문서 DRM 구조  ·  교육·시연용  ·  내용 키(CEK)와 인가 비밀을 분리",
        font=subtitle_font,
        fill=MUTED,
    )

    draw.text((48, 140), "1   발행  seal", font=lane_font, fill=BLUE)
    top = 176
    height = 268
    width = 300
    gap = 28
    left0 = 48
    boxes = []
    for index in range(5):
        left = left0 + index * (width + gap)
        boxes.append((left, top, left + width, top + height))

    card(
        draw,
        boxes[0],
        "평문 문서",
        "발행자가 가진 파일.\n형식은 가리지 않습니다.\n한도 256MiB.",
        MUTED,
        CARD,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes[1],
        "내용 키 CEK",
        "문서마다 임의 32바이트.\n패키지에 평문으로 두지 않습니다.",
        BLUE,
        BLUE_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes[2],
        "AES-256-GCM",
        "암호문과 인증 태그.\nAAD에 정책, 이름,\n크기, 미디어 타입.\n정책을 고치면\n인증이 실패합니다.",
        BLUE,
        BLUE_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes[3],
        ".sdrm 패키지",
        "매직 SDRM, 헤더, 암호문.\n비밀번호가 있으면\nPBKDF2로 KEK를 만들고\nCEK를 포장합니다.",
        BLUE,
        BLUE_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes[4],
        ".sdlic 라이선스",
        "토큰으로 CEK를 포장.\n수신자 정책은 HMAC과\n포장 AAD에 묶입니다.",
        AMBER,
        AMBER_BG,
        card_title,
        card_body,
    )
    for index in range(4):
        start = (boxes[index][2] + 2, (boxes[index][1] + boxes[index][3]) // 2)
        end = (boxes[index + 1][0] - 2, (boxes[index + 1][1] + boxes[index + 1][3]) // 2)
        arrow(draw, start, end)

    mid_y = boxes[0][3] + 18
    arrow(draw, (WIDTH // 2, mid_y), (WIDTH // 2, mid_y + 36))
    draw.text((WIDTH // 2 + 16, mid_y + 6), "sdrm open", font=small, fill=BLUE)

    draw.text((48, 508), "2   열람  open", font=lane_font, fill=GREEN)
    top2 = 544
    boxes2 = []
    for index in range(5):
        left = left0 + index * (width + gap)
        boxes2.append((left, top2, left + width, top2 + height))
    card(
        draw,
        boxes2[0],
        "인가 비밀",
        "비밀번호 또는 키 파일.\n혹은 라이선스와 토큰.\n둘 중 하나만 씁니다.",
        AMBER,
        AMBER_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes2[1],
        "KEK 복원",
        "PBKDF2-HMAC-SHA256\n기본 600,000회.\nKEK로 CEK를 엽니다.\nCLI는 횟수를\n낮추지 않습니다.",
        BLUE,
        BLUE_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes2[2],
        "정책 관문",
        "만료 시각 (UTC).\n최대 열람 횟수.\n워터마크 메모.\n라이선스는 패키지\n한도보다 넓을 수 없음.",
        AMBER,
        AMBER_BG,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes2[3],
        "로컬 열람 기록",
        "opens.json\n기기와 인가 수단별로\n따로 셉니다.\n네트워크 카운터 없음.",
        MUTED,
        CARD,
        card_title,
        card_body,
    )
    card(
        draw,
        boxes2[4],
        "평문 출력",
        "정책을 통과한 뒤에만\n파일을 씁니다.\n내용은 원본과 같습니다.\n워터마크는 안내 문구.",
        GREEN,
        GREEN_BG,
        card_title,
        card_body,
    )
    for index in range(4):
        start = (boxes2[index][2] + 2, (boxes2[index][1] + boxes2[index][3]) // 2)
        end = (boxes2[index + 1][0] - 2, (boxes2[index + 1][1] + boxes2[index + 1][3]) // 2)
        arrow(draw, start, end)

    footer = (48, 860, WIDTH - 48, 1032)
    draw.rounded_rectangle(footer, radius=16, fill=RED_BG, outline=RED, width=2)
    draw.text((72, 878), "이 구조가 보장하지 않는 것", font=footer_title, fill=RED)
    footer_copy = (
        "기업용 DRM이 아닙니다. 관리자 권한이면 메모리나 키 파일에서 키를 꺼낼 수 있고, 연 사람은 평문을 복사할 수 있습니다.\n"
        "열람 횟수는 그 기기의 상태 파일이라, 파일을 지우거나 시계를 바꾸면 다시 적용되지 않습니다.\n"
        "폐기와 화면 캡처 차단은 없습니다. 상용 DRM을 우회하는 기능은 들어 있지 않습니다."
    )
    y = 914
    for line in wrap_text(draw, footer_copy, footer_body, WIDTH - 160):
        draw.text((72, y), line, font=footer_body, fill=INK)
        y += 26

    destination = Path(__file__).with_name("architecture.png")
    image.save(destination, "PNG")
    print(destination)


if __name__ == "__main__":
    main()
