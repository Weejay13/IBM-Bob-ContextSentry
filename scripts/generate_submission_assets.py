from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "submission"
OUT.mkdir(parents=True, exist_ok=True)
WIDTH = 1920
HEIGHT = 1080
PDF_WIDTH = 13.333 * 72
PDF_HEIGHT = 7.5 * 72
FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")
SANS = FONT_DIR / "DejaVuSans.ttf"
SANS_BOLD = FONT_DIR / "DejaVuSans-Bold.ttf"
MONO = FONT_DIR / "DejaVuSansMono.ttf"
MONO_BOLD = FONT_DIR / "DejaVuSansMono-Bold.ttf"
COLORS = {
    "bg": "#07101d",
    "panel": "#0d1a2b",
    "panel2": "#101f33",
    "line": "#1d3550",
    "text": "#f4f7fb",
    "muted": "#9aabc0",
    "cyan": "#42d9ff",
    "green": "#4ce6a1",
    "red": "#ff5d73",
    "amber": "#ffbf4b",
    "purple": "#9b7cff",
    "blue": "#3d8bff",
}


def pil_font(path: Path, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(path), size)


def pdf_font(name: str, path: Path) -> str:
    pdfmetrics.registerFont(TTFont(name, str(path)))
    return name


PDF_SANS = pdf_font("VoxSans", SANS)
PDF_SANS_BOLD = pdf_font("VoxSansBold", SANS_BOLD)
PDF_MONO = pdf_font("VoxMono", MONO)
PDF_MONO_BOLD = pdf_font("VoxMonoBold", MONO_BOLD)


def make_cover() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), COLORS["bg"])
    pixels = image.load()
    for y in range(HEIGHT):
        for x in range(WIDTH):
            radial = max(0.0, 1.0 - (((x - 1450) / 950) ** 2 + ((y - 220) / 800) ** 2))
            pixels[x, y] = (
                int(7 + 10 * radial),
                int(16 + 26 * radial),
                int(29 + 48 * radial),
            )
    glow = Image.new("RGBA", image.size, (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse((1050, -260, 2150, 840), fill=(61, 139, 255, 55))
    gd.ellipse((-350, 620, 650, 1500), fill=(66, 217, 255, 25))
    glow = glow.filter(ImageFilter.GaussianBlur(90))
    image = Image.alpha_composite(image.convert("RGBA"), glow)
    draw = ImageDraw.Draw(image)
    for x in range(0, WIDTH, 64):
        draw.line((x, 0, x, HEIGHT), fill=(65, 110, 160, 22), width=1)
    for y in range(0, HEIGHT, 64):
        draw.line((0, y, WIDTH, y), fill=(65, 110, 160, 22), width=1)
    draw.rounded_rectangle((86, 78, 1834, 1002), radius=28, outline=(66, 217, 255, 70), width=2)
    draw.text((140, 128), "CONTEXTSENTRY  /  IBM BOB 2.0", font=pil_font(MONO_BOLD, 24), fill=COLORS["cyan"])
    draw.text((140, 268), "Let Bob read the code.", font=pil_font(SANS_BOLD, 60), fill=COLORS["text"])
    draw.text((140, 344), "Never obey the code.", font=pil_font(SANS_BOLD, 60), fill=COLORS["cyan"])
    draw.text((144, 446), "Repository context firewall for AI-assisted software development", font=pil_font(SANS, 26), fill=COLORS["muted"])
    draw.rounded_rectangle((145, 552, 500, 606), radius=16, fill="#123a2e", outline=COLORS["green"], width=2)
    draw.text((170, 567), "5 LIFECYCLE EVENTS", font=pil_font(MONO_BOLD, 20), fill=COLORS["green"])
    draw.rounded_rectangle((525, 552, 830, 606), radius=16, fill="#0d3541", outline=COLORS["cyan"], width=2)
    draw.text((552, 567), "40 AUTOMATED TESTS", font=pil_font(MONO_BOLD, 20), fill=COLORS["cyan"])
    draw.rounded_rectangle((855, 552, 1215, 606), radius=16, fill="#2b2247", outline=COLORS["purple"], width=2)
    draw.text((880, 567), "HMAC AUDIT", font=pil_font(MONO_BOLD, 20), fill=COLORS["purple"])
    shield = [(145, 730), (285, 676), (425, 730), (410, 842), (285, 906), (160, 842)]
    draw.line(shield + [shield[0]], fill=COLORS["cyan"], width=7, joint="curve")
    draw.line((215, 790, 265, 842, 360, 746), fill=COLORS["green"], width=12, joint="curve")
    draw.text((145, 946), "DETECT  →  CONSTRAIN  →  PROVE", font=pil_font(MONO_BOLD, 21), fill=COLORS["muted"])
    card = (1100, 260, 1780, 810)
    draw.rounded_rectangle(card, radius=24, fill=(9, 18, 31, 235), outline=COLORS["line"], width=2)
    draw.rounded_rectangle((1100, 260, 1780, 322), radius=24, fill=(16, 31, 51, 255), outline=COLORS["line"], width=2)
    draw.rectangle((1100, 298, 1780, 322), fill=(16, 31, 51, 255))
    draw.ellipse((1130, 282, 1144, 296), fill=COLORS["red"])
    draw.ellipse((1156, 282, 1170, 296), fill=COLORS["amber"])
    draw.ellipse((1182, 282, 1196, 296), fill=COLORS["green"])
    draw.text((1230, 279), "contextsentry · enforcement trace", font=pil_font(MONO, 18), fill=COLORS["muted"])
    rows = [
        ("A", "Workspace read", "src/checkout.py · verified", "ALLOW", COLORS["green"]),
        ("!", "Untrusted instruction", "instructions.py · tainted", "DETECT", COLORS["amber"]),
        ("X", "Secret access", ".env · hard denied", "BLOCK", COLORS["red"]),
        ("X", "External exfiltration", "curl · tainted session", "BLOCK", COLORS["red"]),
        ("A", "Verified remediation", "safe workspace work", "ALLOW", COLORS["green"]),
    ]
    y = 372
    for icon, title, detail, status, color in rows:
        draw.ellipse((1140, y, 1190, y + 50), outline=color, width=2)
        draw.text((1156, y + 12), icon, font=pil_font(MONO_BOLD, 22), fill=color)
        draw.text((1220, y + 4), title, font=pil_font(SANS_BOLD, 22), fill=COLORS["text"])
        draw.text((1220, y + 33), detail, font=pil_font(MONO, 16), fill=COLORS["muted"])
        draw.text((1640, y + 17), status, font=pil_font(MONO_BOLD, 17), fill=color)
        draw.line((1140, y + 68, 1750, y + 68), fill=COLORS["line"], width=1)
        y += 82
    draw.text((170, 567), "5 LIFECYCLE EVENTS", font=pil_font(MONO_BOLD, 20), fill=COLORS["green"])
    draw.text((552, 567), "40 AUTOMATED TESTS", font=pil_font(MONO_BOLD, 20), fill=COLORS["cyan"])
    draw.text((880, 567), "HMAC AUDIT", font=pil_font(MONO_BOLD, 20), fill=COLORS["purple"])
    draw.text((140, 1018), "ibm-bob-contextsentry.onrender.com", font=pil_font(MONO, 18), fill=COLORS["muted"])
    image.convert("RGB").save(OUT / "contextsentry-cover.png", quality=95)


def pdf_color(value: str):
    return HexColor(COLORS[value])


def pdf_text(c: canvas.Canvas, value: str, x: float, y: float, size: float, color: str = "text", bold: bool = False, mono: bool = False) -> None:
    font = PDF_MONO_BOLD if mono and bold else PDF_MONO if mono else PDF_SANS_BOLD if bold else PDF_SANS
    c.setFont(font, size)
    c.setFillColor(pdf_color(color))
    c.drawString(x, y, value)


def pdf_lines(c: canvas.Canvas, value: str, x: float, y: float, max_width: float, size: float, leading: float, color: str = "muted", bold: bool = False, mono: bool = False) -> float:
    font = PDF_MONO_BOLD if mono and bold else PDF_MONO if mono else PDF_SANS_BOLD if bold else PDF_SANS
    words = value.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if pdfmetrics.stringWidth(candidate, font, size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    for line in lines:
        pdf_text(c, line, x, y, size, color, bold, mono)
        y -= leading
    return y


def pdf_box(c: canvas.Canvas, x: float, y: float, w: float, h: float, fill: str = "panel", stroke: str = "line", radius: float = 14) -> None:
    c.setFillColor(pdf_color(fill))
    c.setStrokeColor(pdf_color(stroke))
    c.setLineWidth(1)
    c.roundRect(x, y, w, h, radius, fill=1, stroke=1)


def pdf_polyline(c: canvas.Canvas, points: list[tuple[float, float]]) -> None:
    for start, end in zip(points, points[1:] + points[:1]):
        c.line(start[0], start[1], end[0], end[1])


def pdf_pill(c: canvas.Canvas, value: str, x: float, y: float, w: float, color: str) -> None:
    pdf_box(c, x, y, w, 28, fill=color, stroke=color, radius=14)
    c.setFillColor(pdf_color("bg"))
    c.setFont(PDF_MONO_BOLD, 10)
    c.drawCentredString(x + w / 2, y + 9, value)


def pdf_header(c: canvas.Canvas, kicker: str, title: str, subtitle: str = "") -> None:
    c.setFillColor(pdf_color("bg"))
    c.rect(0, 0, PDF_WIDTH, PDF_HEIGHT, fill=1, stroke=0)
    pdf_text(c, kicker.upper(), 54, PDF_HEIGHT - 54, 11, "cyan", True, True)
    pdf_text(c, title, 54, PDF_HEIGHT - 96, 28, "text", True)
    if subtitle:
        pdf_lines(c, subtitle, 54, PDF_HEIGHT - 122, PDF_WIDTH - 108, 12, 17, "muted")


def pdf_footer(c: canvas.Canvas, number: int) -> None:
    pdf_text(c, "CONTEXTSENTRY  /  IBM BOB 2.0", 54, 28, 9, "muted", False, True)
    pdf_text(c, f"{number:02d}", PDF_WIDTH - 76, 28, 9, "muted", True, True)


def draw_cover_page(c: canvas.Canvas) -> None:
    c.setFillColor(pdf_color("bg"))
    c.rect(0, 0, PDF_WIDTH, PDF_HEIGHT, fill=1, stroke=0)
    c.setStrokeColor(pdf_color("line"))
    c.setLineWidth(1)
    c.roundRect(34, 26, PDF_WIDTH - 68, PDF_HEIGHT - 52, 16, fill=0, stroke=1)
    pdf_text(c, "CONTEXTSENTRY  /  IBM BOB 2.0", 62, PDF_HEIGHT - 72, 11, "cyan", True, True)
    pdf_text(c, "Let Bob read the code.", 62, PDF_HEIGHT - 170, 30, "text", True)
    pdf_text(c, "Never obey the code.", 62, PDF_HEIGHT - 210, 30, "cyan", True)
    pdf_lines(c, "Repository context firewall for AI-assisted software development", 64, PDF_HEIGHT - 244, 460, 12, 16, "muted")
    pdf_pill(c, "5 LIFECYCLE EVENTS", 64, 250, 150, "green")
    pdf_pill(c, "40 AUTOMATED TESTS", 228, 250, 160, "cyan")
    pdf_pill(c, "HMAC-SHA256 AUDIT", 402, 250, 155, "purple")
    c.setStrokeColor(pdf_color("cyan"))
    c.setLineWidth(4)
    shield = [(64, 175), (132, 199), (200, 175), (190, 97), (132, 63), (74, 97)]
    pdf_polyline(c, shield)
    c.setStrokeColor(pdf_color("green"))
    c.setLineWidth(7)
    c.line(102, 135, 124, 113)
    c.line(124, 113, 166, 157)
    pdf_text(c, "DETECT  →  CONSTRAIN  →  PROVE", 64, 48, 10, "muted", True, True)
    pdf_box(c, 590, 120, 500, 350, "panel", "line", 14)
    pdf_box(c, 590, 442, 500, 28, "panel2", "line", 14)
    pdf_text(c, "contextsentry · enforcement trace", 600, 451, 9, "muted", False, True)
    rows = [("A", "Workspace read", "src/checkout.py · verified", "ALLOW", "green"), ("!", "Untrusted instruction", "instructions.py · tainted", "DETECT", "amber"), ("X", "Secret access", ".env · hard denied", "BLOCK", "red"), ("X", "External exfiltration", "curl · tainted session", "BLOCK", "red"), ("A", "Verified remediation", "safe workspace work", "ALLOW", "green")]
    y = 390
    for icon, title, detail, status, color in rows:
        c.setStrokeColor(pdf_color(color))
        c.circle(600, y + 8, 13, fill=0, stroke=1)
        pdf_text(c, icon, 596, y + 4, 9, color, True, True)
        pdf_text(c, title, 630, y + 12, 12, "text", True)
        pdf_text(c, detail, 630, y - 3, 8, "muted", False, True)
        pdf_text(c, status, 1015, y + 4, 9, color, True, True)
        c.setStrokeColor(pdf_color("line"))
        c.line(585, y - 20, 1100, y - 20)
        y -= 56
    pdf_text(c, "ibm-bob-contextsentry.onrender.com", 64, 28, 9, "muted", False, True)


def draw_problem(c: canvas.Canvas) -> None:
    pdf_header(c, "01 / problem", "Repositories are untrusted input", "Coding agents need broad context. That context can contain instructions aimed at the agent, not the user.")
    pdf_text(c, "A single file can carry", 64, 398, 17, "text", True)
    cards = [("PROMPT INJECTION", "Ignore previous instructions", "red"), ("SECRET ACCESS", "Read .env or private keys", "amber"), ("SUPPLY CHAIN", "Run a postinstall exfiltration script", "purple")]
    x = 64
    for title, detail, color in cards:
        pdf_box(c, x, 225, 250, 130, "panel", color)
        pdf_text(c, title, x + 18, 320, 10, color, True, True)
        pdf_lines(c, detail, x + 18, 292, 210, 13, 18, "text", True)
        x += 275
    pdf_box(c, 64, 92, 1110, 78, "panel2", "red")
    pdf_text(c, "The gap", 84, 138, 11, "red", True, True)
    pdf_text(c, "Repository evidence must never silently become machine authority.", 84, 110, 19, "text", True)
    pdf_footer(c, 2)


def draw_solution(c: canvas.Canvas) -> None:
    pdf_header(c, "02 / solution", "ContextSentry is the trust boundary", "Deterministic controls sit outside the model and run at every IBM Bob lifecycle event.")
    steps = [("01", "Bob event", "SessionStart\nPrompt / tool", "cyan"), ("02", "Policy engine", "Paths, commands,\nMCP, consent", "purple"), ("03", "Tool gate", "Allow safe work\nBlock high impact", "green"), ("04", "Audit chain", "Reason, taint,\nHMAC checkpoint", "amber")]
    x = 60
    for index, (num, title, detail, color) in enumerate(steps):
        pdf_box(c, x, 245, 200, 140, "panel", color)
        pdf_text(c, num, x + 16, 352, 10, color, True, True)
        pdf_text(c, title, x + 16, 318, 14, "text", True)
        pdf_lines(c, detail.replace("\n", " "), x + 16, 292, 168, 10, 14, "muted")
        if index < len(steps) - 1:
            pdf_text(c, "→", x + 205, 305, 20, "muted", True)
        x += 225
    pdf_box(c, 64, 95, 1110, 85, "panel2", "cyan")
    pdf_text(c, "DESIGN PRINCIPLE", 84, 152, 10, "cyan", True, True)
    pdf_text(c, "Repository content is evidence. It is never authority.", 84, 122, 18, "text", True)
    pdf_footer(c, 3)


def draw_demo(c: canvas.Canvas) -> None:
    pdf_header(c, "03 / demonstration", "A poisoned repository, contained", "The local simulation shows detection, taint propagation, fail-closed decisions, and a verifiable audit trail.")
    pdf_box(c, 64, 115, 500, 270, "panel", "line")
    pdf_text(c, "FINDINGS", 86, 352, 11, "cyan", True, True)
    findings = [("CRITICAL", "Instruction override", "red"), ("CRITICAL", "Secret access request", "red"), ("CRITICAL", "External exfiltration", "red"), ("HIGH", "Automatic postinstall script", "amber")]
    y = 315
    for severity, title, color in findings:
        pdf_text(c, severity, 88, y, 9, color, True, True)
        pdf_text(c, title, 190, y, 12, "text", True)
        c.setStrokeColor(pdf_color(color))
        c.line(86, y - 12, 540, y - 12)
        y -= 42
    pdf_box(c, 594, 115, 580, 270, "panel", "line")
    pdf_text(c, "POLICY OUTCOMES", 616, 352, 11, "purple", True, True)
    outcomes = [("ALLOW", "Workspace reads", "green"), ("DETECT", "Untrusted instruction content", "amber"), ("BLOCK", "Secret and external actions", "red"), ("SEAL", "HMAC audit checkpoint", "cyan")]
    y = 315
    for status, title, color in outcomes:
        pdf_pill(c, status, 616, y - 3, 82, color)
        pdf_text(c, title, 720, y + 6, 12, "text", True)
        y -= 48
    pdf_box(c, 64, 45, 1110, 48, "panel2", "green")
    pdf_text(c, "BENCHMARK", 86, 64, 9, "green", True, True)
    pdf_text(c, "5/5 seeded attack signals detected", 220, 64, 14, "text", True)
    pdf_text(c, "safe fixture: 0 findings", 650, 64, 12, "muted")
    pdf_footer(c, 4)


def draw_bob(c: canvas.Canvas) -> None:
    pdf_header(c, "04 / IBM BOB", "Bob is the engineering partner", "ContextSentry runs inside Bob's real lifecycle and exposes local read-only MCP tools.")
    pdf_text(c, "REAL WORKFLOW", 64, 395, 11, "cyan", True, True)
    events = [("1", "SessionStart", "scan trusted entry points"), ("2", "UserPromptSubmit", "block direct attacks"), ("3", "PreToolUse", "validate every action"), ("4", "PostToolUse", "propagate taint"), ("5", "Stop", "seal the checkpoint")]
    y = 355
    for num, title, detail in events:
        c.setStrokeColor(pdf_color("cyan"))
        c.circle(78, y + 5, 15, fill=0, stroke=1)
        pdf_text(c, num, 74, y + 1, 10, "cyan", True, True)
        pdf_text(c, title, 112, y + 10, 13, "text", True)
        pdf_text(c, detail, 330, y + 10, 12, "muted")
        y -= 45
    pdf_box(c, 690, 140, 480, 240, "panel", "purple")
    pdf_text(c, "LOCAL MCP TOOLS", 714, 348, 11, "purple", True, True)
    tools = ["scan_path", "scan_text", "get_audit_summary", "check_command"]
    y = 305
    for tool in tools:
        pdf_pill(c, tool, 714, y, 190, "cyan" if tool != "get_audit_summary" else "green")
        y -= 40
    pdf_text(c, "No external AI API required", 714, 175, 12, "muted")
    pdf_footer(c, 5)


def draw_evidence(c: canvas.Canvas) -> None:
    pdf_header(c, "05 / evidence", "Proof that survives the demo", "The repository ships with automated checks, a reproducible fixture benchmark, and real Bob session evidence.")
    metrics = [("40", "automated tests", "green"), ("5/5", "attack signals", "cyan"), ("0", "safe-fixture findings", "purple"), ("HMAC", "audit integrity", "amber")]
    x = 64
    for value, label, color in metrics:
        pdf_box(c, x, 300, 200, 95, "panel", color)
        pdf_text(c, value, x + 16, 352, 24, color, True, True)
        pdf_text(c, label, x + 16, 322, 9, "muted", False, True)
        x += 225
    pdf_box(c, 64, 105, 520, 135, "panel2", "line")
    pdf_text(c, "AUDIT SAMPLE", 86, 210, 10, "cyan", True, True)
    pdf_text(c, "sequence 140", 86, 182, 12, "text", True, True)
    pdf_text(c, "decision  block", 86, 158, 12, "red", True, True)
    pdf_text(c, "reason     TAINTED_EXECUTION", 86, 134, 10, "muted", False, True)
    pdf_text(c, "chain      valid", 86, 112, 12, "green", True, True)
    pdf_box(c, 614, 105, 560, 135, "panel2", "line")
    pdf_text(c, "PUBLIC ARTEFACTS", 636, 210, 10, "purple", True, True)
    pdf_text(c, "github.com/Weejay13/IBM-Bob-ContextSentry", 636, 180, 10, "cyan", False, True)
    pdf_text(c, "ibm-bob-contextsentry.onrender.com", 636, 154, 10, "cyan", False, True)
    pdf_text(c, "bob_sessions/  ·  real task history + screenshot", 636, 128, 9, "muted")
    c.linkURL("https://github.com/Weejay13/IBM-Bob-ContextSentry", (636, 176, 1080, 192), relative=0, thickness=0)
    c.linkURL("https://ibm-bob-contextsentry.onrender.com", (636, 150, 1000, 166), relative=0, thickness=0)
    pdf_footer(c, 6)


def draw_close(c: canvas.Canvas) -> None:
    pdf_header(c, "06 / close", "Make repository context safe to use", "ContextSentry helps teams keep the productivity of coding agents without granting untrusted files authority over the machine.")
    pdf_text(c, "Let Bob read the code.", 64, 375, 30, "text", True)
    pdf_text(c, "Never obey the code.", 64, 327, 30, "cyan", True)
    pdf_box(c, 64, 145, 1110, 105, "panel2", "cyan")
    pdf_text(c, "DETECT", 90, 210, 12, "cyan", True, True)
    pdf_text(c, "→", 210, 208, 18, "muted", True)
    pdf_text(c, "CONSTRAIN", 270, 210, 12, "purple", True, True)
    pdf_text(c, "→", 450, 208, 18, "muted", True)
    pdf_text(c, "PROVE", 510, 210, 12, "green", True, True)
    pdf_text(c, "A safer, reviewable operating loop for AI-assisted development.", 90, 172, 16, "text", True)
    pdf_text(c, "Demo: https://ibm-bob-contextsentry.onrender.com", 64, 92, 11, "cyan", False, True)
    pdf_text(c, "Repository: https://github.com/Weejay13/IBM-Bob-ContextSentry", 64, 68, 10, "muted", False, True)
    c.linkURL("https://ibm-bob-contextsentry.onrender.com", (64, 88, 500, 104), relative=0, thickness=0)
    c.linkURL("https://github.com/Weejay13/IBM-Bob-ContextSentry", (64, 64, 560, 80), relative=0, thickness=0)
    pdf_footer(c, 7)


def make_pdf() -> None:
    path = OUT / "contextsentry-slides.pdf"
    c = canvas.Canvas(str(path), pagesize=(PDF_WIDTH, PDF_HEIGHT), pageCompression=1)
    c.setTitle("ContextSentry — IBM Bob 2.0")
    c.setAuthor("ContextSentry")
    draw_cover_page(c)
    c.showPage()
    draw_problem(c)
    c.showPage()
    draw_solution(c)
    c.showPage()
    draw_demo(c)
    c.showPage()
    draw_bob(c)
    c.showPage()
    draw_evidence(c)
    c.showPage()
    draw_close(c)
    c.save()


if __name__ == "__main__":
    make_cover()
    make_pdf()
    print(OUT / "contextsentry-cover.png")
    print(OUT / "contextsentry-slides.pdf")
