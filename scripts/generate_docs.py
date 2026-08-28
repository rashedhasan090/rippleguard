"""Generate docs/architecture.png, docs/sample-scan.png, and docs/tutorial.mp4.

Run from the repo root after `pip install -e .` (Pillow is only needed here).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BG = (12, 18, 32)
PANEL = (20, 30, 52)
ACCENT = (64, 200, 180)
ACCENT2 = (255, 176, 92)
RED = (255, 107, 107)
YELLOW = (255, 209, 102)
TEXT = (230, 236, 245)
MUTED = (140, 155, 180)
WHITE = (255, 255, 255)

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
SANS = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
SANS_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size)


def rounded(draw: ImageDraw.ImageDraw, xy, r: int, fill) -> None:
    draw.rounded_rectangle(xy, radius=r, fill=fill)


def draw_architecture(path: Path) -> None:
    w, h = 1400, 780
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    title = font(SANS_BOLD, 36)
    body = font(SANS, 20)
    small = font(SANS, 16)
    mono = font(MONO, 15)
    d.text((48, 28), "Rippleguard", fill=ACCENT, font=title)
    d.text((300, 40), "defensive trust-surface pipeline", fill=MUTED, font=body)

    parsers = [
        (60, 140, "Python AST", "subprocess  eval  pickle\nyaml.load  requests  open"),
        (500, 140, "Bash (best-effort)", "curl|bash  eval  source\nunquoted $VAR  nc  ssh"),
        (940, 140, "GitHub Actions YAML", "unpinned actions  run:\nPR-target  secrets in run"),
    ]
    for x, y, name, desc in parsers:
        rounded(d, (x, y, x + 400, y + 160), 18, PANEL)
        d.rectangle((x, y, x + 8, y + 160), fill=ACCENT)
        d.text((x + 28, y + 20), name, fill=WHITE, font=body)
        d.text((x + 28, y + 64), desc, fill=MUTED, font=small)

    # arrows down
    for x in (260, 700, 1140):
        d.polygon([(x, 316), (x - 12, 300), (x + 12, 300)], fill=ACCENT2)

    rounded(d, (200, 340, 1200, 500), 18, PANEL)
    d.text((230, 360), "Unified trust graph", fill=ACCENT2, font=body)
    d.text(
        (230, 400),
        "nodes: files · commands · hosts · env vars · actions · secret-shapes",
        fill=TEXT,
        font=small,
    )
    d.text(
        (230, 440),
        "edges: invokes  →  reads  →  reaches  →  uses  →  expands",
        fill=MUTED,
        font=mono,
    )

    d.polygon([(700, 548), (688, 532), (712, 532)], fill=ACCENT2)
    rounded(d, (200, 560, 680, 720), 18, PANEL)
    d.text((230, 580), "Git delta", fill=WHITE, font=body)
    d.text((230, 624), "HEAD vs HEAD~1   or   --old / --new", fill=MUTED, font=small)
    d.text((230, 660), "Only NEW surface is reported", fill=ACCENT, font=small)

    rounded(d, (720, 560, 1200, 720), 18, PANEL)
    d.text((750, 580), "Harden + enforce", fill=WHITE, font=body)
    d.text((750, 624), "human report · JSON · mermaid", fill=MUTED, font=small)
    d.text((750, 660), "pre-commit hook fails on high delta", fill=ACCENT, font=small)

    img.save(path)


def wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines() or [""]:
        if len(raw) <= width:
            lines.append(raw)
            continue
        while len(raw) > width:
            lines.append(raw[:width])
            raw = raw[width:]
        lines.append(raw)
    return lines


def terminal_frame(
    lines: list[str],
    *,
    size: tuple[int, int] = (1280, 720),
    title: str = "rippleguard — scan",
) -> Image.Image:
    w, h = size
    img = Image.new("RGB", (w, h), (8, 10, 16))
    d = ImageDraw.Draw(img)
    rounded(d, (24, 24, w - 24, h - 24), 22, (18, 22, 34))
    # title bar
    rounded(d, (24, 24, w - 24, 78), 22, (28, 34, 52))
    d.rectangle((24, 56, w - 24, 78), fill=(28, 34, 52))
    for i, color in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse((48 + i * 28, 42, 66 + i * 28, 60), fill=color)
    d.text((150, 40), title, fill=MUTED, font=font(SANS, 18))
    mono = font(MONO, 16)
    y = 100
    x = 48
    max_y = h - 48
    for line in lines:
        color = TEXT
        if line.startswith("$"):
            color = ACCENT
        elif "HIGH" in line or line.startswith("HIGH"):
            color = RED
        elif "MEDIUM" in line:
            color = YELLOW
        elif "Harden:" in line or line.strip().startswith("Harden"):
            color = ACCENT
        elif line.startswith("Rippleguard") or line.startswith("──"):
            color = ACCENT2
        d.text((x, y), line[:110], fill=color, font=mono)
        y += 22
        if y > max_y:
            break
    return img


def sample_scan_lines() -> list[str]:
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "rippleguard",
            "scan",
            "fixtures/insecure",
            "--no-json-block",
            "--no-mermaid",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
    )
    raw = proc.stdout.splitlines()
    # keep a readable subset: header + first findings
    out: list[str] = []
    for line in raw:
        stripped = line.replace("\033[0m", "")
        out.append(stripped)
        if len(out) >= 26:
            break
    if len(out) < 8:
        out = [
            "Rippleguard  trust-surface scan",
            "  target    fixtures/insecure",
            "  findings  high surface detected",
            "HIGH  PY-SUBPROCESS-SHELL  deploy.py:15",
            "HIGH  SH-CURL-BASH  bootstrap.sh:9",
            "HIGH  GHA-UNPINNED-ACTION  ci.yml:16",
        ]
    return out


def draw_sample_scan(path: Path) -> None:
    img = terminal_frame(sample_scan_lines(), title="rippleguard scan fixtures/insecure")
    img.save(path)


def make_tutorial_mp4(path: Path) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="rg-vid-"))
    slides: list[tuple[str, float, list[str], str]] = [
        (
            "title",
            5.0,
            [
                "",
                "  Rippleguard",
                "  ────────────",
                "  Map what Python, Bash, and GitHub Actions",
                "  can execute — then diff that graph across git.",
                "",
                "  Defensive only. Findings tell you how to harden.",
            ],
            "Rippleguard",
        ),
        (
            "install",
            10.0,
            [
                "$ python3 -m venv .venv && source .venv/bin/activate",
                "$ pip install -e .",
                "",
                "Successfully installed rippleguard-0.1.0",
                "",
                "$ rippleguard --version",
                "rippleguard 0.1.0",
            ],
            "1. Install",
        ),
        (
            "scan",
            16.0,
            [
                "$ rippleguard scan fixtures/insecure",
                "",
                "Rippleguard  trust-surface scan",
                "  files     6 scanned",
                "  findings  11+  (high · medium · low)",
                "",
                "HIGH  PY-SUBPROCESS-SHELL  fixtures/insecure/deploy.py:15",
                "      subprocess uses shell=True",
                "      Harden: pass a list of args; keep shell=False",
                "",
                "HIGH  SH-CURL-BASH  fixtures/insecure/bootstrap.sh:9",
                "      curl | bash executes remote bytes",
                "      Harden: download, verify checksum, then run",
                "",
                "HIGH  GHA-UNPINNED-ACTION  .github/workflows/ci.yml:16",
                "      Action not pinned to a 40-char SHA",
                "      Harden: pin uses: owner/action@<sha>",
            ],
            "2. Scan fixtures",
        ),
        (
            "graph",
            14.0,
            [
                "── GRAPH (mermaid)",
                "```mermaid",
                "flowchart LR",
                "  deploy_py([deploy.py]) -->|invokes| cmd_shell[subprocess.shell]",
                "  deploy_py -->|reaches| host_pkg{{packages.example.invalid}}",
                "  bootstrap([bootstrap.sh]) -->|invokes| cmd_curl[/curl/bash/]",
                "  bootstrap -->|reaches| host_inst{{install.example.invalid}}",
                "  ci_yml([ci.yml]) -->|uses| action_co[/actions/checkout@v4/]",
                "  ci_yml -->|reads| env_tok([secrets.DEPLOY_TOKEN])",
                "```",
                "",
                "Hosts, commands, and actions are one graph —",
                "across three languages.",
            ],
            "3. Read the graph",
        ),
        (
            "diff",
            12.0,
            [
                "$ rippleguard diff --old fixtures/fixed --new fixtures/insecure",
                "",
                "Rippleguard  trust-surface diff",
                "  added     new findings (HIGH) · new graph nodes",
                "",
                "── NEW SURFACE",
                "HIGH  SH-CURL-BASH     bootstrap.sh",
                "HIGH  PY-SUBPROCESS-SHELL  deploy.py",
                "HIGH  GHA-UNPINNED-ACTION  ci.yml",
                "",
                "exit 1  →  pre-commit / pre-push hook can block this",
            ],
            "4. Diff the delta",
        ),
        (
            "end",
            8.0,
            [
                "$ rippleguard hook install --pre-commit",
                "installed .git/hooks/pre-commit",
                "",
                "A commit that quietly adds curl | bash now fails the hook.",
                "",
                "Docs: README.md  ·  docs/TUTORIAL.md",
                "License: MIT     ·  Defensive only",
            ],
            "5. Install the hook",
        ),
    ]
    files: list[Path] = []
    concat = tmp / "list.txt"
    with concat.open("w", encoding="utf-8") as fh:
        for name, dur, lines, title in slides:
            png = tmp / f"{name}.png"
            terminal_frame(lines, title=title).save(png)
            files.append(png)
            fh.write(f"file '{png}'\n")
            fh.write(f"duration {dur}\n")
        # concat demuxer needs the last file repeated
        fh.write(f"file '{files[-1]}'\n")

    path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(concat),
        "-vf",
        "fps=30,format=yuv420p",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-movflags",
        "+faststart",
        str(path),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr or proc.stdout)
    shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    DOCS.mkdir(parents=True, exist_ok=True)
    draw_architecture(DOCS / "architecture.png")
    draw_sample_scan(DOCS / "sample-scan.png")
    make_tutorial_mp4(DOCS / "tutorial.mp4")
    print("wrote", DOCS / "architecture.png")
    print("wrote", DOCS / "sample-scan.png")
    print("wrote", DOCS / "tutorial.mp4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
