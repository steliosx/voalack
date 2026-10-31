#!/usr/bin/env python3
"""Generate Voalack's factual editorial diagrams without external dependencies.

Run: python3 generate_diagrams.py
Optional PNG rendering: python3 generate_diagrams.py --render

Canonical design sources, including the seven-state outcome contract:
design/DESIGN.md (repository-relative)
design/DESIGN_AMENDMENTS.md (repository-relative)

SVGs contain only original vector geometry and text. They use a local font
stack; no fonts, images, stylesheets or scripts are fetched. Output is stable
across runs. PNG rendering, when requested, uses the installed Inkscape.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from html import escape
from pathlib import Path
from xml.etree import ElementTree as ET


OUT = Path(__file__).resolve().parent
INK = "#182033"
COBALT = "#5363F0"
PAPER = "#F6F7FB"
WHITE = "#FFFFFF"
MUTED = "#555E75"
LINE = "#CAD0E2"
LAVENDER = "#E9ECFF"
FONT = "DejaVu Sans, Arial, sans-serif"


class SVG:
    def __init__(self, width: int, height: int, title: str, description: str):
        self.width = width
        self.height = height
        self.parts = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
            f"<title id=\"title\">{escape(title)}</title>",
            f"<desc id=\"desc\">{escape(description)}</desc>",
            "<defs>",
            f'<marker id="arrow-cobalt" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="9" markerHeight="9" orient="auto-start-reverse" markerUnits="userSpaceOnUse">'
            f'<path d="M 0 0 L 10 5 L 0 10 Z" fill="{COBALT}"/></marker>',
            f'<marker id="arrow-ink" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="9" markerHeight="9" orient="auto-start-reverse" markerUnits="userSpaceOnUse">'
            f'<path d="M 0 0 L 10 5 L 0 10 Z" fill="{INK}"/></marker>',
            "</defs>",
            f'<rect width="{width}" height="{height}" fill="{PAPER}"/>',
        ]

    def rect(self, x, y, width, height, fill=WHITE, stroke=None, radius=14, stroke_width=2):
        edge = f' stroke="{stroke}" stroke-width="{stroke_width}"' if stroke else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}"{edge}/>'
        )

    def text(self, x, y, value, size=22, fill=INK, weight=400, anchor="start", tracking=None):
        letter_spacing = f' letter-spacing="{tracking}"' if tracking is not None else ""
        self.parts.append(
            f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{letter_spacing}>'
            f'{escape(value)}</text>'
        )

    def path(self, d, stroke=COBALT, width=3, arrow=False, fill="none", dash=None):
        marker = f' marker-end="url(#arrow-{ "ink" if stroke == INK else "cobalt" })"' if arrow else ""
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<path d="{d}" fill="{fill}" stroke="{stroke}" stroke-width="{width}" '
            f'stroke-linecap="round" stroke-linejoin="round"{marker}{dash_attr}/>'
        )

    def circle(self, cx, cy, radius, fill="none", stroke=COBALT, width=3):
        self.parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{width}"/>'
        )

    def save(self, filename):
        result = "\n".join([*self.parts, "</svg>", ""])
        document = ET.fromstring(result)
        ns = {"s": "http://www.w3.org/2000/svg"}
        assert document.find("s:title", ns) is not None
        assert document.find("s:desc", ns) is not None
        assert not document.findall(".//s:image", ns)
        assert not document.findall(".//s:script", ns)
        assert all(float(t.attrib["font-size"]) >= 22 for t in document.findall(".//s:text", ns))
        destination = OUT / filename
        destination.write_text(result, encoding="utf-8")
        return destination


def acknowledgement_flow():
    svg = SVG(
        1280,
        760,
        "Planned acknowledgement flow",
        "Planned architecture, not a claim of implemented runtime. The existing PowerShell alarm feed "
        "runs from ONE to Alerta. Only an authorised human single-alert ACK triggers the proposed local "
        "PostgreSQL transaction, which captures the Alerta ACK and a durable candidate together. "
        "Candidate verification and an exact approved binding precede a separate ONE session owner "
        "worker writing the permitted source ACK. The worker then reads back source state and records "
        "an outcome note in Alerta. ONE-origin ACK mirroring is outside the current scope. Design agreed; "
        "implementation and live qualification remain open.",
    )
    svg.text(48, 47, "PLANNED ARCHITECTURE", 22, COBALT, 700, tracking=1.6)
    svg.text(48, 102, "Planned acknowledgement flow", 40, INK, 700)
    svg.text(48, 142, "An explicit human action starts the proposed delivery path.", 24, MUTED)

    # Two systems above a deliberately separate proposed delivery path.
    svg.rect(48, 182, 350, 164, WHITE, LINE)
    svg.text(72, 226, "Alerta", 30, INK, 700)
    svg.text(72, 270, "User-visible local ACK", 22)
    svg.text(72, 307, "Read-back outcome note", 22)

    svg.rect(886, 182, 346, 164, INK)
    svg.text(910, 226, "ONE", 30, WHITE, 700)
    svg.text(910, 270, "Source alarm state", 22, WHITE)
    svg.text(910, 307, "Source ACK state", 22, WHITE)

    # The alarm feed already exists; its direction is only ONE -> Alerta.
    svg.text(642, 229, "Existing PowerShell", 22, INK, 700, "middle")
    svg.text(642, 258, "alarm feed", 22, INK, 400, "middle")
    svg.path("M 877 281 H 407", INK, arrow=True)

    # The authorised human action is the sole local ACK trigger shown.
    svg.text(64, 394, "Only authorised human", 22, INK, 700)
    svg.text(64, 424, "single-alert ACK", 22, INK)
    svg.path("M 376 355 V 477", arrow=True)

    # The worker returns read-back evidence and an outcome note to Alerta.
    svg.path("M 903 477 V 446 H 427 V 323 H 407", arrow=True)
    svg.text(653, 429, "Evidence + outcome note", 22, COBALT, 700, "middle")

    # Source mutation occurs before read-back. Separate arrows show each direction.
    svg.path("M 1208 477 V 355", arrow=True)
    svg.text(1190, 408, "ACK", 22, COBALT, 700, "end")
    svg.path("M 946 355 V 477", arrow=True)
    svg.text(965, 393, "Then", 24, COBALT)
    svg.text(965, 422, "read-back", 22, COBALT, 700)

    svg.rect(48, 486, 350, 166, COBALT)
    svg.text(72, 527, "Local transaction", 27, WHITE, 700)
    svg.text(72, 559, "PostgreSQL · atomic commit", 22, WHITE)
    svg.text(72, 599, "Alerta ACK + durable", 22, WHITE)
    svg.text(72, 628, "candidate saved together", 22, WHITE)

    svg.rect(502, 486, 280, 166, WHITE, LINE)
    svg.text(526, 527, "Verification", 27, INK, 700)
    svg.text(526, 568, "Candidate checks", 22)
    svg.text(526, 598, "+ exact approved", 22)
    svg.text(526, 628, "binding", 22, INK, 700)

    svg.rect(886, 486, 346, 166, INK)
    svg.text(910, 527, "ONE ACK worker", 27, WHITE, 700)
    svg.text(910, 568, "Separate session owner", 22, WHITE)
    svg.text(910, 598, "Writes permitted ACK", 22, WHITE)
    svg.text(910, 628, "Then reads back", 22, WHITE)

    svg.text(450, 550, "verify", 22, COBALT, 700, "middle")
    svg.path("M 407 570 H 493", arrow=True)
    svg.text(834, 550, "pass", 22, COBALT, 700, "middle")
    svg.path("M 791 570 H 877", arrow=True)

    svg.circle(60, 696, 11, stroke=INK, width=2)
    svg.path("M 52 704 L 68 688", INK, width=2)
    svg.text(84, 704, "ONE-origin ACK mirroring is outside the current scope.", 22, INK, 700)
    svg.text(48, 741, "Design agreed · implementation and live qualification remain open", 22, MUTED)
    return svg.save("planned-acknowledgement-flow.svg")


def outcomes():
    svg = SVG(
        1280,
        1680,
        "Every outcome has a meaning: seven acknowledgement states",
        "Seven operator-facing acknowledgement states from the canonical design contract. "
        "LOCAL_ACK: Alerta changed locally; this never means remote success. Noneligible historical "
        "actions can remain local-only. QUEUED: a local transaction captured a candidate; verification "
        "and policy checks precede any remote access. REMOTE_CONFIRMED: the exact permitted target "
        "and occurrence, with expected ACK evidence, were observed under the qualified contract; "
        "no new send. ALREADY_ACKED: the source was already ACKed; make no attribution claim and "
        "do not re-ACK to add or overwrite a comment. BLOCKED: a named policy, identity, configuration "
        "or qualification reason prevents sending; no send. SUPERSEDED: a new approved binding or "
        "generation invalidated work before send; retain evidence, and never erase a possibly-sent "
        "old attempt. UNCERTAIN: mutation may have reached ONE, or its result cannot be bound safely; "
        "preserve the attempt and suspend affected mutation ownership. Read-only reconciliation only. "
        "Local acknowledgement alone does not confirm delivery.",
    )
    svg.text(48, 49, "PLANNED ACKNOWLEDGEMENT OUTCOMES", 22, COBALT, 700, tracking=1.6)
    svg.text(48, 106, "Every outcome has a meaning", 40, INK, 700)
    svg.text(48, 148, "Seven operator-facing states · meaning and allowed next step", 24, MUTED)

    def icon(cx, cy, kind, color):
        svg.circle(cx, cy, 20, stroke=color)
        if kind == "local":
            svg.rect(cx - 6, cy - 6, 12, 12, color, radius=2)
        elif kind == "queued":
            svg.path(f"M {cx} {cy - 12} V {cy} L {cx + 9} {cy + 6}", color)
        elif kind == "confirmed":
            svg.path(f"M {cx - 10} {cy} L {cx - 3} {cy + 7} L {cx + 11} {cy - 8}", color)
        elif kind == "already":
            svg.path(f"M {cx - 10} {cy} H {cx + 10}", color)
        elif kind == "blocked":
            svg.path(f"M {cx - 13} {cy + 13} L {cx + 13} {cy - 13}", color)
        elif kind == "superseded":
            svg.path(f"M {cx - 11} {cy} H {cx + 10} M {cx + 3} {cy - 7} L {cx + 10} {cy} L {cx + 3} {cy + 7}", color)
        elif kind == "uncertain":
            svg.path(f"M {cx} {cy - 11} V {cy + 2}", color)
            svg.circle(cx, cy + 10, 1.6, fill=color, stroke=color, width=1)

    def panel(x, y, state, meaning, next_step, background, kind):
        # Fixed card geometry keeps exact state identifiers unbroken and readable.
        foreground = WHITE if background == COBALT else INK
        accent = WHITE if background == COBALT else COBALT
        svg.rect(x, y, 580, 332, background, LINE if background == WHITE else None, radius=18)
        svg.text(x + 32, y + 53, state, 28, foreground, 700)
        icon(x + 529, y + 45, kind, accent)
        svg.text(x + 32, y + 97, "MEANING", 22, accent, 700, tracking=1)
        for index, line in enumerate(meaning):
            svg.text(x + 32, y + 134 + 32 * index, line, 24, foreground)
        svg.text(x + 32, y + 237, "NEXT STEP", 22, accent, 700, tracking=1)
        for index, line in enumerate(next_step):
            svg.text(x + 32, y + 274 + 32 * index, line, 24, foreground)

    # Read in canonical row order. No arrows imply a mandatory state progression.
    panel(
        48, 194, "LOCAL_ACK",
        ["Alerta changed locally.", "This never means remote success."],
        ["Noneligible historical actions", "can remain local-only."],
        WHITE, "local",
    )
    panel(
        652, 194, "QUEUED",
        ["Local transaction captured", "a candidate."],
        ["Verify and check policy before", "any remote access."],
        LAVENDER, "queued",
    )
    panel(
        48, 550, "REMOTE_CONFIRMED",
        ["Exact permitted target/occurrence", "+ expected ACK evidence observed", "under the qualified contract."],
        ["No new send."],
        COBALT, "confirmed",
    )
    panel(
        652, 550, "ALREADY_ACKED",
        ["Source was already ACKed.", "No attribution claim."],
        ["Do not re-ACK to add or", "overwrite a comment."],
        WHITE, "already",
    )
    panel(
        48, 906, "BLOCKED",
        ["Named policy, identity, configuration", "or qualification reason."],
        ["No send."],
        WHITE, "blocked",
    )
    panel(
        652, 906, "SUPERSEDED",
        ["New approved binding/generation", "invalidated work before send."],
        ["Retain evidence. A possibly-sent", "old attempt cannot be erased."],
        LAVENDER, "superseded",
    )

    # Uncertain source effects require an especially visible mutation hold.
    svg.rect(48, 1262, 1184, 272, INK, radius=18)
    svg.text(80, 1315, "UNCERTAIN", 28, WHITE, 700)
    icon(1181, 1307, "uncertain", WHITE)
    svg.text(80, 1361, "MEANING", 22, WHITE, 700, tracking=1)
    svg.text(80, 1400, "Mutation may have reached ONE,", 24, WHITE)
    svg.text(80, 1432, "or its result cannot be bound safely.", 24, WHITE)
    svg.text(684, 1361, "NEXT STEP", 22, WHITE, 700, tracking=1)
    svg.text(684, 1400, "Preserve the attempt and suspend", 24, WHITE)
    svg.text(684, 1432, "affected mutation ownership.", 24, WHITE)
    svg.text(684, 1485, "Read-only reconciliation only.", 24, WHITE, 700)

    svg.rect(48, 1570, 1184, 76, WHITE, LINE, radius=14)
    svg.text(640, 1617, "Local acknowledgement alone does not confirm delivery.", 26, INK, 700, "middle")
    return svg.save("acknowledgement-outcomes.svg")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render", action="store_true", help="also render PNG previews using Inkscape")
    args = parser.parse_args()
    outputs = [acknowledgement_flow(), outcomes()]
    for path in outputs:
        print(path)
    if args.render:
        inkscape = shutil.which("inkscape")
        if not inkscape:
            raise SystemExit("Inkscape is required for --render but was not found.")
        for path in outputs:
            preview = path.with_suffix(".png")
            subprocess.run(
                [inkscape, str(path), "--export-type=png", f"--export-filename={preview}", "--export-width=1280"],
                check=True,
                capture_output=True,
                text=True,
            )
            print(preview)


if __name__ == "__main__":
    main()
