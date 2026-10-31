#!/usr/bin/env python3
"""Reproduce Voalack's original Handoff vector identity.

Core generation uses only Python's standard library. The mark is two explicit
filled paths. Every letter is a purpose-drawn outline; no fonts are loaded,
traced or embedded. Optional --render requires local Inkscape and Pillow.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
COBALT = "#5363F0"
PERIWINKLE = "#8B96FF"
INK = "#182033"
PAPER = "#F6F7FB"
WHITE = "#FFFFFF"
MARK_SIZE = 320
LOGO_WIDTH = 1576
LOGO_HEIGHT = 320

# Rounded receiver OPEN LEFT. Its outer right corners have an 88-unit radius;
# inner right corners have a 24-unit radius. The arm and wall weight is 72.
# Arm tips are semicircles of radius 36. All curve coordinates are explicit.
RECEIVER_PATH = (
    "M112 0H232C280.601 0 320 39.399 320 88V232"
    "C320 280.601 280.601 320 232 320H112"
    "C92.118 320 76 303.882 76 284"
    "C76 264.118 92.118 248 112 248H224"
    "C237.255 248 248 237.255 248 224V96"
    "C248 82.745 237.255 72 224 72H112"
    "C92.118 72 76 55.882 76 36C76 16.118 92.118 0 112 0Z"
)

# Incoming capsule is independent of the receiver: 184 x 72, radius 36.
# Its right edge is 64 units clear of the receiver's inner wall at x=248.
HANDOFF_PATH = (
    "M36 124H148C167.882 124 184 140.118 184 160"
    "C184 179.882 167.882 196 148 196H36"
    "C16.118 196 0 179.882 0 160C0 140.118 16.118 124 36 124Z"
)

# Purpose-drawn lowercase wordmark. The shared family characteristics are a
# substantial weight, a single-storey 'a', and a compact circular period.
# These contours are geometry, not a dependency on a third-party typeface.
GLYPHS = {
    "v": "M0 74H46L83 174L119 74H163L104 222H63Z",
    "o": (
        "M81 71C130 71 163 102 163 148C163 194 130 225 81 225"
        "C32 225 0 194 0 148C0 102 32 71 81 71Z"
        "M81 110C58 110 42 125 42 148C42 171 58 186 81 186"
        "C104 186 121 171 121 148C121 125 104 110 81 110Z"
    ),
    "a": (
        "M73 71C91 71 106 78 118 91V74H160V222H118V207"
        "C106 219 91 225 72 225C29 225 0 194 0 149"
        "C0 104 29 71 73 71Z"
        "M81 110C59 110 43 126 43 149C43 172 59 187 81 187"
        "C103 187 119 172 119 149C119 126 103 110 81 110Z"
    ),
    "l": "M0 0H43V222H0Z",
    "c": (
        "M83 71C109 71 131 80 146 98L118 125"
        "C108 115 96 110 83 110C60 110 43 126 43 149"
        "C43 172 60 187 83 187C97 187 110 181 120 170L147 197"
        "C131 216 109 225 82 225C34 225 0 194 0 149"
        "C0 103 35 71 83 71Z"
    ),
    "k": "M0 0H43V125L88 74H141L85 138L147 222H96L56 164L43 178V222H0Z",
}
LETTER_PLACEMENTS = [
    ("v", 0), ("o", 171), ("a", 357), ("l", 542),
    ("a", 610), ("c", 792), ("k", 962),
]
WORD_ORIGIN = (384, 48)
DOT_CENTER = (1550, 244)
DOT_RADIUS = 26


def mark(fill: str, capsule_fill: str | None = None) -> str:
    return ('<g>'
            f'<path fill="{fill}" d="{RECEIVER_PATH}"/>'
            f'<path fill="{capsule_fill or fill}" d="{HANDOFF_PATH}"/>'
            '</g>')


def svg(title: str, width: int, height: int, body: str, description: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'width="{width}" height="{height}" role="img" '
            'aria-labelledby="title" aria-describedby="description">\n'
            f'<title id="title">{title}</title>\n'
            f'<desc id="description">{description}</desc>\n'
            f'{body}\n</svg>\n')


def write(name: str, content: str) -> None:
    (ROOT / name).write_text(content, encoding="utf-8")


def logo_body(symbol_fill: str, capsule_fill: str, letters_fill: str, dot_fill: str) -> str:
    letters = ''.join(
        f'<path transform="translate({x} 0)" d="{GLYPHS[letter]}"/>'
        for letter, x in LETTER_PLACEMENTS
    )
    return (mark(symbol_fill, capsule_fill) + '\n'
            f'<g transform="translate({WORD_ORIGIN[0]} {WORD_ORIGIN[1]})" '
            f'fill="{letters_fill}" fill-rule="evenodd">{letters}</g>\n'
            f'<circle cx="{DOT_CENTER[0]}" cy="{DOT_CENTER[1]}" '
            f'r="{DOT_RADIUS}" fill="{dot_fill}"/>')


ASSETS = {
    'voalack-mark.svg': 'Cobalt receiver and ink capsule; light surfaces.',
    'voalack-mark-dark.svg': 'Periwinkle receiver and off-white capsule; dark surfaces.',
    'voalack-mark-mono.svg': 'Ink mark for light surfaces and one-colour output.',
    'voalack-mark-white.svg': 'White mark for dark surfaces and reversed output.',
    'voalack-logo-light.svg': 'Cobalt receiver and period, ink capsule and letters; light surfaces.',
    'voalack-logo-dark.svg': 'Periwinkle receiver and period, off-white capsule and letters; dark surfaces.',
    'voalack-logo-mono.svg': 'All-ink horizontal lockup; one-colour output.',
    'voalack-logo-white.svg': 'All-white horizontal lockup; reversed one-colour output.',
    'favicon.svg': 'White mark on a padded cobalt rounded square; 16–32 px.',
    'voalack-app-icon.svg': '512-unit master of the same icon composition.',
}


def write_assets() -> None:
    for name, fill, capsule, label in [
        ('voalack-mark.svg', COBALT, INK, 'cobalt and ink'),
        ('voalack-mark-dark.svg', PERIWINKLE, PAPER, 'periwinkle and paper'),
        ('voalack-mark-mono.svg', INK, INK, 'ink'),
        ('voalack-mark-white.svg', WHITE, WHITE, 'white'),
    ]:
        write(name, svg(f'Voalack — Handoff mark, {label}', 320, 320,
              mark(fill, capsule),
              'Two separate solid shapes: a rounded receiver open to the left '
              'and an incoming capsule, with a clear gap before the inner wall.'))
    for name, symbol, capsule, letters, period, label in [
        ('voalack-logo-light.svg', COBALT, INK, INK, COBALT, 'for light backgrounds'),
        ('voalack-logo-dark.svg', PERIWINKLE, PAPER, PAPER, PERIWINKLE, 'for dark backgrounds'),
        ('voalack-logo-mono.svg', INK, INK, INK, INK, 'monochrome ink'),
        ('voalack-logo-white.svg', WHITE, WHITE, WHITE, WHITE, 'monochrome white'),
    ]:
        write(name, svg(f'voalack. — {label}', LOGO_WIDTH, LOGO_HEIGHT,
              logo_body(symbol, capsule, letters, period),
              'The Handoff receiver and capsule beside the outlined lowercase '
              'voalack wordmark and period.'))
    app_body = (f'<rect width="512" height="512" rx="112" fill="{COBALT}"/>\n'
                '<g transform="translate(80 80) scale(1.1)">'
                + mark(WHITE) + '</g>')
    write('voalack-app-icon.svg', svg('Voalack application icon', 512, 512,
          app_body, 'The white Handoff mark on a cobalt rounded square.'))
    favicon_body = (f'<rect width="64" height="64" rx="14" fill="{COBALT}"/>\n'
                    '<g transform="translate(10 10) scale(.1375)">'
                    + mark(WHITE) + '</g>')
    write('favicon.svg', svg('Voalack', 64, 64, favicon_body,
          'A white receiver and incoming capsule on a cobalt rounded square.'))
    spec = {
        'name': 'Voalack',
        'wordmark': 'voalack.',
        'concept': 'Handoff',
        'version': '1.0',
        'date': '2026-10-01',
        'status': 'Original editable vector identity; project adoption pending.',
        'meaning': 'A deliberate acknowledgement is handed toward a precise receiver. '
                   'The visible separation keeps the request and its destination distinct.',
        'palette': {'cobalt': COBALT, 'periwinkle_dark_theme': PERIWINKLE, 'ink': INK, 'paper': PAPER, 'white': WHITE},
        'canonical_mark_viewbox': [0, 0, MARK_SIZE, MARK_SIZE],
        'canonical_logo_viewbox': [0, 0, LOGO_WIDTH, LOGO_HEIGHT],
        'construction': {
            'parts': 2,
            'receiver': 'Rounded receiver open left; one filled path.',
            'handoff': 'Separate 184 by 72 unit capsule, vertically centred; one filled path.',
            'thickness_units': 72,
            'receiver_outer_corner_radius_units': 88,
            'receiver_inner_corner_radius_units': 24,
            'capsule_radius_units': 36,
            'capsule_to_inner_wall_gap_units': 64,
            'mark_to_wordmark_gap_units': 64,
            'wordmark': 'Seven purpose-drawn lowercase letter paths and a circular period.',
            'wordmark_origin': list(WORD_ORIGIN),
            'runtime_fonts': False,
            'external_resources': False,
        },
        'clear_space': {
            'minimum_units': 64,
            'rule': 'Keep one inner-gap width (64 mark units) clear around the complete mark or lockup.',
            'icon_exception': 'Supplied favicon and app icon already include internal padding.',
        },
        'minimum_sizes': {
            'standalone_mark_px': 24,
            'full_wordmark_width_px': 176,
            'desktop_header_width_px': 208,
            'mobile_header_width_px': 180,
            'favicon_px': 16,
            'guidance': 'Use the padded favicon below 24 px. Do not close the gap or add small details.',
        },
        'assets': ASSETS,
        'usage': [
            'Keep the receiver open on the left and the capsule separate.',
            'Preserve the two paths, their weight and the negative-space gap.',
            'Keep the period matched to the receiver colour: cobalt on light surfaces, periwinkle on dark surfaces.',
            'Use the appropriate light, dark, ink or white variant.',
            'Do not stretch, rotate, outline, merge the shapes or add shadows and gradients to the logo.',
            'The mark does not represent bidirectional synchronisation, backup, recovery or guaranteed delivery.',
        ],
        'rights_note': 'Original geometry and lettering. No vendor logos, branded font files or '
                      'third-party artwork are embedded. No trademark clearance, registration, '
                      'certification or affiliation is asserted. Licensing is left to the repository owner.',
        'reproduce': {
            'svg_assets': 'python generate_brand.py',
            'previews_and_png': 'python generate_brand.py --render',
            'core_dependencies': 'Python standard library',
            'render_dependencies': ['Inkscape', 'Pillow'],
        },
    }
    write('brand-spec.json', json.dumps(spec, indent=2, ensure_ascii=False) + '\n')
    write('BRAND.md', '''# Voalack — Handoff

The original Handoff mark uses two solid parts: a **rounded receiver open on the left** and a **separate incoming capsule**. Their clear separation reflects a deliberate acknowledgement moving toward a precise destination. The shape remains distinct from the Alrust and Zabalack symbols while its substantial lowercase lettering relates the three projects.

The display wordmark is **voalack.** The period belongs to the lockup. Branding does not rename any repository, package, command or API.

## Palette

| Colour | Hex | Use |
| --- | --- | --- |
| Cobalt | `#5363F0` | Symbol, punctuation and icon field |
| Periwinkle | `#8B96FF` | Dark-theme receiver and punctuation |
| Ink | `#182033` | Lettering and dark surfaces |
| Paper | `#F6F7FB` | Light surfaces and dark-theme lettering |
| White | `#FFFFFF` | Reversed monochrome and icon symbol |

## Assets

| File | Use |
| --- | --- |
| `voalack-logo-light.svg` | Light surface; ink capsule and lettering, cobalt receiver and period |
| `voalack-logo-dark.svg` | Dark surface; paper capsule and lettering, periwinkle receiver and period |
| `voalack-logo-mono.svg` | Ink monochrome lockup |
| `voalack-logo-white.svg` | White monochrome lockup |
| `voalack-mark.svg` | Cobalt receiver and ink capsule |
| `voalack-mark-dark.svg` | Periwinkle receiver and paper capsule |
| `voalack-mark-mono.svg` | Ink standalone mark |
| `voalack-mark-white.svg` | White standalone mark |
| `favicon.svg` | Padded icon for 16–32 px display |
| `voalack-app-icon.svg` | 512-unit application or repository avatar master |
| `voalack-icon-256.png` | Ready-to-use 256 px icon; produced with `--render` |

All logo and standalone mark backgrounds are transparent. All letterforms are purpose-drawn filled paths. There are no font files, raster embeds, external URLs, scripts, filters, masks or clipping dependencies.

## Construction and size

The mark occupies a **320 × 320** grid. Its receiver and capsule have a **72-unit** weight. The receiver has **88-unit outer right corners**, **24-unit inner right corners**, and **36-unit arm-tip radii**. The capsule is **184 × 72 units** with a **36-unit radius**. Its right edge remains **64 units** from the receiver's inner wall.

Keep at least **64 units of clear space** around the mark or complete lockup. The horizontal lockup is **1576 × 320** units, with **64 units** between the mark and wordmark. The supplied favicon and app icon already contain optical padding.

Use the standalone symbol at **24 px or larger**, and the padded favicon at **16–23 px**. Use the complete wordmark at **176 px wide or larger**; recommended header widths are **208 px desktop** and **180 px mobile**. Preserve the gap and use the appropriate contrast variant.

Do not stretch, rotate, outline, merge the two parts, close the receiver, remove the period, or add shadows and gradients to the logo. Illustrations may interpret the geometry spatially, but the canonical logo remains flat.

## Meaning and independence

The symbol is an original expression of a scoped, accountable handoff. It does not communicate backup or recovery, universal synchronisation, guaranteed delivery, or vendor certification. The product description should accurately distinguish a requested acknowledgement from a confirmed remote result.

No vendor logos, branded font files or third-party artwork are embedded. The assets do not assert trademark clearance, registration or affiliation. Licensing remains the repository owner's decision.

## Reproduction

Run `python generate_brand.py` to deterministically regenerate the ten SVGs, this guide and `brand-spec.json`. Core generation requires only Python's standard library. Run `python generate_brand.py --render` to also produce the 256 px icon, reference image, contact sheet and size proofs using local Inkscape and Pillow.

The source contains each canonical mark path and all seven letter placements once. Every colour variant uses those same paths.
''')


def validate() -> None:
    for name in ASSETS:
        content = (ROOT / name).read_text(encoding='utf-8')
        doc = ET.fromstring(content)
        tags = {node.tag.rsplit('}', 1)[-1] for node in doc.iter()}
        assert not tags & {'text', 'image', 'script', 'foreignObject', 'style', 'filter', 'mask', 'clipPath'}, (name, tags)
        assert 'href=' not in content and 'url(' not in content, name
        assert RECEIVER_PATH in content and HANDOFF_PATH in content, name
        assert doc.attrib.get('viewBox'), name
        assert len(doc.findall('{http://www.w3.org/2000/svg}title')) == 1, name
        assert len(doc.findall('{http://www.w3.org/2000/svg}desc')) == 1, name
    print('10 SVGs written; XML, canonical-geometry and resource checks passed.')


def render() -> None:
    from PIL import Image, ImageDraw, ImageFont
    previews = ROOT / 'previews'
    previews.mkdir(exist_ok=True)

    def png(name: str, width: int, filename: str | None = None, root_output: bool = False) -> Path:
        folder = ROOT if root_output else previews
        output = folder / (filename or f'{Path(name).stem}-{width}.png')
        subprocess.run(['inkscape', str(ROOT / name), '--export-type=png',
                        f'--export-width={width}', f'--export-filename={output}'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return output

    for name in ['voalack-logo-light.svg', 'voalack-logo-dark.svg', 'voalack-logo-mono.svg', 'voalack-logo-white.svg']:
        png(name, LOGO_WIDTH)
    for name in ['voalack-mark.svg', 'voalack-mark-dark.svg', 'voalack-mark-mono.svg', 'voalack-mark-white.svg']:
        png(name, 320)
    png('voalack-app-icon.svg', 512)
    png('voalack-app-icon.svg', 256, 'voalack-icon-256.png', root_output=True)
    for size in [16, 24, 32]:
        png('voalack-mark.svg', size, f'mark-{size}.png')
        png('voalack-mark-mono.svg', size, f'mark-mono-{size}.png')
        png('voalack-mark-white.svg', size, f'mark-white-{size}.png')
        png('favicon.svg', size, f'favicon-{size}.png')
    for size in [176, 180, 208]:
        png('voalack-logo-light.svg', size, f'header-{size}.png')

    def font(size: int):
        for candidate in ['/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 'DejaVuSans.ttf']:
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                pass
        return ImageFont.load_default()

    def paste(canvas, name, x, y, limit=None):
        im = Image.open(name).convert('RGBA')
        if limit:
            im.thumbnail(limit, Image.Resampling.LANCZOS)
        canvas.paste(im, (x, y), im)
        return im

    # A simple clean reference for the illustration agent and identity users.
    reference = Image.new('RGB', (2000, 800), PAPER)
    paste(reference, previews / 'voalack-logo-light-1576.png', 212, 240)
    reference.save(previews / 'voalack-brand-reference.png')

    sheet = Image.new('RGB', (1800, 1500), PAPER)
    draw = ImageDraw.Draw(sheet)
    draw.text((66, 38), 'VOALACK  /  HANDOFF', font=font(30), fill=INK)
    draw.text((66, 88), 'Original vector identity · Acknowledgement, with accountability.', font=font(18), fill='#646D81')
    paste(sheet, previews / 'voalack-logo-light-1576.png', 180, 198, (1440, 293))
    draw.text((66, 525), 'PRIMARY  /  PAPER', font=font(15), fill='#646D81')
    draw.rectangle((0, 570, 1799, 946), fill=INK)
    paste(sheet, previews / 'voalack-logo-dark-1576.png', 220, 626, (1360, 277))
    draw.text((66, 907), 'PRIMARY  /  INK', font=font(15), fill=PAPER)
    draw.text((66, 992), 'SMALL-SIZE ICONS', font=font(19), fill=INK)
    for index, size in enumerate([16, 24, 32]):
        x = 72 + index * 122
        im = paste(sheet, previews / f'favicon-{size}.png', x, 1046 + (32-size)//2)
        draw.text((x, 1096), f'{size} px', font=font(14), fill=INK)
        blown = im.resize((size*4, size*4), Image.Resampling.NEAREST)
        sheet.paste(blown, (x, 1144), blown)
    draw.text((500, 992), 'MONOCHROME', font=font(19), fill=INK)
    paste(sheet, previews / 'voalack-logo-mono-1576.png', 500, 1080, (920, 188))
    paste(sheet, previews / 'voalack-app-icon-512.png', 1500, 1017, (220, 220))
    draw.text((1478, 1273), 'APPLICATION / AVATAR', font=font(15), fill=INK)
    draw.line((66, 1340, 1734, 1340), fill='#D8DDE8', width=1)
    for index, (label, colour) in enumerate([('COBALT  #5363F0', COBALT), ('INK  #182033', INK), ('PAPER  #F6F7FB', PAPER)]):
        x = 66 + index * 550
        draw.rounded_rectangle((x, 1380, x+62, 1442), radius=12, fill=colour, outline='#CBD1DF')
        draw.text((x+86, 1397), label, font=font(18), fill=INK)
    sheet.save(previews / 'voalack-brand-contact-sheet.png')

    tiny = Image.new('RGB', (1600, 1160), PAPER)
    draw = ImageDraw.Draw(tiny)
    draw.text((60, 34), 'HANDOFF / SMALL-SIZE PROOF', font=font(29), fill=INK)
    draw.text((60, 85), 'Left: actual pixels. Right: 6× nearest-neighbour enlargement.', font=font(17), fill='#646D81')
    for row, size in enumerate([16, 24, 32]):
        y = 170 + row * 260
        draw.text((60, y), f'{size} px', font=font(22), fill=INK)
        for col, (key, label, background) in enumerate([
            ('mark-mono', 'Ink silhouette', PAPER),
            ('mark-white', 'White silhouette', INK),
            ('favicon', 'Padded favicon', PAPER),
        ]):
            x = 210 + col * 440
            draw.text((x, y-18), label, font=font(17), fill=INK)
            draw.rectangle((x-14, y+18, x+396, y+230), fill=background)
            im = Image.open(previews / f'{key}-{size}.png').convert('RGBA')
            tiny.paste(im, (x+8, y+64), im)
            enlarged = im.resize((size*6, size*6), Image.Resampling.NEAREST)
            tiny.paste(enlarged, (x+114, y+30), enlarged)
    draw.text((60, 993), 'HEADER LOCKUPS / ACTUAL SIZE', font=font(18), fill=INK)
    for index, size in enumerate([176, 180, 208]):
        x = 470 + index * 350
        paste(tiny, previews / f'header-{size}.png', x, 1000)
        draw.text((x, 1070), f'{size} px wide', font=font(15), fill=INK)
    tiny.save(previews / 'voalack-tiny-size-proof.png')
    print('256 px icon, reference, contact sheet and size proofs written.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--render', action='store_true', help='Render PNG assets and previews with Inkscape and Pillow.')
    args = parser.parse_args()
    write_assets()
    validate()
    if args.render:
        render()
