# Voalack — Handoff

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
