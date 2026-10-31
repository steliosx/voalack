# Design records

The integration design (task T01), its implementability review and the agreed amendments.

| File | SHA-256 | Author | What it is |
|---|---|---|---|
| [`DESIGN.md`](DESIGN.md) | `a8e7d542fcc22ace24cc27d706b7dd0d351c10669e24ec15b16dde2787f684a5` | VO-ASTRA | Integration design, revision 1 |
| [`DESIGN_REVIEW.md`](DESIGN_REVIEW.md) | `1edfaea2a061c9ca8bc74400e1da5a3231806237a7fd71d6960301e9b608e5b2` | VO-LEAD | Implementability review: amendments A1–A5 |
| [`DESIGN_AMENDMENTS.md`](DESIGN_AMENDMENTS.md) | `fd7b4ffee0db2ac2f247bfab39d24808e5a986e3db242aa4b750200bca9495e7` | VO-ASTRA | Agreement to A1–A5, with implementation checks |

Read the design together with the review and the amendments: A1–A5 amend steps 1, 4 and 5
of the design's capture section, and the amendments add implementation checks.

## Later assessments

| File | Author | What it is |
|---|---|---|
| [`T05_REVERSE_STATE.md`](T05_REVERSE_STATE.md) | VO-LEAD | Reverse Veeam ONE state: why ONE-to-Alerta mirroring is not offered, what reconciliation does |

## Provenance

These are derived copies of signed records exchanged between the two agents. Each one
replaces only coordination material (task and message identifiers, transport bindings,
task status) with a short provenance note; the technical sections are unchanged. The
project keeps the signed originals unchanged:

| Published | Signed original | Original SHA-256 |
|---|---|---|
| `DESIGN.md` | `T01_DESIGN.md` | `f082463bf716206a4e94e458b48d1cb06543c8c5df6ddbdd70c8a2cb0ef7b91f` |
| `DESIGN_REVIEW.md` | `T01_REVIEW.md` | `f1097ae7572288aab275738bbaf26affed31edb5d5224bb0d3050e06bb0e1f78` |
| `DESIGN_AMENDMENTS.md` | `T01_CONCURRENCE.md` | `a555c24b85e8b4a62886378edc2b7300cd81227b9673ae0399c29488e7e67258` |

The originals cite a project base and contract hash from the project's history before
this repository was restarted on 2026-10-01. The contract's product requirements are
carried forward in [`../docs/REQUIREMENTS.md`](../docs/REQUIREMENTS.md).
