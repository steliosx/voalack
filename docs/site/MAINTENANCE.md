# Voalack website and GitHub presentation maintenance

## Scope and sources

Maintain the product explanation, evidence-backed status, roadmap, documentation links and existing original identity. The engineering repository is the source of truth; presentation maintenance does not close product acceptance gates or alter engineering records.

At the start of each update, read current `main`, relevant active branches/PRs, the design and its latest accepted amendments, baseline/qualification reports, releases and actual CI results. Inspect applicable repository instructions and current path ownership. Capture exact refs and evidence times before editing. Review new content against the underlying evidence rather than copying agent summaries.

The current publication uses main `539707e90fa1d4470c852f80a38027095101f5d8`: product requirements in `docs/REQUIREMENTS.md`, working rules in `docs/CHARTER.md`, published design records in `design/`, and corrected original-MVP baseline evidence in `baseline/`. Re-discover current paths and refs on each run. The repository was deliberately restarted on 1 October 2026; do not join superseded history or restore removed coordination records.

Keep separate: design agreement, implementation on a development branch, independent review, merge, release, installed-artifact validation and live qualification. The initial 32-test record covers the original synchronous ACK MVP with a mocked database boundary. It does not qualify the planned durable runtime. Read-only source inspection is not an executed test.

Preserve current scoped behaviour unless an accepted design changes it: ONE alarms feed Alerta; authorised human single-alert acknowledgements can be delivered from Alerta to an exact approved ONE target. Do not imply universal reverse ACK mirroring, guaranteed exactly-once delivery or live readiness. Recheck licence and compatibility claims against current evidence.

## Update procedure

1. Retrieve this existing Site's source through the normal Sites workflow using project ID `appgprj_6abebba6cb508191916ffde431a5762b`. Use its returned checkout. Do not assume an old scratch path persists or register a replacement Site.
2. Compare current repository evidence with `content/project.json` and the last publication. Update only substantive changes; a new date alone is not a reason to rebuild or republish.
3. Update the public facts and source-evidence snapshot. Adjust the corresponding prose/rows and source links in `tools/build.py` when the product state changes. The JSON supplies dates, refs and summary fields; status prose also lives in the template and must be reviewed explicitly.
4. Run the three commands in the source README. Inspect changed diagram/image assets if any. Keep art unchanged during routine status updates.
5. Review the resulting HTML and README against the exact source commits. Resolve substantive findings. For plain static Sites, managed browser preview may be unavailable; record that limitation instead of claiming a browser check.
6. Publish through the normal Sites source-push, archive and save/deploy workflow. Preserve the current audience. Verify successful deployment before reporting publication.
7. For GitHub, compare `exports/github/` with the latest repository state. Apply only the intended landing-page and asset changes on an isolated documentation branch/PR. Rebase presentation changes onto fresh main if another agent has moved it; do not force-push or overwrite engineering work. Reuse an existing matching documentation PR instead of creating duplicates. Follow applicable merge rules. At this publication, `docs/CHARTER.md` requires the designated VO-ASTRA (`codex-voalack`) to review the exact head before main advances. An independent presentation check by another agent does not substitute for that designated review. Report a pending review or merge accurately.

## GitHub staging

`tools/stage_github.py` creates `exports/github/` containing only `README.md`, `docs/assets/` and `docs/site/`. The adjacent manifest records the path, size, SHA-256 and Git blob hash of every staged file. The staged tree is a change set, not a complete repository; always base a GitHub tree update on the current full repository tree.

`docs/site/project.json` mirrors the public facts. `docs/site/MAINTENANCE.md` records the presentation workflow so a fresh scheduled run can discover it. Compare the generated README with current main before replacing it: retain useful newer documentation authored by the coding agents.

## Ongoing schedule

The owner's existing evening project review covers Alrust, Zabalack and Voalack and may maintain their GitHub landing pages through authorised documentation workflows. The existing morning website task updates these three Sites when verified changes warrant it. Neither task needs a new production integration, product service, monitoring credential or extra broad security scan.

Keep any private source material out of rendered public content. Publish only appropriate product facts and sanitised status; never reproduce private hostnames, customer/operator records, credentials, raw scan exports or private coordination messages. Preserve other tasks, engineering assignments, acceptance records, releases and repository settings.
