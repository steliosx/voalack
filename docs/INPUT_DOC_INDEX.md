# Input documentation index

Documents inside the two pinned inputs (see [`../inputs/INPUTS.md`](../inputs/INPUTS.md)),
what each claims, and whether this project has reproduced it. Hashes are of the files as
pinned here (the feed's after redaction step 2).

**Evidence classes:** *historical* = reported by the input's authors, not run here;
*reproduced* = re-run by this project, with the evidence named.

## ACK MVP 0.1.0 (`Alerta_Veeam_ONE_Ack_Lab_MVP_2026-09-26.zip`)

| File | SHA-256 | Purpose |
|---|---|---|
| `README.md` | `67b561e149a086631362fb588d127725776d4faa152fff0201ec1a4e75aee1ce` | Design summary, ONE operation, permissions, scope, lab install, binding, recovery, limits |
| `VALIDATION.md` | `7613a06fbc30560b8087b296fd93cc67f8cef4c7f9cb513a498911793c09d608` | Executed checks, independent review findings, untested live items |
| `test-results.xml` | `7e96e1c7a3b1e641ef05def894b4e77e3dd868bd70f4758354e00f2014ceeb02` | JUnit output of the historical test run |
| `config/veeam-one-ack.example.json` | `8ca52ff6e88777954bda47a738fdf14b700b25dc94f1fcf3e3f27a12cfcd3b91` | Example binding/config (lab ONE URL placeholder, dry-run) |

| Claim | Source | Status |
|---|---|---|
| 32 tests plus 21 subtests pass against the installed wheel (Python 3.12.14, `alerta-server==9.1.0`, `pytest==9.1.1`) | `VALIDATION.md` "Executed checks", `test-results.xml` | **Reproduced** — T03a: 32 tests plus 21 subtests passed (JUnit aggregate 53) ([`../baseline/BASELINE_REPORT.md`](../baseline/BASELINE_REPORT.md)) |
| The wheel's entry point loads `VeeamOneAckPlugin` | `VALIDATION.md` "Packaging" | **Reproduced** — T03a `entry-point.txt` |
| Rebuilt wheel matches the shipped one | (implicit) | **Reproduced at member level** — T03a: 9/9 members identical; archive bytes differ, cause not diagnosed |
| ONE ACK is `POST /api/v2.3/alarms/triggeredAlarms/resolve` with `resolveType: Acknowledge`, comment ≤ 1024 | `README.md` "Supported operations and permissions" | Historical (vendor docs + local HTTPS mock); not checked against a live ONE |
| No standalone comment-only alarm endpoint exists | same | Historical (documentation search) |
| The ONE account needs Veeam ONE Administrator for the Alarms POST | same | Historical (vendor docs) |
| Read-only users are denied before hooks; writers succeed; hook runs after the local update | `VALIDATION.md` "Alerta authorization" | Historical in source; T03a re-ran the tests, which mock token decoding and database effects |
| Grouped/child alarms, changed trigger time/count and changed captures are blocked | `README.md` "Scope and identity binding", `VALIDATION.md` | Reproduced only as the MVP's own unit tests (mock ONE) |
| Single-node lab scope: file lock is per host; no conditional ACK token in the API | `README.md` "Why this is single-node lab scope" | Design statement; consistent with source (`core.py`) |
| The feed does not receive ONE acknowledgement changes | `README.md` "Why this is single-node lab scope" | Historical; consistent with the feed README |
| Independent review findings (stale note history, trigger-time marker bypass, Python 3.11 floor) were fixed | `VALIDATION.md` "Astra Ultra independent review" | Historical; the fixed behaviour is covered by the reproduced tests |

## PowerShell feed, revision 2 (`VeeamONE_13.1_Alerta_9.1_Script_Integration_2026-09-24.zip`)

| File | SHA-256 | Purpose |
|---|---|---|
| `README.md` | `adf932a121614f19df3a5be3d6861645fd6547c24a75ad104945ff3419a38e56` | What the starter does, deployment fit, install, receiver config, recovery and limits, acceptance checks |
| `ASTRA_ULTRA_REVIEW.md` | `7bb5f0c028da903acc8560b6af3eaa292e1b00cc34be831f76f61f2b834a0189` | Independent static review of revision 1 and its dispositions |
| `config.example.json` | `2edbd64da357e2d336615a2aafd63220878edbb1edad54a84fed2f4eef4e15ff` | Example sender config, labelled Production — **do not execute** |

| Claim | Source | Status |
|---|---|---|
| The ONE script action documents only Error, Warning and Resolved; no Info or operator-Acknowledged events | `README.md` "What the starter does" | Historical (vendor docs). Implication: ONE-origin acknowledgements are not visible through the feed |
| Capture spools durably; delivery is at least once after successful local spooling, ordered by local capture | `README.md` "What the starter does", "Recovery, monitoring, and limits" | Historical; **NOT_RUN** (needs Windows PowerShell) |
| Active alarms are sent with `timeout=0` so they do not expire | `ASTRA_ULTRA_REVIEW.md` "Findings and disposition" | Historical; NOT_RUN |
| Blackout responses no longer block unrelated alarms | same | Historical; NOT_RUN |
| A delayed Error can interact with a later operator ACK | `ASTRA_ULTRA_REVIEW.md` "Remaining findings and limits" | Historical (reviewer probe of Alerta 9.1 state machine with stubs) |
| Current-state reconciliation is missing | same | Open limitation |
| `Test-LocalQueue.ps1` checks parsing, captures, rejection paths and timeout mapping | `ASTRA_ULTRA_REVIEW.md` "Validation performed and next checks" | Not run by the source reviewer or this project; no execution evidence supplied; needs Windows PowerShell 5.1 |
| `%7` combination ID can aggregate more than one child job | `README.md` "Recovery, monitoring, and limits" | Historical (vendor docs); matters for occurrence identity |
