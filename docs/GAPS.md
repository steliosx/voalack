# Documentation gaps, contradictions and glossary

## Missing references

| Item | Status |
|---|---|
| Lab guide (`Alerta_Veeam_ONE_Ack_Lab_Guide_2026-09-26.md`) | Cited by the original source register; not supplied |
| Veeam ONE architecture and comparison document | Cited by the original source register; not supplied |
| Pinned Veeam ONE REST schema for the deployed build | Not reviewed; design unknown U2 |
| Deployed versions (Alerta, PostgreSQL, Patroni, PgBouncer, ONE) | Not inventoried; design unknowns U4/U5 |
| Windows PowerShell evidence for the feed | No native Windows execution evidence supplied; the source authors report `Test-LocalQueue.ps1` as not run, and this project has not run it |

## Contradictions and tensions

| Topic | Where | Resolution |
|---|---|---|
| "2-way ack" vs. one-way ACK | Repository README first line vs. MVP README, design U6 and requirements | Scope is feed into Alerta plus human ACK back to ONE; ONE-origin ACKs are not mirrored. Wording to be clarified with the GitHub description (owner) |
| Lab-only MVP vs. multi-node target | MVP README "Why this is single-node lab scope" vs. requirements §1 | The MVP stays a baseline; the product needs the durable worker and session owner (gaps G1–G3 in the baseline report) |
| Synchronous post-commit write vs. atomic capture | MVP `plugin.py` vs. requirements §3.2 and design | Planned replacement: the capture adapter (design A1–A5); implementation acceptance pending |
| `CUSTOMER_VIEWS` | MVP and feed READMEs keep `False`; Zabalack requires `True` | Design: do not copy Zabalack's requirement; visibility and ACK permission are separate checks |
| Python floor | MVP `>=3.11`; Zabalack `>=3.12,<3.13` | Two-consumer target is 3.12 (`mise.toml`) |
| Comment format | MVP `[AlertaAck:<id>] Alerta=<uuid> operator=<login>; <text>` vs. design format with "via Voalack" and request time | Design format applies to the product (baseline gap G8) |
| Feed timestamps vs. later operator ACKs | Feed README and its review | Open limitation; delayed Errors can interact with ACKs; needs reconciliation |

## Glossary

| Term | Meaning |
|---|---|
| `%7` / combination ID (`veeamAlarmCombinationId`) | Feed argument identifying an affected-node/alarm combination; can aggregate several child jobs. **Not** the REST `triggeredAlarmId` |
| `triggeredAlarmId` | ONE REST identity of a triggered alarm; the only ID the ACK operation accepts |
| Capture ID (`captureId`) | Feed transport observation ID; a replay is not a new alarm occurrence |
| Occurrence | One instance of an alarm being raised; stable identity across recurrence is unproven (design U1) |
| Binding | Administrator-approved mapping from one Alerta alert to one ONE alarm and its source evidence |
| Intent | Signed, durable record of one human ACK action to deliver to ONE |
| UNCERTAIN | A write may have reached ONE; held for read-only reconciliation, never blindly resent |
| Session owner | The single process allowed to hold a ONE API session for an instance and credential |
| Projection | Writing an integration outcome back into Alerta (as a note), without generating new intents |
