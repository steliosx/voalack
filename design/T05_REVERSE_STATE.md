# Reverse Veeam ONE state: assessment (T05)

## Verdict

Voalack does **not** mirror Veeam ONE acknowledgement state into Alerta, and does not offer it.
Nor does it mirror unacknowledgement, comments, resolve/remediation or grouped alarms. The
supported direction is: the feed brings alarms into Alerta, and an authenticated Alerta human's
ACK is sent back to ONE with visible attribution. The owner placed mirroring of acknowledgements
made in ONE outside this programme (U6 in [`DESIGN.md`](DESIGN.md)).

## What exists, and what each part may do

| Part | Reads ONE | Changes Voalack's ledger | Changes Alerta |
|---|---|---|---|
| Ordinary read-only reconciliation (T04 S3b) | One GET of an **uncertain**, unsettled attempt's original target, through the instance's single session owner. Nothing is read for any other attempt state. | Records the observation under the original attempt. **Automatic** settlement happens only when the read carries that attempt's own completed-operation evidence (`attributable`). A separate, guarded **operator** settlement may also use `acked_unattributed`, `acked_by_other` or `not_acked`, but only under the recorded containment and quiescence requirements. | Never directly. A settlement adds two outcome events (the settlement and the effect's new state); the projector may later publish each as a Voalack note. Alert status and history are not changed. |
| Recovery reads (T04 S3c) | Reads the physical key of a hold adopted after a database restore. A recovery read does not require a surviving uncertain-attempt row; it reserves the recovered hold and its frozen members. | Records under the recovery hold; release follows its own guarded rules. | Never directly. |
| Optional source-state observer (T05b) | Not implemented. A revised design is under review. | Would only record a minimised summary in Voalack's own schema. | Never. An observation could not settle an attempt or produce an outcome event. |

Reconciliation never sends an ACK and never creates an Alerta action, intent or capture. The
provider read and the local settlement are separate steps: the read is evidence, and the
settlement is a guarded database decision on that evidence. A negative read (for example
`not_acked`) does not prove that an earlier attempt had no effect.

The T05a witnesses below cover the ordinary path only, not recovery reads.

Neither part reports who acknowledged an alarm in ONE. The classifications are:

| Classification | Meaning under the fake provider contract |
|---|---|
| `attributable` | ONE shows our own completed operation and exactly the comment of the original frozen request (bound to its request hash). Only this settles automatically. |
| `acked_by_other` | ONE shows a different, well-formed operation identity. |
| `acked_unattributed` | ONE shows the alarm acknowledged with exactly the original request's comment but no operation identity. |
| `not_acked` | ONE shows the alarm unacknowledged, with no operation identity. |
| `evidence_only` | Anything else: an error, the wrong target, a grouped alarm, malformed or contradictory fields, or a comment that only contains our marker. |

These are observations reported by Voalack's own session owner against the fake provider
contract. The operation identity and completion fields are fake-contract fields, not known
fields of the real ONE API (U2). The comment stored in ONE is not a standalone authenticated
signature, and a comment marker such as `[AlertaAck:<uuid>]` can be typed by anyone: marker text
alone is unverified and is never provenance.

## Why mirroring is not offered

| Mirroring would need | Status | Blocker |
|---|---|---|
| Source ordering | ONE is read as its current state. No source sequence or watermark is qualified. The feed's capture ID and spool order are transport order only. | U1, U7 |
| Occurrence identity | `triggeredAlarmId` lifetime, reuse and recurrence are unproven, so a later read may describe a different occurrence. | U1 |
| Original human identity | ONE reports at most a ONE account and a comment. A ONE account is not an Alerta identity. | U2, U4 |
| Conflict precedence | There is no agreed order between the Alerta human's state, ONE's state and an in-flight or uncertain Voalack attempt. | design gap |
| Loop suppression | Applying a ONE acknowledgement to Alerta would run the Alerta ACK path, which captures a new intent and sends an ACK back to ONE. Our own marker is not provenance outside the fake contract. | U1, U2 |
| Scope | Mirroring ONE-origin acknowledgements is outside this programme. | U6 |

A future reverse mutation needs its own reviewed contract covering every row above before any
code is written.

## Evidence

`tests/capture/test_t05a_reverse_state.py` runs against the fake provider in a disposable guest
with real PostgreSQL:

* **E1, echo.** Our ACK reached the fake and its response was lost. Reading it back settles the
  attempt once and creates no intent, capture, effect or attempt. It publishes no note or
  publication itself. Alert status and history stay unchanged, and there is no second ACK. Later
  calls are refused without any read.
* **E2/E5.** A foreign operation, an unattributed acknowledgement or a typed marker is recorded,
  never attributed, and settles nothing.
* **E3.** Replaying a reservation or a record keeps the first result and grants no new read.
* **E4.** A replaced reader's late record is refused (`owner_fenced`) and kept as evidence only.
  It does not overwrite the newer record and settles nothing.
* **E6.** An unacknowledgement in ONE before the read keeps the attempt held and sends nothing.

Real ONE behaviour, occurrence identity and the original human's identity remain unqualified
(U1, U2, U4).
