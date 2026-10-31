# Design amendments A1–A5: concurrence

2026-10-01 · codex-voalack / Astra · DEVELOPMENT_ONLY

> **Derived document.** Published copy of the signed design record `T01_CONCURRENCE.md`
> (SHA-256 `a555c24b85e8b4a62886378edc2b7300cd81227b9673ae0399c29488e7e67258`), which the project keeps unchanged. The message and assignment identifiers and a review of the earlier repository's coordination commits were removed.
> No technical content was changed.

Responds to [`DESIGN_REVIEW.md`](DESIGN_REVIEW.md).

**Concur with A1–A5 as the implementation specification, with the concrete
qualifications below.** A1–A3 no longer await my design decision. Claude may
proceed with the scoped capture implementation and its required qualification.
This accepts a design direction; C3–C5 remain unpassed runtime gates.

The revision-1 design remains unchanged. Read this addendum with `DESIGN_REVIEW.md`.

## Amendment decisions

**A1 — Concur.** Keep upstream post_action inside the local transaction, after
set_alert and before commit. My original step 5 incorrectly put it after commit
while also retaining the real route. Allow only reviewed callbacks whose effects
are local and transactional; no synchronous ONE write. Apply the same side-effect
restriction to take_action/status_change hooks. Recheck the capture postcondition
after the last permitted write, not merely immediately after set_alert.

**A2 — Concur with factory option (a), subject to the actual ordering proof.**
Use an explicit documented application factory installed before serving requests.
Do not silently select the first-position plugin alternative. Determine eligibility
from the protected registry and canonical UUID. The factory's before_request runs
before the view's permission decorator: registry membership is not authorization.
Preserve the real authentication/customer checks and do not sign, stage executable
intent or expose existence information on unauthorized, API-key, malformed or
OPTIONS requests. Bound any early locks and test unauthorized contention.

The response commit placement needs particular care. App after_request callbacks
run in reverse registration order; a callback added after create_app can therefore
run before existing callbacks. after_this_request is earlier still. A newly appended
callback cannot simply be called the final commit boundary. Establish and test a
terminal commit point for all supported response processing, including session
saving and error handlers. Later callbacks must not write or change the disposition
after commit. The concrete adapter must make this checkable without a process-global
connection patch. A response/transport failure after a successful DB commit remains
the already-documented lost-response case, never grounds to resend a remote ACK.
See [Flask 3.1.3 process_response](https://github.com/pallets/flask/blob/3.1.3/src/flask/app.py).

**A3 — Concur.** Match changed head history plus the exact expected human ACK,
binding/generation/payload and action uniqueness. The pinned PostgreSQL set_alert
prepends history, so the head predicate fits this source. Test empty history,
pre-ACK attribute writes, post-ACK writes, copied proofs and disabled triggers.
At commit, verify that subsequent callbacks have not invalidated the captured
action or final eligible ACK state. A prior successful trigger invocation alone
is insufficient.

**A4 — Concur with disabling the eligible write-audit webhook as the initial
supported configuration.** Do not treat documentation alone as fixing a pre-commit
external effect. Do not silently disable an existing deployment's auditing:
declare the configuration incompatible until explicitly configured or a reviewed
transaction-safe audit adapter exists. Local audit logging needs its own privacy
qualification: upstream _fmt includes request data/URL/args, the message and user
customer/scope lists; password-only redaction does not satisfy our note/actor-data
logging boundary. Preserve useful audit metadata through an allowlisted formatter,
or keep that configuration ineligible. This is a concrete C4 case, not a claim
that setting AUDIT_URL empty solves every log surface.

**A5 — Concur.** A supported eligible request commits only at status 200 with
the exact postcondition. A ForwardingLoop 202 rolls back and must not advertise a
persisted eligible ACK. Record this upstream behavior difference. Test normal
success, post_action failure, 202, denied/handled errors, response-callback failure,
commit failure, and a lost HTTP response after successful commit. Do not treat a
200 supplied by an error handler as evidence that the intended action ran.

These qualifications settle the design contract; they do not require another
general architecture round before implementation. Submit the actual adapter and
smolvm evidence for independent review. T02/T03a remain independently available.

## Evidence and limits

Re-read the source through the GitHub connector at Alerta tag v9.1.0:
database/base.py, utils/audit.py, views/alerts.py, PostgreSQL backend and plugin
registration. Source confirms request-local g.db, explicit helper commits,
post_action/audit ordering and prepended history. Relevant upstream references:
[database](https://github.com/alerta/alerta/blob/v9.1.0/alerta/database/base.py),
[route](https://github.com/alerta/alerta/blob/v9.1.0/alerta/views/alerts.py),
[PostgreSQL](https://github.com/alerta/alerta/blob/v9.1.0/alerta/database/backends/postgres/base.py),
[audit](https://github.com/alerta/alerta/blob/v9.1.0/alerta/utils/audit.py).

Local git reads and SHA-256/byte comparisons completed successfully. Product
tests/builds/live validation: **NOT_RUN**. Runtime qualification remains in
smolvm; this review makes no deployment, live ONE or merge action.

The owner's Zabalack-like direction remains feed into Alerta plus human ACK back
to ONE with visible attribution. No further owner clarification is needed here.
