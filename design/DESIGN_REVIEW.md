# T01 implementability review — VO-LEAD


> **Derived document.** Published copy of the signed design record `T01_REVIEW.md`
> (SHA-256 `f1097ae7572288aab275738bbaf26affed31edb5d5224bb0d3050e06bb0e1f78`), which the project keeps unchanged. The transport bindings table was replaced by a short provenance line, and the task-status disposition by the outcome.
> No technical content was changed.
2026-10-01 · claude-voalack (VO-LEAD) · reviews T01 revision 1 by codex-voalack (Astra)

**Verdict: IMPLEMENTABLE_WITH_AMENDMENTS.** T01's completion condition is met: the
design passes VO-LEAD's implementability check and names its open safety unknowns.
Amendments A1–A5 below are carried into T03b. A1–A3 need Astra's concurrence (or a
revision) before T03b capture code is written; A4–A5 are T03b specification inputs.
None blocks T02 or T03a.

This is a static review of source and design. Product tests, builds and live checks
were **NOT_RUN**. Everything below about runtime behavior is a hypothesis for C3–C5 in
smolvm, not a result.

## Provenance

Reviews `DESIGN.md` (revision 1). The review checked the design's assignment, input and
contract bindings; those coordination details are kept by the project.

## What the Alerta 9.1.0 source confirms

Read at tag `v9.1.0` (Flask 3.1.3, psycopg2 2.9.11 per its `requirements.txt`):

- **One connection per request.** `Database.get_db()` (`alerta/database/base.py`) creates
  the psycopg2 connection lazily and stores it in `g.db`; `connect()` is otherwise used
  only by `create_engine` and `destroy`. Every write helper in the PostgreSQL backend
  (`_insert`, `_updateone`, `_updateall`, `_deleteone`, `_deleteall`) commits through
  `self.get_db().commit()`. A request-local wrapper on `g.db` therefore sees every
  write in the request, with no process-global patching.
- **Safety net.** `teardown_db` closes the connection without committing, so an
  unhandled path discards uncommitted work.
- **Route order** (`alerta/views/alerts.py`, `action_alert`): `find_by_id` →
  `process_action` (take_action) → `Alert.from_action` → `process_action(post_action=True)`
  → `write_audit_trail.send` → `200`.

So the design's central mechanism — defer the backend's commits to one outer boundary
in the same request — is feasible. Whether Flask's callback order on handled errors and
the wrapper's transparency to psycopg2 adapters behave as expected is **unproven until
C3 runs**.

## Amendments

**A1 — Post-action runs inside the transaction (amends step 5).** In `action_alert`,
post_action plugins run inside the view before it returns. With the real route kept,
they are necessarily pre-commit. Amend step 5: post_action runs inside the transaction;
an eligible routing chain may contain only allowlisted post_action plugins with no
external side effects; Voalack's own post_action does no I/O. (Replacing the route is
the alternative; the design already rejects it.)

**A2 — Install point for the request transaction (amends step 1).** `Plugins.register`
instantiates plugins without an app reference, and Flask 3.1 refuses `before_request`
registration after the first request, so a plugin cannot install the boundary itself.
Options, both to be proven in C3:

- **(a) Recommended: a documented WSGI factory** wrapping `create_app()` that registers
  `before_request`/`after_request` for the action endpoint. It locks the row before the
  view's `find_by_id`, so the view's own fetch is the refetch under the lock,
  independent of plugin order. It is a deployment change the operator docs must carry.
- (b) A first-position transaction plugin that swaps `g.db` in `take_action` and commits
  through `after_this_request`. It locks only at its chain position and needs an entry
  point separate from the final signer.

Activation must check the protected binding registry first, so non-Voalack alerts
(including Zabalack-routed ones) keep upstream behavior.

**A3 — Capture trigger fires on every UPDATE in the request (amends step 4).**
`HookTrigger.process_status_change` calls `alert.tag()` and `update_attributes()`
unconditionally before `set_alert`; both issue `UPDATE … RETURNING` regardless of
change. `process_action(post_action=True)` can issue more after `set_alert`. Specify the
match as "the head history entry changed and is the expected ACK"
(`OLD.history[1] IS DISTINCT FROM NEW.history[1]` plus the existing UUID/customer/
binding/generation/payload checks), and back it with a uniqueness constraint on the
captured action identity, so a pre-ACK write cannot match and a later write cannot add
a second candidate.

**A4 — Audit webhook is a pre-commit external side effect.** `write_audit_trail.send`
posts to `AUDIT_URL` (`alerta/utils/audit.py`, `requests.post`) inside the view, before
any outer commit. Either eligible deployments disable the audit webhook, or the
operator docs state that `alert-actioned` is request-time and can precede a rollback.

**A5 — Commit only on 200.** `ForwardingLoop` returns `202` with `status: ok`, and
upstream keeps the ACK. For eligible alerts, commit only when the final status is `200`
and the capture postcondition holds; anything else rolls back. Document the `202`
difference.

## Minor notes

- Under A2(a), the authentication decorator's own writes (for example API-key last-used)
  fall inside the deferred transaction; harmless, but cover it in C3.
- The row lock is held across other plugins' `take_action`/`status_change` hooks, which
  may do network I/O, and it blocks deduplicating ingestion of the same alert. Use
  `SET LOCAL lock_timeout` and `statement_timeout`; measure hold times in C4.

## Outcome

- The design is accepted with amendments A1–A5; VO-ASTRA concurred with all five in
  [`DESIGN_AMENDMENTS.md`](DESIGN_AMENDMENTS.md).
- Owner-confirmed scope (U6): a human ACK in Alerta goes back to ONE with visible
  attribution; ONE-origin acknowledgements are not mirrored into Alerta.
