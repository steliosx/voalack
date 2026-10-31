# voalack (development)

Durable capture of human Alerta acknowledgements for delivery to Veeam ONE. **Not qualified;
no delivery to a real Veeam ONE exists yet.** This package implements the T03b capture boundary
(design amendments A1–A5) and, in T04, the verifier and effect ledger, the single ONE session owner
and send path, read-only reconciliation and settlement, and supervised database recovery. The sender
talks only to a loopback fake provider (`fake-one/v1`) in the test guest.

## How capture works

1. **Candidate.** `voalack.boundary` (installed by the `create_app` WSGI factory) recognises
   `PUT /alert/<uuid>/action` with `action=ack` by syntax only. Before authentication it queries
   nothing and takes no lock, so unauthorised callers learn nothing about bindings (A2).
2. **Gate, inside the authorised route.** The pinned Alerta 9.1.0 action view checks permission
   (`@permission(Scope.write_alerts)`), then loads the alert with the caller's customer filter
   (`Alert.find_by_id(alert_id, customers)`), then runs the action hooks (`process_action`).
   Voalack's gate replaces that load for the candidate request only:
   - it loads the alert as upstream does (not found or other customer: upstream `404`);
   - it refuses ACKs from non-human credentials (API keys, Hawk, anonymous access) with `403`,
     for bound and unbound alerts alike, before any registry query. **This changes upstream
     behaviour:** with Voalack installed, API keys cannot acknowledge alerts;
   - it looks up the binding (1 s lock wait, 15 s statement limit); an unbound alert continues
     upstream, untouched;
   - for a bound alert it requires `READ COMMITTED`, refuses with `503` if another
     `request_finished` receiver is registered (B1, before anything is staged), defers Alerta's
     commits into one transaction, locks the alert row (2 s wait; `503` if busy), re-reads the
     binding `FOR SHARE` (so the binding cannot change until this ACK commits or rolls back; if
     it was deactivated meanwhile, the ACK continues upstream) and reloads the complete alert
     under the lock with the same customer filter, which is what the action hooks receive.
   `install` refuses any Alerta version other than 9.1.0, where this order was verified.
3. **Staging.** The `voalack` Alerta plugin (`take_action`) stages a prepared intent, with the
   binding ID and revision, only for an alert that passed the gate and only for a
   server-authenticated human ACK that is a real transition (not already acknowledged).
4. **Capture.** The trigger `voalack_capture_ack` on `public.alerts` fires only when the head
   history entry changed to the expected ACK (A3) and records exactly one capture for the
   staged intent of this transaction.
5. **Terminal commit.** The boundary's `after_request` callback runs last. It commits only if
   the action route returned normally and no later step raised (an error rewritten to `200` by an
   error handler does not count, wherever it was raised before the commit), the response is `200`, and one query joins this transaction's single staged intent,
   its single capture and the alert's current head history, which must equal the captured entry
   and be this user's ACK. It then finalizes the intent's note to that history text. Anything
   else rolls back, and a `200` that fails these checks becomes a `500` (A5). The approved commit
   itself is made when the application's `finalize_request` returns, after response processing,
   session saving and every `request_finished` receiver, in whatever order they ran; after it,
   Flask 3.1.3 only sends the response and tears down the request, neither of which can change
   the HTTP status (a failure then is a lost response after the commit, not a different
   outcome). At that point it re-checks that the session was saved, that `request_finished` was
   sent, that Voalack's is the only `request_finished` receiver, that the response is still `200`, and that the intent, capture, finalized note and head
   history still match; otherwise everything rolls back. An eligible ACK that was not committed
   never leaves with a success status other than the `202` Alerta's action view itself returns
   for a forwarding loop (accepted but not completed; A5), unchanged through response
   processing, whatever a response callback, error handler or receiver set. Genuine error statuses (`401`, `403`, `409`, ...) are kept. Teardown rolls back anything that never reached the
   boundary.

If the binding lookup fails the request gets `503` and nothing is touched.

Response callbacks (`after_request`, blueprint `after_request`, `after_this_request`) run before
the commit decision, so one could announce an ACK that later rolls back (R11). For a bound alert
the gate refuses with `503`, before anything is staged, unless every callback the request will
run is Voalack's own or a reviewed callable object frozen at install: the pinned factory's own
callbacks, identified by code and binding on Alerta 9.1.0 with flask-cors 6.0.5 and
Flask-Compress 1.25 (the request-ID header; the single CORS closure whose code and global
namespace are the real `flask_cors.extension` module's; and Alerta's Compress instance without a
cache backend), plus callbacks named in `VOALACK_REVIEWED_RESPONSE_CALLBACKS`
(`module:qualname`, each resolving to exactly one registered callback). A replacement with the
same name is not reviewed. Alerta's request logger (`log_response`) writes the provisional status,
so it is accepted only while the application logger does not emit INFO records (Alerta's default
`LOG_LEVEL` is `WARNING`). Callbacks registered after the gate has run are not covered.

Post-action plugins in an eligible chain run inside the transaction and must not have external
side effects (A1): `install` refuses an application with an enabled plugin implementing
`status_change`, `take_action` or `post_action` unless it is Voalack's own (the exact class; subclasses need review too) or listed in
`VOALACK_REVIEWED_ACTION_PLUGINS` (hooks are read as Alerta resolves them, on the instance;
an operator statement that its hooks are local and
transactional), and requires the `voalack` plugin itself. In Alerta 9.1.0 every plugin
implements `status_change` (it is abstract), so in practice every other enabled plugin must be
listed. Alerta's default `PLUGINS` include
`forwarder`, which forwards actions over the network, so they are refused. The write audit webhook reports ACKs before they commit, and the local write
audit log records ACK notes and actor data, so `install` refuses an application with `write` in
`AUDIT_TRAIL` and either `AUDIT_URL` or `AUDIT_LOG` set (A4). Voalack must be the only
`request_finished` receiver: receiver order is not guaranteed, so with any other receiver
eligible ACKs roll back and return `500`. Alerta 9.1.0 and its pinned extensions register none.

## Tests (`tests/capture`, real Alerta 9.1.0 on PostgreSQL 18 in a disposable VM)

`lab/run_capture.sh` installs this package (non-editable) and runs the tests. C3 cases: normal
capture; unbound alert unchanged; failure injected after `set_alert`; `ForwardingLoop` 202;
disabled trigger; capture insert failure; commit failure; extra tag/attribute UPDATEs (A3);
unauthenticated and read-only callers; re-ACK; and a real `SIGKILL` of the server process
after `set_alert` and before commit. `test_c3_review_probes.py` holds VO-ASTRA's review probes
unchanged: final note binding, history rewritten after capture, an error handler returning
`200`, a late `202`, re-ACK `409`, and the bounded eligibility lookup; and
`test_c3_review_probes_r4.py`, a response callback that fails before the commit while the
`500` handler returns `200`; `test_c3_session_save.py`, a failing session store (with and
without a `200` error handler) and the commit-after-session-save ordering; and
`test_c3_review_probes_r5.py` and `test_c3_review_probes_r6.py`, a session save that changes
the response or the ACK history, the no-session path, and a failed save never reported as `200`;
`test_c3_request_finished.py`, other `request_finished` receivers that change the response,
raise or only observe (all rejected; each checks that nothing was committed when it ran);
`test_c3_review_probes_r7.py`, a receiver that restores `200` in either dispatch order; and
`test_a4_audit_webhook.py`, the install-time refusal; `test_c3_uncommitted_status.py`, a receiver
turning a failed capture or a `202` into another success status;
`test_c3_review_probes_r8.py`, a response callback setting `201` or `204` before the boundary; and `test_c3_api_key.py`, an
API-key ACK; `test_c3_review_probes_b1b2.py` (VO-ASTRA's B1/B2 probes, unchanged); and
`test_c3_gate.py`: the gate's place in the pinned Alerta source, denied requests (missing or
wrong credentials, API keys, read-only users, other customers) that never query the registry
or wait while both alert rows and the registry are locked, a lock timeout, racing ACKs (the
waiting one receives the reloaded alert and gets `409`), a customer change and a binding removal
while waiting, and the version pin; `test_c3_review_probes_r9.py` (VO-ASTRA's, unchanged), gate
refusals rewritten to `200` by an error handler; `test_a1_action_plugins.py`, the plugin
allowlist; and `test_c3_review_probes_r10.py` (VO-ASTRA's, unchanged), subclasses of Voalack's plugin;
`test_c3_review_probes_r11.py` and `test_c3_review_probes_r12.py` (VO-ASTRA's, unchanged) and
`test_c3_response_callbacks.py`, response callbacks, including a forged CORS callable and an
error after a compressed provisional response; `test_c3_commit_outcome.py` and
`test_c3_review_probes_r13_r15.py` and `test_c3_review_probes_r13b.py` (VO-ASTRA's, unchanged), the gated customer and binding at
commit, interrupted COMMITs and API-key existence.

At the commit point the check also requires the alert's customer to be the one the gate saw, the
intent to carry the binding the gate locked (still active), and the intent's action ID, alert ID
and actor (payload and columns) and the capture's alert ID to be the staged ones. If the COMMIT itself fails without
a server verdict (connection lost), the capture is looked up by action ID on a fresh connection:
found means the ACK was saved (`200`); otherwise the outcome is unknown (`503` with
`"outcome": "unknown"` and the `action_id`, "check the alert before retrying"). A server-reported failure is a rollback (`500`). Non-human credentials are
refused before the alert is looked up, so they learn nothing about which alerts exist.

Known limits: an alert bound after the gate found it unbound is acknowledged upstream without a
capture (bind-time serialization is C4 work); `request_finished` receivers registered while
serving are not covered.

## Signed intent v2

`voalack.envelope` holds the pure parts of the signed intent (design "Signed intent v2"): the
exact 24-key envelope and its strict validator, the single-line ONE comment (at most 1024
UTF-16 code units, the operator note truncated first, refused if the attribution alone does not
fit), the named snapshot projection `alerta-9.1.0/stable-identity/v1` (`id, customer, resource,
event, environment, origin`), and MAC signing/verification with ack-core's `INTENT_V2` profile.
The caller supplies the expected deployment, provider and purpose; keys are looked up by
`(deployment_id, provider, purpose, kid)`, never chosen by the payload. The source target kind
must be `triggered_alarm` (no grouped or child alarms); this checks the label only, not vendor
evidence.

In the capture transaction (`voalack.intent`, `voalack.boundary`), for a bound alert:

* **Gate** (after the permission decorator, R15 first): after the alert row lock, the binding
  revision is read and the binding's generation row locked by the owner function
  `voalack.lock_binding`; the complete reloaded alert must match the revision exactly as the
  frozen MVP binding check did (resource, event, environment, origin, `VeeamOneAlarm` and
  `veeamone:` prefix, customer, `veeamAlarmCombinationId`, `captureId`, active Error/Warning with
  major/warning severity, and the snapshot digest). The login must be verified by the pinned
  permission decorator's own call for this route (`User.check_credentials` → `basic`, or
  `Jwt.parse` with default verification and an allowed provider → `bearer:<provider>`); exactly
  one such record must exist. AuthProxy and anything else are refused (`403`). The active policy
  revision must grant this user ID ACK on the alert's customer (`voalack.lock_grant`, `403`
  otherwise). Missing signing configuration or a source mismatch refuses with `503`. One
  `clock_timestamp()` sample sets `issued_at` and the deadlines; these and the action and request
  IDs, actor, customer, binding, policy, key and message revisions are frozen for the request.
* **Staging** (`take_action`, real transition only): `voalack.stage_intent` allocates the
  binding's next generation once and records the intent; a rollback restores the counter.
* **Capture trigger:** also requires the intent's customer, active binding revision and generation.
* **Approval:** the complete envelope is built from the frozen facts, the revision and the final
  ACK note, signed, and stored (canonical bytes, digest, kid, MAC) by `voalack.approve_intent`,
  which links the digest to the capture of the same action, alert, transaction and generation.
* **Request-private originals:** authentication evidence, the frozen gate facts, the revision,
  the signing configuration snapshot and the generation live in storage keyed by the request
  context, not in `flask.g`; `g` holds only a copy, and a changed copy rolls the ACK back. At first
  install the verifiers (`Jwt.parse`, `User.check_credentials`, `User.verify_password`,
  `alerta.auth.utils.check_password_hash`) must be the pinned Alerta 9.1.0 functions (defined in
  Alerta's own module file with the pinned source digest), and their direct verification
  dependencies must be the pinned entry points (bcrypt 5.0.0 `bcrypt.checkpw`, the native
  `bcrypt._bcrypt` function; PyJWT 2.15.1 `jwt.decode`, the global `PyJWT` instance's `decode` with
  the pinned source digest), or startup is refused. The recorders check the installed wrappers,
  the qualified helpers and those exact entry points immediately before and after each
  verification call (a replacement that restores itself during verification records nothing), and
  the gate checks them again. Library internals beyond
  these entry points, the interpreter and native code are not attested.
* **Commit point (and approval):** the alert is reloaded and must still match the revision exactly
  (the full source predicate and snapshot digest). The stored bytes must hash to the digest linked
  to the capture, verify with the key for the expected context, and equal the envelope rebuilt from
  the private originals, the current revision and the final note; the policy grant must still hold;
  and
  `issued_at <= clock_timestamp() < capture_expires_at` (exclusive, live database clock).

Configuration (trusted, never from requests): `VOALACK_DEPLOYMENT_ID`,
`VOALACK_SIGNING_KEY_FILES` (`kid` → key file, 32–128 bytes), `VOALACK_ACTIVE_KID`,
`VOALACK_ALLOWED_AUTH_PROVIDERS`, `VOALACK_MESSAGE_POLICY_REVISION`, and optionally
`VOALACK_CAPTURE_WINDOW_SECONDS` (1–60, default 60) and `VOALACK_EXECUTION_WINDOW_SECONDS`
(capture window–14400, default 14400). Policy grants are by user ID only in this milestone (no role grants).

**Database roles.** `voalack_admin` (no login) owns schema `voalack`, its tables and functions;
`PUBLIC` has no access. `voalack_app` (no login) may read the registry, policy, intents and
captures and execute `lock_binding`, `lock_grant`, `stage_intent` and `approve_intent`; it has no
direct write on any `voalack` table. Alerta's runtime login is a member of `voalack_app` and never
of `voalack_admin`; `install` refuses a runtime role that is a superuser, a member of
`voalack_admin` or the owner of schema `voalack`. Alerta 9.1.0 alters its own tables at startup,
so its runtime login owns them; it could disable the capture trigger, and eligible ACKs would then
roll back for lack of a capture.

Tests: `tests/envelope` (pure; CI job `envelope`), `tests/capture/test_m2_signing.py` and
`tests/capture/test_m3_qualification.py` (copied proof, generations, key rotation, unsigned legacy
rows, message bounds, window limits, policy/binding serialization, log and response surfaces).

## Operator setup (development; not qualified for production)

**Supported versions.** Alerta 9.1.0 (PostgreSQL backend), Flask 3.1.3, flask-cors 6.0.5,
Flask-Compress 1.25, bcrypt 5.0.0, PyJWT 2.15.1, PostgreSQL with `READ COMMITTED` (tested on
PostgreSQL 18.6 from PGDG; other versions are untested). Install refuses
other Alerta versions and unqualified verifiers; other extension versions make their callbacks
unrecognised, so eligible ACKs are refused.

**Roles** (create once, as a superuser):

* a database owner separate from Alerta's runtime login (lab: `alerta_dbowner`, no login);
* Alerta's runtime login (lab: `alerta`), not a superuser, without CREATEROLE/BYPASSRLS, with
  `CREATE, USAGE` on schema `public` (Alerta creates and alters its own tables at startup);
* `voalack_admin` (no login) and `voalack_app` (no login); `GRANT voalack_app TO <runtime login>`.
  The runtime login must never be a member of, or hold ADMIN on, `voalack_admin`.

**Order.**

1. Start Alerta once (or apply its schema as the runtime login) so its tables exist. Until step 3
   is complete, do not serve requests through the Voalack factory.
2. As a superuser, apply `voalack/sql/schema.sql` (`voalack.schema.apply`); it creates the
   protected schema owned by `voalack_admin`, the capture trigger, the owner functions and the
   runtime grants.
3. As an administrator: insert immutable `binding_revisions`, the `bindings` pointer and a
   `binding_generations` row per binding; insert `authorization_policy` grants (user ID →
   customer) and the active `authorization_policy_active` revision.
4. Configure Alerta: `PLUGINS` includes `voalack` (every other plugin with action hooks must be
   listed in `VOALACK_REVIEWED_ACTION_PLUGINS`), no write audit webhook or write audit log,
   `VOALACK_DEPLOYMENT_ID`, `VOALACK_SIGNING_KEY_FILES` (key files readable only by the service;
   keys never appear in SQL, config values, logs or responses), `VOALACK_ACTIVE_KID`,
   `VOALACK_ALLOWED_AUTH_PROVIDERS`, `VOALACK_MESSAGE_POLICY_REVISION`, and optionally the windows
   `VOALACK_CAPTURE_WINDOW_SECONDS` (1–60, default 60) and `VOALACK_EXECUTION_WINDOW_SECONDS`
   (capture window–14400, default 14400);
   out-of-range windows leave signing unconfigured, so bound ACKs are refused with `503`.
5. Serve through `voalack.boundary:create_app`. Startup refuses a privileged runtime role,
   unqualified verifiers, an unsupported Alerta version, unreviewed action plugins or the write
   audit webhook/log.

**Check after setup.** An ACK of a bound alert by a granted user returns `200` and leaves one
intent with canonical bytes, digest, kid and MAC, and one capture linked to it; an unbound alert
behaves as before.

**Refusals for a bound alert.** `403`: API key, Hawk or anonymous credentials (any alert), no
verified login path, or no policy grant. `503`: signing not configured, source differs from its
binding revision, unreviewed response callback or `request_finished` receiver, unsupported
isolation, alert busy, registry unavailable. `500`: the capture or its signed envelope did not
hold at approval or commit (rolled back). `503` with `"outcome": "unknown"` and the `action_id`:
the COMMIT result is unknown: reconcile the original `action_id` (is the ACK and its capture
present?) before any fresh attempt, and never treat a retry as a new action while the original is
unresolved. Voalack logs refusals under the
`voalack` logger without keys, MACs, envelopes or notes.

**Lab only.** The test fixtures' bindings, revisions, occurrence references and evidence digests
are synthetic. Enrolling real ONE alarms and enabling live write-back remain blocked on the
unresolved ONE occurrence, API and authorization questions (U1, U2, U4); this package performs no
ONE I/O.

## Verification and effects (T04 S1; no ONE I/O)

`voalack.verifier` claims a committed capture, verifies its signed intent and promotes at most one
delivery effect. It holds no ONE endpoint, credential or network configuration; S1 has no adapter.

* **Readiness.** Every entry point (`run_once`, `process`, `check_ready`) first checks, fail closed
  with `NotReady` naming each failed condition, that the login is a plain member of
  `voalack_verifier` (not superuser, CREATEROLE or BYPASSRLS, no membership or ADMIN path to such a
  role, to `voalack_admin` or to `voalack_app`, not the database or schema owner, session and
  current role equal, `session_replication_role = origin`) and that the catalog is as installed:
  `voalack_admin` owns the schema, its relations and functions; every SECURITY DEFINER function
  pins `search_path = pg_catalog, voalack, pg_temp`; the login executes exactly the installed
  signatures of `capture_fingerprint`, `claim_verification`, `record_verification` and
  `promote_effect` (another overload of these names is drift), reads
  the tables it needs, and neither it nor any role it can use (inherited or through `SET ROLE`)
  holds a table, column or sequence write privilege or EXECUTE on another Voalack function; no
  function is executable by `PUBLIC` and the global default EXECUTE revoke for `voalack_admin` is
  in place; the immutability trigger is the installed one (`refuse_change`, BEFORE UPDATE OR
  DELETE, FOR EACH ROW, no WHEN or column list) and fires in ordinary sessions (enabled `O` or
  `A`); `effect_key` and `action_id` each have a full, valid, immediate, NOT NULL single-column
  unique constraint (no predicate or expression). Drift is never repaired by the verifier: the
  operator restores the installed grants, owners and objects.
* **Claim.** `claim_verification(claimant, lease_seconds ≤ 300)` takes one capture without an
  effect or a refusal, `FOR UPDATE SKIP LOCKED`, never-claimed captures first, and bumps its claim
  epoch. A lease is coordination only: every later call names its claim epoch and fails once a
  newer claim exists or the lease has expired. (Claim epochs are not the ACK generations of
  `binding_generations`.)
* **Verify** (in the verifier process, against the trusted context and key ring): signed intent
  present; stored bytes hash to the intent's and the capture's digest; strict v2 verification;
  `kid`, action, alert, request, generation, customer, binding and revision equal the stored
  intent and capture; capture transaction and alert link; actor equals the capture's history
  user; the captured history entry is an ACK with status `ack`, its note and time equal the
  finalized facts stored at approval, and its note reproduces the signed `message` through the
  reviewed normalization and truncation; source fields equal the immutable binding revision;
  stored deadlines equal the signed ones; capture inside its original window; database clock
  before the signed execution deadline (exclusive). An unknown `kid` is a `hold` only until the
  stored original execution deadline; after it, `refused: expired`.
* **Record.** Each run appends an immutable `verifications` row (`verified`, `refused` or `hold`,
  reason, verifier version, kid, digest, and the SHA-256 fingerprint of the complete intent and
  capture rows it checked); a later outcome is appended, never rewritten.
* **Protect.** From `record_verification` to the end of the transaction, the original intent and
  capture rows are locked `FOR SHARE` (locked before the claim row, the same order as claiming), so
  they cannot change between the fingerprint comparison and commit; other claimants skip a capture
  being promoted.
* **Promote.** `promote_effect` runs in the same short transaction, with `lock_timeout` (default
  2 s) and `statement_timeout` (default 10 s) set by the verifier. It requires the claim to be
  current, the verification to be this claim's `verified` row for the stored digest and for
  unchanged, now protected rows (same fingerprint), then locks `FOR SHARE`, in the capture path's order, the
  active binding on the same revision, the binding's generation row (which must still equal this
  intent's generation: a newer committed ACK supersedes it) and the active policy pointer (which
  must still grant the signed revision to this user and customer). Policy, binding and generation
  changes wait for the promotion; a promotion that waited behind a committed change refuses. After
  the effect insert, the last local step, it re-checks the real clock against the original
  deadline and the claim's lease; a failure there undoes the insert. Refusals are appended with
  their reason (`capture_changed`, `binding_changed`, `generation_superseded`, `policy_revoked`,
  `expired`); a key held by another action is `hold: effect_key_taken`. A wait that exceeds the
  lock or statement timeout records nothing (`deferred`); the claim lapses and is retried.

Roles: `voalack_verifier` (no login; lab login `lab_verifier`) reads intents, captures, bindings,
revisions, policy and the ledger, and executes only the four functions above. `voalack_app` gets
nothing new.

**Timestamp precision.** Alerta registers a process-wide psycopg2 adapter that writes every
`datetime` floored to milliseconds. Voalack binds its signed timestamps as the exact signed UTC
strings with `::timestamptz` casts, both when staging the intent and in the commit-point window
check. Intents staged before this change store floored values: the verifier holds exactly that
pattern as `hold: legacy_deadline_precision` until the signed execution deadline passes, then
refuses it as expired; any other difference is `refused: deadline_mismatch`.

Tests: `tests/capture/test_t04_s1_verifier.py` (tampered, copied, unsigned and unknown-key
intents, revoked policy, re-revisioned binding, expiry, stale claimant, competing promotion, role
denials, immutability), `test_t04_s1_timestamps.py` (adapter behaviour, exact stored values,
microsecond window and deadline boundaries, legacy rows) and `test_t04_s1_corrections.py`
(superseded and concurrent newer ACKs, original history and message, capture changed before
promotion, policy and binding changes during promotion, bounded waits, deadline and lease lapsing
during promotion, unknown key past the deadline, claim fairness, original rows protected during
promotion, readiness and drift) and the review probes `test_t04_s1_review_probes_034ba00.py`.

## Session owner and attempts (T04 S2; fake ONE provider only)

`voalack.sender.OwnerSession` owns one configured ONE instance for one process incarnation and is
the only send path. It holds no real ONE endpoint or credential in this stage: the provider is a
loopback fake (`fake-one/v1`) in the test guest.

* **Ownership.** `session_owners` has one row per instance. `acquire_owner` succeeds only from
  `free` or `contained`; nothing expires into a takeover. Every call is fenced on instance,
  generation and the process incarnation, so a restarted process cannot reuse the old generation.
  An owner that loses its database, sees a fence, or cannot know a COMMIT outcome stops issuing
  requests at once and only then tries to write `suspended`. `record_containment` (administrator
  only) needs evidence that the old process has stopped and no request is still executing. An owner
  is bound to the credential and configuration revision it acquired under; any change stops it, and
  a credential can back only one instance.
* **Attempts.** `start_attempt` re-checks eligibility (S1's binding, generation, policy and
  fingerprint checks, plus accepted kid and verifier version), takes the effect and a guard on the
  physical target `(instance, target kind, target id)`, and stores the request bytes built in SQL
  from the signed envelope. `consume_dispatch` is the last local boundary: it re-checks everything,
  including the deadline after all waits, and turns the one-time permit into `dispatched`, or
  definitively aborts the attempt and releases its guard. After that COMMIT is known, `check_dispatch`
  repeats the owner, eligibility, configuration and real-clock checks in the same invocation; any
  failure holds the consumed attempt uncertain. The adapter then sends the returned bytes once,
  within a short hand-off bound, and fences again before the read-back. It logs in only for an
  attempt that is already durable, and a lost database stops the owner locally at once. Only HTTP
  200 responses can confirm.
* **Outcomes.** Only an attributable fake success (operation id equal to the request digest and a
  matching read-back) is `REMOTE_CONFIRMED`. Everything else after dispatch, a crash after
  consumption, an unknown consume COMMIT and attempts left by a contained owner are `UNCERTAIN`;
  the physical guard stays and nothing is resent. Late results from a fenced owner are kept as
  evidence only.

Roles: `voalack_sender` (lab login `lab_sender`) reads effects, attempts, guards, owners and
instance configuration, executes only the owner and attempt functions, and passes the same
readiness checks as the verifier with its own profile. Readiness also refuses any SELECT (table,
column or sequence) outside a profile's listed reads.

Tests: `tests/capture/test_t04_s2_sender.py` with the loopback fake provider in
`tests/capture/fake_one.py`.

## Transport, not-sent and retry (T04 S3a; fake ONE provider only)

Each ACK uses a dedicated connection with implicit reopening disabled: an explicit connect, the
final authority again after the connect (database, committed before any byte), then the single
write. Only a connect step that failed with no socket is `not_sent` (`record_not_sent`, terminal for
that attempt; the guard is released and the effect becomes retryable after a durable backoff, or
`BLOCKED` after three attempts in total). Every failure after a successful connect — including
HTTP 401/403/429/5xx, resets, partial writes and timeouts — is uncertain and never retried.
`apply_with_retry` retries only after a known-committed `not_sent`; the budget, backoff and retry
lineage are enforced by `start_attempt`: only the live owner process that recorded the `not_sent` may
retry. An effect whose lineage belongs to a stopped or replaced process stays `QUEUED` and is never
resent; it can only be retired neutrally (`BLOCKED`, a later reviewed stage), and a new delivery
needs a new captured human action. The not-sent evidence records the kernel's connect error
(class and errno) from the original attempt. Preflight requires the fake's explicit `kind = triggered_alarm`; a grouped
or child target is closed without dispatch (`BLOCKED`).

Tests: `tests/capture/test_t04_s3a_transport.py`.

## Reconciliation and settlement (T04 S3b; fake ONE provider only)

An `UNCERTAIN` attempt stays `uncertain` for good; its resolution is one append-only settlement.

* **Reconciliation** (`OwnerSession.reconcile`) only reads. The current fenced owner reserves one
  read of the attempt's original target (taken from the attempt, never a binding), commits, checks
  its fence again, reads, and records the observation under the original identities and its own.
  A configuration change, fence or lost database stops the owner and keeps the guard.
* **Classification** is strict: `attributable` (our operation id, exact comment, completed),
  `acked_by_other`, `acked_unattributed`, `not_acked`, or `evidence_only` for anything else.
* **Automatic settlement** happens only for `attributable` (`REMOTE_CONFIRMED`).
* **Operator settlement** (`voalack.settler.settle`, role `voalack_settler`, lab login
  `lab_settler`) records `confirmed_by_operator` or `superseded_remote` (`ALREADY_ACKED`, no
  attribution claim) or `retired_after_quiescence` (`BLOCKED`; not proof the old action had no
  effect). Every holder of the target must be contained and quiescent: every provider session it
  opened (registered by digest before use) revoked and then seen with no executing request. The
  read must come from a successor reserved after that.
* **Decisions** are idempotent by decision id; nothing returns an effect to `QUEUED`. A new
  delivery needs a new captured human action.

`record_quiescence`, like `record_containment`, is an administrator function. The settler reads
`attempts` through an explicit column list without `request_bytes`, and readiness refuses any other
column or a table-wide grant.

Tests: `tests/capture/test_t04_s3b_settlement.py`.

## Supervised database recovery (T04 S3c; fake ONE provider only)

> **Current release: no supported restore.** With coexistence 3a installed (S1-S3b, this release), the staged
> restore and backup-bound recovery described below refuse and leave the anchor and the data unchanged
> (tests `test_s3a_staged_*`). Recovery markers from earlier layouts grant no restore authority. This section
> describes the T04 S3c/S4 design and its historical evidence for Voalack-only and pre-3a shared layouts. A
> supported restore for the protected installation (the planned coexistence restore, 3a S3c) is not part of this
> release, and no replacement procedure has been tested.

A restore of the Voalack database to an earlier point can make finished or possibly sent work look
unsent. S3c makes the authority to use the provider depend on a record the restore cannot roll back,
and adopts a restored database without resending anything.

* **Recovery anchor.** `voalack.recovery` keeps a supervisor-written, hash-chained log outside the
  database (`anchor.log` in a fixed directory): `open` → `closed` → `inventoried` → `recovering` →
  `open` at the next epoch. Linked documents (inventory, review, adoption manifest) are
  content-addressed files with exact schemas. Workers only read it; any read or validation failure
  counts as closed, including a missing or changed document while the anchor is open.
* **Epoch gate.** An ordinary owner acquires only at the anchor's open head, which the database
  (`recovery_epoch`) must name; a maintenance owner (recovery reads only) acquires only at the
  `recovering` head. Every gated function checks the owner's epoch and anchor line after
  its database waits. The worker re-reads the anchor last before every provider operation and both
  final ACK checks, and stops on any change. A close makes every gate refuse.
* **Live journal.** Each owner keeps a volatile journal of its attempts, written before each permit
  consumption, and stops when the database shows a regression of its own work (for example after an
  unannounced restore).
* **Supervised procedure** (administrator): close; stop, contain and quiesce every owner, and record
  a credential-wide provider cleanup (`record_recovery_cleanup`); take the complete inventory
  (`recovery_inventory`); restore only while the anchor names that inventory; record a review that
  binds the backup's exact bytes; adopt (`adopt_recovery`); reopen (`open_recovery`). Close, adoption
  and reopening support retrying their partial transitions after a crash. Resume from the validated
  anchor phase and the documents already published; do not blindly repeat every completed step (for
  example, the inventory cannot be taken again once its line is published).
* **Holds.** Adoption permanently blocks every effect key whose facts differ between the inventory
  and the restored database (it never sends again) and holds every physical key with unresolved work
  or a restored guard. Holds and their frozen holder proof survive later recoveries.
* **Release.** In the `recovering` phase a maintenance capability may only read held keys
  (`recovery_read`). The settler (`voalack.settler.settle_hold`) releases a hold after such a read,
  inventory quiescence and cleanup of every holder. It releases only guards whose attempts still
  carry the complete frozen identity; their effects become `BLOCKED`, never `QUEUED`.

* **Shared database (added in S4).** Voalack and Alerta share one database, and Alerta's
  `public.alerts` carries Voalack's capture trigger, which depends on `voalack.capture_ack()`. The
  bare restore command (`pg_restore --clean --if-exists` of a `pg_dump -Fc -n voalack` dump) therefore
  fails there; the S3c tests restored Voalack-only copies and did not cover this layout. Use
  `voalack.recovery.restore_shared(anchor, admin_dsn, dump, inventory_sha256, journal_dir,
  layout="shared")` instead:
  * it runs only while the anchor is inventoried with that exact inventory;
  * it refuses any cross-schema dependency other than the capture trigger, and any capture trigger
    that differs from the approved definition;
  * it detaches that one trigger, runs the unchanged restore (a non-zero exit is a failure), and
    recreates the trigger from the installed schema source;
  * it validates the result.

  Each step is journaled in `journal_dir` (outside the database and the anchor; one run at a time per
  inventory). After a crash, run the same call again. A torn or out-of-order journal, or a trigger
  missing without a journaled detach, is refused for manual review. While the trigger is detached,
  an eligible Alerta ACK fails with an error and its local ACK rolls back.
* **Declared layout.** `recover()` and `reopen()` take `layout="shared"` or
  `layout="voalack_only"`, which is never inferred. For a shared database restored from a backup,
  both also require that restore's validated journal (`journal_dir=`), bound to the reviewed backup.

Limits: an announced, supervised, database-only restore of the same schema version, with a trusted
supervisor and administrator. Rollback of the anchor itself, whole-machine or cross-host restores,
an unannounced restore seen by a fresh process, and live ONE remain open. The shared-layout route
behaviour (an ACK while the trigger is detached) is tested on the lab database, step by step.

Tests: `tests/capture/test_t04_s3c_recovery.py`, `test_t04_s3c_restore.py`,
`test_t04_s3c_corrections.py`, and the review probes `test_t04_s3c_review_probes_ea8c30a.py` and
`test_t04_s3c_b5e8191_extra_review.py`.

## Operator projection (T04 S4; fake ONE provider only)

S4 shows each delivery, settlement and recovery outcome as one Alerta note on the alert the human
acknowledged. Projection is display only: it cannot send, settle, release a hold, requeue or create
an intent.

* **Outcome events.** Database triggers on effects, settlements, recovered effects, recovered holds
  and hold settlements append one immutable event per operator-visible change
  (`voalack.outcome_events`), in the same transaction and in statement order. Each event records:
  * its recovery epoch and a dense per-action revision;
  * the destination (alert and customer, taken from the accepted intent, never from current
    attributes);
  * the exact note text and time, and a SHA-256 digest over them. The note id is derived from that
    digest (RFC 9562 UUIDv8).

  Every code path that records an event first locks the recovery epoch row.
* **Projector.** `voalack.projector.run(dsn, anchor_dir, name)` (role `voalack_projector`) publishes
  one note per event through `voalack.project_next`, in one transaction: the note in `public.notes`,
  its protected publication record, its marker and its position. It pauses unless the database is
  open at the anchor's head. Writing notes directly means no Alerta route or action hook runs, so a
  projected note can never create an intent.
* **Ordering.** The latest *published* event, by (epoch, revision), decides what is current.
  Publication records live in schema `voalack_publication`, which the supported Voalack-only restore
  does not touch. Ordinary notes cannot change the order, even forged ones, because Alerta's own
  login can write notes.
* **Explicit outcomes.** The following are recorded as markers, never overwritten or republished:
  * an older event: `superseded_by_publication`;
  * a reused revision with different content: `publication_conflict`;
  * a changed or deleted alert: `destination_conflict`, a stop;
  * an unproven note holding the derived id: `note_conflict`, a stop.

  `voalack.projector.status(conn, action_id)` reports the latest publication, and whether its note
  is still exactly as published (`valid`, `altered` or `missing`).
* **Failure.** A failed notes write retries only the projection; nothing on the delivery side runs
  again. After an unknown COMMIT, `voalack.projector.resolve` checks the event, marker, publication
  and actual note together.
* **Upgrade.** `voalack.backfill_projection_snapshot()` (administrator, once) adds one snapshot event
  for each existing action that has no events.

Setup: create `voalack_projector` (no login) and a projector login in it. Schema application (as a
superuser, after Alerta's tables exist) grants the definer role `voalack_admin` `SELECT, INSERT` on
`public.notes`, and `SELECT, UPDATE (id)` on `public.alerts` for the row lock. It refuses any other
right there, and refuses a `public.notes` table that is not Alerta 9.1.0's layout. Every worker's
readiness check also covers the event triggers, the publication schema and access to Alerta's
tables.

Limits: Alerta 9.1.0 in one database shared with Voalack; display only. A stopped action
(`destination_conflict`, `note_conflict`) shows no later outcome; delivery continues. S4 provides no
procedure to clear the stop: its conflict marker is immutable and still blocks later revisions after
the note or alert is changed, and resolution requires a separately reviewed procedure outside S4.
`status` and `resolve` only inspect state; `resolve` addresses an unknown COMMIT and cannot clear a
stop. Altered or missing published notes are reported, never repaired or republished. The
`voalack.epoch_pin` setting is an internal guard, not a capability (any
caller can set it); runtime roles cannot write event sources or call the private helpers. Live ONE,
target Alerta deployment, and rollback of the whole database or of the publication records remain
open. Mirroring ONE's own acknowledgement state into Alerta is not offered; see
[`design/T05_REVERSE_STATE.md`](../../design/T05_REVERSE_STATE.md).

Tests: `tests/capture/test_t04_s4_projection.py`, `test_t04_s4_recovery.py`,
`test_t04_s4_shared_restore.py`, and the review probes `test_t04_s4_review_probes_399eb4b.py`.

Not yet: C4 concurrency and privacy, C5 role matrix, role-based policy grants, PgBouncer,
multi-node.

## Ledger-only source observer (T05b; fake ONE provider only)

T05b can record what Veeam ONE currently shows for a bound alarm, in Voalack's own ledger only. An
observation never sends an ACK, writes an Alerta note, settles an attempt, releases a hold or creates
an intent. It is **off by default**.

* **Switch.** `voalack.instance_config.observer_enabled` (default `false`). Changing it bumps
  `config_revision`, so every running sender of that instance is fenced and must be reacquired
  before it can observe or send again.
* **Reading.** `OwnerSession.observe(alert_id)` reserves the read in the database first
  (`voalack.begin_observation`), checks the owner fence again, logs in if needed, does one GET of the
  bound target, and records a typed, minimised summary (`voalack.record_observation`). A refused
  reservation uses no credential and no network. The summary keeps field states and SHA-256 digests
  only, never the comment text; a comment that is not valid Unicode is recorded as invalid.
* **Admission.** The record is admitted by one SQL statement after every lock wait: owner fence and
  saved acquisition pin, configuration, flag, binding and ambiguity, and any holder of the target. A
  refused record stores nothing.
* **Classification** is derived in SQL in a fixed order (unreadable, invalid, contradictory,
  not_acked, acked with our matching completed operation, acked with a known request hash, acked by
  another operation, acked with an unverified marker, acked unattributed). It is history only: no
  other function reads the observation tables, and no observation can become settlement evidence.
* **Status.** `voalack.observation_status(alert_id)` (administrator only) returns the latest stored
  state of each chain (one per binding revision and physical key) and completion counts.
* **Installation audit.** `voalack.observer_audit.audit(cursor)` (as the administrator) compares
  the named observer objects (tables, columns, sequences, constraints, function metadata, the six
  named triggers, ACLs) with the frozen inventory shipped as `sql/observer_inventory.json`. It
  detects drift in that named structural metadata only: it does not compare function bodies, does
  not look for extra unnamed triggers, and checks sequences by type, start and increment only. It
  is not a complete installation or full-catalog check. Sender readiness separately refuses a
  missing flag-fence trigger or observer uniqueness constraint.
* **Upgrade.** Applying the schema to an S4 installation adds the observer switched off, keeps every
  existing row and revision, and can be repeated: a reapplication keeps the flag, the revision, the
  observation history and the reservation sequence. A failed application rolls back entirely.
  Downgrade is not supported.
* **Recovery.** Observations are not part of the recovery inventory (deliberately: they confer no
  authority). A supervised restore keeps the observation history that the backup contains; anything
  observed after the backup point may be lost. A restored owner from before the restore is fenced, a
  reservation left without a completion can never be recorded by another reader, and a fresh owner
  observes only after the supervised reopen. Both the Voalack-only and the pre-3a shared-database
  procedures were covered at their historical commits; with coexistence 3a installed the supervised
  restore refuses (see "Current release: no supported restore" above).

Limits: fake ONE provider only; one GET per call, no scheduler; function bodies are not covered by
the installation audit; observations are not mirrored into Alerta (see
[`design/T05_REVERSE_STATE.md`](../../design/T05_REVERSE_STATE.md)).

Tests: `tests/capture/test_t05b_s1_observer.py`, `test_t05b_s2_observe.py`,
`test_t05b_s3_observer.py`.
