# T01 — Voalack acknowledgement integration design


> **Derived document.** Published copy of the signed design record `T01_DESIGN.md`
> (SHA-256 `f082463bf716206a4e94e458b48d1cb06543c8c5df6ddbdd70c8a2cb0ef7b91f`), which the project keeps unchanged. The assignment and transport bindings were replaced by the inputs list below.
> No technical content was changed.
2026-10-01 · codex-voalack / Astra · revision 1

**Verdict: DESIGN_READY for VO-LEAD's implementation review.** This is a source-based
design, not implemented behavior, a test pass, deployment approval or permission
to enable remote writes. The required transaction adapter and unresolved ONE
occurrence guarantees below are explicit implementation/enablement gates.

The owner confirmed the product scope: alarms flow from ONE into Alerta, and a
Service Desk operator's Alerta acknowledgement goes back to ONE with visible
integration and human attribution. This is the requested Zabalack-like behavior.

## Inputs and provenance

| Input | Identity |
|---|---|
| ACK MVP ZIP | `bcb91cb5a60dd2cfc9fb894c37081995b07c56712c089aa6dc2de4cd98e57ee0` |
| Redacted feed ZIP | `8b9610dd1698387a4473eb3ca09e323921c1756f0fb57b6640976256d340f9c0` (the design was written against the step-1 redaction `077067b2…`; step 2 changed only README text and example config values, see `inputs/INPUTS.md`) |
| Zabalack reference | `494768d8c41c230a124b7c748ebaec10e7d4b6ad`, tree `d47d4c0e1f30d1f6f6a885ae8d4f198dcd9749f5` |

The inputs were verified against their recorded hashes, and the 85 files of the Zabalack
reference subset against Git blobs at the stated commit. The older
`a3317dc41890ef56411e7597b32c44c70b878416` (`main` at preparation time) is comparison
evidence, not the selected source. The capture-plugin delta between the two adds
logging-extra/query-string redaction; retain that protection. The private reference
subset is not republished. No original production hostname is needed in this design.

Source locations below are relative to their supplied archive roots. Product
tests/builds were **NOT_RUN** during this design review; historical MVP test
counts are not new results. No ONE/Alerta live endpoint was contacted. Public
upstream source and documentation reads are listed at the end.

## ADR-001: extract a small pure library, keep provider state separate

Build three independently installable distributions: existing Zabalack, Voalack,
and a small ACK library (package names remain provisional). Initially extract
only canonical encoding/HMAC primitives, bounded validation helpers and small
typed outcome definitions. Prove two consumers with an isolated Zabalack v1
compatibility wrapper and Voalack v2. Preserve Zabalack v1 bytes, marker grammar,
validation outcomes and key configuration; do not migrate installed Zabalack.

Do not extract the database schema, worker scheduler, Alerta hooks or remote
client into a universal framework. Their policy and failure semantics differ.
Use their contracts and regression cases to implement a separate `voalack`
schema and ONE adapter. The core has no Alerta, PostgreSQL, HTTP or provider
runtime imports, background threads, credential loading or schema lifecycle.
No plugin imports undocumented internals of the other distribution.

Pure extraction with wrappers is preferred to a wholesale copy: it proves
actual reuse while minimizing changes to the existing consumer. Contract-only
reuse is appropriate for the stateful components below. Wrapping the entire
Zabbix worker is rejected: it resolves Zabbix-specific cohorts/events and permits
concurrency that does not establish ONE session safety.

### Reuse decisions R1–R8

Blob prefixes are those in the verified inventory at `494768d`; tests named here
are obligations, not claims that they ran against a new core.

| Row | Decision and dependency boundary | Invariant and regression obligation |
|---|---|---|
| R1 `crypto.py` (`05203f73`) | **Extract** canonical encoding and fixed-profile HMAC primitives; **wrap** v1 in Zabalack. Keep provider validators outside the core. V2 has its own grammar/domain/key namespace and binds the message. | No v1 byte changes; strict types/key sets, UTF-8 bounds, constant-time MAC comparison, unknown key means hold. Carry `test_crypto_policy.py`, `test_binding_boundary.py`, proof-redaction cases; add v1/v2 cross-provider substitution and fixed golden vectors. |
| R2 `policy.py` | **Contract-only**. Implement Voalack's human, customer and binding policy explicitly; reject importing Zabbix numeric-ID/cohort logic. | API keys and mutable attributes cannot manufacture actor authority. Default/read-only users cannot ACK; Service Desk/Escalation need no delete grant. Include cross-customer, forged actor, null customer, admin exception and revoked-policy cases. |
| R3 `plugins.py` (`62f54e41`) | **Contract-only**. Reuse final-effective-route checks and privacy lessons. Reject copying staged intents into alert attributes. Requires the transaction adapter below. | No unsupported route signs; no staged intent in JSON/JSONP/history/search/count/group/sort/error/log output. Carry T40/T41 intent/privacy/retirement cases, routing tests and `test_access_log_route.py`; actual query-builder rebinding must be covered. |
| R4 migrations 001–013; `008_generation_fence.sql` (`0f157827`); trigger (`71ffa283`) | **Adapt contracts into a separate schema**, not an installed-schema rename/copy. Narrow application, verifier, session-owner, projection and operator SQL APIs. | Durable action/effect uniqueness, monotonic generations, stale/late attempt evidence, fail-closed catalog readiness, safe migration order. Carry generation, stateful-ledger, late-response, settled-expiry, abandoned-attempt, ambiguous-API and migration refusal cases on real PostgreSQL. |
| R5 `worker.py` (`002fceb1`) | **Contract-only initially**; share outcome types, not its loops/SQL facade. ONE gets one session owner across reads and writes. | Verify before endpoint/credential resolution, separate verification from delivery, durable attempt before send, no uncertain resend. Carry `test_worker.py`, `test_delivery_invariants.py`, worker-path/native-fault tests with ONE-specific oracles. |
| R6 `reconciler.py` (`f6fcc004`) | **Contract-only**; implement ONE reads separately. Do not inherit Zabbix marker/history evidence semantics. | Reconciliation cannot mutate ONE. Absence of marker/ACK is not proof of no prior effect. Carry reconciler scheduling, drift, late-result and source-observation cases. |
| R7 `rpc.py` (`deb23dcc`), `config.py` | **Extract or narrowly wrap** demonstrably pure protected-file/bounds helpers after inspecting their imports. Keep endpoint policy, HTTP client, login/revoke and provider error classification local. | Admin-fixed logical instance lookup, TLS, no redirects/inherited proxy, bounded body/time, no secrets in exceptions. Carry `test_rpc.py`, `test_rpc_boundaries.py`, protected-file owner/mode/symlink and config consistency cases. |
| R8 design/security/amendment documents | **Reference contracts**, not copied product claims. Read amendments over older diagrams. | G1–G8/B1 gates stay with Zabalack. A5's intermediate commits and privacy failures, A6's ambiguity and source-versus-deployment distinctions remain explicit. |

The reference is Apache-2.0. Preserve LICENSE, NOTICE, copyright headers,
upstream Alerta notices and changed-file provenance for actual extracted code.
Record each original full Git blob ID and new file digest in the implementation
change. Nothing in this design re-licenses material or proves third-party package
name availability. Zabalack's Python `>=3.12,<3.13` remains the initial two-consumer
qualification target; widening it is a separate tested compatibility change.

## Trust and authorization

Only a server-authenticated human single-alert `PUT /alert/<canonical UUID>/action`
with `action=ack` and an actual legal transition to ACK can create an executable
intent. `/status`, notes, bulk, ingestion, unack, close and integration projections
cannot do so. Ignore actor/provider/customer/target assertions in request text or
mutable alert attributes. API-key ownership is not human authentication.

Keep existing Duo/OIDC configuration, customer visibility, plugin lists and role
mappings. In particular, **do not copy Zabalack's requirement to enable
`CUSTOMER_VIEWS=True`** into a deployment intended to let engineers see all clients.
Visibility and permission to acknowledge a mapped customer are separate checks.
Use authenticated user ID/login and verified server role/scope information against
a versioned, administrator-owned integration authorization policy. Map the existing
Engineer/Service Desk/Escalation roles to ACK only; default users remain read-only.
The policy must explicitly identify customer/source scope, including approved
cross-customer engineers and administrator exceptions. No delete permission or
new upstream administrator privilege is granted. If the deployed claims/roles
cannot be verified, keep write-back disabled; use labeled synthetic claims for
development. A non-null top-level customer is necessary but not provenance.

Resolve targets through a protected binding registry. Alert attributes may help
compare a source snapshot, but cannot select an endpoint or authorize a binding.
Recheck the binding/policy revisions before promotion and before send; revocation
blocks queued work. A different revision is not permission to retarget an old
intent. Missing keys/configuration are holds, not forged-proof accusations.

## Signed intent v2

The shared library exposes named, fixed profiles; it does not let an untrusted
payload choose arbitrary signing domains, algorithms or validators. V1 remains
`zabalack\x00v1\x00` with its unchanged wrapper. V2 signs exactly:

```text
HMAC-SHA256(provider_key,
  b"alerta-ack-core\x00intent\x00v2\x00" + canonical_json(envelope))
```

V2 verification receives an **expected provider** from the trusted consumer and
selects keys by `(deployment_id, provider, purpose, kid)`; never by the untrusted
payload alone. Use fresh provider-specific secrets. Even accidental reuse of the
same secret must not let a v1 proof or a v2 Zabbix intent validate as a ONE intent.

The envelope has exactly these top-level keys (no extension bag):

| Keys | Meaning and source |
|---|---|
| `version`, `purpose`, `algorithm`, `kid` | Exact `2`, `human_ack_intent`, `HMAC-SHA256`, approved bounded key ID; all signed. |
| `deployment_id`, `provider`, `customer`, `source_namespace`, `instance_id` | Trusted logical identifiers; provider is `veeam_one` for this consumer. No URL or credential reference from the alert. |
| `alert_id`, `action_id`, `request_id` | Canonical UUIDs. Server-generated action/request IDs; a client idempotency hint is never authority. |
| `generation`, `binding_id`, `binding_revision` | Positive DB-assigned per-binding/alert generation and immutable administrator registry revision. |
| `source` | Exact object `{target_kind, target_id, occurrence_ref, occurrence_evidence_sha256, snapshot_sha256}`; ONE validator requires single triggered alarm, canonical positive target ID and approved occurrence evidence. |
| `actor` | Exact object `{user_id, login, auth_type, authorization_policy_revision, authorized_customer}`; server-owned human context, no full customer directory. |
| `route`, `action` | Exact canonical action route and `ack`. |
| `message`, `message_policy_revision` | Exact final normalized ONE comment bytes as a Unicode string, including attribution/opaque correlation reference; constructed before signing. |
| `issued_at`, `capture_expires_at`, `execution_expires_at` | Canonical UTC timestamps; initial capture window 60 seconds and execution lifetime 4 hours. Policy may shorten, never silently extend old intents. |

JSON encoding: UTF-8, sorted keys, compact separators, `ensure_ascii=False`,
`allow_nan=False`. Reject duplicate object keys on decode, floats, bool-as-int,
unknown keys, invalid/lone surrogates, forbidden controls and noncanonical UUIDs,
IDs/timestamps. Do not Unicode-normalize a signed string during verification.
Cap the canonical envelope at 16 KiB; IDs at documented byte bounds (128 bytes
for logical IDs, 256 for login), marker at 256 bytes and inbound note at 8 KiB.
Normalize newline/control handling and bound the ONE comment to at most 1024
UTF-16 code units **before** signing. Preserve required marker/attribution; if
those alone overflow, reject rather than truncate their identity. The caller
cannot alter/comment-append after signing. V1's lack of this message field is
not retroactively changed.

The normal ACK history may carry an opaque suffix such as
`[voalack:v2 action=<uuid> kid=<kid> mac=<64 lowercase hex>]`. Its action, key ID,
MAC and grammar must agree with the protected sidecar envelope. Do not expose
the envelope or actor directory in attributes. A copied committed marker cannot
create another eligible effect: capture records bind exact alert, generation,
history identity and payload digest and enforce unique consumed action identity.
Reject nested/duplicate/reserved proof prefixes. A correlation marker visible in
ONE is a reference, not a ONE idempotency token or proof that our actor acted.

Deduplicate verified effects by `(deployment_id, provider, customer,
source_namespace, instance_id, target_id, occurrence_ref, action)` as well as
unique `action_id`. Do not let an unverified candidate reserve that effect key.
Repeated transport delivery does not create a generation. An intentional fresh
human action gets a new action ID but cannot bypass an unsettled occurrence-level
attempt or reuse a retired binding. Verification, delivery and source occurrence
generations are distinct counters.

## Local transaction contract: capture before any remote operation

The MVP's `post_action()` calls `run_ack()` after Alerta has saved the ACK. That
is not a durable queue. A kill there can leave a local ACK without any intent,
attempt or note. Adding an outbox insert in that callback would preserve the gap.

Upstream's action route runs pre-action processing, `from_action`, then
post-action processing. `from_action` builds the normal ACK history and calls
`db.set_alert`. That final database update is the useful atomic capture point.
The PostgreSQL backend commits inside its update helper. Ordinary action/status
plugin processing also writes tags and whole attribute dictionaries separately.
These facts prevent treating the whole request as a transaction without an
explicit adapter. See the pinned upstream references below.

The Zabalack source stages its generation and unsigned intent in an earlier
committed operation, then captures candidate evidence with a trigger on signed
ACK history. It does not make preparation and ACK a single transaction. Its
amendment A5 documents the privacy/fencing consequences. Preserve those lessons,
but do not copy its attribute staging into this integration.

**Selected design:** a narrowly scoped, version-pinned Alerta 9.1 PostgreSQL
transaction adapter plus a separate `voalack` sidecar schema. It is an explicit
T03b deliverable, not something ordinary PluginBase hooks already supply.

1. Retain the real authenticated action route and authorization checks. For an
   eligible registered Voalack ACK, acquire the request's PostgreSQL connection
   and lock the exact alert row before invoking action plugins. Refetch the
   snapshot under that lock; preserve standard legal-transition behavior.
2. Enter an explicit request-local transaction context in the supported backend
   adapter. All tag, attribute, status and history writes in this path use that
   same connection. Upstream helper commits are deferred to the outer boundary;
   no private connection, autocommit, nested commit or alternate backend can
   escape. Outside this context ordinary Alerta behavior is unchanged. Do not
   patch process-global connection methods or assume connection-pool affinity.
3. Validate actor, trusted binding and source snapshot; allocate the protected
   generation and stage the bounded envelope in `voalack.prepared_intents` in
   this transaction. The last effective signing callback freezes the actual
   message and context. Only normal ACK history receives the opaque proof suffix.
   No envelope/staging attributes are written to `public.alerts`.
4. The final `set_alert` statement invokes a reviewed `AFTER UPDATE` capture
   trigger. It matches a new ACK history record, exact UUID/customer/binding/
   generation, and immutable sidecar payload; it inserts candidate capture and
   verification-queue rows in the same transaction. The trigger need not possess
   the signing secret: an unverified candidate is never deliverable work.
5. Before the sole outer commit, assert that the exact eligible action has both
   its local ACK history and capture/queue records. Trigger disabled/drifted,
   missing candidate, unexpected routing or failed insertion rolls back the
   eligible ACK. Health checks are useful but cannot replace this transaction's
   postcondition. Run post-action processing only after a successful commit;
   the old synchronous ONE-writing hook is not in the eligible route.
6. The worker claims a verification lease, verifies the proof and current policy,
   then promotes exactly one eligible effect. Endpoint and credential lookup
   happens later. No request handler performs ONE network I/O.

The adapter must preserve existing plugin policy hooks and normal timeout/history
semantics; bypassing them to obtain atomicity is unacceptable. An unsupported
plugin that commits through another connection or performs a pre-commit external
side effect makes that routing configuration ineligible. If the pinned backend
cannot provide this transaction context safely, **block durable enablement** and
submit a narrow alternative integration proposal; do not silently fall back to
post-action capture. This is the main implementability check requested of VO-LEAD.

Row locking across this short local transaction also prevents stale whole-object
attribute writes from overwriting a newer ingestion update between action hooks.
No lock is held across a ONE call. Use one documented lock order: exact alert row,
binding/generation row, then capture/effect rows; code that only appends attempt
evidence must not invert it. Projection takes the same order when it needs both.
Use bounded waits and transaction-local timeouts; any deadlock abort is a failed
local transaction, not a successful ACK.

| Interruption | Required durable observation |
|---|---|
| Before local commit, including after staging | Neither this action's ACK nor its capture/queue is committed. |
| Capture insertion or commit fails | ACK transaction rolls back; report a local failure. |
| Commit succeeds, HTTP response is lost | ACK and candidate remain. Look up original action before considering a fresh request; do not replay by absence of UI response. |
| Process dies after commit, before worker | Candidate remains verifiable; no local-ACK/no-intent gap. |
| Worker dies after attempt is recorded | Treat as possibly sent until positively settled, even if it might have died before network send. |
| Remote succeeds, projection fails | Retain remote evidence; retry projection only. |

All of these need failure injection on actual Alerta 9.1/PostgreSQL in smolvm.
Mocks or SQLite cannot close the transaction gate. Existing MVP crash-gap
records are not backfilled into authenticated human intents by scanning ACKed
alerts; report them as historical local-only/unknown delivery.

## Database ownership and privacy

Use `voalack` tables for installation/readiness, immutable binding revisions,
prepared intents, generations, captures, effect ledger, attempts, session-owner
state, projections and audit. The shared library owns no database objects.
Do not modify `zabalack.*` or overwrite Alerta history/source fields for queue
state. Review trigger attachment and backend integration independently of schema
migrations. A disabled/missing trigger on an otherwise eligible path must be
detected by the transaction postcondition and abort, not silently lose capture.

Revoke PUBLIC access. Grant narrow SECURITY DEFINER functions with fixed
`search_path` and explicit principal checks; no runtime superuser, DB-owner,
DDL or broad table grants. Application capture access, verifier access, ONE
session-owner access, restricted projection and operator settlement are separate
capabilities. Same OS/account deployment remains a cooperative boundary, not
proof against compromise of the signing application or database owner.

Use ordinary row/transaction locks and short transactions. PgBouncer transaction
pooling must not depend on session advisory locks, temp tables or session SET
state. Reconnect between phases safely. Database lease expiry does not fence
remote I/O. Monotonic fence allocation must remain ordered across connections
(including sequence caching/rollback assumptions), with explicit readiness checks.
Preserve catalog fingerprints, migration drift refusal and failed-attempt evidence.

Prepared envelopes never enter alert attributes, so reader queries cannot use
them as predicates. Still regression-test JSON/JSONP, alert/history serializers,
counts, grouping, sorting, error bodies, SQL debug logs and WSGI/proxy logs. Keep
logs allowlisted: no raw request/note, MAC, credential, URL query or actor directory.
Preserve later generation fences when confidential payloads are retired; no
automatic destructive retention policy is invented by this design. Existing
committed history's normal human attribution is distinct from private staging.

## ONE identity and binding

For the first supported cohort, require an administrator-approved binding of
one canonical Alerta UUID/customer/source namespace to one configured ONE instance
and one non-grouped triggered alarm. The registry version pins the approved target,
template, source object, source snapshot and occurrence evidence. Only controlled
administration can create/replace it; ordinary Alerta attribute writes cannot.

| Value | Permitted interpretation |
|---|---|
| `%7` / `veeamAlarmCombinationId` | Feed grouping/correlation input; never cast or guess into REST `triggeredAlarmId`. |
| `captureId`, spool sequence/time | Transport observation identity/order only; replay is not a new source occurrence. |
| Alert `resource`, name or template | Comparison/context; not proof of immutable target or occurrence. |
| `triggeredAlarmId` | REST target identity; recurrence/non-reuse semantics require evidence for the pinned ONE build. |
| Trigger time, repeat count, status | Freshness/race signals. They do not provide a compare-and-set precondition. |
| Registry occurrence reference | Locally approved label bound to source evidence; cannot manufacture a missing vendor guarantee. |

Refuse missing/changed binding, wrong customer/instance/template/object, unresolved
identity, grouped/child alarm, capture mismatch, disallowed source state or revoked
policy. Keep the MVP's conservative baseline comparisons; do not let a trusted
signature make an unproven binding trustworthy. New feed captures may refer to
the same occurrence; until a protected lineage mechanism exists, require explicit
binding review rather than automatic re-enrollment.

The GET-to-POST race remains: ONE can change/reuse an alarm between inspection and
mutation. Neither timestamp checking, a DB generation nor a marker closes it.
**Automatic live writes remain disabled while stable occurrence/conditional-write
semantics are unresolved.** A future named manual pilot would need an explicit
review of residual risk; this document does not authorize one. Do not claim
exactly-once remote effects or provenance from an arbitrary source comment.

## Provider interface and durable attempts

The core defines values, not a scheduler. The ONE adapter/session owner implements:

```text
authorize_and_bind(verified_intent, policy, registry) -> BoundIntent | Blocked
preflight(bound_intent, session_owner) -> Ready | AlreadyAcked | Superseded | Blocked
apply_once(bound_intent, durable_attempt, session_owner) -> WriteResponse | Uncertain
read_back(bound_intent, durable_attempt, session_owner) -> Confirmed | Uncertain
reconcile(bound_intent, attempt_evidence, session_owner) -> ReadObservation
project(ledger_outcome, generation) -> Projected | ProjectionPending
```

All return values carry the original action, provider/instance, binding revision,
generation, attempt identity if any, redacted reason and evidence reference.
An adapter cannot replace the target or create a new human action. `apply_once`
accepts only an actual durable attempt authorized by the database and current
session owner; a convenient in-memory Boolean does not suffice.

| State | Meaning / allowed next step |
|---|---|
| `LOCAL_ACK` | Alerta changed locally; never means remote success. Noneligible historical actions can remain local-only. |
| `QUEUED` | Local transaction captured a candidate; verification/policy still precede any remote access. |
| `REMOTE_CONFIRMED` | Exact permitted target/occurrence and expected ACK evidence observed under the qualified contract; no new send. |
| `ALREADY_ACKED` | Source was already ACKed; no attribution claim and no re-ACK to add/overwrite a comment. |
| `BLOCKED` | Named policy/identity/configuration/qualification reason; no send. |
| `SUPERSEDED` | New approved binding/generation invalidated work before send; retain evidence. It cannot erase a possibly-sent old attempt. |
| `UNCERTAIN` | Mutation might have reached ONE or its result cannot be bound safely; preserve attempt and suspend affected mutation ownership. Read-only reconciliation only. |

Internal verification states, pre-send retry delay, expiry and projection-pending
are separate from these operator-facing outcomes. Before a permitted send:
verify capture; check policy/expiry/current binding; obtain the one ONE session
owner; preflight; durably create `attempt_started`; only then invoke the one-ID
ACK operation. Freeze the exact request-body digest before sending.

The baseline uses `POST /api/v2.3/alarms/triggeredAlarms/resolve`,
`resolveType=Acknowledge`, one validated ID and the bounded signed comment. Keep
that operation contract pending a pinned vendor-schema review; never substitute
`Action` or `Resolve`. HTTP success alone is not confirmation. No generic retry
middleware around login/session mutation or the ACK POST.

Any timeout/reset/cancellation/5xx/malformed response after possible transmission
is UNCERTAIN. Classify 401/403/429 as definitely no-effect only if the actual
versioned endpoint contract and transport evidence justify it; otherwise preserve
ambiguity. Proven pre-send failures can retry with bounded backoff within the
original lifetime. Creating a new action cannot bypass an uncertain old effect.

Use one active owner per ONE instance/dedicated credential for login, token use,
discovery, ACK, reconciliation and revoke. Separate DB verification capacity from
that owner. A lease is coordination only: automatic takeover after elapsed time
is forbidden. On loss of owner health/lease/DB connectivity, stop new requests;
hold mutations until the former sender and outstanding remote processing are
demonstrably contained. Token revocation alone is not proof an in-flight request
stopped. Cross-host failover requires independent fencing evidence, not a file
lock or generation token that ONE never checks.

Read-only reconciliation records source state and evidence without claiming who
ACKed it. Missing marker or later Warning does not prove the earlier attempt had
no effect on another occurrence. Late results append evidence under the original
attempt and cannot overwrite a newer lease generation. After PostgreSQL/Patroni
failover, state loss/RPO can invalidate ownership/attempt knowledge; suspend and
reconcile rather than resend missing rows. No zero-loss guarantee is assumed.

## Projection, ONE-visible attribution and coexistence

Project summaries as separate notes or through a narrowly reviewed projection
function. The MVP deliberately uses `Note.from_alert`, avoiding `Alert.add_note`
because that also appends potentially stale status history. Preserve that behavior
for outcome notes; do not replace alert attributes with a stale snapshot. Make
projection retry idempotent by ledger action/outcome revision, preserve newer source
generations and emit no new outbound human intent.

The owner confirmed **feed into Alerta plus Alerta-human-ACK back to ONE**.
The dedicated integration service account performs the ONE API action; its
comment supplies the human attribution without impersonating the Alerta user.
The final signed, single-line comment follows this bounded format:

```text
[AlertaAck:<action_uuid>] via Voalack; Alerta user=<verified login>; Alerta ACK requested=<UTC timestamp>; alert=<alert_uuid>; note=<operator text>
```

The timestamp is the Alerta action request time, explicitly labelled as such;
queue delay must not make it appear to be the remote commit time. The ledger
separately records capture, attempt and read-back times. ONE's own event history
supplies the remote event time where qualified. Preserve integration, actor,
timestamp and references within the baseline's 1024 UTF-16-unit limit; truncate
the operator note first, then sign the exact final message. Reject if required
attribution cannot fit. The API limit and actual visible history remain U2
qualification requirements. UUID references do not accept caller-supplied URLs.
An already-acknowledged alarm retains its existing comment; report that outcome
without claiming Voalack performed the acknowledgement. An uncertain remote
outcome remains uncertain in the Alerta note and ledger.

Mirroring acknowledgements made directly in ONE back into Alerta is outside this
clarified scope, as are unacknowledgement, resolve/delete and arbitrary comment
mirroring. T05 may provide read-only reconciliation under the binding and evidence
rules above. Any future reverse mutation requires a separately agreed contract
for source ordering, occurrence identity, attribution, conflict precedence and
prevention of acknowledgement loops.

Keep the existing PowerShell feed unchanged by default (apart from the supplied
redaction). Its at-least-once replay, delayed-event behavior, grouping and missing
current-state reconciliation remain named limitations. A future protected source
watermark is a separate design/qualification task, not something inferred from
capture time or repeat count.

Both plugin distributions must install independently, with distinct entry points,
configuration/key namespaces, schemas and proof prefixes. The shared library
version is constrained explicitly by each tested consumer. Its uninstall cannot
drop data or remove the other plugin's dependency. Migrations never silently
adopt another installation's schema or readiness seal.

Coexistence has a real routing constraint: the pinned Zabalack signer requires
itself to be last in the effective plugin chain. Simply appending two signers
cannot satisfy that for both. Qualify mutually exclusive provider-specific routing
chains, preserving each provider's policy plugins and final signer. Routing is
an optimization only; the trusted registry/context still authorizes the provider.
If that cannot be configured without changing current behavior, disable the new
capture route and submit a reviewed compatibility adapter. Never weaken the
existing final-effective-callback check to make installation succeed.

## Contract tests and implementation order

All new execution/build evidence must come from smolvm. Use synthetic data and
test keys; no host credentials or live endpoints in test processes. Native
PostgreSQL, Python mocks, real Alerta, Windows feed and live ONE evidence remain
distinct. The static checks in this review prove source identity, not behavior.

| Gate | Test oracle / counterexample |
|---|---|
| C1 two consumers | Same extracted wheel consumed by isolated Zabalack wrapper and Voalack; Zabalack v1 golden bytes/negative cases unchanged; each installs without the other provider runtime. |
| C2 proof boundary | Change provider/customer/instance/target/occurrence/generation/actor/message/revision/kid; reject before endpoint resolution. V1, wrong-purpose and cross-provider proofs fail even with the same secret. Duplicate keys, NaN, bool IDs, extra keys and Unicode edge cases reject. |
| C3 transaction | Instrument real upstream route/backend commits; crash before/after staging and final UPDATE; fail trigger/outbox insertion/commit; disable trigger after health probe. Eligible ACK and candidate commit together or neither does. Verify effective role/connection, not mocked commit counts. |
| C4 concurrency/privacy | Ingest a newer source state between hooks; hold/release locks; no stale overwrite. Stage actor/message then exercise all reader/query/log surfaces and query-builder rebinding; no envelope leak or predicate oracle. |
| C5 access | Real route/decorators plus synthetic authenticated contexts: read-only denied; permitted human accepted without delete; API key and direct status/bulk/note ignored for intents; customer visibility unchanged; unauthorized binding/customer denied. |
| C6 identity | Combination-ID resemblance, renamed object, reused target, new capture of same occurrence, true recurrence, grouped/child target and stale binding never cause guessed writes. Force recurrence between preflight and send; keep the write gate blocked if no conditional identity guarantee exists. |
| C7 durability | Duplicate captures cannot reserve two verified effects. Crash after durable attempt and after actual send; lost response yields UNCERTAIN. Later human action/lease expiry cannot bypass it; late evidence never changes newer ownership. |
| C8 ONE session | Two app nodes, worker/reconciler/discovery, expired owner and token failures; at most one permitted owner and no automatic standby POST. Exercise login/revoke overlap and fail-closed takeover. |
| C9 DB topology | Real PostgreSQL roles, function search_path, migration drift, pool reconnects and PgBouncer transaction pooling; no session-affinity assumption. Simulated promotion with lost attempt state stays held; declare actual RPO limits. |
| C10 attribution/projection | Bounded ONE comment preserves integration, verified actor, correctly labelled request time and action reference, including delayed queues. Already-ACKed alarms retain their comments. Failed note projection never repeats ACK; duplicate/out-of-order read-only observations cannot generate outbound intents. |
| C11 artifact/feed | Wheels installed outside source directories; both/each plugin entry points and clean uninstall; no shared-schema destruction. Preserve PowerShell regression scenarios, with native Windows execution separately NOT_RUN until available. |

VO-LEAD sequence: reproduce MVP evidence (T03a) and inventory docs (T08a);
extract pure core plus v1 compatibility proof (T02); demonstrate the atomic
capture adapter first (T03b/C3–C5); implement trusted bindings and ONE session
owner/attempt ledger (T03b/T04); qualify failure scenarios; then read-only
reconciliation (T05). Astra reviews exact changes
and the integrated candidate (T06); artifact/coexistence evidence and matching
operator documentation follow (T07/T08). Do not defer the transaction proof
until after building the remote sender.

## Named unknowns and enablement holds

| ID | Unknown / disposition |
|---|---|
| U1 | ONE target lifetime, recurrence identity and conditional ACK semantics. Blocks automated live mutation and strong reverse-state claims; develop refusal and uncertainty paths meanwhile. |
| U2 | Pinned ONE REST schema, exact deployed build, account privilege/auth/MFA/session behavior, comment limit and read-back semantics. Baseline is evidence of a local implementation, not vendor/deployment proof. No privilege or MFA bypass. |
| U3 | Narrow request transaction adapter compatibility with actual Alerta 9.1 hooks/backend and installed plugin chains. Blocks durable capture enablement until C3–C5 pass. |
| U4 | Actual customer/role claims, deployment versions and source-ingestion lineage. Keep current visibility; deny write-back where authorization/binding cannot be established. |
| U5 | Actual PostgreSQL/Patroni/PgBouncer versions, RPO and independent sender fencing. No automatic cross-site takeover or no-loss guarantee. |
| U6 | **Resolved by owner:** feed into Alerta plus human ACK back to ONE with visible attribution. Mirroring ONE-origin acknowledgements into Alerta is outside this scope. |
| U7 | Windows PowerShell/DPAPI/native feed evidence and missed-transition reconciliation. Existing reports remain historical; no Windows/live qualification claim from Linux tests. |

Missing supplemental architecture/lab documents are context gaps, not reasons
to invent facts or halt source-supported development. No general orchestration
framework, new paid service or live run is needed for this design phase.

## Primary upstream references inspected

- [Alerta 9.1 action route](https://github.com/alerta/alerta/blob/v9.1.0/alerta/views/alerts.py): authorization and pre/action/post ordering.
- [Alerta 9.1 alert model](https://github.com/alerta/alerta/blob/v9.1.0/alerta/models/alert.py): `from_action`, normal history construction and the extra history side effect of `add_note`.
- [Alerta 9.1 API helpers](https://github.com/alerta/alerta/blob/v9.1.0/alerta/utils/api.py): truthy hook results cause tag/attribute writes.
- [Alerta 9.1 hook receiver](https://github.com/alerta/alerta/blob/v9.1.0/alerta/utils/hooks.py): `HookTrigger.process_status_change` performs additional tag/attribute writes even after its plugin loop. This strengthens the need for a transaction adapter.
- [Alerta 9.1 PostgreSQL backend](https://github.com/alerta/alerta/blob/v9.1.0/alerta/database/backends/postgres/base.py): `set_alert` writes normal history and `_updateone` commits. The design's new outer transaction is a proposed change, not upstream behavior.
- [Veeam ONE acknowledgement guide](https://helpcenter.veeam.com/docs/one/userguide/acknowledge_single_alarms.html): source ACK includes a comment. This does not establish REST idempotency, occurrence stability or conditional mutation.

The supplied baseline cites ONE 13 REST Alarms/Overview/privilege references;
the Alarms reference could not be retrieved through the web tool in this pass.
Its exact API claims therefore remain baseline-supported and subject to U2,
not independently revalidated vendor guarantees. No VSPC API behavior was
substituted for ONE. The feed's historical independent-review report and
Zabalack A5/A6 amendments were inspected as project evidence.
