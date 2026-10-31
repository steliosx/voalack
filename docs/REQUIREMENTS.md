# Requirements

Derived from the owner's original programme contract of 2026-09-28 (SHA-256
`10f1d6298df74ddd0733884163d18bb99b6f71982ee94d760b564f59504ab208`, kept by the
project, not published), keeping its product, correctness and security requirements.
Its staffing and budget sections no longer apply; see [`CHARTER.md`](CHARTER.md).

## 1. Starting point

- Inputs: the ACK MVP 0.1.0 (Alerta 9.1.0, Veeam ONE 13.1 / REST 2.3) and the PowerShell
  feed, pinned in [`../inputs/INPUTS.md`](../inputs/INPUTS.md). Historical test reports are
  historical evidence, not tests run here. Never execute the feed's example configuration;
  use a synthetic configuration with outbound delivery disabled.
- The MVP writes to ONE synchronously after Alerta's local ACK, uses a single-host file lock,
  administrator-owned exact bindings and a manual retry, and has no durable outbox. It
  excludes API-key actors, bulk and grouped alarms. Keep these conservative defaults until
  a reviewed replacement proves the relevant property.
- `%7` / combination ID is not proven equal to REST `triggeredAlarmId`.
- Scope: the feed brings alarms into Alerta; a human Alerta ACK goes back to ONE. Do not
  present this as reverse ACK/unack or comment synchronisation.
- Target runtime: several Alerta application nodes across sites, PostgreSQL with Patroni,
  etcd and PgBouncer, and existing authenticated human access. Pin the deployed versions;
  do not change them. Prefer an integration schema on the existing PostgreSQL service and a
  separate worker process on an approved application host. No broker, extra VM,
  Kubernetes, SQLite substitute or new paid service by default.
- Access policy to preserve: engineers see all clients; Service Desk and Escalation may
  acknowledge without delete permission; default users are read-only. Keep existing
  plugin/action lists, identity-provider settings and customer visibility. A ONE service
  account's vendor privileges are not permissions on human Alerta roles.
- Zabalack reference: `main` at preparation time, `a3317dc41890ef56411e7597b32c44c70b878416`,
  and the product snapshot `494768d8c41c230a124b7c748ebaec10e7d4b6ad`. Record lineage; do not treat them as
  identical or silently pick one.

## 2. Product outcome

- Three independently versioned Python distributions: existing Zabalack, a separate Veeam
  plugin, and a small shared ACK core (names provisional).
- Reuse only what is justified: intent-capture contracts, canonical signed envelopes,
  privacy protections, durable ledger/outbox patterns, verification/delivery leases,
  generation fencing, typed outcomes, bounded safe retries, read-only reconciliation,
  restricted outcome projection, tests and packaging conventions. Record for each reuse:
  source path and commit, dependency, licence/notice, invariant, method and regression test.
  Prefer extraction with preserved behaviour or a narrow wrapper; no wholesale copies or
  generic framework before two consumers exist.
- Keep provider-specific identity, API/session handling, ACK semantics, ambiguity handling,
  recurrence and comment behaviour in adapters. Neither plugin may need the other provider's
  runtime, secrets or configuration.
- A separate Zabalack compatibility checkout tests consuming the exact core artifact. That
  change is never merged into Zabalack's `main` automatically, and deployed Zabalack is not
  changed.

## 3. Correctness and security

1. Capture only a server-authenticated, authorised human single-alert action. Never trust
   operator, target, source ID, binding, customer or provider from mutable alert attributes.
   Deny by default; never grant `delete:alerts` for this integration.
2. Prove the Alerta ACK and the durable intent commit together on real Alerta/PostgreSQL. A
   post-commit callback is not a transactional outbox. Do not store integration state by
   overwriting Alerta's alert rows or history. Any trigger or model integration needs its
   own reviewed migration.
3. Bind signatures and deduplication to schema version, provider, customer/source namespace,
   instance, alert UUID, source occurrence/generation, binding version, action/request ID,
   authenticated actor and the intended message. Validate before touching the target. Keep
   staged content out of reader, search, filter and grouping surfaces. Carry forward the
   pinned Zabalack source's privacy, retirement, fencing and uncertainty regression tests.
4. Start with administrator-owned, exact, single non-grouped alarm mappings. Names,
   timestamps, capture UUIDs and combination IDs are not occurrence identity, and a new
   transport capture is not necessarily a new alarm occurrence. If identity cannot be
   proven, block; never guess. Group and child targets need their own contract and tests.
5. Use only ONE's narrow ACK operation: `POST /api/v2.3/alarms/triggeredAlarms/resolve` with
   `resolveType: Acknowledge`, one validated ID and a comment bounded to 1024 UTF-16 units,
   then read back. The 1024-unit UTF-16 bound is conservative and provisional pending
   verified vendor behaviour. Never substitute `Action` or `Resolve`; never re-ACK an
   acknowledged alarm to overwrite its comment; use no unsupported standalone comment
   endpoint.
6. HTTP success, a comment marker and an outbox do not give exactly-once delivery. A
   possibly-sent request is UNCERTAIN: hold it, reconcile read-only, never blindly resend.
   A later Warning status alone does not prove the earlier write had no effect on another
   occurrence. Proven pre-send retries and recovery of a possibly-sent request are
   distinct. Keep the original intent and every attempt.
7. One API session owner per ONE instance and credential, including reads. A row lease or
   generation cannot fence a request already in flight. Failover is fail-closed until the
   old sender is contained; no promotion based only on elapsed time.
8. PgBouncer transaction pooling must not rely on session advisory locks or session
   affinity. Test roles, transaction failures, stale leases and failover; state real RPO
   limits and make no no-loss claim after an asynchronous failover. Database-owner and
   SQL-superuser credentials are not worker credentials.
9. Keep local ACK, queued, remote-confirmed, already-ACKed, blocked, superseded and
   uncertain outcomes distinct. A projection failure must not repeat a remote write.
   Projections preserve newer incoming source state and ACK permissions, and
   integration-originated projections never create new outbound intents.
10. TLS verification stays on. Administrator-fixed endpoint allowlist, bounded sizes and
    timeouts, secret redaction, approved credential storage, no arbitrary redirects, no
    targets discovered from comments. Confirm ONE privileges against vendor documentation;
    never bypass MFA.

## 4. First candidate

- Preserves the feed; delivers durable human ACK write-back with honest failure semantics,
  restricted bindings and write-back disabled by default.
- Shows the shared core consumed by both plugins without changing deployed Zabalack.
- Includes install, remove, rollback and coexistence tests.
- Ships code, input inventory, reuse decisions, tests and limitations, checksummed wheel and
  sdist, dependency pins, migration review, operator notes and a one-page owner summary.
- Without live access its status is `READY_FOR_LAB_REVIEW` or `NOT_LIVE_VALIDATED`, never
  production-ready.
