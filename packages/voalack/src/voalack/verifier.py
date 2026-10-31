"""T04 S1: the verification worker (no endpoint, credential or network access).

Claims a committed capture, verifies its signed intent against the complete original capture and
the trusted expected context, records an immutable verification bound to the exact capture rows it
checked, and promotes at most one effect. The database fences stale claimants and, under row locks,
re-checks current eligibility at promotion; the cryptographic and capture-link checks happen here
(a cooperative trusted-verifier boundary). Every entry point first checks that its database login
and Voalack's catalog are as installed (fail closed).
"""
from __future__ import annotations

import hashlib
from typing import Any, Callable, Mapping, NamedTuple, Optional

import psycopg2
import psycopg2.errors
import psycopg2.extras

from . import envelope as v2

VERSION = "voalack-verifier/s1"
LOCK_TIMEOUT_MS = 2000          # bounded waits on the binding, generation and policy rows
STATEMENT_TIMEOUT_MS = 10000

LOAD = """
SELECT p.action_id::text AS action_id, p.alert_id, p.txid AS p_txid, p.actor_login, p.request_id::text AS request_id,
       p.customer, p.binding_id, p.binding_revision, p.generation AS p_generation, p.issued_at,
       p.capture_expires_at, p.execution_expires_at, p.envelope_canonical, p.envelope_sha256 AS p_sha256,
       p.kid, p.mac, p.payload,
       c.alert_id AS c_alert_id, c.txid AS c_txid, c.history_user, c.history_time, c.history_text,
       c.history_type, c.history_status, c.generation AS c_generation,
       c.envelope_sha256 AS c_sha256, c.captured_at, voalack.capture_fingerprint(p.action_id) AS fingerprint,
       COALESCE(%s::timestamptz, clock_timestamp()) AS db_now
  FROM voalack.prepared_intents p JOIN voalack.captures c ON c.action_id = p.action_id
 WHERE p.action_id = %s
"""

REVISION = """
SELECT * FROM voalack.binding_revisions WHERE binding_id = %s AND binding_revision = %s
"""

# The functions this login may execute, and the tables it must be able to read.
# Exact signatures: another overload of an approved name is not an approved capability.
VERIFIER_FUNCTIONS = ("voalack.capture_fingerprint(uuid)", "voalack.claim_verification(text, integer, uuid)",
                      "voalack.record_verification(uuid, bigint, text, text, text, text, text, text, text, text)",
                      "voalack.promote_effect(uuid, bigint, bigint)",
                      # Coexistence 3a S2 (contract r8): the ownership audit is the verifier's alone.
                      "voalack.audit_ownership()")
VERIFIER_READS = ("prepared_intents", "captures", "bindings", "binding_revisions", "authorization_policy",
                  "authorization_policy_active", "verifications", "effects", "verification_claims")
DEFINER_SEARCH_PATH = "search_path=pg_catalog, voalack, pg_temp"

# T04 S4 (R4, r3 C3): the outcome-event triggers, as (table, trigger, event mask). Each runtime
# profile lists the ones its own writes rely on; the projector relies on all of them.
EVENT_EFFECTS_INSERT = ("effects", "effects_outcome_insert", "INSERT")
EVENT_EFFECTS_STATE = ("effects", "effects_outcome_state", "UPDATE OF state")
EVENT_SETTLEMENTS = ("settlements", "settlements_outcome", "INSERT")
EVENT_RECOVERED_EFFECTS = ("recovered_effects", "recovered_effects_outcome", "INSERT")
EVENT_RECOVERED_HOLDS = ("recovered_holds", "recovered_holds_outcome", "INSERT")
EVENT_RECOVERY_SETTLEMENTS = ("recovery_settlements", "recovery_settlements_outcome", "INSERT")
ALL_EVENTS = (EVENT_EFFECTS_INSERT, EVENT_EFFECTS_STATE, EVENT_SETTLEMENTS, EVENT_RECOVERED_EFFECTS,
              EVENT_RECOVERED_HOLDS, EVENT_RECOVERY_SETTLEMENTS)


class Profile(NamedTuple):
    """What one runtime login may do: its group role, the roles it must have no path to, its exact
    functions and reads, the immutability triggers it relies on and the full single-column
    uniqueness (NOT NULL) it relies on."""
    required_role: str
    forbidden_roles: tuple
    functions: tuple
    reads: tuple
    immutable: tuple          # (table, trigger)
    unique: tuple             # (table, "col[,col...]", columns must be NOT NULL)
    column_reads: tuple = ()  # T04 S3b: (table, "col[,col...]"): exactly these columns, never the table
    guarded: tuple = ()       # T04 S3c: (table, trigger, "function()"): a BEFORE UPDATE OR DELETE row trigger
                              # with exactly that function (immutability rules other than refuse_change)
    events: tuple = ()        # T04 S4: (table, trigger, mask): an AFTER row trigger with voalack._outcome_event()
    before_update: tuple = () # T05b S1: (table, trigger, "function()"): exactly a BEFORE UPDATE row trigger
                              # (no INSERT/DELETE, no WHEN, no column list) with that function, enabled


VERIFIER = Profile("voalack_verifier", ("voalack_admin", "voalack_app", "voalack_sender", "voalack_settler",
                                        "voalack_projector"),
                   VERIFIER_FUNCTIONS,
                   VERIFIER_READS, (("verifications", "verifications_immutable"),),
                   (("effects", "effect_key", True), ("effects", "action_id", True)),
                   events=(EVENT_EFFECTS_INSERT,))

# Each column is true when the named readiness condition FAILS. Privilege conditions are checked
# for every role this login can use (membership with INHERIT or SET, and itself), including column
# grants; trigger and uniqueness conditions require the installed forms exactly (ordinary-session
# trigger, full immediate valid unique constraints).
READINESS = """
WITH me AS (SELECT r.* FROM pg_roles r WHERE r.rolname = current_user),
     reach AS (SELECT r.oid FROM pg_roles r WHERE pg_has_role(current_user, r.oid, 'MEMBER')),
     ns AS (SELECT n.oid, n.nspowner FROM pg_namespace n WHERE n.nspname = 'voalack'),
     adm AS (SELECT a.oid FROM pg_roles a WHERE a.rolname = 'voalack_admin'),
     fns AS (SELECT p.* FROM pg_proc p JOIN ns ON p.pronamespace = ns.oid),
     allowed AS (SELECT to_regprocedure(s)::oid AS oid FROM unnest(%(functions)s::text[]) s),
     -- T04 S4: catalog lookups by name (no runtime role may use the publication schema, so no
     -- to_regclass/to_regprocedure there)
     pub AS (SELECT (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'voalack_publication' AND c.relname = 'publications') AS rel, (SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'voalack_publication' AND p.proname = 'refuse_change' AND p.pronargs = 0) AS fn)
SELECT
  session_user <> current_user                                                     AS session_role_changed,
  current_setting('session_replication_role') <> 'origin'                           AS replication_role,
  (SELECT rolsuper OR rolcreaterole OR rolbypassrls FROM me)                         AS privileged_login,
  EXISTS (SELECT 1 FROM pg_roles r, me WHERE r.oid <> me.oid AND pg_has_role(me.oid, r.oid, 'MEMBER')
            AND (r.rolsuper OR r.rolcreaterole OR r.rolbypassrls))                    AS privileged_membership,
  EXISTS (SELECT 1 FROM pg_roles a, me WHERE a.rolname = ANY(%(forbidden)s::text[])
            AND (pg_has_role(me.oid, a.oid, 'MEMBER')
                 OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = a.oid AND m.admin_option
                              AND pg_has_role(me.oid, m.member, 'MEMBER'))))          AS admin_or_app_path,
  NOT pg_has_role(current_user, %(required)s, 'USAGE')                                AS missing_required_role,
  (SELECT pg_has_role(current_user, d.datdba, 'MEMBER') FROM pg_database d
    WHERE d.datname = current_database())                                            AS database_owner,
  NOT EXISTS (SELECT 1 FROM ns, adm WHERE ns.nspowner = adm.oid)                      AS schema_owner_drift,
  EXISTS (SELECT 1 FROM ns, reach WHERE pg_has_role(current_user, ns.nspowner, 'MEMBER')
            OR has_schema_privilege(reach.oid, ns.oid, 'CREATE'))                     AS schema_power,
  EXISTS (SELECT 1 FROM pg_class c JOIN ns ON c.relnamespace = ns.oid, adm
           WHERE c.relkind IN ('r', 'S', 'v', 'm', 'p') AND c.relowner <> adm.oid)    AS relation_owner_drift,
  EXISTS (SELECT 1 FROM pg_class c JOIN ns ON c.relnamespace = ns.oid, reach
           WHERE pg_has_role(current_user, c.relowner, 'MEMBER')
              OR (c.relkind IN ('r', 'p', 'v', 'm')
                  AND (has_table_privilege(reach.oid, c.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                       OR has_any_column_privilege(reach.oid, c.oid, 'INSERT, UPDATE, REFERENCES')))
              OR (c.relkind = 'S' AND has_sequence_privilege(reach.oid, c.oid, 'USAGE, UPDATE')))
                                                                                     AS table_power,
  EXISTS (SELECT 1 FROM unnest(%(reads)s::text[]) t(name)
           WHERE to_regclass('voalack.' || t.name) IS NULL
              OR NOT has_table_privilege(current_user, to_regclass('voalack.' || t.name), 'SELECT'))
                                                                                     AS read_missing,
  EXISTS (SELECT 1 FROM pg_class c JOIN ns ON c.relnamespace = ns.oid, reach
           WHERE NOT c.relname = ANY(%(reads)s::text[]) AND NOT c.relname = ANY(%(column_tables)s::text[])
             AND ((c.relkind IN ('r', 'p', 'v', 'm')
                   AND (has_table_privilege(reach.oid, c.oid, 'SELECT')
                        OR has_any_column_privilege(reach.oid, c.oid, 'SELECT')))
                  OR (c.relkind = 'S' AND has_sequence_privilege(reach.oid, c.oid, 'SELECT'))))
                                                                                     AS extra_read,
  -- A column-read table: the login reads exactly the listed columns, and no reachable role (or
  -- PUBLIC) holds table-wide SELECT or SELECT on any other column (e.g. attempts.request_bytes).
  EXISTS (SELECT 1 FROM unnest(%(column_tables)s::text[], %(column_lists)s::text[]) cr(tbl, cols)
           WHERE to_regclass('voalack.' || cr.tbl) IS NULL
              OR EXISTS (SELECT 1 FROM unnest(string_to_array(cr.cols, ',')) w(name)
                          WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
                                             WHERE a.attrelid = to_regclass('voalack.' || cr.tbl)
                                               AND a.attname = w.name AND a.attnum > 0 AND NOT a.attisdropped
                                               AND has_column_privilege(current_user, a.attrelid, a.attnum, 'SELECT')))
              OR EXISTS (SELECT 1 FROM reach
                          WHERE has_table_privilege(reach.oid, to_regclass('voalack.' || cr.tbl), 'SELECT')
                             OR EXISTS (SELECT 1 FROM pg_attribute a
                                         WHERE a.attrelid = to_regclass('voalack.' || cr.tbl) AND a.attnum > 0
                                           AND NOT a.attisdropped
                                           AND NOT a.attname = ANY(string_to_array(cr.cols, ','))
                                           AND has_column_privilege(reach.oid, a.attrelid, a.attnum, 'SELECT'))))
                                                                                     AS column_read_drift,
  EXISTS (SELECT 1 FROM fns, adm WHERE fns.proowner <> adm.oid)                       AS function_owner_drift,
  EXISTS (SELECT 1 FROM fns WHERE fns.prosecdef
            AND fns.proconfig IS DISTINCT FROM ARRAY[%(search_path)s]::text[])        AS definer_config_drift,
  EXISTS (SELECT 1 FROM fns WHERE fns.proacl IS NULL
            OR EXISTS (SELECT 1 FROM aclexplode(fns.proacl) x
                        WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE'))        AS public_execute,
  NOT EXISTS (SELECT 1 FROM pg_default_acl d, adm
               WHERE d.defaclrole = adm.oid AND d.defaclobjtype = 'f' AND d.defaclnamespace = 0
                 AND NOT EXISTS (SELECT 1 FROM aclexplode(d.defaclacl) x
                                  WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE')) AS default_execute,
  EXISTS (SELECT 1 FROM allowed WHERE allowed.oid IS NULL
             OR NOT EXISTS (SELECT 1 FROM fns WHERE fns.oid = allowed.oid AND fns.prosecdef))
                                                                                     AS function_missing,
  EXISTS (SELECT 1 FROM fns WHERE has_function_privilege(current_user, fns.oid, 'EXECUTE')
            <> (fns.oid IN (SELECT oid FROM allowed WHERE oid IS NOT NULL)))
  OR EXISTS (SELECT 1 FROM fns, reach WHERE fns.oid NOT IN (SELECT oid FROM allowed WHERE oid IS NOT NULL)
               AND has_function_privilege(reach.oid, fns.oid, 'EXECUTE'))            AS execute_drift,
  -- Ordinary sessions fire triggers enabled 'O' (origin) or 'A' (always), not 'R' or 'D'.
  EXISTS (SELECT 1 FROM unnest(%(trigger_tables)s::text[], %(trigger_names)s::text[]) req(tbl, name)
           WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = to_regclass('voalack.' || req.tbl) AND t.tgname = req.name
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal
                 AND t.tgfoid = to_regprocedure('voalack.refuse_change()')
                 AND t.tgtype & 1 = 1 AND t.tgtype & 2 = 2               -- FOR EACH ROW, BEFORE
                 AND t.tgtype & 8 = 8 AND t.tgtype & 16 = 16             -- DELETE and UPDATE
                 AND t.tgqual IS NULL AND cardinality(t.tgattr::int2[]) = 0))  -- no WHEN, no column list
                                                                                     AS immutability_drift,
  -- T04 S3c: a guarded table's own row trigger, installed exactly as required.
  EXISTS (SELECT 1 FROM unnest(%(guarded_tables)s::text[], %(guarded_names)s::text[], %(guarded_functions)s::text[])
                        req(tbl, name, fn)
           WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = to_regclass('voalack.' || req.tbl) AND t.tgname = req.name
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal
                 AND t.tgfoid = to_regprocedure('voalack.' || req.fn)
                 AND t.tgtype & 1 = 1 AND t.tgtype & 2 = 2 AND t.tgtype & 8 = 8 AND t.tgtype & 16 = 16
                 AND t.tgqual IS NULL AND cardinality(t.tgattr::int2[]) = 0))         AS guarded_drift,
  -- T05b S1: an UPDATE-only BEFORE row trigger (the observer flag fence), installed exactly as required.
  EXISTS (SELECT 1 FROM unnest(%(bu_tables)s::text[], %(bu_names)s::text[], %(bu_functions)s::text[])
                        req(tbl, name, fn)
           WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = to_regclass('voalack.' || req.tbl) AND t.tgname = req.name
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal
                 AND t.tgfoid = to_regprocedure('voalack.' || req.fn)
                 AND t.tgtype = 19                                       -- ROW | BEFORE | UPDATE only
                 AND t.tgqual IS NULL AND cardinality(t.tgattr::int2[]) = 0)) AS before_update_drift,
  -- Each required uniqueness is a constraint over exactly the listed columns, in order (single or
  -- composite); NOT NULL where required (a nullable marker column may hold many NULLs by design).
  EXISTS (SELECT 1 FROM unnest(%(unique_tables)s::text[], %(unique_columns)s::text[], %(unique_notnull)s::boolean[])
                        col(tbl, names, need_not_null)
           WHERE NOT EXISTS (
             SELECT 1 FROM pg_constraint k
               JOIN pg_index i ON i.indexrelid = k.conindid
              WHERE k.conrelid = to_regclass('voalack.' || col.tbl) AND k.contype IN ('u', 'p')
                AND k.conkey = (SELECT array_agg(a.attnum ORDER BY u.ord)
                                  FROM unnest(string_to_array(col.names, ',')) WITH ORDINALITY u(name, ord)
                                  JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attname = u.name)
                AND cardinality(k.conkey) = cardinality(string_to_array(col.names, ','))
                AND (NOT col.need_not_null OR NOT EXISTS (SELECT 1 FROM pg_attribute a
                                                     WHERE a.attrelid = k.conrelid AND a.attnum = ANY(k.conkey)
                                                       AND NOT a.attnotnull))
                AND NOT k.condeferrable AND k.convalidated
                AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indimmediate
                AND i.indpred IS NULL AND i.indexprs IS NULL))                       AS uniqueness_drift,
  -- T04 S4 (R4): each outcome-event trigger the profile relies on, exactly as installed: AFTER, FOR
  -- EACH ROW, voalack._outcome_event(), the exact event mask, no WHEN, not a constraint trigger.
  EXISTS (SELECT 1 FROM unnest(%(event_tables)s::text[], %(event_names)s::text[], %(event_masks)s::text[])
                        req(tbl, name, mask)
           WHERE NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = to_regclass('voalack.' || req.tbl) AND t.tgname = req.name
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal AND t.tgconstraint = 0
                 AND t.tgfoid = to_regprocedure('voalack._outcome_event()')
                 AND t.tgtype & 1 = 1 AND t.tgtype & 2 = 0 AND t.tgtype & 64 = 0 AND t.tgqual IS NULL
                 AND CASE req.mask
                       WHEN 'INSERT' THEN t.tgtype & 60 = 4 AND cardinality(t.tgattr::int2[]) = 0
                       WHEN 'UPDATE OF state' THEN t.tgtype & 60 = 16 AND cardinality(t.tgattr::int2[]) = 1
                            AND t.tgattr[0] = (SELECT a.attnum FROM pg_attribute a        -- int2vector: subscript 0
                                                WHERE a.attrelid = t.tgrelid AND a.attname = 'state')
                       ELSE false END))                                              AS event_trigger_drift,
  -- T04 S4 (C1, D2, D5): the protected publication schema: owned by voalack_admin, objects owned by it,
  -- its functions plain (not definer) with the fixed search path and no PUBLIC EXECUTE.
  NOT EXISTS (SELECT 1 FROM pg_namespace n, adm WHERE n.nspname = 'voalack_publication' AND n.nspowner = adm.oid)
  OR (SELECT pub.rel FROM pub) IS NULL
  OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, adm
              WHERE n.nspname = 'voalack_publication' AND c.relowner <> adm.oid)
  OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, adm
              WHERE n.nspname = 'voalack_publication'
                AND (p.proowner <> adm.oid OR p.prosecdef
                     OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, pg_temp']::text[]
                     OR p.proacl IS NULL
                     OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x
                                 WHERE x.grantee = 0 AND x.privilege_type = 'EXECUTE')))  AS publication_schema_drift,
  -- No role this login can use (or PUBLIC) has any right in it, membership of an owner included.
  EXISTS (SELECT 1 FROM pg_namespace n, reach WHERE n.nspname = 'voalack_publication'
            AND (pg_has_role(current_user, n.nspowner, 'MEMBER')
                 OR has_schema_privilege(reach.oid, n.oid, 'USAGE, CREATE')))
  OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, reach
              WHERE n.nspname = 'voalack_publication'
                AND (pg_has_role(current_user, c.relowner, 'MEMBER')
                     OR (c.relkind IN ('r', 'p', 'v', 'm')
                         AND (has_table_privilege(reach.oid, c.oid, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                              OR has_any_column_privilege(reach.oid, c.oid, 'SELECT, INSERT, UPDATE, REFERENCES')))
                     OR (c.relkind = 'S' AND has_sequence_privilege(reach.oid, c.oid, 'USAGE, SELECT, UPDATE'))))
  OR EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, reach
              WHERE n.nspname = 'voalack_publication' AND has_function_privilege(reach.oid, p.oid, 'EXECUTE'))
                                                                                     AS publication_access,
  -- Its immutability (row and TRUNCATE guards with its own function) and its two uniqueness rules.
  NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = (SELECT pub.rel FROM pub) AND t.tgname = 'publications_immutable'
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal
                 AND t.tgfoid = (SELECT pub.fn FROM pub)
                 AND t.tgtype & 1 = 1 AND t.tgtype & 2 = 2 AND t.tgtype & 60 = 24
                 AND t.tgqual IS NULL AND cardinality(t.tgattr::int2[]) = 0)
  OR NOT EXISTS (SELECT 1 FROM pg_trigger t
               WHERE t.tgrelid = (SELECT pub.rel FROM pub) AND t.tgname = 'publications_no_truncate'
                 AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal
                 AND t.tgfoid = (SELECT pub.fn FROM pub)
                 AND t.tgtype & 1 = 0 AND t.tgtype & 2 = 2 AND t.tgtype & 60 = 32 AND t.tgqual IS NULL)
  OR EXISTS (SELECT 1 FROM unnest(ARRAY['note_id', 'action_id,epoch,revision']) u(names)
              WHERE NOT EXISTS (
                SELECT 1 FROM pg_constraint k JOIN pg_index i ON i.indexrelid = k.conindid
                 WHERE k.conrelid = (SELECT pub.rel FROM pub) AND k.contype IN ('u', 'p')
                   AND k.conkey = (SELECT array_agg(a.attnum ORDER BY w.ord)
                                     FROM unnest(string_to_array(u.names, ',')) WITH ORDINALITY w(name, ord)
                                     JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attname = w.name)
                   AND NOT k.condeferrable AND k.convalidated AND i.indisunique AND i.indisvalid AND i.indisready
                   AND i.indislive AND i.indimmediate AND i.indpred IS NULL AND i.indexprs IS NULL))
                                                                                     AS publication_guard_drift,
  -- r1 §5: no runtime login has any right on Alerta's notes or alerts, or a path to their owner.
  EXISTS (SELECT 1 FROM unnest(ARRAY['public.notes', 'public.alerts']) t(name), reach
           WHERE to_regclass(t.name) IS NOT NULL
             AND (pg_has_role(current_user, (SELECT c.relowner FROM pg_class c WHERE c.oid = to_regclass(t.name)), 'MEMBER')
                  OR has_table_privilege(reach.oid, to_regclass(t.name), 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
                  OR has_any_column_privilege(reach.oid, to_regclass(t.name), 'SELECT, INSERT, UPDATE, REFERENCES')))
                                                                                     AS alerta_table_access
"""


class NotReady(RuntimeError):
    """The verifier's database login or Voalack's catalog is not as installed."""


def check_ready(conn, profile: Profile = VERIFIER) -> None:
    """Fail closed unless this login is a plain member of the profile's role with no path to the
    forbidden roles (owner, capture role, other workers) or any privileged role, and the protected
    catalog is as installed (owners, SECURITY DEFINER search_path, exact EXECUTE and table grants,
    no PUBLIC or default EXECUTE, the immutability triggers and the uniqueness the profile relies
    on). Drift is refused, never repaired here. A failed condition name of ``admin_or_app_path``
    means a path to any forbidden role."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(READINESS, {"reads": list(profile.reads), "functions": list(profile.functions),
                            "search_path": DEFINER_SEARCH_PATH, "required": profile.required_role,
                            "forbidden": list(profile.forbidden_roles),
                            "trigger_tables": [t for t, _ in profile.immutable],
                            "trigger_names": [n for _, n in profile.immutable],
                            "unique_tables": [t for t, _, _ in profile.unique],
                            "unique_columns": [c for _, c, _ in profile.unique],
                            "unique_notnull": [n for _, _, n in profile.unique],
                            "column_tables": [t for t, _ in profile.column_reads],
                            "column_lists": [c for _, c in profile.column_reads],
                            "guarded_tables": [t for t, _, _ in profile.guarded],
                            "guarded_names": [n for _, n, _ in profile.guarded],
                            "guarded_functions": [f for _, _, f in profile.guarded],
                            "event_tables": [t for t, _, _ in profile.events],
                            "event_names": [n for _, n, _ in profile.events],
                            "event_masks": [m for _, _, m in profile.events],
                            "bu_tables": [t for t, _, _ in profile.before_update],
                            "bu_names": [n for _, n, _ in profile.before_update],
                            "bu_functions": [f for _, _, f in profile.before_update]})
    failed = sorted(name for name, value in cur.fetchone().items() if value is not False)
    conn.rollback()
    if failed:
        raise NotReady("voalack verifier not ready: " + ", ".join(failed))


def _floor_ms(value):
    return value.replace(microsecond=value.microsecond - value.microsecond % 1000)


def evaluate(cur, action_id: str, ctx: v2.Context, keys: v2.KeyRing, at: Optional[str] = None) -> tuple:
    """Return (outcome, reason, sha256, kid, fingerprint) for one committed capture.

    ``at`` replaces the database clock with an exact instant (UTC ISO string) for boundary tests only.
    """
    cur.execute(LOAD, (at, action_id))
    row = cur.fetchone()
    if row is None:
        return "refused", "no_intent", None, None, None
    fingerprint, kid = row["fingerprint"], row["kid"]
    if row["envelope_canonical"] is None or row["mac"] is None:
        return "refused", "legacy_unsigned", None, None, fingerprint
    canonical = bytes(row["envelope_canonical"])
    sha = hashlib.sha256(canonical).hexdigest()
    if sha != row["p_sha256"] or sha != row["c_sha256"]:
        return "refused", "digest_link_mismatch", None, kid, fingerprint
    db_now = v2.parse_utc(row["db_now"])
    try:
        env = v2.verify(canonical, row["mac"], ctx, keys)
    except v2.KeyUnavailable:
        # Unauthenticated bytes give no deadline; the stored original execution deadline (trusted
        # metadata, never later than the signed one) bounds how long the hold lasts.
        stored_deadline = row["execution_expires_at"]
        if stored_deadline is None or not db_now < v2.parse_utc(stored_deadline):
            return "refused", "expired", sha, kid, fingerprint
        return "hold", "key_unavailable", sha, kid, fingerprint
    except (v2.EnvelopeError, v2.ProofError) as exc:
        return "refused", f"invalid_proof:{exc.args[0] if exc.args else 'unknown'}"[:128], sha, kid, fingerprint
    reason = _original_capture_mismatch(cur, env, row)
    if reason:
        return "refused", reason, sha, kid, fingerprint
    # Signed versus stored deadlines; capture inside its original exclusive window; execution
    # before its original deadline (no new window is invented here).
    issued = v2.parse_utc(env["issued_at"])
    capture_deadline = v2.parse_utc(env["capture_expires_at"])
    execution_deadline = v2.parse_utc(env["execution_expires_at"])
    signed = (issued, capture_deadline, execution_deadline)
    stored = (v2.parse_utc(row["issued_at"]), v2.parse_utc(row["capture_expires_at"]),
              v2.parse_utc(row["execution_expires_at"]))
    expired = not db_now < execution_deadline                       # signed deadline, exclusive
    if stored != signed:
        # Captures staged before the T04 S1 timestamp fix stored each value floored to milliseconds
        # by Alerta's global datetime adapter. Exactly that pattern is held (never backfilled into
        # eligible work) until its signed execution deadline passes; anything else is refused.
        if stored == tuple(_floor_ms(value) for value in signed):
            return ("refused", "expired", sha, kid, fingerprint) if expired else (
                "hold", "legacy_deadline_precision", sha, kid, fingerprint)
        return "refused", "deadline_mismatch", sha, kid, fingerprint
    if not (issued <= v2.parse_utc(row["captured_at"]) < capture_deadline):
        return "refused", "captured_outside_window", sha, kid, fingerprint
    if expired:
        return "refused", "expired", sha, kid, fingerprint
    return "verified", "ok", sha, kid, fingerprint


def _original_capture_mismatch(cur, env: Mapping[str, Any], row: Mapping[str, Any]) -> Optional[str]:
    """The complete original capture (D1): identities, transaction link, generation, actor, the
    captured ACK history entry and finalized facts, the authenticated message, and the source."""
    if env["kid"] != row["kid"]:
        return "kid_mismatch"
    if (env["action_id"], env["alert_id"], env["request_id"]) != (row["action_id"], row["alert_id"], row["request_id"]):
        return "identity_mismatch"
    if row["c_alert_id"] != row["alert_id"] or row["c_txid"] != row["p_txid"]:
        return "capture_link_mismatch"
    if not (env["generation"] == row["p_generation"] == row["c_generation"]):
        return "generation_mismatch"
    if (env["customer"], env["binding_id"], env["binding_revision"]) != (
            row["customer"], row["binding_id"], row["binding_revision"]):
        return "binding_mismatch"
    if not (env["actor"]["login"] == row["actor_login"] == row["history_user"]):
        return "actor_mismatch"
    if (row["history_type"], row["history_status"]) != ("ack", "ack"):
        return "history_not_ack"
    final = row["payload"] if isinstance(row["payload"], dict) else {}
    history_time = row["history_time"]
    if (final.get("note") != (row["history_text"] or "") or history_time is None
            or final.get("history_time") != history_time.isoformat()):
        return "history_mismatch"
    try:
        message = v2.build_message(env["action_id"], env["actor"]["login"], env["issued_at"], env["alert_id"],
                                   row["history_text"])
    except v2.EnvelopeError:
        return "message_mismatch"
    if message != env["message"]:
        return "message_mismatch"
    cur.execute(REVISION, (row["binding_id"], row["binding_revision"]))
    revision = cur.fetchone()
    if revision is None:
        return "revision_missing"
    source = env["source"]
    if ((revision["customer"], revision["source_namespace"], revision["instance_id"])
            != (env["customer"], env["source_namespace"], env["instance_id"])
            or (revision["target_kind"], revision["target_id"], revision["occurrence_ref"],
                revision["occurrence_evidence_sha256"], revision["snapshot_sha256"])
            != (source["target_kind"], source["target_id"], source["occurrence_ref"],
                source["occurrence_evidence_sha256"], source["snapshot_sha256"])):
        return "source_mismatch"
    return None


def _bound(cur, lock_timeout_ms: int, statement_timeout_ms: int) -> None:
    cur.execute("SELECT set_config('lock_timeout', %s, true), set_config('statement_timeout', %s, true)",
                (f"{int(lock_timeout_ms)}ms", f"{int(statement_timeout_ms)}ms"))


def run_once(conn, claimant: str, ctx: v2.Context, keys: v2.KeyRing, lease_seconds: int = 60,
             on_promoted: Optional[Callable[[Mapping[str, Any]], None]] = None,
             action_id: Optional[str] = None, lock_timeout_ms: int = LOCK_TIMEOUT_MS,
             statement_timeout_ms: int = STATEMENT_TIMEOUT_MS) -> Optional[dict]:
    """Claim and process one capture. ``on_promoted`` stands for the later stages' endpoint
    resolution and is only ever called after a successful promotion."""
    check_ready(conn)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    _bound(cur, lock_timeout_ms, statement_timeout_ms)
    cur.execute("SELECT * FROM voalack.claim_verification(%s, %s, %s)", (claimant, lease_seconds, action_id))
    claim = cur.fetchone()
    conn.commit()
    if claim is None:
        return None
    return process(conn, str(claim["action_id"]), claim["claim_epoch"], ctx, keys, on_promoted,
                   lock_timeout_ms=lock_timeout_ms, statement_timeout_ms=statement_timeout_ms)


def process(conn, action_id: str, claim_epoch: int, ctx: v2.Context, keys: v2.KeyRing,
            on_promoted=None, *, lock_timeout_ms: int = LOCK_TIMEOUT_MS,
            statement_timeout_ms: int = STATEMENT_TIMEOUT_MS) -> dict:
    check_ready(conn)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    sha = kid = fingerprint = None

    def record(outcome, reason):
        cur.execute("SELECT voalack.record_verification(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) AS id",
                    (action_id, claim_epoch, VERSION, ctx.deployment_id, ctx.provider, kid, outcome, reason,
                     sha, fingerprint))
        return cur.fetchone()["id"]

    try:
        _bound(cur, lock_timeout_ms, statement_timeout_ms)
        outcome, reason, sha, kid, fingerprint = evaluate(cur, action_id, ctx, keys)
        verification_id = record(outcome, reason)
        effect_id = None
        if outcome == "verified":
            cur.execute("SELECT * FROM voalack.promote_effect(%s, %s, %s)", (action_id, claim_epoch, verification_id))
            promoted = cur.fetchone()
            if promoted["reason"] == "promoted":
                effect_id = promoted["effect_id"]
            else:
                # Appended, never rewritten (D1): lost current eligibility is a refusal; an effect
                # key already held by another action is a hold (never a second effect).
                outcome = "hold" if promoted["reason"] == "effect_key_taken" else "refused"
                reason = promoted["reason"]
                record(outcome, reason)
        conn.commit()
    except (psycopg2.errors.LockNotAvailable, psycopg2.errors.QueryCanceled) as exc:
        # A bounded wait ran out: nothing was recorded; the claim lapses and is retried later.
        conn.rollback()
        timeout = "lock_timeout" if isinstance(exc, psycopg2.errors.LockNotAvailable) else "statement_timeout"
        return {"action_id": action_id, "outcome": "deferred", "reason": timeout, "effect_id": None}
    except psycopg2.Error as exc:
        conn.rollback()
        # T04 S4 (D1): promotion found the database closed, recovering or not initialized: nothing was
        # recorded; the claim lapses and is retried once the database is open again.
        if exc.pgcode in ("VA003", "VA004"):
            reason = "recovery_not_open" if exc.pgcode == "VA003" else "recovery_uninitialized"
            return {"action_id": action_id, "outcome": "deferred", "reason": reason, "effect_id": None}
        raise
    except Exception:
        conn.rollback()
        raise
    result = {"action_id": action_id, "outcome": outcome, "reason": reason, "effect_id": effect_id}
    if effect_id is not None and on_promoted is not None:
        on_promoted(result)
    return result
