-- ==== Coexistence 3a S3a: DDL protector, part 1 (r8 sections 3 and 10) ====
-- Applied first, in the same transaction as schema.sql and guard_post.sql (bootstrap order: guard, voalack,
-- voalack_lifetime, the four public triggers, the two event triggers last). The enabled guard checks
-- inventory-breaking DDL from every session_user, superusers included; a superuser can still bypass it by disabling
-- the event triggers (event-trigger DDL fires no event trigger): a disclosed limitation, not an admission path.

-- First statement (F7): on first install no guard state may pre-exist. A voalack_guard schema without a non-empty frozen
-- inventory, or a leftover guard event trigger, is a pre-existing or partial guard: refused here, before this file
-- creates, rewrites or grants anything, so the inspection objects it then creates can hide nothing.
DO $$
DECLARE
    frozen boolean := false;
BEGIN
    IF to_regclass('voalack_guard.frozen_inventory') IS NOT NULL THEN
        EXECUTE 'SELECT EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory)' INTO frozen;
    END IF;
    IF NOT frozen AND (to_regnamespace('voalack_guard') IS NOT NULL
                       OR EXISTS (SELECT 1 FROM pg_event_trigger WHERE evtname LIKE 'voalack%')) THEN
        RAISE EXCEPTION 'voalack: pre-existing or partial guard state on first install; refused before any change';
    END IF;
END;
$$;

-- Prerequisite role (deployment prerequisite, provisioned by the operator; never created or normalised here).
DO $$
DECLARE
    r record;
BEGIN
    SELECT rolname, rolcanlogin, rolsuper, rolinherit, oid INTO r FROM pg_roles WHERE rolname = 'voalack_guard_owner';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: prerequisite role voalack_guard_owner is absent (provision it NOLOGIN, no members)';
    END IF;
    IF r.rolcanlogin OR r.rolsuper THEN
        RAISE EXCEPTION 'voalack: voalack_guard_owner must be NOLOGIN and not a superuser';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = r.oid) THEN
        RAISE EXCEPTION 'voalack: voalack_guard_owner must have no members (no path to guard ownership)';
    END IF;
END;
$$;

-- Reapply: an installed guard is verified first and never repaired. Any problem refuses the whole apply.
DO $$
BEGIN
    IF to_regprocedure('voalack_guard.inventory_problems()') IS NOT NULL
       AND EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'voalack_guard' AND tablename = 'frozen_inventory') THEN
        IF EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory) AND
           cardinality(voalack_guard.inventory_problems()) > 0 THEN
            RAISE EXCEPTION 'voalack: protected inventory drifted; reapply refused (no repair): %',
                voalack_guard.inventory_problems();
        END IF;
    END IF;
END;
$$;

CREATE SCHEMA IF NOT EXISTS voalack_guard AUTHORIZATION voalack_guard_owner;
ALTER SCHEMA voalack_guard OWNER TO voalack_guard_owner;
REVOKE ALL ON SCHEMA voalack_guard FROM PUBLIC;

-- ==== Coexistence 3a S3b: recovery windows, executor registration, write-ahead journal, effect receipts ====
-- (r8 section 11; S3b delta r2 + r3, concurred 78f1861c; early source review 7d13602a.) One recovery window at a
-- time; one registered coordinator backend per window (the S3b no-restore profile; S3c adds the restore backend).
-- Enforcement lives in the admitted write paths themselves: BEFORE INSERT/UPDATE triggers on these tables take the
-- window row lock, derive the caller's exact identity, and compute every sequence number, identity, prior, target,
-- effect xid, status and seal evidence themselves (caller-supplied values are overwritten), running the step's
-- predicates, the validation and the protector probe in the insert. The functions further below are convenience
-- wrappers around those inserts. Every record is append-only (UPDATE/DELETE row triggers, TRUNCATE statement
-- triggers). Disclosed: a trusted superuser can still skip row triggers (session_replication_role = replica) or write
-- catalogs directly; that is raw catalog corruption by a trusted executor, not a supported executor path, exactly as
-- for disabling the event triggers above.
CREATE TABLE IF NOT EXISTS voalack_guard.recovery_windows (
    window_id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    database               name NOT NULL,
    system_identifier      bigint NOT NULL,
    source_sha256          text NOT NULL CHECK (source_sha256 ~ '^[0-9a-f]{64}$'),
    executor_role          name NOT NULL,
    created_pid            integer NOT NULL,
    created_backend_start  timestamptz NOT NULL,
    attestation            jsonb NOT NULL,
    preload                text NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS voalack_guard.executor_backends (
    registration_id    bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    window_id          bigint NOT NULL REFERENCES voalack_guard.recovery_windows (window_id),
    role               text NOT NULL DEFAULT 'coordinator' CHECK (role = 'coordinator'),
    source_sha256      text NOT NULL,
    pid                integer NOT NULL,
    backend_start      timestamptz NOT NULL,
    database           name NOT NULL,
    session_user_name  name NOT NULL,
    registered_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS voalack_guard.recovery_journal (
    window_id        bigint NOT NULL REFERENCES voalack_guard.recovery_windows (window_id),
    seq              bigint NOT NULL CHECK (seq >= 1),
    kind             text NOT NULL CHECK (kind IN ('open', 'register', 'retire', 'intent', 'seal', 'lab', 'disposition',
                                                   'close')),
    step             text CHECK (step IN ('contain', 'detach', 'transition', 'recreate', 'validate', 'close',
                                          'release')),
    intent_seq       bigint,
    registration_id  bigint REFERENCES voalack_guard.executor_backends (registration_id),
    prior            jsonb,
    target           jsonb,
    evidence         jsonb,
    effect_xid       xid8,
    xid_status       text CHECK (xid_status IN ('committed', 'unavailable')),
    pid              integer NOT NULL,
    backend_start    timestamptz NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (window_id, seq)
);
CREATE TABLE IF NOT EXISTS voalack_guard.recovery_effects (
    window_id      bigint NOT NULL,
    intent_seq     bigint NOT NULL,
    effect_xid     xid8 NOT NULL,
    effect         jsonb NOT NULL,
    pid            integer NOT NULL,
    backend_start  timestamptz NOT NULL,
    recorded_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (window_id, intent_seq),
    FOREIGN KEY (window_id, intent_seq) REFERENCES voalack_guard.recovery_journal (window_id, seq)
);
ALTER TABLE voalack_guard.recovery_windows OWNER TO voalack_guard_owner;
ALTER TABLE voalack_guard.executor_backends OWNER TO voalack_guard_owner;
ALTER TABLE voalack_guard.recovery_journal OWNER TO voalack_guard_owner;
ALTER TABLE voalack_guard.recovery_effects OWNER TO voalack_guard_owner;
REVOKE ALL ON voalack_guard.recovery_windows, voalack_guard.executor_backends, voalack_guard.recovery_journal,
              voalack_guard.recovery_effects FROM PUBLIC;

-- Append-only: one function for both trigger forms (FOR EACH ROW on UPDATE/DELETE, FOR EACH STATEMENT on TRUNCATE).
CREATE OR REPLACE FUNCTION voalack_guard.refuse_rewrite() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'voalack: % on %.% refused: recovery records are append-only', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME;
END;
$$;
CREATE OR REPLACE TRIGGER recovery_windows_append_only BEFORE UPDATE OR DELETE ON voalack_guard.recovery_windows
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER recovery_windows_no_truncate BEFORE TRUNCATE ON voalack_guard.recovery_windows
    FOR EACH STATEMENT EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER executor_backends_append_only BEFORE UPDATE OR DELETE ON voalack_guard.executor_backends
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER executor_backends_no_truncate BEFORE TRUNCATE ON voalack_guard.executor_backends
    FOR EACH STATEMENT EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER recovery_journal_append_only BEFORE UPDATE OR DELETE ON voalack_guard.recovery_journal
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER recovery_journal_no_truncate BEFORE TRUNCATE ON voalack_guard.recovery_journal
    FOR EACH STATEMENT EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER recovery_effects_append_only BEFORE UPDATE OR DELETE ON voalack_guard.recovery_effects
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER recovery_effects_no_truncate BEFORE TRUNCATE ON voalack_guard.recovery_effects
    FOR EACH STATEMENT EXECUTE FUNCTION voalack_guard.refuse_rewrite();

-- Maintenance permits (r8 section 10). Admitted writes only (permits_guard below): opened under a window's detach
-- intent by its registered coordinator, moved detach -> recreate by exact compare-and-set, closed one way; never
-- deleted. At most one open permit; a window has at most one permit, never reopened.
CREATE TABLE IF NOT EXISTS voalack_guard.maintenance_permits (
    permit_id   bigserial PRIMARY KEY,
    executor    text NOT NULL,
    phase       text NOT NULL CHECK (phase IN ('detach', 'recreate')),
    intent      jsonb NOT NULL DEFAULT '{}'::jsonb,
    opened_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at   timestamptz,
    window_id   bigint NOT NULL UNIQUE,
    intent_seq  bigint NOT NULL,
    FOREIGN KEY (window_id, intent_seq) REFERENCES voalack_guard.recovery_journal (window_id, seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS maintenance_permits_one_open ON voalack_guard.maintenance_permits ((true))
    WHERE closed_at IS NULL;

-- The frozen inventory: recorded once, at bootstrap, from the approved source (section 3). kind/name/attrs.
CREATE TABLE IF NOT EXISTS voalack_guard.frozen_inventory (
    kind   text NOT NULL,
    name   text NOT NULL,
    attrs  text NOT NULL,
    PRIMARY KEY (kind, name)
);
ALTER TABLE voalack_guard.maintenance_permits OWNER TO voalack_guard_owner;
ALTER TABLE voalack_guard.frozen_inventory OWNER TO voalack_guard_owner;
REVOKE ALL ON voalack_guard.maintenance_permits, voalack_guard.frozen_inventory FROM PUBLIC;

-- The four public triggers' frozen definitions, rendered by pg_get_triggerdef under this schema's fixed search_path
-- (public.alerts and the voalack functions qualified).
CREATE OR REPLACE FUNCTION voalack_guard.public_trigger_defs() RETURNS TABLE (name text, def text)
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    VALUES
      ('voalack_capture_ack', 'CREATE TRIGGER voalack_capture_ack AFTER UPDATE ON public.alerts FOR EACH ROW WHEN '
       '(((old.history[1] IS DISTINCT FROM new.history[1]) AND (new.history[1].type = ''ack''::text) '
       'AND (new.status = ''ack''::text))) EXECUTE FUNCTION voalack.capture_ack()'),
      ('voalack_alert_ownership', 'CREATE TRIGGER voalack_alert_ownership AFTER DELETE OR UPDATE ON public.alerts '
       'FOR EACH ROW EXECUTE FUNCTION voalack.alert_ownership()'),
      ('voalack_alert_lifetime', 'CREATE TRIGGER voalack_alert_lifetime AFTER INSERT ON public.alerts FOR EACH ROW '
       'EXECUTE FUNCTION voalack.alert_lifetime()'),
      ('voalack_alert_no_truncate', 'CREATE TRIGGER voalack_alert_no_truncate BEFORE TRUNCATE ON public.alerts '
       'FOR EACH STATEMENT EXECUTE FUNCTION voalack.alert_no_truncate()')
$$;

-- The protected functions of section 3 (and their direct callees), by signature. Resolved through the catalog by
-- name and argument types, never through name-input lookups: those need USAGE on the function's schema, which the
-- guard owner does not hold when it inspects a predecessor installation before the first install (F7 admission).
CREATE OR REPLACE FUNCTION voalack_guard.protected_functions() RETURNS SETOF regprocedure
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT p.oid::regprocedure
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname || '.' || p.proname || '(' || replace(oidvectortypes(p.proargtypes), ' ', '') || ')' IN (SELECT s FROM unnest(ARRAY[
        'voalack.capture_ack()', 'voalack.alert_class(text,text)', 'voalack.alert_ownership()',
        'voalack.alert_lifetime()', 'voalack.alert_id_reserved(text)', 'voalack._require_fresh_snapshot()',
        'voalack.alert_no_truncate()', 'voalack.alert_open_lifetime(text)', 'voalack.bindings_guard()',
        'voalack.enroll_binding(text,text,integer)', 'voalack.audit_ownership()', 'voalack.protections_intact()',
        'voalack.attest_legacy_revision(text,integer,bigint,text,text)',
        'voalack_lifetime.refuse_change()', 'voalack_lifetime.only_close()', 'voalack.refuse_change()',
        'voalack_guard.protect()', 'voalack_guard.inventory_problems()', 'voalack_guard.current_inventory()',
        'voalack_guard.public_trigger_defs()', 'voalack_guard.protected_functions()',
        -- S3b
        'voalack_guard.refuse_rewrite()', 'voalack_guard.writer_logins()', 'voalack_guard.connect_logins()',
        'voalack_guard.outside_digest(oid[])', 'voalack_guard.lifetime_digest()', 'voalack_guard.containment_snapshot()',
        'voalack_guard.caller_backend_start()', 'voalack_guard.window_active(bigint)', 'voalack_guard.current_registration(bigint)',
        'voalack_guard.preload_deny_v1()', 'voalack_guard.window_snapshot(bigint)', 'voalack_guard.cold_problems(bigint)',
        'voalack_guard.client_problems(bigint)', 'voalack_guard.trusted_superusers(bigint)', 'voalack_guard.role_problems(bigint,text)',
        'voalack_guard.window_problems(bigint,text)', 'voalack_guard.effect_problems(bigint,text,jsonb)', 'voalack_guard.step_phase(text)',
        'voalack_guard.open_intent(bigint)', 'voalack_guard.next_step(bigint)', 'voalack_guard.lock_window(bigint)',
        'voalack_guard.require_coordinator(bigint)', 'voalack_guard.receipt_binding(bigint,bigint)', 'voalack_guard.validation_problems(bigint)',
        'voalack_guard.run_probe()', 'voalack_guard.windows_insert_guard()', 'voalack_guard.windows_after_insert()',
        'voalack_guard.backends_insert_guard()', 'voalack_guard.backends_after_insert()', 'voalack_guard.journal_insert_guard()',
        'voalack_guard.journal_after_insert()', 'voalack_guard.effects_insert_guard()', 'voalack_guard.permits_guard()',
        'voalack_guard.open_window(text,jsonb)', 'voalack_guard.register_backend(bigint,text)', 'voalack_guard.begin_step(bigint,text)',
        'voalack_guard.record_effect(bigint,bigint)', 'voalack_guard.seal_step(bigint,bigint)', 'voalack_guard.lab_gap(bigint)',
        'voalack_guard.open_permit(bigint,bigint)', 'voalack_guard.transition_permit(bigint,bigint,text,text)', 'voalack_guard.close_permit(bigint,bigint)',
        'voalack_guard.close_window(bigint)', 'voalack_guard.record_disposition(bigint,text,text,text)']) s)
$$;

-- The current inventory, canonically: every protected function (body digest, language, owner, security, proconfig,
-- ACL, volatility), every trigger on public.alerts that is named as a protection or calls a voalack function (enabled
-- state and exact definition), the two event triggers, the guard and lifetime relations, their triggers, columns,
-- constraints and indexes, and the two protected schemas (owner and ACL).
CREATE OR REPLACE FUNCTION voalack_guard.current_inventory() RETURNS TABLE (kind text, name text, attrs text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    -- (search_path without voalack or voalack_guard: every rendered name is fully qualified)
    -- (every component is non-NULL or coalesced to a tagged form: one NULL would null the whole attrs string, and NULL
    -- is not DISTINCT from NULL, so drift would go unseen. The body digest covers the tagged prosrc and the tagged
    -- SQL-standard parsed body, so an absent prosrc never equals an empty one; the language is kept.)
    SELECT 'function', p.oid::regprocedure::text,
           encode(sha256(convert_to(coalesce('src:' || p.prosrc, 'src-null') || '|' ||
                                    coalesce('sqlbody:' || pg_get_function_sqlbody(p.oid), 'sqlbody-null'),
                                    'UTF8')), 'hex') || '|' || l.lanname::text || '|' || pg_get_userbyid(p.proowner) || '|' ||
           p.prosecdef::text || '|' || coalesce(array_to_string(p.proconfig, ','), '') || '|' ||
           coalesce(p.proacl::text, 'default') || '|' || p.provolatile::text
      FROM pg_proc p JOIN pg_language l ON l.oid = p.prolang
     WHERE p.oid IN (SELECT f FROM voalack_guard.protected_functions() f WHERE f IS NOT NULL)
    UNION ALL
    SELECT 'public_trigger', t.tgname, t.tgenabled::text || '|' || pg_get_triggerdef(t.oid)
      FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid
     WHERE t.tgrelid = 'public.alerts'::regclass AND NOT t.tgisinternal
       AND (p.pronamespace IN (to_regnamespace('voalack'), to_regnamespace('voalack_guard'))
            OR t.tgname IN (SELECT d.name FROM voalack_guard.public_trigger_defs() d))
    UNION ALL
    SELECT 'event_trigger', e.evtname, e.evtevent || '|' || e.evtenabled::text || '|' || e.evtfoid::regprocedure::text ||
           '|' || coalesce(array_to_string(e.evttags, ','), '')
      FROM pg_event_trigger e
     WHERE e.evtname LIKE 'voalack%' OR e.evtfoid = to_regprocedure('voalack_guard.protect()')
    UNION ALL
    SELECT 'relation', c.oid::regclass::text,
           c.relkind::text || '|' || pg_get_userbyid(c.relowner) || '|' || coalesce(c.relacl::text, 'default')
      FROM pg_class c
     WHERE c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    SELECT 'relation_trigger', t.tgrelid::regclass::text || '.' || t.tgname, t.tgenabled::text || '|' || pg_get_triggerdef(t.oid)
      FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
     WHERE NOT t.tgisinternal
       AND c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    -- Protected relation structure: every live column of every table (position, type, not-null, default, identity,
    -- generation), every constraint and every index definition in the two protected schemas.
    SELECT 'relation_column', a.attrelid::regclass::text || '.' || a.attname::text,
           a.attnum::text || '|' || format_type(a.atttypid, a.atttypmod) || '|' ||
           CASE a.attcollation WHEN 0 THEN 'nocollation' ELSE 'collation:' || a.attcollation::regcollation::text END || '|' ||
           a.attnotnull::text || '|' || coalesce('default:' || pg_get_expr(d.adbin, d.adrelid), 'nodefault') || '|' ||
           'identity:' || a.attidentity::text || '|' || 'generated:' || a.attgenerated::text
      FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
      LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
     WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
       AND c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    SELECT 'relation_constraint', co.conrelid::regclass::text || '.' || co.conname::text,
           co.contype::text || '|' || co.convalidated::text || '|' || co.condeferrable::text || '|' ||
           co.condeferred::text || '|' || co.connoinherit::text || '|' || pg_get_constraintdef(co.oid)
      FROM pg_constraint co JOIN pg_class c ON c.oid = co.conrelid
     WHERE c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    SELECT 'index', i.indexrelid::regclass::text,
           i.indisprimary::text || '|' || i.indimmediate::text || '|' || i.indisvalid::text || '|' ||
           i.indisreplident::text || '|' || pg_get_indexdef(i.indexrelid)
      FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
     WHERE c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    -- Amendment A1: exactly two nonpublic attachments (enabled state and exact form), nothing wider.
    SELECT 'attachment', t.tgrelid::regclass::text || '.' || t.tgname, t.tgenabled::text || '|' || pg_get_triggerdef(t.oid)
      FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE NOT t.tgisinternal AND n.nspname = 'voalack'
       AND ((c.relname = 'bindings' AND t.tgname = 'bindings_guard')
            OR (c.relname = 'binding_revisions' AND t.tgname = 'binding_revisions_immutable'))
    UNION ALL
    -- Protected sequences: definition parameters and the owning column (serial 'a' or identity 'i' dependency), never
    -- the evolving value (last_value is not frozen).
    SELECT 'sequence', sq.seqrelid::regclass::text,
           format_type(sq.seqtypid, NULL) || '|' || sq.seqstart::text || '|' || sq.seqincrement::text || '|' ||
           sq.seqmin::text || '|' || sq.seqmax::text || '|' || sq.seqcache::text || '|' || sq.seqcycle::text || '|' ||
           coalesce((SELECT 'owned:' || dp.deptype::text || ':' || dp.refobjid::regclass::text || '.' || at.attname::text
                       FROM pg_depend dp JOIN pg_attribute at ON at.attrelid = dp.refobjid AND at.attnum = dp.refobjsubid
                      WHERE dp.classid = 'pg_class'::regclass AND dp.objid = sq.seqrelid
                        AND dp.refclassid = 'pg_class'::regclass AND dp.deptype IN ('a', 'i')), 'unowned')
      FROM pg_sequence sq JOIN pg_class c ON c.oid = sq.seqrelid
     WHERE c.relnamespace IN (to_regnamespace('voalack_guard'),
                              coalesce(to_regnamespace('voalack_lifetime'), to_regnamespace('voalack_guard')))
    UNION ALL
    -- The two protected schemas: owner and raw ACL (NULL rendered 'default', distinct from {} and explicit entries).
    SELECT 'namespace', n.nspname::text, pg_get_userbyid(n.nspowner) || '|' || coalesce(n.nspacl::text, 'default')
      FROM pg_namespace n WHERE n.nspname IN ('voalack_guard', 'voalack_lifetime')
$$;

-- Problems against the frozen inventory: missing, extra and differing entries. Empty means intact.
CREATE OR REPLACE FUNCTION voalack_guard.inventory_problems() RETURNS text[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT coalesce(array_agg(x ORDER BY x), ARRAY[]::text[]) FROM (
        SELECT 'missing ' || f.kind || ' ' || f.name AS x
          FROM voalack_guard.frozen_inventory f
         WHERE NOT EXISTS (SELECT 1 FROM voalack_guard.current_inventory() c WHERE c.kind = f.kind AND c.name = f.name)
        UNION ALL
        SELECT 'extra ' || c.kind || ' ' || c.name FROM voalack_guard.current_inventory() c
         WHERE NOT EXISTS (SELECT 1 FROM voalack_guard.frozen_inventory f WHERE f.kind = c.kind AND f.name = c.name)
        UNION ALL
        SELECT 'differs ' || f.kind || ' ' || f.name
          FROM voalack_guard.frozen_inventory f JOIN voalack_guard.current_inventory() c
            ON c.kind = f.kind AND c.name = f.name AND c.attrs IS DISTINCT FROM f.attrs) problems
$$;

-- The protector (both event triggers). Outside a permit: any DDL that leaves the inventory with a problem raises and
-- rolls back, whoever runs it. Inside the one open permit (executor = session_user only): the phase's operations.
CREATE OR REPLACE FUNCTION voalack_guard.protect() RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    p voalack_guard.maintenance_permits%ROWTYPE;
    problems text[];
    d record;
    c record;
    four text[] := ARRAY(SELECT name FROM voalack_guard.public_trigger_defs());
BEGIN
    SELECT * INTO p FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL;
    IF NOT FOUND THEN
        problems := voalack_guard.inventory_problems();
        IF cardinality(problems) > 0 THEN
            RAISE EXCEPTION 'voalack: DDL refused, protected inventory would change: %', problems;
        END IF;
        RETURN;
    END IF;
    IF p.executor IS DISTINCT FROM session_user THEN
        RAISE EXCEPTION 'voalack: DDL refused, a maintenance permit is open for another executor';
    END IF;
    -- S3b (r8a r7 section 8): only the window's registered coordinator backend acts under its permit, by exact
    -- identity: pid, backend start, session user and database. This definer function reads backend_start through
    -- the guard owner's pg_read_all_stats membership (a recovery prerequisite, checked when a window opens); an
    -- unreadable backend start never weakens the match: it refuses.
    IF NOT EXISTS (SELECT 1 FROM voalack_guard.executor_backends b JOIN pg_stat_activity a ON a.pid = b.pid
                    WHERE b.registration_id = voalack_guard.current_registration(p.window_id)
                      AND b.pid = pg_backend_pid() AND b.session_user_name = session_user
                      AND b.database = current_database()
                      AND a.backend_start IS NOT NULL AND a.backend_start = b.backend_start) THEN
        RAISE EXCEPTION 'voalack: DDL refused, the permit of window % belongs to its registered coordinator (exact pid '
                        'and backend start)', p.window_id;
    END IF;
    -- A recreate permit names the triggers it may drop: intent->'drop' must be a JSON array. A missing key, JSON null or
    -- any other type refuses every DDL under the permit (never an UNKNOWN that skips a check).
    IF p.phase = 'recreate' AND jsonb_typeof(p.intent -> 'drop') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'voalack: DDL refused, permit % (recreate) has no valid drop intent (a JSON array of names)',
            p.permit_id;
    END IF;
    IF TG_EVENT = 'sql_drop' THEN
        FOR d IN SELECT * FROM pg_event_trigger_dropped_objects() LOOP
            IF NOT coalesce(d.object_type = 'trigger' AND d.schema_name = 'public'
                    AND d.object_identity IN (SELECT n || ' on public.alerts' FROM unnest(four) n), false) THEN
                RAISE EXCEPTION 'voalack: DDL refused, permit % (%) does not allow dropping % %',
                    p.permit_id, p.phase, d.object_type, d.object_identity;
            END IF;
            IF p.phase = 'recreate'
               AND NOT coalesce((p.intent -> 'drop') ? split_part(d.object_identity, ' on ', 1), false) THEN
                RAISE EXCEPTION 'voalack: DDL refused, % is not named in the recreate step''s intent', d.object_identity;
            END IF;
        END LOOP;
        RETURN;
    END IF;
    IF NOT ((p.phase = 'detach' AND TG_TAG = 'DROP TRIGGER')
            OR (p.phase = 'recreate' AND TG_TAG IN ('DROP TRIGGER', 'CREATE TRIGGER'))) THEN
        RAISE EXCEPTION 'voalack: DDL refused, permit % (%) does not allow %', p.permit_id, p.phase, TG_TAG;
    END IF;
    -- Every object the command created must be one of the four public triggers (by identity: for a trigger,
    -- pg_event_trigger_ddl_commands() reports schema_name NULL and identity '<name> on public.alerts'). A DROP
    -- reports no rows here; its objects are checked at sql_drop.
    FOR c IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
        IF NOT coalesce(c.object_type = 'trigger'
                        AND c.object_identity IN (SELECT n || ' on public.alerts' FROM unnest(four) n), false) THEN
            RAISE EXCEPTION 'voalack: DDL refused, permit % (%) does not allow creating % %',
                p.permit_id, p.phase, c.object_type, c.object_identity;
        END IF;
    END LOOP;
    -- A CREATE TRIGGER that reports no created address is not a supported case: refused, never admitted unchecked.
    IF TG_TAG = 'CREATE TRIGGER' AND NOT EXISTS (SELECT 1 FROM pg_event_trigger_ddl_commands()) THEN
        RAISE EXCEPTION 'voalack: DDL refused, permit % (%): CREATE TRIGGER reported no created object',
            p.permit_id, p.phase;
    END IF;
    -- Everything but the four public triggers' presence must be intact; a present one must be in frozen form.
    problems := ARRAY(SELECT x FROM unnest(voalack_guard.inventory_problems()) x
                       WHERE x NOT IN (SELECT 'missing public_trigger ' || n FROM unnest(four) n));
    IF cardinality(problems) > 0 THEN
        RAISE EXCEPTION 'voalack: DDL refused under permit % (%): %', p.permit_id, p.phase, problems;
    END IF;
END;
$$;

-- ---- S3b inventories (logins only; superusers excluded; computed from the catalog, never from a caller) ----
-- W: logins with write authority on public.alerts: direct, by membership (inheritance), through PUBLIC (all three via
-- has_table_privilege / has_any_column_privilege), or by SET ROLE to a role that has it.
CREATE OR REPLACE FUNCTION voalack_guard.writer_logins() RETURNS TABLE (role_oid oid, role_name name)
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT l.oid, l.rolname FROM pg_roles l
     WHERE l.rolcanlogin AND NOT l.rolsuper
       AND (has_table_privilege(l.oid, 'public.alerts', 'INSERT,UPDATE,DELETE,TRUNCATE')
            OR has_any_column_privilege(l.oid, 'public.alerts', 'INSERT,UPDATE')
            OR EXISTS (SELECT 1 FROM pg_roles r
                        WHERE r.oid <> l.oid AND pg_has_role(l.oid, r.oid, 'SET')
                          AND (has_table_privilege(r.oid, 'public.alerts', 'INSERT,UPDATE,DELETE,TRUNCATE')
                               OR has_any_column_privilege(r.oid, 'public.alerts', 'INSERT,UPDATE'))))
$$;
-- C: logins with CONNECT on this database.
CREATE OR REPLACE FUNCTION voalack_guard.connect_logins() RETURNS TABLE (role_oid oid, role_name name)
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT l.oid, l.rolname FROM pg_roles l
     WHERE l.rolcanlogin AND NOT l.rolsuper AND has_database_privilege(l.oid, current_database(), 'CONNECT')
$$;
-- R: every role outside the given set, with its limit (cluster-wide; detects unrelated limit changes).
CREATE OR REPLACE FUNCTION voalack_guard.outside_digest(p_k oid[]) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT encode(sha256(convert_to(coalesce(string_agg(r.oid::text || ':' || r.rolname || ':' || r.rolconnlimit::text,
                                                        ',' ORDER BY r.oid), ''), 'UTF8')), 'hex')
      FROM pg_roles r WHERE NOT (r.oid = ANY (p_k))
$$;
-- L: the lifetime data, byte for byte (held equal from contained through permits_closed).
-- (plpgsql: guard_pre.sql runs before schema.sql creates voalack_lifetime, so the tables resolve at call time)
CREATE OR REPLACE FUNCTION voalack_guard.lifetime_digest() RETURNS text
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    RETURN encode(sha256(convert_to(
        coalesce((SELECT string_agg(l::text, E'\n' ORDER BY l.lifetime_id) FROM voalack_lifetime.alert_lifetimes l), '')
        || E'\n--\n' ||
        coalesce((SELECT string_agg(b::text, E'\n' ORDER BY b.retirement_id) FROM voalack_lifetime.binding_retirements b), ''),
        'UTF8')), 'hex');
END;
$$;
-- The containment snapshot recorded in the contain intent: K = W union C with exact prior limits, and R, L.
CREATE OR REPLACE FUNCTION voalack_guard.containment_snapshot() RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    WITH w AS (SELECT * FROM voalack_guard.writer_logins()), c AS (SELECT * FROM voalack_guard.connect_logins()),
         k AS (SELECT r.oid, r.rolname, r.rolconnlimit, r.oid IN (SELECT role_oid FROM w) AS in_w,
                      r.oid IN (SELECT role_oid FROM c) AS in_c
                 FROM pg_roles r WHERE r.oid IN (SELECT role_oid FROM w UNION SELECT role_oid FROM c))
    SELECT jsonb_build_object(
        'k', coalesce((SELECT jsonb_agg(jsonb_build_object('oid', k.oid::bigint, 'name', k.rolname, 'w', k.in_w,
                                                            'c', k.in_c, 'limit', k.rolconnlimit) ORDER BY k.oid) FROM k),
                      '[]'::jsonb),
        'r_digest', voalack_guard.outside_digest(ARRAY(SELECT k.oid FROM k)),
        'lifetime_digest', voalack_guard.lifetime_digest())
$$;

CREATE OR REPLACE FUNCTION voalack_guard.caller_backend_start() RETURNS timestamptz
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT a.backend_start FROM pg_stat_activity a WHERE a.pid = pg_backend_pid()
$$;
CREATE OR REPLACE FUNCTION voalack_guard.window_active(p_window bigint) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal o WHERE o.window_id = p_window AND o.kind = 'open')
       AND NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal c WHERE c.window_id = p_window AND c.kind = 'close')
$$;
-- The current coordinator: the latest register entry with no later retire entry.
CREATE OR REPLACE FUNCTION voalack_guard.current_registration(p_window bigint) RETURNS bigint
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT r.registration_id FROM voalack_guard.recovery_journal r
     WHERE r.window_id = p_window AND r.kind = 'register'
       AND NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal x
                        WHERE x.window_id = r.window_id AND x.kind = 'retire' AND x.registration_id = r.registration_id)
     ORDER BY r.seq DESC LIMIT 1
$$;
-- The frozen preload restriction (versioned): libraries that launch SQL-executing workers.
CREATE OR REPLACE FUNCTION voalack_guard.preload_deny_v1() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT ARRAY['pg_cron', 'pg_background', 'pg_partman_bgw', 'timescaledb', 'citus', 'pglogical']
$$;

-- ---- S3b predicates ----
-- The recorded containment snapshot of the window (the contain intent's prior), or NULL before containment.
CREATE OR REPLACE FUNCTION voalack_guard.window_snapshot(p_window bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT j.prior FROM voalack_guard.recovery_journal j
     WHERE j.window_id = p_window AND j.kind = 'intent' AND j.step = 'contain' ORDER BY j.seq LIMIT 1
$$;
-- Cold prerequisites (P2), excluding role limits: prepared transactions, client backends other than the coordinator
-- (superuser clients are the trusted, detection-only exception and are not problems here), background workers other
-- than parallel workers led by the coordinator, logical replication workers, enabled subscriptions, scratch databases
-- and their backends, and a changed preload setting.
CREATE OR REPLACE FUNCTION voalack_guard.cold_problems(p_window bigint) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    WITH reg AS (SELECT b.* FROM voalack_guard.executor_backends b
                  WHERE b.registration_id = voalack_guard.current_registration(p_window))
    SELECT coalesce(array_agg(x ORDER BY x), ARRAY[]::text[]) FROM (
        SELECT 'prepared transaction ' || p.gid AS x FROM pg_prepared_xacts p
        UNION ALL
        SELECT 'background worker pid ' || a.pid FROM pg_stat_activity a
         WHERE a.backend_type = 'background worker' AND (a.datname IS NULL OR a.datname = current_database())
           AND a.leader_pid IS DISTINCT FROM (SELECT pid FROM reg)
        UNION ALL
        SELECT 'logical replication worker pid ' || a.pid FROM pg_stat_activity a
         WHERE a.backend_type IN ('logical replication worker', 'parallel apply worker', 'tablesync worker')
        UNION ALL
        SELECT 'enabled subscription ' || s.subname FROM pg_subscription s JOIN pg_database d ON d.oid = s.subdbid
         WHERE d.datname = current_database() AND s.subenabled
        UNION ALL
        SELECT 'scratch database ' || d.datname FROM pg_database d WHERE d.datname LIKE 'voalack\_scratch\_%'
        UNION ALL
        SELECT 'scratch backend pid ' || a.pid FROM pg_stat_activity a WHERE a.datname LIKE 'voalack\_scratch\_%'
        UNION ALL
        SELECT 'shared_preload_libraries changed' FROM voalack_guard.recovery_windows w
         WHERE w.window_id = p_window AND w.preload IS DISTINCT FROM current_setting('shared_preload_libraries')) q
$$;
-- Client backends on this database other than the coordinator, excluding superusers (trusted, detection only):
-- checked from the contained seal on (before it, the containment effect terminates them).
CREATE OR REPLACE FUNCTION voalack_guard.client_problems(p_window bigint) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT coalesce(array_agg('unregistered client backend pid ' || a.pid ORDER BY a.pid), ARRAY[]::text[])
      FROM pg_stat_activity a JOIN pg_roles r ON r.oid = a.usesysid
     WHERE a.backend_type = 'client backend' AND a.datname = current_database() AND NOT r.rolsuper
       AND a.pid NOT IN (SELECT b.pid FROM voalack_guard.executor_backends b
                          WHERE b.registration_id = voalack_guard.current_registration(p_window))
$$;
-- Superuser client sessions other than the coordinator: trusted, detection only; recorded in seal evidence.
CREATE OR REPLACE FUNCTION voalack_guard.trusted_superusers(p_window bigint) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT coalesce(jsonb_agg(jsonb_build_object('pid', a.pid, 'role', r.rolname, 'backend_start', a.backend_start)
                              ORDER BY a.pid), '[]'::jsonb)
      FROM pg_stat_activity a JOIN pg_roles r ON r.oid = a.usesysid
     WHERE a.backend_type = 'client backend' AND r.rolsuper
       AND a.pid NOT IN (SELECT b.pid FROM voalack_guard.executor_backends b
                          WHERE b.registration_id = voalack_guard.current_registration(p_window))
$$;
-- Inventory and limit problems against the recorded snapshot. p_limits: 'zero' (contained through pre-release) or
-- 'prior' (released). W and C are recomputed by oid and name; R and the identities of K are compared.
CREATE OR REPLACE FUNCTION voalack_guard.role_problems(p_window bigint, p_limits text) RETURNS text[]
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    WITH snap AS (SELECT voalack_guard.window_snapshot(p_window) AS s),
         k AS (SELECT (e ->> 'oid')::oid AS oid, e ->> 'name' AS name, (e ->> 'w')::boolean AS in_w,
                      (e ->> 'c')::boolean AS in_c, (e ->> 'limit')::integer AS prior
                 FROM snap, jsonb_array_elements(snap.s -> 'k') e)
    SELECT coalesce(array_agg(x ORDER BY x), ARRAY[]::text[]) FROM (
        SELECT 'no containment snapshot' AS x FROM snap WHERE snap.s IS NULL
        UNION ALL
        SELECT 'contained role ' || k.name || ' changed identity' FROM k
         WHERE NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = k.oid AND r.rolname = k.name)
        UNION ALL
        SELECT 'contained role ' || k.name || ' limit ' || r.rolconnlimit || ' is not ' ||
               CASE p_limits WHEN 'zero' THEN '0' ELSE 'its prior ' || k.prior END
          FROM k JOIN pg_roles r ON r.oid = k.oid
         WHERE r.rolconnlimit <> CASE p_limits WHEN 'zero' THEN 0 ELSE k.prior END
        UNION ALL
        SELECT 'writer login set changed: ' || coalesce(string_agg(d, ', '), '') FROM (
            (SELECT w.role_oid::text || ':' || w.role_name AS d FROM voalack_guard.writer_logins() w
             EXCEPT SELECT k.oid::text || ':' || k.name FROM k WHERE k.in_w)
            UNION ALL
            (SELECT k.oid::text || ':' || k.name FROM k WHERE k.in_w
             EXCEPT SELECT w.role_oid::text || ':' || w.role_name FROM voalack_guard.writer_logins() w)) dw
        HAVING count(*) > 0
        UNION ALL
        SELECT 'CONNECT login set changed: ' || coalesce(string_agg(d, ', '), '') FROM (
            (SELECT c.role_oid::text || ':' || c.role_name AS d FROM voalack_guard.connect_logins() c
             EXCEPT SELECT k.oid::text || ':' || k.name FROM k WHERE k.in_c)
            UNION ALL
            (SELECT k.oid::text || ':' || k.name FROM k WHERE k.in_c
             EXCEPT SELECT c.role_oid::text || ':' || c.role_name FROM voalack_guard.connect_logins() c)) dc
        HAVING count(*) > 0
        UNION ALL
        SELECT 'roles outside the containment set changed' FROM snap
         WHERE snap.s IS NOT NULL
           AND voalack_guard.outside_digest(ARRAY(SELECT k.oid FROM k)) IS DISTINCT FROM snap.s ->> 'r_digest'
        UNION ALL
        SELECT 'session of contained role pid ' || a.pid FROM pg_stat_activity a
         WHERE p_limits = 'zero' AND a.usesysid IN (SELECT k.oid FROM k)) q
$$;
-- Phase predicate for a seal (r2 section E, r3 sections 3-4). Phases: contained, detached, transitioned, recreated,
-- validated, permits_closed, pre_release, released. 'released' has no cold-client clause.
CREATE OR REPLACE FUNCTION voalack_guard.window_problems(p_window bigint, p_phase text) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    four text[] := ARRAY(SELECT name FROM voalack_guard.public_trigger_defs());
    missing_four text[] := ARRAY(SELECT 'missing public_trigger ' || n FROM unnest(four) n);
    p voalack_guard.maintenance_permits%ROWTYPE;
    inv text[] := voalack_guard.inventory_problems();
    out text[] := ARRAY[]::text[];
    snap jsonb := voalack_guard.window_snapshot(p_window);
    want_phase text := CASE p_phase WHEN 'detached' THEN 'detach' ELSE 'recreate' END;
BEGIN
    IF p_phase NOT IN ('contained', 'detached', 'transitioned', 'recreated', 'validated', 'permits_closed',
                       'pre_release', 'released') THEN
        RAISE EXCEPTION 'voalack: unknown phase %', p_phase;
    END IF;
    SELECT * INTO p FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL;
    IF p_phase <> 'released' THEN
        out := out || voalack_guard.cold_problems(p_window) || voalack_guard.client_problems(p_window)
                   || voalack_guard.role_problems(p_window, 'zero');
    ELSE
        out := out || voalack_guard.role_problems(p_window, 'prior');
    END IF;
    IF p_phase IN ('contained', 'detached', 'transitioned', 'recreated', 'validated', 'permits_closed')
       AND snap IS NOT NULL AND voalack_guard.lifetime_digest() IS DISTINCT FROM snap ->> 'lifetime_digest' THEN
        out := out || 'lifetime data changed in the window'::text;
    END IF;
    IF p_phase = 'contained' THEN
        IF p.permit_id IS NOT NULL THEN out := out || 'a permit is open'::text; END IF;
        IF cardinality(inv) > 0 THEN out := out || inv; END IF;
    ELSIF p_phase IN ('detached', 'transitioned', 'recreated', 'validated') THEN
        IF p.permit_id IS NULL OR p.window_id IS DISTINCT FROM p_window THEN
            out := out || 'no open permit of this window'::text;
        ELSIF p.phase <> want_phase THEN
            out := out || ('permit phase ' || p.phase)::text;
        END IF;
        IF p_phase IN ('detached', 'transitioned') THEN
            IF EXISTS (SELECT 1 FROM unnest(missing_four) m WHERE NOT (m = ANY (inv))) THEN
                out := out || 'a public trigger is present'::text;
            END IF;
            out := out || ARRAY(SELECT x FROM unnest(inv) x WHERE NOT (x = ANY (missing_four)));
        ELSIF cardinality(inv) > 0 THEN
            out := out || inv;
        END IF;
    ELSE   -- permits_closed, pre_release, released: normal protection
        IF p.permit_id IS NOT NULL THEN out := out || 'a permit is open'::text; END IF;
        IF cardinality(inv) > 0 THEN out := out || inv; END IF;
    END IF;
    RETURN out;
END;
$$;

-- What each step's catalog effect is, given its intent (checked inside T_effect by record_effect and again in the
-- seal's fresh snapshot).
CREATE OR REPLACE FUNCTION voalack_guard.effect_problems(p_window bigint, p_step text, p_intent jsonb) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    four text[] := ARRAY(SELECT name FROM voalack_guard.public_trigger_defs());
    inv text[] := voalack_guard.inventory_problems();
    p voalack_guard.maintenance_permits%ROWTYPE;
BEGIN
    SELECT * INTO p FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL;
    CASE p_step
    WHEN 'contain' THEN
        RETURN ARRAY(SELECT x FROM unnest(voalack_guard.role_problems(p_window, 'zero')) x WHERE x LIKE 'contained role %');
    WHEN 'detach' THEN
        IF p.permit_id IS NULL OR p.window_id IS DISTINCT FROM p_window OR p.phase <> 'detach' THEN
            RETURN ARRAY['no open detach permit of this window'];
        END IF;
        RETURN ARRAY(SELECT 'public trigger present ' || n FROM unnest(four) n
                      WHERE NOT (('missing public_trigger ' || n) = ANY (inv)));
    WHEN 'transition' THEN
        IF p.permit_id IS NULL OR p.window_id IS DISTINCT FROM p_window OR p.phase <> 'recreate' THEN
            RETURN ARRAY['no open recreate permit of this window'];
        END IF;
        RETURN ARRAY[]::text[];
    WHEN 'recreate' THEN
        RETURN inv;
    WHEN 'close' THEN
        IF EXISTS (SELECT 1 FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL) THEN
            RETURN ARRAY['a permit is open'];
        END IF;
        RETURN ARRAY[]::text[];
    WHEN 'release' THEN
        RETURN ARRAY(SELECT x FROM unnest(voalack_guard.role_problems(p_window, 'prior')) x WHERE x LIKE 'contained role %');
    ELSE
        RAISE EXCEPTION 'voalack: step % has no effect transaction', p_step;
    END CASE;
END;
$$;
-- The seal phase of each step.
CREATE OR REPLACE FUNCTION voalack_guard.step_phase(p_step text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT CASE p_step WHEN 'contain' THEN 'contained' WHEN 'detach' THEN 'detached' WHEN 'transition' THEN 'transitioned'
                       WHEN 'recreate' THEN 'recreated' WHEN 'validate' THEN 'validated'
                       WHEN 'close' THEN 'permits_closed' WHEN 'release' THEN 'released' END
$$;
-- The latest unsealed intent of the window, if any.
CREATE OR REPLACE FUNCTION voalack_guard.open_intent(p_window bigint) RETURNS voalack_guard.recovery_journal
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT j.* FROM voalack_guard.recovery_journal j
     WHERE j.window_id = p_window AND j.kind = 'intent'
       AND NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal s
                        WHERE s.window_id = j.window_id AND s.kind = 'seal' AND s.intent_seq = j.seq)
     ORDER BY j.seq DESC LIMIT 1
$$;
-- ---- S3b order, lock and identity ----
-- The frozen step order (r8 section 11, S3b no-restore profile): the next step after the last sealed one.
CREATE OR REPLACE FUNCTION voalack_guard.next_step(p_window bigint) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
    SELECT CASE coalesce((SELECT j.step FROM voalack_guard.recovery_journal j
                           WHERE j.window_id = p_window AND j.kind = 'seal' ORDER BY j.seq DESC LIMIT 1), '')
             WHEN '' THEN 'contain'
             WHEN 'contain' THEN 'detach'
             WHEN 'detach' THEN 'transition'
             WHEN 'transition' THEN 'recreate'
             WHEN 'recreate' THEN 'validate'
             WHEN 'validate' THEN 'close'
             WHEN 'close' THEN 'release'
           END
$$;
-- Serialization (concurrence 78f1861c) and recorded identity (early review 7d13602a): the window row lock, READ
-- COMMITTED (every later statement sees the state as of after the wait), this database and this cluster.
CREATE OR REPLACE FUNCTION voalack_guard.lock_window(p_window bigint) RETURNS voalack_guard.recovery_windows
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w voalack_guard.recovery_windows%ROWTYPE;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'voalack: recovery decisions run in READ COMMITTED (rechecked after the lock)';
    END IF;
    SELECT * INTO w FROM voalack_guard.recovery_windows WHERE window_id = p_window FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: recovery window % does not exist', p_window;
    END IF;
    IF w.database <> current_database()
       OR w.system_identifier <> (SELECT system_identifier FROM pg_control_system()) THEN
        RAISE EXCEPTION 'voalack: recovery window % belongs to another database or cluster', p_window;
    END IF;
    RETURN w;
END;
$$;
-- The caller must be the window's current registered coordinator: exact pid, backend start, database, session user.
CREATE OR REPLACE FUNCTION voalack_guard.require_coordinator(p_window bigint) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    reg voalack_guard.executor_backends%ROWTYPE;
BEGIN
    SELECT * INTO reg FROM voalack_guard.executor_backends
     WHERE registration_id = voalack_guard.current_registration(p_window);
    IF NOT FOUND OR reg.pid <> pg_backend_pid() OR reg.backend_start IS DISTINCT FROM voalack_guard.caller_backend_start()
       OR reg.database <> current_database() OR reg.session_user_name <> session_user THEN
        RAISE EXCEPTION 'voalack: the caller is not the registered coordinator of window %', p_window;
    END IF;
    RETURN reg.registration_id;
END;
$$;

-- ---- S3b receipts, validation and the probe ----
-- A seal's receipt binding (r3 section 1, review 7d13602a): the receipt of exactly this window and intent, visible in
-- this snapshot, recording exactly the intent's target, written by a registered backend of this window; not this
-- transaction's; not in progress or aborted; 'unavailable' recorded honestly for a too-old xid.
-- (bigint, bigint): a composite-type argument would render unqualified under this search_path and fall out of the
-- protected-function list.
CREATE OR REPLACE FUNCTION voalack_guard.receipt_binding(p_window bigint, p_intent_seq bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    p_intent voalack_guard.recovery_journal%ROWTYPE;
    r voalack_guard.recovery_effects%ROWTYPE;
    st text;
BEGIN
    SELECT * INTO p_intent FROM voalack_guard.recovery_journal
     WHERE window_id = p_window AND seq = p_intent_seq AND kind = 'intent';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: intent % does not exist in window %', p_intent_seq, p_window;
    END IF;
    SELECT * INTO r FROM voalack_guard.recovery_effects WHERE window_id = p_window AND intent_seq = p_intent.seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: intent % has no visible effect receipt', p_intent.seq;
    END IF;
    IF r.effect IS DISTINCT FROM p_intent.target THEN
        RAISE EXCEPTION 'voalack: the receipt of intent % records another effect', p_intent.seq;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM voalack_guard.executor_backends b WHERE b.window_id = p_window AND b.pid = r.pid
                                                                    AND b.backend_start = r.backend_start) THEN
        RAISE EXCEPTION 'voalack: the receipt of intent % was not written by a registered backend', p_intent.seq;
    END IF;
    IF r.effect_xid = pg_current_xact_id_if_assigned() THEN
        RAISE EXCEPTION 'voalack: a seal cannot share its effect''s transaction (receipt xid %)', r.effect_xid;
    END IF;
    st := pg_xact_status(r.effect_xid);
    IF st IN ('in progress', 'aborted') THEN
        RAISE EXCEPTION 'voalack: the effect transaction % is %', r.effect_xid, st;
    END IF;
    RETURN jsonb_build_object('xid', r.effect_xid::text, 'status', CASE WHEN st IS NULL THEN 'unavailable' ELSE st END);
END;
$$;
-- r8 section 11 validation (no restore in S3b): the validated phase predicate and every active binding referencing
-- its alert's open lifetime.
CREATE OR REPLACE FUNCTION voalack_guard.validation_problems(p_window bigint) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    RETURN voalack_guard.window_problems(p_window, 'validated')
        || ARRAY(SELECT 'active binding ' || b.alert_id || ' does not reference its alert''s open lifetime'
                   FROM voalack.bindings b
                   LEFT JOIN voalack.binding_revisions r
                     ON r.binding_id = b.binding_id AND r.binding_revision = b.binding_revision
                  WHERE b.active
                    AND (b.alert_lifetime_id IS NULL
                         OR b.alert_lifetime_id IS DISTINCT FROM r.alert_lifetime_id
                         OR b.alert_lifetime_id IS DISTINCT FROM (SELECT l.lifetime_id
                                                                     FROM voalack_lifetime.alert_lifetimes l
                                                                    WHERE l.alert_id = b.alert_id
                                                                      AND l.closed_at IS NULL)));
END;
$$;
-- The protector probe (r3; exact match, review 7d13602a): disabling the capture trigger on public.alerts, in an
-- exception subtransaction, must be refused by protect() with exactly SQLSTATE P0001 and exactly this message, and is
-- rolled back. Any other error propagates; an admitted DDL raises. Returns the evidence.
CREATE OR REPLACE FUNCTION voalack_guard.run_probe() RETURNS jsonb
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    want text := 'voalack: DDL refused, protected inventory would change: {"differs public_trigger voalack_capture_ack"}';
    st text;
    msg text;
BEGIN
    BEGIN
        EXECUTE 'ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack';
    EXCEPTION WHEN raise_exception THEN
        GET STACKED DIAGNOSTICS st = RETURNED_SQLSTATE, msg = MESSAGE_TEXT;
        IF st IS DISTINCT FROM 'P0001' OR msg IS DISTINCT FROM want THEN
            RAISE;
        END IF;
    END;
    IF msg IS NULL THEN
        RAISE EXCEPTION 'voalack: the protector admitted the probe DDL; protection is broken';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.alerts'::regclass
                                             AND tgname = 'voalack_capture_ack' AND tgenabled = 'O') THEN
        RAISE EXCEPTION 'voalack: the probe was not rolled back (the capture trigger is not enabled)';
    END IF;
    RETURN jsonb_build_object('probe', 'ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack',
                              'sqlstate', st, 'message', msg, 'rolled_back', true, 'trigger_enabled_after', true);
END;
$$;

-- ---- S3b enforcement: the admitted write paths ----
-- recovery_windows: one active window; superuser; the identity-reader prerequisite; attestation bound to this
-- database and cluster; preload not denied. Identity and catalog fields are set here.
CREATE OR REPLACE FUNCTION voalack_guard.windows_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    sysid bigint := (SELECT system_identifier FROM pg_control_system());
    lib text;
    a jsonb := NEW.attestation;
    c jsonb;
    attested timestamptz;
BEGIN
    IF NOT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false) THEN
        RAISE EXCEPTION 'voalack: only a superuser executor opens a recovery window';
    END IF;
    -- Recovery prerequisite (operator-provisioned, never granted here): the guard owner reads backend identities.
    IF NOT pg_has_role('voalack_guard_owner', 'pg_read_all_stats', 'USAGE') THEN
        RAISE EXCEPTION 'voalack: recovery prerequisite missing: voalack_guard_owner must have pg_read_all_stats (the '
                        'protector compares the coordinator''s exact backend start)';
    END IF;
    LOCK TABLE voalack_guard.recovery_windows IN EXCLUSIVE MODE;
    IF EXISTS (SELECT 1 FROM voalack_guard.recovery_windows x WHERE voalack_guard.window_active(x.window_id)) THEN
        RAISE EXCEPTION 'voalack: a recovery window is already active (closed only after release or disposition)';
    END IF;
    IF EXISTS (SELECT 1 FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL) THEN
        RAISE EXCEPTION 'voalack: a maintenance permit is open outside any active window';
    END IF;
    -- Q4 operator attestation, canonical schema voalack-recovery-attestation/v1 (review 81d9912b F1). It records an
    -- operator prerequisite only: it observes no service and authorizes nothing. Exactly these keys:
    --   schema "voalack-recovery-attestation/v1"; actor, basis: non-empty JSON strings;
    --   attested_at: ISO-8601 string (YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+HH:MM)) naming a finite timestamp;
    --   stopped: an object with exactly alerta_application, housekeeping, job_runner, each exactly
    --            {"stopped": true, "held_stopped": true, "detail": non-empty JSON string};
    --   database, system_identifier: JSON strings equal to this database and cluster.
    -- Deterministic order (review a178ba6f): each container's type is checked by its own statement before its keys or
    -- entries are enumerated, so jsonb_object_keys/jsonb_each never see a non-object and the refusal never depends on
    -- expression evaluation order.
    IF jsonb_typeof(a) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(a) k)
       IS DISTINCT FROM ARRAY['actor', 'attested_at', 'basis', 'database', 'schema', 'stopped', 'system_identifier'] THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    IF a -> 'schema' IS DISTINCT FROM '"voalack-recovery-attestation/v1"'::jsonb
       OR jsonb_typeof(a -> 'actor') IS DISTINCT FROM 'string' OR btrim(a ->> 'actor') = ''
       OR jsonb_typeof(a -> 'basis') IS DISTINCT FROM 'string' OR btrim(a ->> 'basis') = ''
       OR jsonb_typeof(a -> 'attested_at') IS DISTINCT FROM 'string'
       OR NOT (a ->> 'attested_at')
              ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$'
       OR jsonb_typeof(a -> 'database') IS DISTINCT FROM 'string' OR a ->> 'database' IS DISTINCT FROM current_database()
       OR jsonb_typeof(a -> 'system_identifier') IS DISTINCT FROM 'string'
       OR a ->> 'system_identifier' IS DISTINCT FROM sysid::text THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    IF jsonb_typeof(a -> 'stopped') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(a -> 'stopped') k)
       IS DISTINCT FROM ARRAY['alerta_application', 'housekeeping', 'job_runner'] THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    FOR c IN SELECT value FROM jsonb_each(a -> 'stopped') LOOP
        IF jsonb_typeof(c) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                            'database/cluster (schema voalack-recovery-attestation/v1)';
        END IF;
        IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(c) k)
              IS DISTINCT FROM ARRAY['detail', 'held_stopped', 'stopped']
           OR c -> 'stopped' IS DISTINCT FROM 'true'::jsonb OR c -> 'held_stopped' IS DISTINCT FROM 'true'::jsonb
           OR jsonb_typeof(c -> 'detail') IS DISTINCT FROM 'string' OR btrim(c ->> 'detail') = '' THEN
            RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                            'database/cluster (schema voalack-recovery-attestation/v1)';
        END IF;
    END LOOP;
    BEGIN
        attested := (a ->> 'attested_at')::timestamptz;
    EXCEPTION WHEN others THEN
        attested := NULL;
    END;
    IF attested IS NULL OR NOT isfinite(attested) THEN
        RAISE EXCEPTION 'voalack: the operator attestation is missing, incomplete, mistyped or bound to another '
                        'database/cluster (schema voalack-recovery-attestation/v1)';
    END IF;
    FOREACH lib IN ARRAY string_to_array(replace(current_setting('shared_preload_libraries'), ' ', ''), ',') LOOP
        IF lib = ANY (voalack_guard.preload_deny_v1()) THEN
            RAISE EXCEPTION 'voalack: shared_preload_libraries contains %, which launches SQL-executing workers', lib;
        END IF;
    END LOOP;
    NEW.database := current_database();
    NEW.system_identifier := sysid;
    NEW.executor_role := session_user;
    NEW.created_pid := pg_backend_pid();
    NEW.created_backend_start := voalack_guard.caller_backend_start();
    NEW.preload := current_setting('shared_preload_libraries');
    NEW.created_at := clock_timestamp();
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.windows_after_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind) VALUES (NEW.window_id, 'open');
    RETURN NULL;
END;
$$;

-- executor_backends: the caller registers itself (before any permit), for the window's executor role, with the
-- window's approved source identity; refused while the current coordinator (exact pid and backend start) is present.
CREATE OR REPLACE FUNCTION voalack_guard.backends_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w voalack_guard.recovery_windows%ROWTYPE := voalack_guard.lock_window(NEW.window_id);
    cur voalack_guard.executor_backends%ROWTYPE;
BEGIN
    IF NOT voalack_guard.window_active(NEW.window_id) THEN
        RAISE EXCEPTION 'voalack: recovery window % is not active', NEW.window_id;
    END IF;
    IF session_user <> w.executor_role
       OR NOT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false) THEN
        RAISE EXCEPTION 'voalack: only the window''s executor superuser % registers', w.executor_role;
    END IF;
    IF NEW.source_sha256 IS DISTINCT FROM w.source_sha256 THEN
        RAISE EXCEPTION 'voalack: the approved source identity does not match window % (resume refused)', NEW.window_id;
    END IF;
    SELECT * INTO cur FROM voalack_guard.executor_backends
     WHERE registration_id = voalack_guard.current_registration(NEW.window_id);
    IF FOUND AND EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.pid = cur.pid AND a.backend_start = cur.backend_start) THEN
        RAISE EXCEPTION 'voalack: the registered coordinator (pid %) is still connected', cur.pid;
    END IF;
    NEW.role := 'coordinator';
    NEW.pid := pg_backend_pid();
    NEW.backend_start := voalack_guard.caller_backend_start();
    NEW.database := current_database();
    NEW.session_user_name := session_user;
    NEW.registered_at := clock_timestamp();
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.backends_after_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    cur bigint := voalack_guard.current_registration(NEW.window_id);
BEGIN
    IF cur IS NOT NULL THEN
        INSERT INTO voalack_guard.recovery_journal (window_id, kind, registration_id) VALUES (NEW.window_id, 'retire', cur);
    END IF;
    INSERT INTO voalack_guard.recovery_journal (window_id, kind, registration_id)
    VALUES (NEW.window_id, 'register', NEW.registration_id);
    RETURN NULL;
END;
$$;

-- recovery_journal: every entry. Sequence, identity, prior, target, effect xid, status and evidence are computed
-- here; the step's predicates, the validation and the probe run here. A seal certifies only what this insert
-- executed.
CREATE OR REPLACE FUNCTION voalack_guard.journal_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w voalack_guard.recovery_windows%ROWTYPE := voalack_guard.lock_window(NEW.window_id);
    i voalack_guard.recovery_journal%ROWTYPE;
    prev voalack_guard.recovery_journal%ROWTYPE;
    reg voalack_guard.executor_backends%ROWTYPE;
    p voalack_guard.maintenance_permits%ROWTYPE;
    four text[] := ARRAY(SELECT name FROM voalack_guard.public_trigger_defs());
    inv text[];
    present jsonb;
    problems text[] := ARRAY[]::text[];
    rs jsonb;
    probe jsonb;
    snap jsonb;
BEGIN
    SELECT * INTO prev FROM voalack_guard.recovery_journal WHERE window_id = NEW.window_id ORDER BY seq DESC LIMIT 1;
    NEW.seq := coalesce(prev.seq, 0) + 1;
    NEW.pid := pg_backend_pid();
    NEW.backend_start := voalack_guard.caller_backend_start();
    NEW.recorded_at := clock_timestamp();
    IF NEW.kind = 'open' THEN
        IF NEW.seq <> 1 OR NEW.pid <> w.created_pid OR NEW.backend_start IS DISTINCT FROM w.created_backend_start THEN
            RAISE EXCEPTION 'voalack: an open entry is written only by the window''s own creation';
        END IF;
        NEW.step := NULL; NEW.intent_seq := NULL; NEW.registration_id := NULL; NEW.prior := NULL; NEW.target := NULL;
        NEW.evidence := NULL; NEW.effect_xid := NULL; NEW.xid_status := NULL;
        RETURN NEW;
    END IF;
    IF NOT voalack_guard.window_active(NEW.window_id) THEN
        RAISE EXCEPTION 'voalack: recovery window % is not active', NEW.window_id;
    END IF;
    NEW.effect_xid := NULL; NEW.xid_status := NULL;
    CASE NEW.kind
    WHEN 'register', 'retire' THEN
        -- Only from a registration row the caller has just inserted (backends_after_insert).
        SELECT * INTO reg FROM voalack_guard.executor_backends b
         WHERE b.window_id = NEW.window_id AND b.pid = NEW.pid AND b.backend_start = NEW.backend_start
           AND NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal j
                            WHERE j.window_id = b.window_id AND j.kind = 'register' AND j.registration_id = b.registration_id)
         ORDER BY b.registration_id DESC LIMIT 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'voalack: % entries come only from the caller''s own new registration', NEW.kind;
        END IF;
        IF NEW.kind = 'register' AND (NEW.registration_id IS DISTINCT FROM reg.registration_id
                                      OR voalack_guard.current_registration(NEW.window_id) IS NOT NULL) THEN
            RAISE EXCEPTION 'voalack: a registration needs the previous coordinator retired first';
        END IF;
        IF NEW.kind = 'retire' AND NEW.registration_id IS DISTINCT FROM voalack_guard.current_registration(NEW.window_id) THEN
            RAISE EXCEPTION 'voalack: only the current coordinator is retired';
        END IF;
        NEW.step := NULL; NEW.intent_seq := NULL; NEW.prior := NULL; NEW.target := NULL; NEW.evidence := NULL;
    WHEN 'intent' THEN
        NEW.registration_id := voalack_guard.require_coordinator(NEW.window_id);
        IF (voalack_guard.open_intent(NEW.window_id)).seq IS NOT NULL THEN
            RAISE EXCEPTION 'voalack: an intent is still unsealed in window %', NEW.window_id;
        END IF;
        IF NEW.step IS DISTINCT FROM voalack_guard.next_step(NEW.window_id) THEN
            RAISE EXCEPTION 'voalack: % is not the next step in window % (expected %)', NEW.step, NEW.window_id,
                voalack_guard.next_step(NEW.window_id);
        END IF;
        SELECT * INTO p FROM voalack_guard.maintenance_permits WHERE closed_at IS NULL;
        inv := voalack_guard.inventory_problems();
        present := to_jsonb(ARRAY(SELECT n FROM unnest(four) n WHERE NOT (('missing public_trigger ' || n) = ANY (inv))));
        CASE NEW.step
        WHEN 'contain' THEN
            problems := voalack_guard.cold_problems(NEW.window_id) || inv;
            IF p.permit_id IS NOT NULL THEN problems := problems || 'a permit is open'::text; END IF;
            NEW.prior := voalack_guard.containment_snapshot();
            NEW.target := jsonb_build_object('limit', 0);
        WHEN 'detach' THEN
            NEW.prior := jsonb_build_object('present', present);
            NEW.target := jsonb_build_object('permit', 'detach', 'absent', to_jsonb(four));
        WHEN 'transition' THEN
            NEW.prior := jsonb_build_object('permit_id', p.permit_id, 'phase', p.phase);
            NEW.target := jsonb_build_object('phase', 'recreate', 'drop', present);
        WHEN 'recreate' THEN
            IF (p.intent -> 'drop') IS DISTINCT FROM present THEN
                problems := ARRAY['the present triggers differ from the recreate permit''s drop intent'];
            END IF;
            NEW.prior := jsonb_build_object('present', present, 'drop', p.intent -> 'drop');
            NEW.target := jsonb_build_object('frozen', to_jsonb(four));
        WHEN 'validate' THEN
            NEW.prior := '{}'::jsonb; NEW.target := '{}'::jsonb;
        WHEN 'close' THEN
            NEW.prior := jsonb_build_object('permit_id', p.permit_id);
            NEW.target := jsonb_build_object('open_permits', 0);
        WHEN 'release' THEN
            problems := voalack_guard.window_problems(NEW.window_id, 'pre_release');
            NEW.prior := jsonb_build_object('k', voalack_guard.window_snapshot(NEW.window_id) -> 'k');
            NEW.target := jsonb_build_object('limits', 'prior');
        END CASE;
        IF cardinality(problems) > 0 THEN
            RAISE EXCEPTION 'voalack: % refused before its intent: %', NEW.step, problems;
        END IF;
        NEW.intent_seq := NULL; NEW.evidence := NULL;
    WHEN 'seal' THEN
        NEW.registration_id := voalack_guard.require_coordinator(NEW.window_id);
        i := voalack_guard.open_intent(NEW.window_id);
        IF i.seq IS NULL OR i.seq IS DISTINCT FROM NEW.intent_seq OR i.step IS DISTINCT FROM NEW.step THEN
            RAISE EXCEPTION 'voalack: intent % is not the window''s latest unsealed % intent', NEW.intent_seq, NEW.step;
        END IF;
        NEW.prior := NULL; NEW.target := NULL;
        IF i.step = 'validate' THEN
            problems := voalack_guard.validation_problems(NEW.window_id);
            IF cardinality(problems) > 0 THEN
                RAISE EXCEPTION 'voalack: validation fails: %', problems;
            END IF;
            NEW.evidence := jsonb_build_object('validated_by', 'journal_insert_guard/v1',
                'checks', jsonb_build_array('cold', 'roles zero', 'lifetime digest', 'permit recreate', 'inventory frozen',
                                            'bindings reference open lifetimes'),
                'lifetime_digest', voalack_guard.lifetime_digest(),
                'trusted_superusers', voalack_guard.trusted_superusers(NEW.window_id));
            RETURN NEW;
        END IF;
        rs := voalack_guard.receipt_binding(NEW.window_id, i.seq);
        problems := voalack_guard.effect_problems(NEW.window_id, i.step, i.target)
                    || voalack_guard.window_problems(NEW.window_id, voalack_guard.step_phase(i.step));
        IF cardinality(problems) > 0 THEN
            RAISE EXCEPTION 'voalack: the % seal predicate fails: %', i.step, problems;
        END IF;
        IF i.step = 'close' THEN
            probe := voalack_guard.run_probe();
            problems := voalack_guard.window_problems(NEW.window_id, 'permits_closed');
            IF cardinality(problems) > 0 THEN
                RAISE EXCEPTION 'voalack: the permits_closed predicate fails after the probe: %', problems;
            END IF;
        END IF;
        NEW.effect_xid := (rs ->> 'xid')::xid8;
        NEW.xid_status := rs ->> 'status';
        NEW.evidence := coalesce(probe, '{}'::jsonb)
                        || jsonb_build_object('trusted_superusers', voalack_guard.trusted_superusers(NEW.window_id));
    WHEN 'lab' THEN
        NEW.registration_id := voalack_guard.require_coordinator(NEW.window_id);
        IF voalack_guard.next_step(NEW.window_id) IS DISTINCT FROM 'transition'
           OR (voalack_guard.open_intent(NEW.window_id)).seq IS NOT NULL
           OR EXISTS (SELECT 1 FROM voalack_guard.recovery_journal WHERE window_id = NEW.window_id AND kind = 'lab') THEN
            RAISE EXCEPTION 'voalack: the no-restore lab gap belongs only after the detach seal, once';
        END IF;
        NEW.step := NULL; NEW.intent_seq := NULL; NEW.prior := NULL; NEW.target := NULL;
        NEW.evidence := jsonb_build_object('lab', 'no-restore', 'restore', 'absent before S3c');
    WHEN 'disposition' THEN
        -- Operator dispositions (actor, basis): a superuser backend that is not the window's coordinator.
        IF NOT coalesce((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), false) THEN
            RAISE EXCEPTION 'voalack: only a superuser operator records a disposition';
        END IF;
        IF EXISTS (SELECT 1 FROM voalack_guard.executor_backends b
                    WHERE b.registration_id = voalack_guard.current_registration(NEW.window_id)
                      AND b.pid = NEW.pid AND b.backend_start = NEW.backend_start) THEN
            RAISE EXCEPTION 'voalack: the coordinator cannot record its own window''s disposition';
        END IF;
        IF jsonb_typeof(NEW.evidence) IS DISTINCT FROM 'object'
           OR coalesce(btrim(NEW.evidence ->> 'actor'), '') = '' OR coalesce(btrim(NEW.evidence ->> 'basis'), '') = ''
           OR NEW.evidence ->> 'decision' NOT IN ('note', 'revoke_permit', 'abandon')
           OR (NEW.evidence ->> 'decision') IS NULL THEN
            RAISE EXCEPTION 'voalack: a disposition needs an actor, a basis and a decision (note, revoke_permit, abandon)';
        END IF;
        snap := voalack_guard.window_snapshot(NEW.window_id);
        IF NEW.evidence ->> 'decision' = 'revoke_permit' THEN
            -- First, before any limit is restored: the window's exemption is closed (one way). The role catalog is
            -- locked first (SHARE: ALTER ROLE waits), so 'contained' below is decided after any concurrent limit
            -- change has committed, and no restoration can commit before this revocation does (review 94308a5d).
            LOCK TABLE pg_catalog.pg_authid IN SHARE MODE;
            UPDATE voalack_guard.maintenance_permits SET closed_at = clock_timestamp()
             WHERE window_id = NEW.window_id AND closed_at IS NULL;
        ELSIF NEW.evidence ->> 'decision' = 'abandon' THEN
            -- Only a fully settled window is abandoned: no open permit, normal protection intact, and (once contained)
            -- every role back at its exact prior with the W, C and outside sets unchanged. Anything else stays an
            -- active, unresolved hold that refuses a successor.
            IF EXISTS (SELECT 1 FROM voalack_guard.maintenance_permits WHERE window_id = NEW.window_id AND closed_at IS NULL) THEN
                problems := problems || 'the window''s permit is still open (revoke it first)'::text;
            END IF;
            -- Order (review 51defbf6): a window that had a permit needs a committed revoke_permit disposition recorded
            -- while containment still held, i.e. before any prior limit was restored.
            IF EXISTS (SELECT 1 FROM voalack_guard.maintenance_permits WHERE window_id = NEW.window_id)
               AND NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal d
                                WHERE d.window_id = NEW.window_id AND d.kind = 'disposition'
                                  AND d.evidence ->> 'decision' = 'revoke_permit'
                                  AND (d.evidence -> 'checked' ->> 'contained')::boolean
                                  -- committed: the revocation's TOP-LEVEL transaction (recorded by this trigger;
                                  -- savepoints share it) has committed; 'in progress' (this transaction, any savepoint)
                                  -- never counts (review 9dce333b). A NULL status (too old) is a visible, committed row.
                                  -- a present, well-formed, trigger-derived xact only; a missing or malformed one
                                  -- never counts (review cbee1d9a)
                                  AND d.evidence ->> 'xact' ~ '^[0-9]{1,20}$'
                                  AND coalesce(pg_xact_status((d.evidence ->> 'xact')::xid8), 'committed') = 'committed') THEN
                problems := problems || 'no committed permit revocation is recorded while containment held (revoke, '
                                        'commit, then restore limits)'::text;
            END IF;
            problems := problems || voalack_guard.inventory_problems();
            IF snap IS NOT NULL THEN
                problems := problems || voalack_guard.role_problems(NEW.window_id, 'prior');
            END IF;
            IF cardinality(problems) > 0 THEN
                RAISE EXCEPTION 'voalack: abandon refused, the window is not settled: %', problems;
            END IF;
        END IF;
        NEW.evidence := jsonb_build_object('actor', NEW.evidence ->> 'actor', 'basis', NEW.evidence ->> 'basis',
            'decision', NEW.evidence ->> 'decision', 'xact', pg_current_xact_id()::text,
            'next_step', voalack_guard.next_step(NEW.window_id),
            'open_intent', (voalack_guard.open_intent(NEW.window_id)).seq,
            'checked', jsonb_build_object('open_permits', (SELECT count(*) FROM voalack_guard.maintenance_permits
                                                            WHERE window_id = NEW.window_id AND closed_at IS NULL),
                                          'contained', snap IS NOT NULL AND NOT EXISTS (
                                              SELECT 1 FROM unnest(voalack_guard.role_problems(NEW.window_id, 'zero')) x
                                               WHERE x LIKE 'contained role %'),
                                          'inventory_problems', to_jsonb(voalack_guard.inventory_problems()),
                                          'role_problems', CASE WHEN snap IS NULL THEN '[]'::jsonb
                                                                ELSE to_jsonb(voalack_guard.role_problems(NEW.window_id, 'prior')) END));
        NEW.step := NULL; NEW.intent_seq := NULL; NEW.registration_id := NULL; NEW.prior := NULL; NEW.target := NULL;
    WHEN 'close' THEN
        IF prev.kind = 'disposition' AND prev.evidence ->> 'decision' = 'abandon' AND prev.pid = NEW.pid
           AND prev.backend_start = NEW.backend_start THEN
            NULL;                                                   -- the abandon disposition's own close
        ELSE
            NEW.registration_id := voalack_guard.require_coordinator(NEW.window_id);
            IF NOT EXISTS (SELECT 1 FROM voalack_guard.recovery_journal
                            WHERE window_id = NEW.window_id AND kind = 'seal' AND step = 'release') THEN
                RAISE EXCEPTION 'voalack: window % closes only after its release seal', NEW.window_id;
            END IF;
        END IF;
        NEW.step := NULL; NEW.intent_seq := NULL; NEW.prior := NULL; NEW.target := NULL; NEW.evidence := NULL;
    END CASE;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.journal_after_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    IF NEW.kind = 'disposition' AND NEW.evidence ->> 'decision' = 'abandon' THEN
        INSERT INTO voalack_guard.recovery_journal (window_id, kind) VALUES (NEW.window_id, 'close');
    END IF;
    RETURN NULL;
END;
$$;

-- recovery_effects: the receipt, inside T_effect. Its own xid; the latest unsealed intent's exact target; the
-- coordinator; no earlier receipt; the effect holding now, in this transaction.
CREATE OR REPLACE FUNCTION voalack_guard.effects_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w voalack_guard.recovery_windows%ROWTYPE := voalack_guard.lock_window(NEW.window_id);
    reg bigint := voalack_guard.require_coordinator(NEW.window_id);
    i voalack_guard.recovery_journal%ROWTYPE := voalack_guard.open_intent(NEW.window_id);
    problems text[];
BEGIN
    IF i.seq IS NULL OR i.seq IS DISTINCT FROM NEW.intent_seq THEN
        RAISE EXCEPTION 'voalack: intent % is not the window''s latest unsealed intent', NEW.intent_seq;
    END IF;
    IF i.step = 'validate' THEN
        RAISE EXCEPTION 'voalack: validate has no effect transaction';
    END IF;
    IF EXISTS (SELECT 1 FROM voalack_guard.recovery_effects WHERE window_id = NEW.window_id AND intent_seq = NEW.intent_seq) THEN
        RAISE EXCEPTION 'voalack: intent % already has its effect receipt', NEW.intent_seq;
    END IF;
    problems := voalack_guard.effect_problems(NEW.window_id, i.step, i.target);
    IF cardinality(problems) > 0 THEN
        RAISE EXCEPTION 'voalack: the % effect does not hold: %', i.step, problems;
    END IF;
    NEW.effect_xid := pg_current_xact_id();
    NEW.effect := i.target;
    NEW.pid := pg_backend_pid();
    NEW.backend_start := voalack_guard.caller_backend_start();
    NEW.recorded_at := clock_timestamp();
    RETURN NEW;
END;
$$;

-- maintenance_permits: open only under the window's current detach intent by its coordinator (one permit per window,
-- never reopened); the phase moves only detach -> recreate by exact compare-and-set under the current transition
-- intent, with that intent's drop list; closing is one way and always possible; nothing else changes; no delete.
CREATE OR REPLACE FUNCTION voalack_guard.permits_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w voalack_guard.recovery_windows%ROWTYPE;
    i voalack_guard.recovery_journal%ROWTYPE;
    problems text[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        w := voalack_guard.lock_window(NEW.window_id);
        PERFORM voalack_guard.require_coordinator(NEW.window_id);
        i := voalack_guard.open_intent(NEW.window_id);
        IF i.seq IS DISTINCT FROM NEW.intent_seq OR i.step IS DISTINCT FROM 'detach' THEN
            RAISE EXCEPTION 'voalack: a permit opens only under the window''s current detach intent';
        END IF;
        IF EXISTS (SELECT 1 FROM voalack_guard.maintenance_permits WHERE window_id = NEW.window_id) THEN
            RAISE EXCEPTION 'voalack: window % already had a permit (a closed permit is never reopened)', NEW.window_id;
        END IF;
        problems := voalack_guard.window_problems(NEW.window_id, 'contained');
        IF cardinality(problems) > 0 THEN
            RAISE EXCEPTION 'voalack: the permit refuses to open: %', problems;
        END IF;
        NEW.executor := session_user;
        NEW.phase := 'detach';
        NEW.intent := '{}'::jsonb;
        NEW.opened_at := clock_timestamp();
        NEW.closed_at := NULL;
        RETURN NEW;
    END IF;
    IF (NEW.permit_id, NEW.executor, NEW.window_id, NEW.intent_seq, NEW.opened_at)
       IS DISTINCT FROM (OLD.permit_id, OLD.executor, OLD.window_id, OLD.intent_seq, OLD.opened_at) THEN
        RAISE EXCEPTION 'voalack: a permit''s identity never changes';
    END IF;
    IF OLD.closed_at IS NOT NULL THEN
        RAISE EXCEPTION 'voalack: a closed permit never changes (and is never reopened)';
    END IF;
    IF NEW.closed_at IS NOT NULL THEN
        IF (NEW.phase, NEW.intent) IS DISTINCT FROM (OLD.phase, OLD.intent) THEN
            RAISE EXCEPTION 'voalack: closing a permit changes nothing else';
        END IF;
        RETURN NEW;                                                 -- one-way close: always possible
    END IF;
    w := voalack_guard.lock_window(NEW.window_id);
    PERFORM voalack_guard.require_coordinator(NEW.window_id);
    i := voalack_guard.open_intent(NEW.window_id);
    IF i.step IS DISTINCT FROM 'transition' OR OLD.phase <> 'detach' OR NEW.phase <> 'recreate'
       OR i.prior ->> 'phase' IS DISTINCT FROM 'detach' OR (i.prior ->> 'permit_id')::bigint IS DISTINCT FROM OLD.permit_id
       OR NEW.intent IS DISTINCT FROM jsonb_build_object('drop', i.target -> 'drop') THEN
        RAISE EXCEPTION 'voalack: a permit changes only by the current transition intent''s exact compare-and-set';
    END IF;
    RETURN NEW;
END;
$$;

-- ---- S3b convenience wrappers (the triggers above decide; each wrapper is one insert or update) ----
CREATE OR REPLACE FUNCTION voalack_guard.open_window(p_source_sha256 text, p_attestation jsonb) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    w bigint;
BEGIN
    INSERT INTO voalack_guard.recovery_windows (source_sha256, attestation) VALUES (p_source_sha256, p_attestation)
    RETURNING window_id INTO w;
    RETURN w;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.register_backend(p_window bigint, p_source_sha256 text) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    r bigint;
BEGIN
    INSERT INTO voalack_guard.executor_backends (window_id, source_sha256) VALUES (p_window, p_source_sha256)
    RETURNING registration_id INTO r;
    RETURN r;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.begin_step(p_window bigint, p_step text) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind, step) VALUES (p_window, 'intent', p_step)
    RETURNING seq INTO n;
    RETURN n;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.record_effect(p_window bigint, p_intent_seq bigint) RETURNS xid8
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    x xid8;
BEGIN
    INSERT INTO voalack_guard.recovery_effects (window_id, intent_seq) VALUES (p_window, p_intent_seq)
    RETURNING effect_xid INTO x;
    RETURN x;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.seal_step(p_window bigint, p_intent_seq bigint) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind, step, intent_seq)
    SELECT p_window, 'seal', j.step, p_intent_seq FROM voalack_guard.recovery_journal j
     WHERE j.window_id = p_window AND j.seq = p_intent_seq AND j.kind = 'intent'
    RETURNING seq INTO n;
    IF n IS NULL THEN
        RAISE EXCEPTION 'voalack: intent % does not exist in window %', p_intent_seq, p_window;
    END IF;
    RETURN n;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.lab_gap(p_window bigint) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind) VALUES (p_window, 'lab') RETURNING seq INTO n;
    RETURN n;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.open_permit(p_window bigint, p_intent_seq bigint) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    INSERT INTO voalack_guard.maintenance_permits (executor, phase, window_id, intent_seq)
    VALUES (session_user, 'detach', p_window, p_intent_seq) RETURNING permit_id INTO n;
    RETURN n;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.transition_permit(p_window bigint, p_intent_seq bigint, p_prior text,
                                                           p_target text) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n integer;
BEGIN
    IF p_prior IS DISTINCT FROM 'detach' OR p_target IS DISTINCT FROM 'recreate' THEN
        RAISE EXCEPTION 'voalack: S3b admits only the detach -> recreate transition';
    END IF;
    UPDATE voalack_guard.maintenance_permits m
       SET phase = p_target,
           intent = jsonb_build_object('drop', (SELECT j.target -> 'drop' FROM voalack_guard.recovery_journal j
                                                 WHERE j.window_id = p_window AND j.seq = p_intent_seq))
     WHERE m.window_id = p_window AND m.phase = p_prior AND m.closed_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 1 THEN
        RAISE EXCEPTION 'voalack: the transition compare-and-set matched % permits', n;
    END IF;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.close_permit(p_window bigint, p_intent_seq bigint) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n integer;
BEGIN
    IF (voalack_guard.open_intent(p_window)).seq IS DISTINCT FROM p_intent_seq
       OR (voalack_guard.open_intent(p_window)).step IS DISTINCT FROM 'close' THEN
        RAISE EXCEPTION 'voalack: the coordinator closes its permit only under the window''s current close intent';
    END IF;
    UPDATE voalack_guard.maintenance_permits SET closed_at = clock_timestamp()
     WHERE window_id = p_window AND closed_at IS NULL;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n <> 1 THEN
        RAISE EXCEPTION 'voalack: the close matched % open permits of window %', n, p_window;
    END IF;
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.close_window(p_window bigint) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind) VALUES (p_window, 'close');
END;
$$;
CREATE OR REPLACE FUNCTION voalack_guard.record_disposition(p_window bigint, p_actor text, p_basis text,
                                                            p_decision text) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, voalack_guard, pg_temp AS $$
DECLARE
    n bigint;
BEGIN
    INSERT INTO voalack_guard.recovery_journal (window_id, kind, evidence)
    VALUES (p_window, 'disposition', jsonb_build_object('actor', p_actor, 'basis', p_basis, 'decision', p_decision))
    RETURNING seq INTO n;
    RETURN n;
END;
$$;

-- The enforcement triggers (after their functions).
CREATE OR REPLACE TRIGGER recovery_windows_insert_guard BEFORE INSERT ON voalack_guard.recovery_windows
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.windows_insert_guard();
CREATE OR REPLACE TRIGGER recovery_windows_open_entry AFTER INSERT ON voalack_guard.recovery_windows
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.windows_after_insert();
CREATE OR REPLACE TRIGGER executor_backends_insert_guard BEFORE INSERT ON voalack_guard.executor_backends
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.backends_insert_guard();
CREATE OR REPLACE TRIGGER executor_backends_journal_entries AFTER INSERT ON voalack_guard.executor_backends
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.backends_after_insert();
CREATE OR REPLACE TRIGGER recovery_journal_insert_guard BEFORE INSERT ON voalack_guard.recovery_journal
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.journal_insert_guard();
CREATE OR REPLACE TRIGGER recovery_journal_abandon_close AFTER INSERT ON voalack_guard.recovery_journal
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.journal_after_insert();
CREATE OR REPLACE TRIGGER recovery_effects_insert_guard BEFORE INSERT ON voalack_guard.recovery_effects
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.effects_insert_guard();
CREATE OR REPLACE TRIGGER maintenance_permits_guard BEFORE INSERT OR UPDATE ON voalack_guard.maintenance_permits
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.permits_guard();
CREATE OR REPLACE TRIGGER maintenance_permits_no_delete BEFORE DELETE ON voalack_guard.maintenance_permits
    FOR EACH ROW EXECUTE FUNCTION voalack_guard.refuse_rewrite();
CREATE OR REPLACE TRIGGER maintenance_permits_no_truncate BEFORE TRUNCATE ON voalack_guard.maintenance_permits
    FOR EACH STATEMENT EXECUTE FUNCTION voalack_guard.refuse_rewrite();
ALTER FUNCTION voalack_guard.public_trigger_defs() OWNER TO voalack_guard_owner;
ALTER FUNCTION voalack_guard.protected_functions() OWNER TO voalack_guard_owner;
ALTER FUNCTION voalack_guard.current_inventory() OWNER TO voalack_guard_owner;
ALTER FUNCTION voalack_guard.inventory_problems() OWNER TO voalack_guard_owner;
ALTER FUNCTION voalack_guard.protect() OWNER TO voalack_guard_owner;
DO $$
DECLARE f regprocedure;
BEGIN
    -- S3b: every recovery function and trigger function is owned by the guard owner (SECURITY INVOKER; EXECUTE is
    -- revoked from PUBLIC below, so only superusers call them).
    FOR f IN SELECT p.oid::regprocedure FROM pg_proc p
              WHERE p.pronamespace = 'voalack_guard'::regnamespace AND p.proname = ANY (ARRAY['backends_after_insert', 'backends_insert_guard', 'begin_step', 'caller_backend_start', 'client_problems', 'close_permit', 'close_window', 'cold_problems', 'connect_logins', 'containment_snapshot', 'current_registration', 'effect_problems', 'effects_insert_guard', 'journal_after_insert', 'journal_insert_guard', 'lab_gap', 'lifetime_digest', 'lock_window', 'next_step', 'open_intent', 'open_permit', 'open_window', 'outside_digest', 'permits_guard', 'preload_deny_v1', 'receipt_binding', 'record_disposition', 'record_effect', 'refuse_rewrite', 'register_backend', 'require_coordinator', 'role_problems', 'run_probe', 'seal_step', 'step_phase', 'transition_permit', 'trusted_superusers', 'validation_problems', 'window_active', 'window_problems', 'window_snapshot', 'windows_after_insert', 'windows_insert_guard', 'writer_logins']) LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO voalack_guard_owner', f);
    END LOOP;
END;
$$;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA voalack_guard FROM PUBLIC;
-- voalack.protections_intact() (owner voalack_admin, definer) reads the inventory problems.
GRANT USAGE ON SCHEMA voalack_guard TO voalack_admin;
GRANT EXECUTE ON FUNCTION voalack_guard.inventory_problems() TO voalack_admin;
