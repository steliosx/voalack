-- Voalack capture schema (T03b, development). Lives beside Alerta's tables; it never stores
-- integration state in public.alerts. Idempotent: safe to apply repeatedly.
-- Apply as a superuser. Prerequisite roles: voalack_admin (owns everything here, no login) and
-- voalack_app (no login; holds only the capture path's grants). Alerta's runtime login is a
-- member of voalack_app and never of voalack_admin; it owns Alerta's own tables (Alerta alters
-- them at startup), so it could disable the capture trigger on public.alerts: an eligible ACK then
-- finds no capture and rolls back (fail closed).
-- T04 S4: also voalack_projector (no login; the projector's grants only). Applied after Alerta has
-- created its tables, the definer role gets SELECT and INSERT on public.notes and SELECT and UPDATE (id)
-- on public.alerts (the alert-row lock), and nothing else there.
CREATE SCHEMA IF NOT EXISTS voalack;

-- Administrator-approved bindings: only alerts listed here are eligible for capture.
CREATE TABLE IF NOT EXISTS voalack.bindings (
    alert_id          text PRIMARY KEY,
    binding_id        text NOT NULL,
    binding_revision  integer NOT NULL CHECK (binding_revision > 0),
    active            boolean NOT NULL DEFAULT true
);

-- Intents staged by the capture plugin inside the ACK request's transaction. The txid binds a
-- staged intent to the transaction that created it; the trigger only captures that pairing.
CREATE TABLE IF NOT EXISTS voalack.prepared_intents (
    action_id   uuid PRIMARY KEY,
    alert_id    text NOT NULL,
    txid        bigint NOT NULL,
    actor_login text NOT NULL,
    payload     jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS prepared_intents_alert_txid ON voalack.prepared_intents (alert_id, txid);

-- One capture per action: the durable queue candidate for verification and delivery.
CREATE TABLE IF NOT EXISTS voalack.captures (
    action_id     uuid PRIMARY KEY REFERENCES voalack.prepared_intents (action_id),
    alert_id      text NOT NULL,
    txid          bigint NOT NULL,
    history_user  text NOT NULL,
    history_time  timestamp NOT NULL,
    captured_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- The exact ACK history entry this capture observed; the request boundary requires the alert's
-- head history to still equal it at commit (design amendment A3, review finding R1).
ALTER TABLE voalack.captures ADD COLUMN IF NOT EXISTS history_text text;
ALTER TABLE voalack.captures ADD COLUMN IF NOT EXISTS history_type text;
ALTER TABLE voalack.captures ADD COLUMN IF NOT EXISTS history_status text;

-- Capture fires only when the head history entry changed and is the expected human ACK
-- (design amendment A3): Alerta's tag/attribute UPDATEs in the same request do not change
-- history[1], and a later UPDATE cannot add a second capture (primary key on action_id).
-- capture_ack() is defined below with the M2 columns.




-- M2 (signed intent v2): immutable binding revisions, per-binding generations, the
-- authorization policy, and the staged/approved intent columns.
CREATE TABLE IF NOT EXISTS voalack.binding_revisions (
    binding_id                 text NOT NULL CHECK (octet_length(binding_id) BETWEEN 1 AND 128),
    binding_revision           integer NOT NULL CHECK (binding_revision > 0),
    customer                   text NOT NULL CHECK (octet_length(customer) BETWEEN 1 AND 128),
    source_namespace           text NOT NULL CHECK (octet_length(source_namespace) BETWEEN 1 AND 128),
    instance_id                text NOT NULL CHECK (octet_length(instance_id) BETWEEN 1 AND 128),
    resource                   text NOT NULL CHECK (resource LIKE 'veeamone:_%'),
    event                      text NOT NULL CHECK (event = 'VeeamOneAlarm'),
    environment                text NOT NULL CHECK (octet_length(environment) BETWEEN 1 AND 1024),
    origin                     text NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 1024),
    combination_id             text NOT NULL CHECK (octet_length(combination_id) BETWEEN 1 AND 128),
    capture_id                 text NOT NULL CHECK (octet_length(capture_id) BETWEEN 1 AND 128),
    target_kind                text NOT NULL CHECK (target_kind = 'triggered_alarm'),
    target_id                  text NOT NULL CHECK (target_id ~ '^[1-9][0-9]{0,18}$'
                                                    AND target_id::numeric <= 9223372036854775807),
    alarm_template_id          bigint NOT NULL CHECK (alarm_template_id >= 0),
    object_id                  bigint NOT NULL CHECK (object_id >= 0),
    repeat_count               bigint NOT NULL CHECK (repeat_count >= 0),
    triggered_time             timestamptz NOT NULL,
    occurrence_ref             text NOT NULL CHECK (octet_length(occurrence_ref) BETWEEN 1 AND 128),
    occurrence_evidence_sha256 text NOT NULL CHECK (occurrence_evidence_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot_sha256            text NOT NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    created_at                 timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (binding_id, binding_revision)
);

CREATE OR REPLACE FUNCTION voalack.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'voalack: % rows are immutable', TG_TABLE_NAME;
END;
$$;
DROP TRIGGER IF EXISTS binding_revisions_immutable ON voalack.binding_revisions;
CREATE TRIGGER binding_revisions_immutable BEFORE UPDATE OR DELETE ON voalack.binding_revisions
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'bindings_revision_fk') THEN
        ALTER TABLE voalack.bindings ADD CONSTRAINT bindings_revision_fk
            FOREIGN KEY (binding_id, binding_revision) REFERENCES voalack.binding_revisions;
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS voalack.binding_generations (
    binding_id  text PRIMARY KEY,
    generation  bigint NOT NULL DEFAULT 0 CHECK (generation >= 0)
);

-- Authorization policy: user-ID grants per customer (M2 limitation: no role-based grants).
CREATE TABLE IF NOT EXISTS voalack.authorization_policy (
    policy_revision integer NOT NULL CHECK (policy_revision > 0),
    user_id         text NOT NULL CHECK (octet_length(user_id) BETWEEN 1 AND 128),
    customer        text NOT NULL CHECK (octet_length(customer) BETWEEN 1 AND 128),
    PRIMARY KEY (policy_revision, user_id, customer)
);
DROP TRIGGER IF EXISTS authorization_policy_immutable ON voalack.authorization_policy;
CREATE TRIGGER authorization_policy_immutable BEFORE UPDATE OR DELETE ON voalack.authorization_policy
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
CREATE TABLE IF NOT EXISTS voalack.authorization_policy_active (
    singleton       boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    policy_revision integer NOT NULL CHECK (policy_revision > 0)
);

ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS request_id uuid;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS customer text;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS binding_id text;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS binding_revision integer;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS generation bigint;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS issued_at timestamptz;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS capture_expires_at timestamptz;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS execution_expires_at timestamptz;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS envelope_canonical bytea;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS envelope_sha256 text;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS kid text;
ALTER TABLE voalack.prepared_intents ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE voalack.captures ADD COLUMN IF NOT EXISTS generation bigint;
ALTER TABLE voalack.captures ADD COLUMN IF NOT EXISTS envelope_sha256 text;

-- Capture (extends the part 1 trigger): the staged intent of this transaction must carry the
-- alert's customer, its active binding revision and an allocated generation.
CREATE OR REPLACE FUNCTION voalack.capture_ack() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    intent voalack.prepared_intents%ROWTYPE;
BEGIN
    SELECT * INTO intent FROM voalack.prepared_intents
     WHERE alert_id = NEW.id AND txid = txid_current()
       AND NOT EXISTS (SELECT 1 FROM voalack.captures c WHERE c.action_id = prepared_intents.action_id)
     ORDER BY created_at DESC LIMIT 1;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF (NEW.history[1])."user" IS DISTINCT FROM intent.actor_login THEN
        RAISE EXCEPTION 'voalack: ACK history user does not match the staged intent';
    END IF;
    IF intent.generation IS NULL OR NEW.customer IS DISTINCT FROM intent.customer
       OR NOT EXISTS (SELECT 1 FROM voalack.bindings b
                       WHERE b.alert_id = NEW.id AND b.active AND b.binding_id = intent.binding_id
                         AND b.binding_revision = intent.binding_revision) THEN
        RAISE EXCEPTION 'voalack: staged intent does not match the alert customer, binding or generation';
    END IF;
    INSERT INTO voalack.captures (action_id, alert_id, txid, history_user, history_time,
                                  history_text, history_type, history_status, generation)
    VALUES (intent.action_id, NEW.id, txid_current(), (NEW.history[1])."user", (NEW.history[1]).update_time,
            (NEW.history[1]).text, (NEW.history[1]).type, (NEW.history[1]).status, intent.generation);
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS voalack_capture_ack ON public.alerts;
CREATE TRIGGER voalack_capture_ack
    AFTER UPDATE ON public.alerts
    FOR EACH ROW
    WHEN (OLD.history[1] IS DISTINCT FROM NEW.history[1]
          AND (NEW.history[1]).type = 'ack'
          AND NEW.status = 'ack')
    EXECUTE FUNCTION voalack.capture_ack();

-- The gate's locked read of an active binding and its revision; also locks the binding's
-- generation row (lock order: alert row, binding, generation). Row locks need UPDATE
-- privilege, which the application role must not have, so the owner function takes them.
DROP FUNCTION IF EXISTS voalack.lock_binding(text);
CREATE FUNCTION voalack.lock_binding(p_alert_id text)
RETURNS TABLE (binding_id text, binding_revision integer, customer text, source_namespace text,
               instance_id text, resource text, event text, environment text, origin text,
               combination_id text, capture_id text, target_kind text, target_id text,
               occurrence_ref text, occurrence_evidence_sha256 text, snapshot_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    found_id text;
BEGIN
    SELECT b.binding_id INTO found_id FROM voalack.bindings b
     WHERE b.alert_id = p_alert_id AND b.active FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    -- The generation row is created with the binding by the administrator; this only locks it.
    PERFORM 1 FROM voalack.binding_generations g WHERE g.binding_id = found_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;                            -- no generation row: not an eligible binding
    END IF;
    RETURN QUERY
        SELECT r.binding_id, r.binding_revision, r.customer, r.source_namespace, r.instance_id,
               r.resource, r.event, r.environment, r.origin, r.combination_id, r.capture_id,
               r.target_kind, r.target_id, r.occurrence_ref, r.occurrence_evidence_sha256,
               r.snapshot_sha256
          FROM voalack.bindings b
          JOIN voalack.binding_revisions r
            ON r.binding_id = b.binding_id AND r.binding_revision = b.binding_revision
         WHERE b.alert_id = p_alert_id AND b.active;
END;
$$;

-- The active policy revision granting ACK on a customer to a user ID; locks the active pointer
-- so a policy change waits for this ACK to finish.
CREATE OR REPLACE FUNCTION voalack.lock_grant(p_user_id text, p_customer text) RETURNS integer
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT a.policy_revision FROM voalack.authorization_policy_active a
      JOIN voalack.authorization_policy p
        ON p.policy_revision = a.policy_revision AND p.user_id = p_user_id AND p.customer = p_customer
       FOR SHARE OF a
$$;

-- Staging: allocates the next generation of the locked binding once and records the intent in
-- the current transaction. A rollback restores the counter.
CREATE OR REPLACE FUNCTION voalack.stage_intent(
    p_action_id uuid, p_alert_id text, p_request_id uuid, p_actor_login text, p_payload jsonb,
    p_customer text, p_binding_id text, p_binding_revision integer, p_issued_at timestamptz,
    p_capture_expires_at timestamptz, p_execution_expires_at timestamptz) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    next_generation bigint;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM voalack.bindings b
                    WHERE b.alert_id = p_alert_id AND b.active AND b.binding_id = p_binding_id
                      AND b.binding_revision = p_binding_revision) THEN
        RAISE EXCEPTION 'voalack: binding is not active';
    END IF;
    UPDATE voalack.binding_generations SET generation = generation + 1
     WHERE binding_id = p_binding_id RETURNING generation INTO next_generation;
    IF next_generation IS NULL THEN
        RAISE EXCEPTION 'voalack: binding generation is not initialised';
    END IF;
    INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload, request_id,
                                          customer, binding_id, binding_revision, generation, issued_at,
                                          capture_expires_at, execution_expires_at)
    VALUES (p_action_id, p_alert_id, txid_current(), p_actor_login, p_payload, p_request_id, p_customer,
            p_binding_id, p_binding_revision, next_generation, p_issued_at, p_capture_expires_at,
            p_execution_expires_at);
    RETURN next_generation;
END;
$$;

-- Approval: stores the signed canonical envelope on this transaction's unapproved intent and links
-- its digest to the matching capture (same action, alert, transaction and generation).
CREATE OR REPLACE FUNCTION voalack.approve_intent(
    p_action_id uuid, p_canonical bytea, p_sha256 text, p_kid text, p_mac text, p_final jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    intent voalack.prepared_intents%ROWTYPE;
    linked integer;
BEGIN
    IF encode(sha256(p_canonical), 'hex') IS DISTINCT FROM p_sha256
       OR p_mac !~ '^[0-9a-f]{64}$' OR p_kid !~ '^[A-Za-z0-9_.-]{1,32}$' THEN
        RAISE EXCEPTION 'voalack: malformed approval';
    END IF;
    UPDATE voalack.prepared_intents
       SET envelope_canonical = p_canonical, envelope_sha256 = p_sha256, kid = p_kid, mac = p_mac,
           payload = payload || p_final
     WHERE action_id = p_action_id AND txid = txid_current() AND envelope_canonical IS NULL
    RETURNING * INTO intent;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: no unapproved intent for this action in this transaction';
    END IF;
    UPDATE voalack.captures SET envelope_sha256 = p_sha256
     WHERE action_id = p_action_id AND txid = txid_current() AND alert_id = intent.alert_id
       AND generation = intent.generation AND envelope_sha256 IS NULL;
    GET DIAGNOSTICS linked = ROW_COUNT;
    IF linked <> 1 THEN
        RAISE EXCEPTION 'voalack: no unlinked capture for this action in this transaction';
    END IF;
END;
$$;

-- T04 S1: verification claims, immutable verification records and effects. Verification is done by
-- the trusted verifier process (cryptographic checks happen there, not in SQL); the database fences
-- stale claimants, keeps records immutable, binds each verification to the exact capture facts it
-- checked, and allows at most one effect per key and per action. Claim epochs (verifier leases) are
-- distinct from the ACK generations of binding_generations.
CREATE TABLE IF NOT EXISTS voalack.verification_claims (
    action_id        uuid PRIMARY KEY REFERENCES voalack.captures (action_id),
    claim_epoch      bigint NOT NULL CHECK (claim_epoch > 0),
    claimant         text NOT NULL CHECK (octet_length(claimant) BETWEEN 1 AND 128),
    lease_until      timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS voalack.verifications (
    verification_id     bigserial PRIMARY KEY,
    action_id           uuid NOT NULL REFERENCES voalack.captures (action_id),
    claim_epoch         bigint NOT NULL,
    verifier_version    text NOT NULL,
    deployment_id       text NOT NULL,
    provider            text NOT NULL,
    kid                 text,
    outcome             text NOT NULL CHECK (outcome IN ('verified', 'refused', 'hold')),
    reason              text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 128),
    envelope_sha256     text CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    capture_fingerprint text CHECK (capture_fingerprint ~ '^[0-9a-f]{64}$'),
    verified_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (outcome <> 'verified' OR (envelope_sha256 IS NOT NULL AND capture_fingerprint IS NOT NULL))
);
DROP TRIGGER IF EXISTS verifications_immutable ON voalack.verifications;
CREATE TRIGGER verifications_immutable BEFORE UPDATE OR DELETE ON voalack.verifications
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
CREATE TABLE IF NOT EXISTS voalack.effects (
    effect_id        bigserial PRIMARY KEY,
    effect_key       text NOT NULL UNIQUE,
    instance_id      text NOT NULL,
    target_id        text NOT NULL,
    action_id        uuid NOT NULL UNIQUE REFERENCES voalack.captures (action_id),
    verification_id  bigint NOT NULL REFERENCES voalack.verifications (verification_id),
    state            text NOT NULL CHECK (state IN ('QUEUED', 'REMOTE_CONFIRMED', 'ALREADY_ACKED', 'BLOCKED',
                                                    'SUPERSEDED', 'UNCERTAIN')),
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- SHA-256 of the complete stored intent and capture rows: a verification records the fingerprint of
-- the rows it checked, and promotion requires the rows to be unchanged since.
CREATE OR REPLACE FUNCTION voalack.capture_fingerprint(p_action_id uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT encode(sha256(convert_to(jsonb_build_object('intent', to_jsonb(p), 'capture', to_jsonb(c))::text,
                                    'UTF8')), 'hex')
      FROM voalack.prepared_intents p JOIN voalack.captures c ON c.action_id = p.action_id
     WHERE p.action_id = p_action_id
$$;

-- One capture per call with no effect and no refusal whose claim is absent or expired; never-claimed
-- captures first, then the longest-expired claims (held work cannot starve new work).
CREATE OR REPLACE FUNCTION voalack.claim_verification(p_claimant text, p_lease_seconds integer,
                                                      p_action_id uuid DEFAULT NULL)
RETURNS TABLE (action_id uuid, claim_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    chosen uuid;
BEGIN
    IF p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 300 THEN
        RAISE EXCEPTION 'voalack: verification lease out of range';
    END IF;
    SELECT c.action_id INTO chosen
      FROM voalack.captures c
      LEFT JOIN voalack.verification_claims vc ON vc.action_id = c.action_id
     WHERE (p_action_id IS NULL OR c.action_id = p_action_id)
       AND NOT EXISTS (SELECT 1 FROM voalack.effects e WHERE e.action_id = c.action_id)
       AND NOT EXISTS (SELECT 1 FROM voalack.verifications v
                        WHERE v.action_id = c.action_id AND v.outcome = 'refused')
       AND (vc.action_id IS NULL OR vc.lease_until <= clock_timestamp())
     ORDER BY vc.lease_until NULLS FIRST, c.captured_at
     LIMIT 1
       FOR UPDATE OF c SKIP LOCKED;
    IF chosen IS NULL THEN
        RETURN;
    END IF;
    RETURN QUERY
        INSERT INTO voalack.verification_claims AS vc (action_id, claim_epoch, claimant, lease_until)
        VALUES (chosen, 1, p_claimant, clock_timestamp() + make_interval(secs => p_lease_seconds))
        ON CONFLICT ON CONSTRAINT verification_claims_pkey DO UPDATE
           SET claim_epoch = vc.claim_epoch + 1, claimant = EXCLUDED.claimant,
               lease_until = EXCLUDED.lease_until
        RETURNING vc.action_id, vc.claim_epoch;
END;
$$;

-- Protects the original intent and capture rows (FOR SHARE) for the rest of the caller's
-- transaction. Lock order everywhere is original rows, then the claim row, as in
-- claim_verification (capture, then claim), so claiming and promotion cannot form a lock cycle.
CREATE OR REPLACE FUNCTION voalack._lock_original(p_action_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    PERFORM 1 FROM voalack.prepared_intents p WHERE p.action_id = p_action_id FOR SHARE;
    PERFORM 1 FROM voalack.captures c WHERE c.action_id = p_action_id FOR SHARE;
END;
$$;

-- Locks the caller's claim row; fails unless the claim is this epoch and its lease is unexpired.
CREATE OR REPLACE FUNCTION voalack._require_current_claim(p_action_id uuid, p_claim_epoch bigint)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    PERFORM 1 FROM voalack.verification_claims vc
     WHERE vc.action_id = p_action_id AND vc.claim_epoch = p_claim_epoch
       AND vc.lease_until > clock_timestamp()
       FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: stale or expired verification claim';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION voalack.record_verification(
    p_action_id uuid, p_claim_epoch bigint, p_version text, p_deployment text, p_provider text,
    p_kid text, p_outcome text, p_reason text, p_sha256 text, p_fingerprint text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    new_id bigint;
    cur_phase text;
BEGIN
    -- T04 S4 (D12, F2): the first protected call of the verifier's transaction pins the epoch row before
    -- any original, claim or verification lock; a verification that will be promoted also needs the open
    -- phase here, before those locks (promote_effect re-checks it). A missing row or another phase defers
    -- (VA004/VA003: nothing recorded).
    IF NOT voalack._pin_epoch() THEN
        IF p_outcome = 'verified' THEN
            RAISE EXCEPTION USING ERRCODE = 'VA004', MESSAGE = 'voalack: recovery epoch is not initialized';
        END IF;
    ELSIF p_outcome = 'verified' THEN
        SELECT r.phase INTO cur_phase FROM voalack.recovery_epoch r;      -- pinned above
        IF cur_phase <> 'open' THEN
            RAISE EXCEPTION USING ERRCODE = 'VA003', MESSAGE = 'voalack: the database is not open for promotion';
        END IF;
    END IF;
    PERFORM voalack._lock_original(p_action_id);
    PERFORM voalack._require_current_claim(p_action_id, p_claim_epoch);
    INSERT INTO voalack.verifications (action_id, claim_epoch, verifier_version, deployment_id, provider,
                                       kid, outcome, reason, envelope_sha256, capture_fingerprint)
    VALUES (p_action_id, p_claim_epoch, p_version, p_deployment, p_provider, p_kid, p_outcome, p_reason,
            p_sha256, p_fingerprint)
    RETURNING verification_id INTO new_id;
    RETURN new_id;
END;
$$;

-- Promotion, in one short transaction. Locks the original intent and capture rows, then requires
-- the claim to be current, the verification to be this claim's 'verified' record for the stored
-- digest and for the unchanged (now protected) capture rows, then
-- locks (FOR SHARE, the capture path's order: binding, generation, active policy pointer) and
-- requires the active binding on the same revision, the binding's current ACK generation equal to
-- this intent's (a newer committed ACK supersedes it), and the signed policy revision still active
-- and granting this user and customer. Policy, binding and generation changes wait for the
-- promotion to finish; a promotion that waited behind a committed change re-reads the new row
-- (READ COMMITTED) and refuses. The deadline and claim are checked again after the effect insert,
-- the last local step; a failure there undoes the insert. Returns the effect id and 'promoted', or
-- NULL and the refusal reason ('effect_key_taken' when the key or action already has an effect).
DROP FUNCTION IF EXISTS voalack.promote_effect(uuid, bigint, bigint);
CREATE FUNCTION voalack.promote_effect(p_action_id uuid, p_claim_epoch bigint, p_verification_id bigint)
RETURNS TABLE (effect_id bigint, reason text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    intent voalack.prepared_intents%ROWTYPE;
    fingerprint text;
    env jsonb;
    new_id bigint;
    cur_phase text;
BEGIN
    -- T04 S4 (D1): the recovery epoch first (FOR SHARE, before every lock adoption, close or open
    -- takes), so a promotion and an epoch change never wait for each other in opposite orders. Only
    -- the open phase promotes; a closed or recovering database, or one not initialized, defers the
    -- verification (VA003/VA004: nothing is recorded and the claim lapses). After a wait the locked
    -- row is read again and shows the new phase.
    IF NOT voalack._pin_epoch() THEN
        RAISE EXCEPTION USING ERRCODE = 'VA004', MESSAGE = 'voalack: recovery epoch is not initialized';
    END IF;
    SELECT r.phase INTO cur_phase FROM voalack.recovery_epoch r;      -- pinned above
    IF cur_phase <> 'open' THEN
        RAISE EXCEPTION USING ERRCODE = 'VA003', MESSAGE = 'voalack: the database is not open for promotion';
    END IF;
    -- The original rows are locked first (normally already by record_verification in this
    -- transaction), so the fingerprint compared below cannot change before this transaction ends.
    PERFORM voalack._lock_original(p_action_id);
    PERFORM voalack._require_current_claim(p_action_id, p_claim_epoch);
    SELECT * INTO intent FROM voalack.prepared_intents i WHERE i.action_id = p_action_id;
    IF NOT FOUND OR intent.envelope_canonical IS NULL THEN
        RETURN QUERY SELECT NULL::bigint, 'no_signed_intent'::text; RETURN;
    END IF;
    SELECT v.capture_fingerprint INTO fingerprint FROM voalack.verifications v
     WHERE v.verification_id = p_verification_id AND v.action_id = p_action_id
       AND v.claim_epoch = p_claim_epoch AND v.outcome = 'verified'
       AND v.envelope_sha256 = intent.envelope_sha256;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::bigint, 'verification_mismatch'::text; RETURN;
    END IF;
    IF fingerprint IS DISTINCT FROM voalack.capture_fingerprint(p_action_id) THEN
        RETURN QUERY SELECT NULL::bigint, 'capture_changed'::text; RETURN;
    END IF;
    env := convert_from(intent.envelope_canonical, 'UTF8')::jsonb;
    PERFORM 1 FROM voalack.bindings b
     WHERE b.alert_id = intent.alert_id AND b.active AND b.binding_id = intent.binding_id
       AND b.binding_revision = intent.binding_revision
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::bigint, 'binding_changed'::text; RETURN;
    END IF;
    PERFORM 1 FROM voalack.binding_generations g
     WHERE g.binding_id = intent.binding_id AND g.generation = intent.generation
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::bigint, 'generation_superseded'::text; RETURN;
    END IF;
    PERFORM 1 FROM voalack.authorization_policy_active a
      JOIN voalack.authorization_policy p
        ON p.policy_revision = a.policy_revision AND p.user_id = env->'actor'->>'user_id'
       AND p.customer = intent.customer
     WHERE a.policy_revision = (env->'actor'->>'authorization_policy_revision')::integer
       FOR SHARE OF a;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::bigint, 'policy_revoked'::text; RETURN;
    END IF;
    BEGIN
        INSERT INTO voalack.effects (effect_key, instance_id, target_id, action_id, verification_id, state)
        VALUES (concat_ws('|', env->>'deployment_id', env->>'provider', env->>'customer',
                          env->>'source_namespace', env->>'instance_id', env->'source'->>'target_id',
                          env->'source'->>'occurrence_ref', env->>'action'),
                env->>'instance_id', env->'source'->>'target_id', p_action_id, p_verification_id, 'QUEUED')
        ON CONFLICT DO NOTHING
        RETURNING effects.effect_id INTO new_id;
        IF new_id IS NULL THEN
            RETURN QUERY SELECT NULL::bigint, 'effect_key_taken'::text; RETURN;
        END IF;
        -- Last local boundary, after every wait above: real clock before the original deadline
        -- (exclusive) and the claim still this epoch with an unexpired lease.
        IF NOT (clock_timestamp() < intent.execution_expires_at) THEN
            RAISE EXCEPTION USING ERRCODE = 'VA001', MESSAGE = 'voalack: expired at promotion';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM voalack.verification_claims vc
                        WHERE vc.action_id = p_action_id AND vc.claim_epoch = p_claim_epoch
                          AND vc.lease_until > clock_timestamp()) THEN
            RAISE EXCEPTION USING ERRCODE = 'VA002', MESSAGE = 'voalack: claim expired at promotion';
        END IF;
    EXCEPTION
        WHEN SQLSTATE 'VA001' THEN
            RETURN QUERY SELECT NULL::bigint, 'expired'::text; RETURN;
        WHEN SQLSTATE 'VA002' THEN
            RAISE EXCEPTION 'voalack: stale or expired verification claim';
    END;
    RETURN QUERY SELECT new_id, 'promoted'::text;
END;
$$;

-- T04 S2: session owner, attempts with a one-time dispatch permit, physical-target guards.
-- Fake provider contract only ('fake-one/v1'); no ONE endpoint or credential is stored here.
CREATE TABLE IF NOT EXISTS voalack.instance_config (
    instance_id       text PRIMARY KEY CHECK (octet_length(instance_id) BETWEEN 1 AND 128),
    credential_ref    text NOT NULL UNIQUE CHECK (octet_length(credential_ref) BETWEEN 1 AND 128),
    provider_contract text NOT NULL CHECK (provider_contract = 'fake-one/v1'),
    config_revision   integer NOT NULL CHECK (config_revision > 0)
);
-- Upgrades from d263af6: the credential uniqueness is added to an existing table as well.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'instance_config_credential_ref_key'
                     AND conrelid = 'voalack.instance_config'::regclass) THEN
        ALTER TABLE voalack.instance_config ADD CONSTRAINT instance_config_credential_ref_key UNIQUE (credential_ref);
    END IF;
END;
$$;
-- Keys and verifier versions accepted for dispatch: the trusted authority for key eligibility
-- (SQL cannot consult the key ring). Administrator-maintained.
CREATE TABLE IF NOT EXISTS voalack.accepted_kids (
    kid text PRIMARY KEY CHECK (kid ~ '^[A-Za-z0-9_.-]{1,32}$')
);
CREATE TABLE IF NOT EXISTS voalack.accepted_verifier_versions (
    verifier_version text PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS voalack.session_owners (
    instance_id      text PRIMARY KEY REFERENCES voalack.instance_config (instance_id),
    owner_generation bigint NOT NULL DEFAULT 0 CHECK (owner_generation >= 0),
    incarnation      uuid,
    owner_id         text CHECK (octet_length(owner_id) BETWEEN 1 AND 128),
    state            text NOT NULL DEFAULT 'free' CHECK (state IN ('free', 'active', 'suspended', 'contained')),
    changed_at       timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((state = 'free') = (incarnation IS NULL))
);
-- The credential and configuration revision an owner acquired under; a change needs a new owner.
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS bound_credential_ref text;
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS bound_config_revision integer;
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS bound_provider_contract text;
-- T04 S3c: the recovery epoch this database was initialized or adopted at, bound to one line of the
-- external anchor (administrator functions only; no row means nothing may acquire or operate), and
-- the epoch, anchor line and mode each owner acquired under.
CREATE TABLE IF NOT EXISTS voalack.recovery_epoch (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch        bigint NOT NULL CHECK (epoch >= 1),
    phase        text NOT NULL CHECK (phase IN ('open', 'closed', 'recovering')),
    head_seq     integer NOT NULL CHECK (head_seq >= 1),
    head_sha256  text NOT NULL CHECK (head_sha256 ~ '^[0-9a-f]{64}$'),
    adoption_id  bigint,
    changed_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS voalack.recovery_transitions (
    transition_id bigserial PRIMARY KEY,
    epoch         bigint NOT NULL,
    phase         text NOT NULL,
    head_seq      integer NOT NULL,
    head_sha256   text NOT NULL,
    detail        jsonb NOT NULL CHECK (octet_length(detail::text) <= 16384),
    decided_by    text NOT NULL,
    recorded_at   timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS recovery_transitions_immutable ON voalack.recovery_transitions;
CREATE TRIGGER recovery_transitions_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_transitions
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS acquired_epoch bigint;
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS acquired_head_sha256 text;
ALTER TABLE voalack.session_owners ADD COLUMN IF NOT EXISTS mode text NOT NULL DEFAULT 'ordinary'
    CHECK (mode IN ('ordinary', 'maintenance'));
CREATE TABLE IF NOT EXISTS voalack.owner_containment (
    containment_id   bigserial PRIMARY KEY,
    instance_id      text NOT NULL REFERENCES voalack.instance_config (instance_id),
    owner_generation bigint NOT NULL,
    incarnation      uuid NOT NULL,
    evidence         jsonb NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS owner_containment_immutable ON voalack.owner_containment;
CREATE TRIGGER owner_containment_immutable BEFORE UPDATE OR DELETE ON voalack.owner_containment
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
ALTER TABLE voalack.effects ADD COLUMN IF NOT EXISTS in_flight_attempt uuid UNIQUE;
CREATE TABLE IF NOT EXISTS voalack.attempts (
    attempt_id        uuid PRIMARY KEY,
    effect_id         bigint NOT NULL REFERENCES voalack.effects (effect_id),
    action_id         uuid NOT NULL,
    instance_id       text NOT NULL REFERENCES voalack.instance_config (instance_id),
    credential_ref    text NOT NULL,
    provider_contract text NOT NULL,
    config_revision   integer NOT NULL,
    owner_generation  bigint NOT NULL,
    incarnation       uuid NOT NULL,
    target_kind       text NOT NULL,
    target_id         text NOT NULL,
    request_bytes     bytea NOT NULL,
    request_sha256    text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    permit_state      text NOT NULL CHECK (permit_state IN ('unconsumed', 'consumed', 'revoked')),
    state             text NOT NULL CHECK (state IN ('started', 'dispatched', 'confirmed', 'uncertain',
                                                     'aborted_before_dispatch', 'not_sent')),
    started_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at     timestamptz,
    settled_at        timestamptz,
    CHECK ((permit_state = 'unconsumed') = (state = 'started')),
    CHECK ((permit_state = 'consumed') = (state IN ('dispatched', 'confirmed', 'not_sent') OR (state = 'uncertain' AND dispatched_at IS NOT NULL))),
    CHECK (encode(sha256(request_bytes), 'hex') = request_sha256)
);
-- T04 S3a upgrade of an existing attempts table: the not_sent terminal state (permit consumed).
ALTER TABLE voalack.attempts DROP CONSTRAINT IF EXISTS attempts_state_check,
    DROP CONSTRAINT IF EXISTS attempts_check1;
ALTER TABLE voalack.attempts ADD CONSTRAINT attempts_state_check CHECK (state IN ('started', 'dispatched', 'confirmed',
        'uncertain', 'aborted_before_dispatch', 'not_sent')),
    ADD CONSTRAINT attempts_check1 CHECK ((permit_state = 'consumed') = (state IN ('dispatched', 'confirmed', 'not_sent')
        OR (state = 'uncertain' AND dispatched_at IS NOT NULL)));
-- Protected per-effect retry budget and durable backoff (S3a): written only by start_attempt and
-- record_not_sent.
ALTER TABLE voalack.effects ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 0;
-- Upgrade from S2 (runs in the one administrative schema transaction, schema.apply): with attempt
-- creation and release excluded, count every attempt an effect already had, in any state (only ever
-- raised, never capped or reset), and retire queued effects whose budget is already used and that
-- have nothing in flight as neutral BLOCKED (budget exhaustion, not proof of remote non-effect).
-- In-flight, uncertain and settled effects keep their existing handling, guards and lineage.
-- T04 S4 (D7.4 corrected): the recovery epoch row first when it exists (an outcome event for a retired
-- effect requires the row pin, and every writer takes it before the effect locks). Without a row (a
-- pre-S3c installation not yet bootstrapped) a retirement here, by the superuser schema application, is
-- history from before initialization: it gets no event, and the administrator's snapshot backfill covers
-- it after bootstrap.
DO $$
DECLARE
    pinned boolean := false;
BEGIN
    IF to_regclass('voalack.recovery_epoch') IS NOT NULL THEN
        PERFORM 1 FROM voalack.recovery_epoch r FOR SHARE;
        pinned := FOUND;
    END IF;
    IF pinned THEN
        PERFORM set_config('voalack.epoch_pin', txid_current()::text, true);
    END IF;
END;
$$;
LOCK TABLE voalack.effects, voalack.attempts IN SHARE ROW EXCLUSIVE MODE;
UPDATE voalack.effects e SET attempt_count = c.n
  FROM (SELECT a.effect_id, count(*)::integer AS n FROM voalack.attempts a GROUP BY a.effect_id) c
 WHERE c.effect_id = e.effect_id AND e.attempt_count < c.n;
UPDATE voalack.effects e SET state = 'BLOCKED'
 WHERE e.state = 'QUEUED' AND e.in_flight_attempt IS NULL AND e.attempt_count >= 3;
ALTER TABLE voalack.effects ADD COLUMN IF NOT EXISTS next_attempt_after timestamptz;
-- Retry lineage: the owner generation and process incarnation that recorded the known not_sent.
-- Only that same live owner may start the retry; a restarted or successor process may not.
ALTER TABLE voalack.effects ADD COLUMN IF NOT EXISTS retry_owner_generation bigint;
ALTER TABLE voalack.effects ADD COLUMN IF NOT EXISTS retry_incarnation uuid;

CREATE TABLE IF NOT EXISTS voalack.target_guards (
    instance_id text NOT NULL,
    target_kind text NOT NULL,
    target_id   text NOT NULL,
    attempt_id  uuid NOT NULL UNIQUE REFERENCES voalack.attempts (attempt_id),
    state       text NOT NULL CHECK (state IN ('in_flight', 'uncertain')),
    PRIMARY KEY (instance_id, target_kind, target_id)
);
CREATE TABLE IF NOT EXISTS voalack.attempt_evidence (
    evidence_id      bigserial PRIMARY KEY,
    attempt_id       uuid NOT NULL REFERENCES voalack.attempts (attempt_id),
    owner_generation bigint NOT NULL,
    incarnation      uuid NOT NULL,
    kind             text NOT NULL CHECK (octet_length(kind) BETWEEN 1 AND 64),
    detail           jsonb NOT NULL,
    recorded_at      timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS attempt_evidence_immutable ON voalack.attempt_evidence;
CREATE TRIGGER attempt_evidence_immutable BEFORE UPDATE OR DELETE ON voalack.attempt_evidence
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

-- The one-target ACK request, built only from the signed envelope and the administrator-fixed
-- instance configuration (reviewed encoder; callers never supply bytes).
CREATE OR REPLACE FUNCTION voalack.encode_ack_request(p_effect_id bigint) RETURNS bytea
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT convert_to(jsonb_build_object(
               'contract', ic.provider_contract, 'operation', 'ack', 'instance_id', ic.instance_id,
               'target', jsonb_build_object('kind', env->'source'->>'target_kind', 'id', env->'source'->>'target_id'),
               'comment', env->>'message')::text, 'UTF8')
      FROM voalack.effects e
      JOIN voalack.prepared_intents p ON p.action_id = e.action_id
      CROSS JOIN LATERAL (SELECT convert_from(p.envelope_canonical, 'UTF8')::jsonb AS env) x
      JOIN voalack.instance_config ic ON ic.instance_id = env->>'instance_id'
     WHERE e.effect_id = p_effect_id AND e.instance_id = env->>'instance_id'
       AND e.target_id = env->'source'->>'target_id'
$$;

-- T04 S3c: the database is in the phase that admits this mode, bound to exactly this epoch and anchor
-- line (recovery_epoch FOR SHARE, so a concurrent close waits for the caller and the caller, after
-- any wait, sees the close).
CREATE OR REPLACE FUNCTION voalack._epoch_pin(p_epoch bigint, p_head_sha256 text, p_mode text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    PERFORM 1 FROM voalack.recovery_epoch r
     WHERE r.epoch = p_epoch AND r.head_sha256 = p_head_sha256
       AND r.phase = CASE p_mode WHEN 'ordinary' THEN 'open' WHEN 'maintenance' THEN 'recovering' END
       FOR SHARE;
    RETURN FOUND;
END;
$$;

-- Owner fence: the caller's instance, generation and process incarnation must be current and in one
-- of the given states; locks the owner row FOR SHARE. T04 S3c: an ordinary owner whose acquired
-- epoch and anchor line are those of the open database (checked after the owner-row wait).
CREATE OR REPLACE FUNCTION voalack._owner_fenced(p_instance text, p_generation bigint, p_incarnation uuid,
                                                 p_states text[]) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    o voalack.session_owners%ROWTYPE;
BEGIN
    SELECT * INTO o FROM voalack.session_owners x
     WHERE x.instance_id = p_instance AND x.owner_generation = p_generation
       AND x.incarnation = p_incarnation AND x.state = ANY(p_states)
       FOR SHARE;
    IF NOT FOUND OR o.mode IS DISTINCT FROM 'ordinary' THEN
        RETURN false;
    END IF;
    RETURN voalack._epoch_pin(o.acquired_epoch, o.acquired_head_sha256, 'ordinary');
END;
$$;

-- Current dispatch eligibility of an effect (S1's promotion checks, re-applied; promote_effect is
-- left unchanged). Locks original rows, binding, generation and policy pointer FOR SHARE, in the
-- capture path's order; the deadline is compared last, after every wait. NULL means eligible.
CREATE OR REPLACE FUNCTION voalack._dispatch_eligibility(p_effect_id bigint) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    eff voalack.effects%ROWTYPE;
    intent voalack.prepared_intents%ROWTYPE;
    ver voalack.verifications%ROWTYPE;
    env jsonb;
BEGIN
    SELECT * INTO eff FROM voalack.effects e WHERE e.effect_id = p_effect_id;
    IF NOT FOUND THEN
        RETURN 'no_effect';
    END IF;
    PERFORM voalack._lock_original(eff.action_id);
    SELECT * INTO intent FROM voalack.prepared_intents i WHERE i.action_id = eff.action_id;
    SELECT * INTO ver FROM voalack.verifications v WHERE v.verification_id = eff.verification_id;
    IF intent.envelope_canonical IS NULL OR ver.outcome IS DISTINCT FROM 'verified'
       OR ver.envelope_sha256 IS DISTINCT FROM intent.envelope_sha256 THEN
        RETURN 'verification_mismatch';
    END IF;
    IF ver.capture_fingerprint IS DISTINCT FROM voalack.capture_fingerprint(eff.action_id) THEN
        RETURN 'capture_changed';
    END IF;
    env := convert_from(intent.envelope_canonical, 'UTF8')::jsonb;
    PERFORM 1 FROM voalack.bindings b
     WHERE b.alert_id = intent.alert_id AND b.active AND b.binding_id = intent.binding_id
       AND b.binding_revision = intent.binding_revision
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'binding_changed';
    END IF;
    PERFORM 1 FROM voalack.binding_generations g
     WHERE g.binding_id = intent.binding_id AND g.generation = intent.generation
       FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'generation_superseded';
    END IF;
    PERFORM 1 FROM voalack.authorization_policy_active a
      JOIN voalack.authorization_policy p
        ON p.policy_revision = a.policy_revision AND p.user_id = env->'actor'->>'user_id'
       AND p.customer = intent.customer
     WHERE a.policy_revision = (env->'actor'->>'authorization_policy_revision')::integer
       FOR SHARE OF a;
    IF NOT FOUND THEN
        RETURN 'policy_revoked';
    END IF;
    PERFORM 1 FROM voalack.accepted_kids k WHERE k.kid = intent.kid FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'key_not_accepted';
    END IF;
    PERFORM 1 FROM voalack.accepted_verifier_versions av WHERE av.verifier_version = ver.verifier_version FOR SHARE;
    IF NOT FOUND THEN
        RETURN 'verifier_not_accepted';
    END IF;
    IF NOT (clock_timestamp() < intent.execution_expires_at) THEN
        RETURN 'expired';
    END IF;
    RETURN NULL;
END;
$$;

-- T04 S3c: acquisition names the anchor head the worker read; there is no epoch-less acquisition.
DROP FUNCTION IF EXISTS voalack.acquire_owner(text, text, uuid);
CREATE OR REPLACE FUNCTION voalack.acquire_owner(p_instance text, p_owner_id text, p_incarnation uuid,
                                                 p_epoch bigint, p_head_seq integer, p_head_sha256 text,
                                                 p_mode text)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    new_generation bigint;
    ic voalack.instance_config%ROWTYPE;
    r voalack.recovery_epoch%ROWTYPE;
BEGIN
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: instance is not configured';
    END IF;
    IF p_mode IS NULL OR p_mode NOT IN ('ordinary', 'maintenance') THEN
        RAISE EXCEPTION 'voalack: unknown owner mode';
    END IF;
    SELECT * INTO r FROM voalack.recovery_epoch x FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: recovery epoch is not initialized';
    END IF;
    IF (r.epoch, r.head_seq, r.head_sha256) IS DISTINCT FROM (p_epoch, p_head_seq, p_head_sha256)
       OR r.phase IS DISTINCT FROM (CASE p_mode WHEN 'ordinary' THEN 'open' ELSE 'recovering' END) THEN
        RAISE EXCEPTION 'voalack: anchor head does not match the database recovery epoch';
    END IF;
    -- One live owner per credential, across rotation: an earlier owner (any instance) that acquired
    -- under this credential and is not contained still holds it. An uncontained owner whose acquired
    -- credential is unknown (acquired before the snapshot existed) may hold any credential: fail
    -- closed until it is contained (never backfilled from today's configuration).
    PERFORM pg_advisory_xact_lock(hashtext('voalack.credential:' || ic.credential_ref));
    IF EXISTS (SELECT 1 FROM voalack.session_owners o2
                WHERE o2.instance_id <> p_instance AND o2.state IN ('active', 'suspended')
                  AND (o2.bound_credential_ref = ic.credential_ref OR o2.bound_credential_ref IS NULL)) THEN
        RAISE EXCEPTION 'voalack: credential is held by another owner until it is contained';
    END IF;
    INSERT INTO voalack.session_owners (instance_id) VALUES (p_instance)
    ON CONFLICT (instance_id) DO NOTHING;
    UPDATE voalack.session_owners o
       SET owner_generation = o.owner_generation + 1, incarnation = p_incarnation, owner_id = p_owner_id,
           state = 'active', changed_at = clock_timestamp(),
           bound_credential_ref = ic.credential_ref, bound_config_revision = ic.config_revision,
           bound_provider_contract = ic.provider_contract,
           acquired_epoch = p_epoch, acquired_head_sha256 = p_head_sha256, mode = p_mode
     WHERE o.instance_id = p_instance AND o.state IN ('free', 'contained')
    RETURNING o.owner_generation INTO new_generation;
    IF new_generation IS NULL THEN
        RAISE EXCEPTION 'voalack: instance owner is not free or contained';
    END IF;
    RETURN new_generation;
END;
$$;

-- The caller's owner state, or 'config_changed' when the instance's credential or configuration
-- revision is no longer the one this owner acquired under (its session must not be used). T04 S3c:
-- 'epoch_changed' when an active owner's acquired epoch, anchor line or mode no longer matches the
-- database's recovery phase.
CREATE OR REPLACE FUNCTION voalack.check_owner(p_instance text, p_generation bigint, p_incarnation uuid)
RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT CASE WHEN (o.bound_credential_ref, o.bound_config_revision, o.bound_provider_contract)
                     IS DISTINCT FROM (ic.credential_ref, ic.config_revision, ic.provider_contract) THEN 'config_changed'
                WHEN o.state = 'active'
                     AND NOT voalack._epoch_pin(o.acquired_epoch, o.acquired_head_sha256, o.mode) THEN 'epoch_changed'
                ELSE o.state END
      FROM voalack.session_owners o JOIN voalack.instance_config ic ON ic.instance_id = o.instance_id
     WHERE o.instance_id = p_instance AND o.owner_generation = p_generation AND o.incarnation = p_incarnation
$$;

CREATE OR REPLACE FUNCTION voalack.suspend_owner(p_instance text, p_generation bigint, p_incarnation uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    UPDATE voalack.session_owners o SET state = 'suspended', changed_at = clock_timestamp()
     WHERE o.instance_id = p_instance AND o.owner_generation = p_generation AND o.incarnation = p_incarnation
       AND o.state IN ('active', 'suspended');
END;
$$;

-- Administrator only (granted to no runtime role).
CREATE OR REPLACE FUNCTION voalack.record_containment(p_instance text, p_generation bigint, p_evidence jsonb)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    owner voalack.session_owners%ROWTYPE;
BEGIN
    SELECT * INTO owner FROM voalack.session_owners o WHERE o.instance_id = p_instance FOR UPDATE;
    IF NOT FOUND OR owner.owner_generation <> p_generation OR owner.state NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION 'voalack: containment must name the latest active or suspended generation';
    END IF;
    IF (p_evidence->>'process_stopped') IS DISTINCT FROM 'true'
       OR (p_evidence->>'no_requests_executing') IS DISTINCT FROM 'true'
       OR coalesce(length(p_evidence->>'basis'), 0) = 0 THEN
        RAISE EXCEPTION 'voalack: containment evidence must establish quiescence';
    END IF;
    INSERT INTO voalack.owner_containment (instance_id, owner_generation, incarnation, evidence)
    VALUES (p_instance, p_generation, owner.incarnation, p_evidence);
    UPDATE voalack.session_owners o SET state = 'contained', changed_at = clock_timestamp()
     WHERE o.instance_id = p_instance;
END;
$$;

-- True when the (locked) current configuration equals the snapshot this owner acquired under.
CREATE OR REPLACE FUNCTION voalack._owner_config_matches(p_instance text, p_generation bigint, p_incarnation uuid,
                                                         p_credential text, p_revision integer, p_contract text)
RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM voalack.session_owners o
                    WHERE o.instance_id = p_instance AND o.owner_generation = p_generation
                      AND o.incarnation = p_incarnation
                      AND (o.bound_credential_ref, o.bound_config_revision, o.bound_provider_contract)
                          = (p_credential, p_revision, p_contract))
$$;

-- Releases an unsettled attempt's guard and in-flight marker (same transaction as its state change).
CREATE OR REPLACE FUNCTION voalack._release_no_dispatch(p_attempt uuid, p_effect_state text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    UPDATE voalack.attempts a SET state = 'aborted_before_dispatch', permit_state = 'revoked',
           settled_at = clock_timestamp()
     WHERE a.attempt_id = p_attempt AND a.state = 'started' AND a.permit_state = 'unconsumed';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: only a started attempt with an unconsumed permit can be aborted';
    END IF;
    DELETE FROM voalack.target_guards g WHERE g.attempt_id = p_attempt;
    -- An effect whose attempt budget is used is never returned to QUEUED (it could never start).
    UPDATE voalack.effects e SET in_flight_attempt = NULL,
           state = CASE WHEN p_effect_state = 'QUEUED' AND e.attempt_count >= 3 THEN 'BLOCKED' ELSE p_effect_state END
     WHERE e.in_flight_attempt = p_attempt;
END;
$$;

CREATE OR REPLACE FUNCTION voalack._hold_uncertain(p_attempt uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    UPDATE voalack.attempts a
       SET state = 'uncertain', permit_state = CASE WHEN a.permit_state = 'consumed' THEN 'consumed' ELSE 'revoked' END,
           settled_at = clock_timestamp()
     WHERE a.attempt_id = p_attempt AND a.state IN ('started', 'dispatched');
    UPDATE voalack.target_guards g SET state = 'uncertain' WHERE g.attempt_id = p_attempt;
    UPDATE voalack.effects e SET state = 'UNCERTAIN' WHERE e.in_flight_attempt = p_attempt;
END;
$$;

CREATE OR REPLACE FUNCTION voalack.start_attempt(p_attempt uuid, p_effect_id bigint, p_instance text,
                                                 p_generation bigint, p_incarnation uuid)
RETURNS TABLE (outcome text, permit_state text, request_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    eff voalack.effects%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
    existing voalack.attempts%ROWTYPE;
    reason text;
    bytes bytea;
    sha text;
    kind text;
BEGIN
    SELECT * INTO eff FROM voalack.effects e WHERE e.effect_id = p_effect_id;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_effect'::text, NULL::text, NULL::text; RETURN;
    END IF;
    reason := voalack._dispatch_eligibility(p_effect_id);         -- original rows, binding, generation, policy
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = p_effect_id FOR UPDATE;
    SELECT * INTO eff FROM voalack.effects e WHERE e.effect_id = p_effect_id;
    IF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN QUERY SELECT 'owner_fenced'::text, NULL::text, NULL::text; RETURN;
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                         ic.config_revision, ic.provider_contract) THEN
        RETURN QUERY SELECT 'config_changed'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF eff.instance_id IS DISTINCT FROM p_instance THEN
        RETURN QUERY SELECT 'wrong_instance'::text, NULL::text, NULL::text; RETURN;
    END IF;
    bytes := voalack.encode_ack_request(p_effect_id);
    sha := encode(sha256(bytes), 'hex');
    SELECT * INTO existing FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF FOUND THEN
        -- Idempotent only for the complete original tuple and an unconsumed permit.
        IF (existing.effect_id, existing.action_id, existing.instance_id, existing.credential_ref,
            existing.provider_contract, existing.config_revision, existing.owner_generation,
            existing.incarnation, existing.request_sha256, existing.state)
           IS DISTINCT FROM (eff.effect_id, eff.action_id, ic.instance_id, ic.credential_ref,
                             ic.provider_contract, ic.config_revision, p_generation, p_incarnation, sha, 'started') THEN
            RETURN QUERY SELECT 'attempt_id_conflict'::text, existing.permit_state, NULL::text; RETURN;
        END IF;
        IF reason IS NOT NULL THEN
            RETURN QUERY SELECT reason, existing.permit_state, NULL::text; RETURN;
        END IF;
        -- After every wait above: a repeated call never outlives or refreshes the original deadline.
        IF NOT (clock_timestamp() < (SELECT p.execution_expires_at FROM voalack.prepared_intents p
                                      WHERE p.action_id = existing.action_id)) THEN
            RETURN QUERY SELECT 'expired'::text, existing.permit_state, NULL::text; RETURN;
        END IF;
        RETURN QUERY SELECT 'started'::text, existing.permit_state, existing.request_sha256; RETURN;
    END IF;
    IF reason IS NOT NULL THEN
        RETURN QUERY SELECT reason, NULL::text, NULL::text; RETURN;
    END IF;
    IF eff.state <> 'QUEUED' OR eff.in_flight_attempt IS NOT NULL THEN
        RETURN QUERY SELECT 'effect_not_queued'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF eff.attempt_count >= 3 THEN                    -- total attempts per effect, including the first
        RETURN QUERY SELECT 'attempt_budget_exhausted'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF eff.next_attempt_after IS NOT NULL AND clock_timestamp() < eff.next_attempt_after THEN
        RETURN QUERY SELECT 'backoff_pending'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF eff.retry_incarnation IS NOT NULL
       AND (eff.retry_owner_generation, eff.retry_incarnation) IS DISTINCT FROM (p_generation, p_incarnation) THEN
        RETURN QUERY SELECT 'retry_lineage_mismatch'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF NOT (clock_timestamp() < (SELECT p.execution_expires_at FROM voalack.prepared_intents p
                                  WHERE p.action_id = eff.action_id)) THEN
        RETURN QUERY SELECT 'expired'::text, NULL::text, NULL::text; RETURN;      -- after every wait
    END IF;
    kind := (SELECT convert_from(p.envelope_canonical, 'UTF8')::jsonb->'source'->>'target_kind'
               FROM voalack.prepared_intents p WHERE p.action_id = eff.action_id);
    -- T04 S3c: an effect key or action held by a recovery adoption never sends again; an active
    -- recovered hold on the physical key guards it like an uncertain guard.
    IF EXISTS (SELECT 1 FROM voalack.recovered_effects r WHERE r.effect_key = eff.effect_key OR r.action_id = eff.action_id) THEN
        RETURN QUERY SELECT 'recovered_effect'::text, NULL::text, NULL::text; RETURN;
    END IF;
    PERFORM 1 FROM voalack.recovered_holds h
     WHERE (h.instance_id, h.target_kind, h.target_id) = (eff.instance_id, kind, eff.target_id) AND h.status = 'active';
    IF FOUND THEN
        RETURN QUERY SELECT 'target_guarded'::text, NULL::text, NULL::text; RETURN;
    END IF;
    PERFORM 1 FROM voalack.target_guards g
     WHERE g.instance_id = eff.instance_id AND g.target_kind = kind AND g.target_id = eff.target_id;
    IF FOUND THEN
        RETURN QUERY SELECT 'target_guarded'::text, NULL::text, NULL::text; RETURN;
    END IF;
    BEGIN
        INSERT INTO voalack.attempts (attempt_id, effect_id, action_id, instance_id, credential_ref, provider_contract,
                                      config_revision, owner_generation, incarnation, target_kind, target_id,
                                      request_bytes, request_sha256, permit_state, state)
        VALUES (p_attempt, eff.effect_id, eff.action_id, ic.instance_id, ic.credential_ref, ic.provider_contract,
                ic.config_revision, p_generation, p_incarnation, kind, eff.target_id, bytes, sha, 'unconsumed', 'started');
        -- A concurrent attempt on the same physical target (another effect) commits first: the
        -- primary key of target_guards refuses this one; the subtransaction undoes the attempt row.
        INSERT INTO voalack.target_guards (instance_id, target_kind, target_id, attempt_id, state)
        VALUES (eff.instance_id, kind, eff.target_id, p_attempt, 'in_flight');
        UPDATE voalack.effects e SET in_flight_attempt = p_attempt, attempt_count = e.attempt_count + 1
         WHERE e.effect_id = eff.effect_id;
        -- After the persistence waits (a concurrent guard insert): the deadline once more.
        IF NOT (clock_timestamp() < (SELECT p.execution_expires_at FROM voalack.prepared_intents p
                                      WHERE p.action_id = eff.action_id)) THEN
            RAISE EXCEPTION USING ERRCODE = 'VA003', MESSAGE = 'voalack: expired while starting';
        END IF;
    EXCEPTION
        WHEN unique_violation THEN
            RETURN QUERY SELECT 'target_guarded'::text, NULL::text, NULL::text; RETURN;
        WHEN SQLSTATE 'VA003' THEN
            RETURN QUERY SELECT 'expired'::text, NULL::text, NULL::text; RETURN;
    END;
    RETURN QUERY SELECT 'started'::text, 'unconsumed'::text, sha;
END;
$$;

-- The last local boundary before a possible send: one-time permit consumption after re-checking
-- owner, eligibility, configuration, request bytes and the deadline (real clock, after all locks).
-- An ineligible started attempt is definitively aborted in the same transaction.
CREATE OR REPLACE FUNCTION voalack.consume_dispatch(p_attempt uuid, p_instance text, p_generation bigint,
                                                    p_incarnation uuid)
RETURNS TABLE (outcome text, request_bytes bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
    reason text;
    fresh bytea;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_attempt'::text, NULL::bytea; RETURN;
    END IF;
    reason := voalack._dispatch_eligibility(att.effect_id);
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF att.state <> 'started' OR att.permit_state <> 'unconsumed' THEN
        RETURN QUERY SELECT ('not_consumable:' || att.state)::text, NULL::bytea; RETURN;
    END IF;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance) THEN
        -- Not this attempt's owner: no change (a foreign caller cannot abort another owner's attempt).
        RETURN QUERY SELECT 'not_attempt_owner'::text, NULL::bytea; RETURN;
    END IF;
    IF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        -- The attempt's own owner is no longer active: its unconsumed permit can never be used.
        IF voalack._recovered_protected(p_attempt) THEN
            PERFORM voalack._hold_uncertain(p_attempt);        -- T04 S3c (R4): never requeued
            RETURN QUERY SELECT 'held:recovered'::text, NULL::bytea; RETURN;
        END IF;
        PERFORM voalack._release_no_dispatch(p_attempt, 'QUEUED');
        RETURN QUERY SELECT 'aborted:owner_fenced'::text, NULL::bytea; RETURN;
    END IF;
    IF voalack._recovered_protected(p_attempt) THEN
        PERFORM voalack._hold_uncertain(p_attempt);            -- T04 S3c (R4): an older permit never sends
        RETURN QUERY SELECT 'held:recovered'::text, NULL::bytea; RETURN;
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        reason := 'config_changed';                -- never concealed by an earlier eligibility reason
    END IF;
    fresh := voalack.encode_ack_request(att.effect_id);
    IF fresh IS DISTINCT FROM att.request_bytes OR encode(sha256(att.request_bytes), 'hex') <> att.request_sha256 THEN
        reason := coalesce(reason, 'request_changed');
    END IF;
    IF reason IS NULL AND NOT (clock_timestamp() < (SELECT p.execution_expires_at FROM voalack.prepared_intents p
                                                    WHERE p.action_id = att.action_id)) THEN
        reason := 'expired';
    END IF;
    IF reason IS NOT NULL THEN
        PERFORM voalack._release_no_dispatch(p_attempt, 'BLOCKED');
        RETURN QUERY SELECT ('aborted:' || reason)::text, NULL::bytea; RETURN;
    END IF;
    UPDATE voalack.attempts a SET state = 'dispatched', permit_state = 'consumed', dispatched_at = clock_timestamp()
     WHERE a.attempt_id = p_attempt;
    RETURN QUERY SELECT 'dispatched'::text, att.request_bytes;
END;
$$;

-- The final check before the transport write, after consume_dispatch is known committed, in the
-- original invocation: this attempt is dispatched under this owner, the owner is still active and
-- fenced, the configuration and request bytes are unchanged, eligibility still holds and the real
-- clock is before the original deadline. It never grants authority: on any failure the consumed
-- attempt is held uncertain by the caller (no abort, no release). NULL means proceed.
CREATE OR REPLACE FUNCTION voalack.check_dispatch(p_attempt uuid, p_instance text, p_generation bigint,
                                                  p_incarnation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
    reason text;
BEGIN
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    reason := voalack._dispatch_eligibility(att.effect_id);
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR SHARE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    IF att.state <> 'dispatched' OR att.permit_state <> 'consumed' THEN
        RETURN 'not_dispatched:' || att.state;
    END IF;
    IF voalack._recovered_protected(p_attempt) THEN
        RETURN 'recovered_hold';                                -- T04 S3c (R4): held by the caller
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';                   -- never concealed by an earlier eligibility reason
    END IF;
    IF voalack.encode_ack_request(att.effect_id) IS DISTINCT FROM att.request_bytes THEN
        RETURN coalesce(reason, 'request_changed');
    END IF;
    IF reason IS NULL AND NOT (clock_timestamp() < (SELECT p.execution_expires_at FROM voalack.prepared_intents p
                                                    WHERE p.action_id = att.action_id)) THEN
        RETURN 'expired';
    END IF;
    RETURN reason;
END;
$$;

-- Preflight found the exact target already acknowledged (explicit fake-contract state): the started
-- attempt with an unconsumed permit is closed without dispatch, the effect becomes ALREADY_ACKED (no
-- attribution claim), the guard is released; the observation is kept as evidence.
CREATE OR REPLACE FUNCTION voalack.close_already_acked(p_attempt uuid, p_instance text, p_generation bigint,
                                                       p_incarnation uuid, p_observation jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    IF att.state <> 'started' OR att.permit_state <> 'unconsumed' THEN
        RETURN 'not_closable:' || att.state;
    END IF;
    -- The observation was made with this owner's session: settle only while the locked current
    -- configuration still equals both the owner's and the attempt's snapshots.
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, 'preflight_already_acked', p_observation);
    PERFORM voalack._release_no_dispatch(p_attempt, 'ALREADY_ACKED');
    RETURN 'already_acked';
END;
$$;

-- S3a: the cooperative adapter positively observed a failed connect step before any ACK byte was
-- written (dedicated connection, no implicit reopen). Terminal for this attempt only; the effect
-- becomes retryable after a durable backoff, or BLOCKED once its attempt budget is used. SQL can
-- check only the digest and the zero-write claim; the remaining phase facts are the adapter's.
CREATE OR REPLACE FUNCTION voalack.record_not_sent(p_attempt uuid, p_instance text, p_generation bigint,
                                                   p_incarnation uuid, p_evidence jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    eff voalack.effects%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    SELECT * INTO eff FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';
    END IF;
    IF att.state <> 'dispatched' OR att.permit_state <> 'consumed' OR eff.in_flight_attempt IS DISTINCT FROM p_attempt
       OR NOT EXISTS (SELECT 1 FROM voalack.target_guards g WHERE g.attempt_id = p_attempt) THEN
        RETURN 'not_recordable:' || att.state;
    END IF;
    IF p_evidence->>'request_sha256' IS DISTINCT FROM att.request_sha256
       OR (p_evidence->>'ack_writes') IS DISTINCT FROM '0' THEN
        RETURN 'evidence_mismatch';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, 'not_sent', p_evidence);
    UPDATE voalack.attempts a SET state = 'not_sent', settled_at = clock_timestamp() WHERE a.attempt_id = p_attempt;
    DELETE FROM voalack.target_guards g WHERE g.attempt_id = p_attempt;
    UPDATE voalack.effects e
       SET in_flight_attempt = NULL,
           state = CASE WHEN e.attempt_count >= 3 THEN 'BLOCKED' ELSE 'QUEUED' END,
           next_attempt_after = clock_timestamp() + make_interval(secs => power(2, greatest(e.attempt_count - 1, 0))),
           retry_owner_generation = p_generation, retry_incarnation = p_incarnation
     WHERE e.effect_id = att.effect_id;
    RETURN 'not_sent';
END;
$$;

-- S3a: preflight found unsupported target metadata (not a single triggered alarm): the started
-- attempt with an unconsumed permit is closed without dispatch and the effect BLOCKED.
CREATE OR REPLACE FUNCTION voalack.close_unsupported_target(p_attempt uuid, p_instance text, p_generation bigint,
                                                            p_incarnation uuid, p_observation jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    IF att.state <> 'started' OR att.permit_state <> 'unconsumed' THEN
        RETURN 'not_closable:' || att.state;
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, 'preflight_unsupported_target', p_observation);
    PERFORM voalack._release_no_dispatch(p_attempt, 'BLOCKED');
    RETURN 'unsupported_target';
END;
$$;

CREATE OR REPLACE FUNCTION voalack.abort_attempt(p_attempt uuid, p_instance text, p_generation bigint,
                                                 p_incarnation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active', 'suspended']) THEN
        RETURN 'owner_fenced';
    END IF;
    IF att.state <> 'started' OR att.permit_state <> 'unconsumed' THEN
        RETURN 'not_abortable:' || att.state;
    END IF;
    PERFORM voalack._release_no_dispatch(p_attempt, 'QUEUED');
    RETURN 'aborted';
END;
$$;

CREATE OR REPLACE FUNCTION voalack.hold_attempt(p_attempt uuid, p_instance text, p_generation bigint,
                                                p_incarnation uuid, p_reason text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance) THEN
        RETURN 'owner_fenced';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, 'hold', jsonb_build_object('reason', p_reason));
    IF att.state NOT IN ('started', 'dispatched') THEN
        RETURN 'unchanged:' || att.state;
    END IF;
    PERFORM voalack._hold_uncertain(p_attempt);
    RETURN 'uncertain';
END;
$$;

-- Settlement in S2: 'confirmed' only for attributable fake-contract evidence matching this
-- attempt (operation id = request digest, read-back of the same target and comment); anything
-- else after dispatch is held uncertain. Never downgrades a settled attempt.
CREATE OR REPLACE FUNCTION voalack.record_result(p_attempt uuid, p_instance text, p_generation bigint,
                                                 p_incarnation uuid, p_observation jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
    req jsonb;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN 'no_attempt';
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    IF (att.owner_generation, att.incarnation, att.instance_id) IS DISTINCT FROM (p_generation, p_incarnation, p_instance)
       OR NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    -- Settlement under the configuration the attempt was made with: after the locks (and any wait),
    -- the current configuration must equal both the attempt's and the owner's acquired snapshots.
    -- Otherwise the observation is kept as late evidence, a dispatched attempt is held uncertain
    -- with its guard, and the caller stops the whole owner.
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.provider_contract, ic.config_revision)
       IS DISTINCT FROM (att.credential_ref, att.provider_contract, att.config_revision)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
        VALUES (p_attempt, p_generation, p_incarnation, 'late_result', p_observation);
        IF att.state = 'dispatched' THEN
            PERFORM voalack._hold_uncertain(p_attempt);
        END IF;
        RETURN 'config_changed';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, 'result', p_observation);
    IF att.state <> 'dispatched' THEN
        RETURN 'unchanged:' || att.state;
    END IF;
    req := convert_from(att.request_bytes, 'UTF8')::jsonb;
    IF p_observation->>'kind' = 'fake_ack'
       AND p_observation->>'status' = '200' AND p_observation->>'read_status' = '200'
       AND p_observation->'response'->>'operation_id' = att.request_sha256
       AND p_observation->'response'->>'result' = 'acked'
       AND p_observation->'response'->>'target_id' = att.target_id
       AND p_observation->'read_back'->>'target_id' = att.target_id
       AND p_observation->'read_back'->>'acked_by_operation' = att.request_sha256
       AND p_observation->'read_back'->>'comment' = req->>'comment' THEN
        UPDATE voalack.attempts a SET state = 'confirmed', settled_at = clock_timestamp() WHERE a.attempt_id = p_attempt;
        DELETE FROM voalack.target_guards g WHERE g.attempt_id = p_attempt;
        UPDATE voalack.effects e SET state = 'REMOTE_CONFIRMED', in_flight_attempt = NULL
         WHERE e.in_flight_attempt = p_attempt;
        RETURN 'confirmed';
    END IF;
    PERFORM voalack._hold_uncertain(p_attempt);
    RETURN 'uncertain';
END;
$$;

-- Late or out-of-band evidence under the attempt's original generation and incarnation, whether or
-- not that owner is still current. Append-only; never changes any state.
CREATE OR REPLACE FUNCTION voalack.record_evidence(p_attempt uuid, p_generation bigint, p_incarnation uuid,
                                                   p_kind text, p_detail jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    PERFORM 1 FROM voalack.attempts a
     WHERE a.attempt_id = p_attempt AND a.owner_generation = p_generation AND a.incarnation = p_incarnation;
    IF NOT FOUND THEN
        RETURN 'no_matching_attempt';
    END IF;
    INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
    VALUES (p_attempt, p_generation, p_incarnation, p_kind, p_detail);
    RETURN 'recorded';
END;
$$;

-- A new owner (after containment) settles what earlier generations left: started attempts with an
-- unconsumed permit can never be consumed now (their owner is fenced), so they are aborted;
-- dispatched ones become uncertain. Uncertain guards stay.
CREATE OR REPLACE FUNCTION voalack.release_stale_started(p_instance text, p_generation bigint, p_incarnation uuid)
RETURNS TABLE (attempt_id uuid, outcome text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att record;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    IF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RAISE EXCEPTION 'voalack: owner fenced';
    END IF;
    -- T04 S4 (D5): every effect and attempt this call can change is locked before the first outcome
    -- event, then their projection rows in action order; the loop below keeps its order.
    PERFORM 1 FROM voalack.effects e
     WHERE e.effect_id IN (SELECT a.effect_id FROM voalack.attempts a
                            WHERE a.instance_id = p_instance AND a.owner_generation < p_generation
                              AND a.state IN ('started', 'dispatched'))
     ORDER BY e.effect_id FOR UPDATE;
    PERFORM 1 FROM voalack.attempts a
     WHERE a.instance_id = p_instance AND a.owner_generation < p_generation AND a.state IN ('started', 'dispatched')
     ORDER BY a.attempt_id FOR UPDATE;
    PERFORM voalack._lock_projection_actions(ARRAY(
        SELECT a.action_id FROM voalack.attempts a
         WHERE a.instance_id = p_instance AND a.owner_generation < p_generation AND a.state IN ('started', 'dispatched')));
    FOR att IN SELECT a.attempt_id AS id, a.effect_id, a.state FROM voalack.attempts a
                WHERE a.instance_id = p_instance AND a.owner_generation < p_generation
                  AND a.state IN ('started', 'dispatched') ORDER BY a.started_at LOOP
        PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
        PERFORM 1 FROM voalack.attempts a WHERE a.attempt_id = att.id FOR UPDATE;
        -- T04 S3c (R4): restored work under recovery protection may have progressed further than its
        -- row shows: it is held, never freed or requeued.
        IF voalack._recovered_protected(att.id) THEN
            PERFORM voalack._hold_uncertain(att.id);
            RETURN QUERY SELECT att.id, 'held_recovered'::text;
        ELSIF att.state = 'started' THEN
            PERFORM voalack._release_no_dispatch(att.id, 'QUEUED');
            RETURN QUERY SELECT att.id, 'aborted_before_dispatch'::text;
        ELSE
            PERFORM voalack._hold_uncertain(att.id);
            RETURN QUERY SELECT att.id, 'uncertain'::text;
        END IF;
    END LOOP;
END;
$$;

-- T04 S3b: read-only reconciliation of uncertain attempts and guarded settlement (design e738794b
-- A3/A4/A7 with refinements B1-B6 of c193a789). An uncertain attempt row stays 'uncertain' (its
-- transport classification); a resolution is one append-only settlement that references it. Only a
-- settlement releases the attempt's own uncertain guard, and no settlement makes an effect QUEUED
-- again (a resend needs a new captured, signed human action through the full path).

-- Every provider session an owner incarnation opened, by digest (never the token), registered
-- before the session is used for any read or ACK. Quiescence must cover all of a holder's sessions.
CREATE TABLE IF NOT EXISTS voalack.provider_sessions (
    session_ref      text PRIMARY KEY CHECK (session_ref ~ '^[0-9a-f]{64}$'),
    instance_id      text NOT NULL REFERENCES voalack.instance_config (instance_id),
    owner_generation bigint NOT NULL,
    incarnation      uuid NOT NULL,
    credential_ref   text NOT NULL,
    opened_at        timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS provider_sessions_immutable ON voalack.provider_sessions;
CREATE TRIGGER provider_sessions_immutable BEFORE UPDATE OR DELETE ON voalack.provider_sessions
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

CREATE TABLE IF NOT EXISTS voalack.reconciliation_reads (
    read_id              uuid PRIMARY KEY,
    attempt_id           uuid NOT NULL REFERENCES voalack.attempts (attempt_id),
    effect_id            bigint NOT NULL,
    action_id            uuid NOT NULL,
    request_sha256       text NOT NULL,
    instance_id          text NOT NULL,
    target_kind          text NOT NULL,
    target_id            text NOT NULL,
    original_generation  bigint NOT NULL,
    original_incarnation uuid NOT NULL,
    reader_generation    bigint NOT NULL,
    reader_incarnation   uuid NOT NULL,
    credential_ref       text NOT NULL,
    config_revision      integer NOT NULL,
    provider_contract    text NOT NULL,
    reserved_at          timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS reconciliation_reads_immutable ON voalack.reconciliation_reads;
CREATE TRIGGER reconciliation_reads_immutable BEFORE UPDATE OR DELETE ON voalack.reconciliation_reads
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

CREATE TABLE IF NOT EXISTS voalack.reconciliations (
    reconciliation_id    bigserial PRIMARY KEY,
    read_id              uuid NOT NULL UNIQUE REFERENCES voalack.reconciliation_reads (read_id),
    attempt_id           uuid NOT NULL REFERENCES voalack.attempts (attempt_id),
    effect_id            bigint NOT NULL,
    action_id            uuid NOT NULL,
    request_sha256       text NOT NULL,
    instance_id          text NOT NULL,
    target_kind          text NOT NULL,
    target_id            text NOT NULL,
    original_generation  bigint NOT NULL,
    original_incarnation uuid NOT NULL,
    reader_generation    bigint NOT NULL,
    reader_incarnation   uuid NOT NULL,
    credential_ref       text NOT NULL,
    config_revision      integer NOT NULL,
    provider_contract    text NOT NULL,
    reserved_at          timestamptz NOT NULL,
    read_started_at      timestamptz,            -- adapter-attested provider read timing
    read_completed_at    timestamptz,
    recorded_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    classification       text NOT NULL CHECK (classification IN ('attributable', 'acked_by_other',
                                                                 'acked_unattributed', 'not_acked', 'evidence_only')),
    observation          jsonb NOT NULL CHECK (octet_length(observation::text) <= 16384)
);
DROP TRIGGER IF EXISTS reconciliations_immutable ON voalack.reconciliations;
CREATE TRIGGER reconciliations_immutable BEFORE UPDATE OR DELETE ON voalack.reconciliations
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

-- Administrator-attested quiescence of one contained holder (instance, generation, incarnation):
-- its process exit, and for every provider session it registered, a successful revocation and then
-- a successful exact-session executing = 0 observation. SQL checks presence, coverage, binding and
-- ordering; the administrator is trusted for the facts.
CREATE TABLE IF NOT EXISTS voalack.quiescence (
    quiescence_id    bigserial PRIMARY KEY,
    containment_id   bigint NOT NULL REFERENCES voalack.owner_containment (containment_id),
    instance_id      text NOT NULL,
    owner_generation bigint NOT NULL,
    incarnation      uuid NOT NULL,
    session_refs     text[] NOT NULL,
    evidence         jsonb NOT NULL CHECK (octet_length(evidence::text) <= 16384),
    recorded_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (instance_id, owner_generation, incarnation)
);
DROP TRIGGER IF EXISTS quiescence_immutable ON voalack.quiescence;
CREATE TRIGGER quiescence_immutable BEFORE UPDATE OR DELETE ON voalack.quiescence
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

CREATE TABLE IF NOT EXISTS voalack.settlements (
    settlement_id            bigserial PRIMARY KEY,
    decision_id              uuid NOT NULL UNIQUE,
    decision_input_sha256    text NOT NULL CHECK (decision_input_sha256 ~ '^[0-9a-f]{64}$'),
    attempt_id               uuid NOT NULL UNIQUE REFERENCES voalack.attempts (attempt_id),
    effect_id                bigint NOT NULL REFERENCES voalack.effects (effect_id),
    action_id                uuid NOT NULL,
    request_sha256           text NOT NULL,
    instance_id              text NOT NULL,
    target_kind              text NOT NULL,
    target_id                text NOT NULL,
    original_generation      bigint NOT NULL,
    original_incarnation     uuid NOT NULL,
    outcome                  text NOT NULL CHECK (outcome IN ('confirmed_attributed', 'confirmed_by_operator',
                                                              'superseded_remote', 'retired_after_quiescence')),
    path                     text NOT NULL CHECK (path IN ('automatic', 'operator')),
    reconciliation_id        bigint NOT NULL REFERENCES voalack.reconciliations (reconciliation_id),
    reader_generation        bigint NOT NULL,
    reader_incarnation       uuid NOT NULL,
    reader_credential_ref    text NOT NULL,
    reader_config_revision   integer NOT NULL,
    reader_provider_contract text NOT NULL,
    holders                  jsonb NOT NULL,
    quiescence_ids           bigint[] NOT NULL,
    prior_effect_state       text NOT NULL,
    prior_in_flight_attempt  uuid NOT NULL,
    prior_guard_state        text NOT NULL,
    effect_state             text NOT NULL,
    decided_by               text NOT NULL,
    decided_at               timestamptz NOT NULL DEFAULT clock_timestamp(),
    note                     text NOT NULL CHECK (octet_length(note) <= 1024)
);
DROP TRIGGER IF EXISTS settlements_immutable ON voalack.settlements;
CREATE TRIGGER settlements_immutable BEFORE UPDATE OR DELETE ON voalack.settlements
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

-- Register a session the fenced active owner just opened, before any use of it.
CREATE OR REPLACE FUNCTION voalack.register_session(p_session_ref text, p_instance text, p_generation bigint,
                                                    p_incarnation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    owner voalack.session_owners%ROWTYPE;
    ps voalack.provider_sessions%ROWTYPE;
BEGIN
    SELECT * INTO owner FROM voalack.session_owners o WHERE o.instance_id = p_instance FOR SHARE;
    IF NOT FOUND OR (owner.owner_generation, owner.incarnation, owner.state)
                    IS DISTINCT FROM (p_generation, p_incarnation, 'active') THEN
        RETURN 'owner_fenced';
    END IF;
    -- T04 S3c: the owner's epoch and anchor line are those of the database's phase for its mode.
    IF NOT voalack._epoch_pin(owner.acquired_epoch, owner.acquired_head_sha256, owner.mode) THEN
        RETURN 'epoch_changed';
    END IF;
    IF p_session_ref IS NULL OR p_session_ref !~ '^[0-9a-f]{64}$' THEN
        RETURN 'bad_session_ref';
    END IF;
    SELECT * INTO ps FROM voalack.provider_sessions s WHERE s.session_ref = p_session_ref;
    IF FOUND THEN
        RETURN CASE WHEN (ps.instance_id, ps.owner_generation, ps.incarnation) = (p_instance, p_generation, p_incarnation)
                    THEN 'registered' ELSE 'session_conflict' END;
    END IF;
    INSERT INTO voalack.provider_sessions (session_ref, instance_id, owner_generation, incarnation, credential_ref)
    VALUES (p_session_ref, p_instance, p_generation, p_incarnation, owner.bound_credential_ref);
    RETURN 'registered';
END;
$$;

-- Holders of a physical key: every (generation, incarnation) with an attempt on it that may still
-- be issuing or executing: started, dispatched, or uncertain without a settlement.
CREATE OR REPLACE FUNCTION voalack._target_holders(p_instance text, p_kind text, p_target text)
RETURNS TABLE (owner_generation bigint, incarnation uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT DISTINCT a.owner_generation, a.incarnation FROM voalack.attempts a
     WHERE a.instance_id = p_instance AND a.target_kind = p_kind AND a.target_id = p_target
       AND (a.state IN ('started', 'dispatched')
            OR (a.state = 'uncertain'
                AND NOT EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = a.attempt_id)))
     ORDER BY 1, 2
$$;

-- Effect, attempt and the attempt's physical guard, in the S2 order. Returns the attempt row.
CREATE OR REPLACE FUNCTION voalack._lock_attempt(p_attempt uuid) RETURNS voalack.attempts
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
BEGIN
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt FOR UPDATE;
    PERFORM 1 FROM voalack.target_guards tg
     WHERE (tg.instance_id, tg.target_kind, tg.target_id) = (att.instance_id, att.target_kind, att.target_id)
       FOR UPDATE;
    RETURN att;
END;
$$;

-- The reader is the current fenced active owner and the configuration equals both its acquired
-- snapshot and the given read snapshot (owner row FOR SHARE, configuration FOR SHARE, after waits).
CREATE OR REPLACE FUNCTION voalack._reader_current(p_instance text, p_generation bigint, p_incarnation uuid,
                                                   p_credential text, p_revision integer, p_contract text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    ic voalack.instance_config%ROWTYPE;
BEGIN
    IF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RETURN 'owner_fenced';
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.config_revision, ic.provider_contract)
       IS DISTINCT FROM (p_credential, p_revision, p_contract)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';
    END IF;
    RETURN NULL;
END;
$$;

-- Reserve one read of the original physical target by the current fenced owner, freezing the
-- original identities from the attempt row (never a binding, occurrence or capture). A known
-- reservation is never handed out again: a replayed read id grants no read.
CREATE OR REPLACE FUNCTION voalack.begin_reconciliation(p_read uuid, p_attempt uuid, p_instance text,
                                                        p_generation bigint, p_incarnation uuid)
RETURNS TABLE (outcome text, r_target_kind text, r_target_id text, r_request_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    g voalack.target_guards%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
    refusal text;
BEGIN
    att := voalack._lock_attempt(p_attempt);
    IF att.attempt_id IS NULL THEN
        RETURN QUERY SELECT 'no_attempt'::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.reconciliation_reads r WHERE r.read_id = p_read) THEN
        RETURN QUERY SELECT 'already_reserved'::text, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    SELECT * INTO g FROM voalack.target_guards tg
     WHERE (tg.instance_id, tg.target_kind, tg.target_id) = (att.instance_id, att.target_kind, att.target_id);
    IF att.instance_id <> p_instance THEN
        refusal := 'wrong_instance';                     -- not this owner's attempt; no fence implied
    ELSIF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        refusal := 'owner_fenced';
    ELSIF att.state <> 'uncertain'
          OR EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = p_attempt) THEN
        refusal := 'not_uncertain';
    ELSIF g.attempt_id IS DISTINCT FROM p_attempt OR g.state IS DISTINCT FROM 'uncertain' THEN
        refusal := 'guard_mismatch';
    ELSE
        SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
        IF NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                             ic.config_revision, ic.provider_contract) THEN
            refusal := 'config_changed';
        ELSIF EXISTS (SELECT 1 FROM voalack._target_holders(att.instance_id, att.target_kind, att.target_id) h
                       WHERE (h.owner_generation, h.incarnation) IS DISTINCT FROM (p_generation, p_incarnation)
                         AND NOT EXISTS (SELECT 1 FROM voalack.owner_containment oc
                                          WHERE (oc.instance_id, oc.owner_generation, oc.incarnation)
                                                = (att.instance_id, h.owner_generation, h.incarnation))) THEN
            refusal := 'holder_not_contained';
        END IF;
    END IF;
    IF refusal IS NOT NULL THEN
        RETURN QUERY SELECT refusal, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    INSERT INTO voalack.reconciliation_reads (read_id, attempt_id, effect_id, action_id, request_sha256, instance_id,
                                              target_kind, target_id, original_generation, original_incarnation,
                                              reader_generation, reader_incarnation, credential_ref,
                                              config_revision, provider_contract)
    VALUES (p_read, p_attempt, att.effect_id, att.action_id, att.request_sha256, att.instance_id, att.target_kind,
            att.target_id, att.owner_generation, att.incarnation, p_generation, p_incarnation, ic.credential_ref,
            ic.config_revision, ic.provider_contract);
    RETURN QUERY SELECT 'reserved'::text, att.target_kind, att.target_id, att.request_sha256;
END;
$$;

-- Strict classification of one read of the original target under the frozen fake contract.
CREATE OR REPLACE FUNCTION voalack._classify(p_attempt uuid, p_observation jsonb, p_reserved_at timestamptz)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    req jsonb;
    al jsonb := p_observation->'alarm';
    op jsonb;
    started timestamptz;
BEGIN
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = p_attempt;
    req := convert_from(att.request_bytes, 'UTF8')::jsonb;
    BEGIN
        started := (p_observation->>'read_started_at')::timestamptz;
    EXCEPTION WHEN others THEN
        RETURN 'evidence_only';
    END;
    -- Common prerequisites: a complete successful response for exactly the original target and
    -- kind, read after the reservation, with a boolean acked flag.
    IF started IS NULL OR started < p_reserved_at
       OR jsonb_typeof(p_observation->'status') IS DISTINCT FROM 'number' OR p_observation->'status' <> '200'::jsonb
       OR jsonb_typeof(al) IS DISTINCT FROM 'object'
       OR jsonb_typeof(al->'target_id') IS DISTINCT FROM 'string' OR al->>'target_id' <> att.target_id
       OR jsonb_typeof(al->'kind') IS DISTINCT FROM 'string' OR al->>'kind' <> att.target_kind
       OR al ? 'children' OR jsonb_typeof(al->'acked') IS DISTINCT FROM 'boolean' THEN
        RETURN 'evidence_only';
    END IF;
    op := al->'acked_by_operation';
    IF NOT (al->>'acked')::boolean THEN
        RETURN CASE WHEN op IS NULL OR op = 'null'::jsonb THEN 'not_acked' ELSE 'evidence_only' END;
    END IF;
    IF op IS NULL OR op = 'null'::jsonb THEN
        RETURN CASE WHEN jsonb_typeof(al->'comment') = 'string' AND al->>'comment' = req->>'comment'
                    THEN 'acked_unattributed' ELSE 'evidence_only' END;
    END IF;
    IF jsonb_typeof(op) IS DISTINCT FROM 'string' OR op #>> '{}' !~ '^[0-9a-f]{64}$' THEN
        RETURN 'evidence_only';                          -- malformed operation identity
    END IF;
    IF op #>> '{}' <> att.request_sha256 THEN
        RETURN 'acked_by_other';
    END IF;
    -- Our operation: attribution needs the exact original comment and the fake contract's
    -- positive completed-operation marker (published atomically with the effect).
    IF jsonb_typeof(al->'comment') = 'string' AND al->>'comment' = req->>'comment'
       AND al->'operation_status' = '"completed"'::jsonb THEN
        RETURN 'attributable';
    END IF;
    RETURN 'evidence_only';
END;
$$;

-- Record the read under the original identities and the reader's, after re-checking (after any
-- wait) the reader's fence and configuration. Otherwise, and for a conflicting duplicate, the
-- observation is kept as evidence only and the first record is never changed.
CREATE OR REPLACE FUNCTION voalack.record_reconciliation(p_read uuid, p_instance text, p_generation bigint,
                                                         p_incarnation uuid, p_observation jsonb)
RETURNS TABLE (outcome text, r_reconciliation_id bigint, r_classification text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    rr voalack.reconciliation_reads%ROWTYPE;
    att voalack.attempts%ROWTYPE;
    rec voalack.reconciliations%ROWTYPE;
    refusal text;
    cls text;
    rid bigint;
    started timestamptz;
    completed timestamptz;
BEGIN
    SELECT * INTO rr FROM voalack.reconciliation_reads r WHERE r.read_id = p_read;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_reservation'::text, NULL::bigint, NULL::text;
        RETURN;
    END IF;
    IF (rr.instance_id, rr.reader_generation, rr.reader_incarnation)
       IS DISTINCT FROM (p_instance, p_generation, p_incarnation) THEN
        RETURN QUERY SELECT 'not_reader'::text, NULL::bigint, NULL::text;
        RETURN;
    END IF;
    IF p_observation IS NULL OR octet_length(p_observation::text) > 16384 THEN
        RETURN QUERY SELECT 'bad_observation'::text, NULL::bigint, NULL::text;
        RETURN;
    END IF;
    att := voalack._lock_attempt(rr.attempt_id);
    PERFORM 1 FROM voalack.reconciliation_reads r WHERE r.read_id = p_read FOR UPDATE;
    SELECT * INTO rec FROM voalack.reconciliations x WHERE x.read_id = p_read;
    IF FOUND THEN
        IF rec.observation = p_observation THEN
            RETURN QUERY SELECT 'recorded'::text, rec.reconciliation_id, rec.classification;
        ELSE
            INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
            VALUES (att.attempt_id, p_generation, p_incarnation, 'conflicting_reconciliation',
                    jsonb_build_object('read_id', p_read, 'observation', p_observation));
            RETURN QUERY SELECT 'already_recorded'::text, rec.reconciliation_id, rec.classification;
        END IF;
        RETURN;
    END IF;
    refusal := voalack._reader_current(p_instance, p_generation, p_incarnation, rr.credential_ref,
                                       rr.config_revision, rr.provider_contract);
    IF refusal IS NOT NULL THEN
        INSERT INTO voalack.attempt_evidence (attempt_id, owner_generation, incarnation, kind, detail)
        VALUES (att.attempt_id, p_generation, p_incarnation, 'late_reconciliation',
                jsonb_build_object('read_id', p_read, 'reason', refusal, 'observation', p_observation));
        RETURN QUERY SELECT refusal, NULL::bigint, NULL::text;
        RETURN;
    END IF;
    cls := voalack._classify(att.attempt_id, p_observation, rr.reserved_at);
    BEGIN
        started := (p_observation->>'read_started_at')::timestamptz;
        completed := (p_observation->>'read_completed_at')::timestamptz;
    EXCEPTION WHEN others THEN
        started := NULL;
        completed := NULL;
    END;
    INSERT INTO voalack.reconciliations (read_id, attempt_id, effect_id, action_id, request_sha256, instance_id,
                                         target_kind, target_id, original_generation, original_incarnation,
                                         reader_generation, reader_incarnation, credential_ref, config_revision,
                                         provider_contract, reserved_at, read_started_at, read_completed_at,
                                         classification, observation)
    VALUES (p_read, rr.attempt_id, rr.effect_id, rr.action_id, rr.request_sha256, rr.instance_id, rr.target_kind,
            rr.target_id, rr.original_generation, rr.original_incarnation, rr.reader_generation,
            rr.reader_incarnation, rr.credential_ref, rr.config_revision, rr.provider_contract, rr.reserved_at,
            started, completed, cls, p_observation)
    RETURNING reconciliation_id INTO rid;
    RETURN QUERY SELECT 'recorded'::text, rid, cls;
END;
$$;

-- The one settlement transition; callers hold the effect, attempt and guard locks and have checked
-- the evidence, reader and coverage. Releases only the settled attempt's own uncertain guard.
CREATE OR REPLACE FUNCTION voalack._settle(p_decision uuid, p_input text, p_reconciliation bigint, p_outcome text,
                                           p_effect_state text, p_path text, p_holders jsonb,
                                           p_quiescence bigint[], p_note text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    rec voalack.reconciliations%ROWTYPE;
    att voalack.attempts%ROWTYPE;
    eff voalack.effects%ROWTYPE;
    g voalack.target_guards%ROWTYPE;
BEGIN
    SELECT * INTO rec FROM voalack.reconciliations x WHERE x.reconciliation_id = p_reconciliation;
    SELECT * INTO att FROM voalack.attempts a WHERE a.attempt_id = rec.attempt_id;
    IF EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = att.attempt_id) THEN
        RETURN 'conflict';
    END IF;
    IF att.state <> 'uncertain' THEN
        RETURN 'not_uncertain';
    END IF;
    SELECT * INTO eff FROM voalack.effects e WHERE e.effect_id = att.effect_id;
    IF eff.state <> 'UNCERTAIN' OR eff.in_flight_attempt IS DISTINCT FROM att.attempt_id THEN
        RETURN 'effect_mismatch';
    END IF;
    SELECT * INTO g FROM voalack.target_guards tg
     WHERE (tg.instance_id, tg.target_kind, tg.target_id) = (att.instance_id, att.target_kind, att.target_id);
    IF g.attempt_id IS DISTINCT FROM att.attempt_id OR g.state IS DISTINCT FROM 'uncertain' THEN
        RETURN 'guard_mismatch';
    END IF;
    INSERT INTO voalack.settlements (decision_id, decision_input_sha256, attempt_id, effect_id, action_id,
                                     request_sha256, instance_id, target_kind, target_id, original_generation,
                                     original_incarnation, outcome, path, reconciliation_id, reader_generation,
                                     reader_incarnation, reader_credential_ref, reader_config_revision,
                                     reader_provider_contract, holders, quiescence_ids, prior_effect_state,
                                     prior_in_flight_attempt, prior_guard_state, effect_state, decided_by, note)
    VALUES (p_decision, p_input, att.attempt_id, att.effect_id, att.action_id, att.request_sha256, att.instance_id,
            att.target_kind, att.target_id, att.owner_generation, att.incarnation, p_outcome, p_path,
            p_reconciliation, rec.reader_generation, rec.reader_incarnation, rec.credential_ref,
            rec.config_revision, rec.provider_contract, p_holders, p_quiescence, eff.state, eff.in_flight_attempt,
            g.state, p_effect_state, session_user, p_note);
    DELETE FROM voalack.target_guards tg WHERE tg.attempt_id = att.attempt_id AND tg.state = 'uncertain';
    UPDATE voalack.effects e SET state = p_effect_state, in_flight_attempt = NULL
     WHERE e.effect_id = att.effect_id AND e.in_flight_attempt = att.attempt_id;
    RETURN 'settled';
END;
$$;

-- One normalized semantic input per decision: identical input → the stored result; any other use
-- of the decision id → decision_conflict.
CREATE OR REPLACE FUNCTION voalack._decision_input(p_attempt uuid, p_outcome text, p_reconciliation bigint,
                                                   p_path text, p_note text) RETURNS text
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT encode(sha256(convert_to(jsonb_build_object('attempt_id', p_attempt, 'outcome', p_outcome,
                                                       'reconciliation_id', p_reconciliation, 'path', p_path,
                                                       'note', coalesce(p_note, ''))::text, 'UTF8')), 'hex')
$$;

CREATE OR REPLACE FUNCTION voalack._decision_replay(p_decision uuid, p_input text) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT CASE WHEN s.decision_input_sha256 = p_input THEN 'already_settled' ELSE 'decision_conflict' END
      FROM voalack.settlements s WHERE s.decision_id = p_decision
$$;

-- Automatic settlement by the reader that recorded an attributable reconciliation.
CREATE OR REPLACE FUNCTION voalack.settle_by_reconciliation(p_decision uuid, p_reconciliation bigint,
                                                            p_instance text, p_generation bigint,
                                                            p_incarnation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    rec voalack.reconciliations%ROWTYPE;
    att voalack.attempts%ROWTYPE;
    input text;
    replay text;
    refusal text;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    SELECT * INTO rec FROM voalack.reconciliations x WHERE x.reconciliation_id = p_reconciliation;
    IF NOT FOUND THEN
        RETURN 'no_reconciliation';
    END IF;
    att := voalack._lock_attempt(rec.attempt_id);
    input := voalack._decision_input(rec.attempt_id, 'confirmed_attributed', p_reconciliation, 'automatic', '');
    replay := voalack._decision_replay(p_decision, input);
    IF replay IS NOT NULL THEN
        RETURN replay;
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = att.attempt_id) THEN
        RETURN 'conflict';                               -- another decision already settled it
    END IF;
    IF (rec.instance_id, rec.reader_generation, rec.reader_incarnation)
       IS DISTINCT FROM (p_instance, p_generation, p_incarnation) THEN
        RETURN 'not_reader';
    END IF;
    refusal := voalack._reader_current(p_instance, p_generation, p_incarnation, rec.credential_ref,
                                       rec.config_revision, rec.provider_contract);
    IF refusal IS NOT NULL THEN
        RETURN refusal;
    END IF;
    IF rec.classification <> 'attributable' THEN
        RETURN 'not_attributable';
    END IF;
    RETURN voalack._settle(p_decision, input, p_reconciliation, 'confirmed_attributed', 'REMOTE_CONFIRMED',
                           'automatic', '[]'::jsonb, '{}'::bigint[], '');
END;
$$;

-- Operator settlement (settler role only). Every path re-checks, after waits, that the evidence is
-- this attempt's and that its reader is still the current fenced owner with an unchanged
-- configuration. Every outcome except an attributed confirmation also needs: each holder of the
-- physical target no longer active or suspended, with registered sessions all covered by its
-- quiescence record, the reader not a holder, and the read reserved strictly after the latest of
-- those quiescence records.
CREATE OR REPLACE FUNCTION voalack.settle_uncertain(p_decision uuid, p_attempt uuid, p_outcome text,
                                                    p_reconciliation bigint, p_note text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    att voalack.attempts%ROWTYPE;
    rec voalack.reconciliations%ROWTYPE;
    h record;
    q voalack.quiescence%ROWTYPE;
    input text;
    replay text;
    refusal text;
    need text;
    new_state text;
    holders jsonb := '[]'::jsonb;
    qids bigint[] := '{}';
    latest timestamptz;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    need := CASE p_outcome WHEN 'confirmed_attributed' THEN 'attributable'
                           WHEN 'confirmed_by_operator' THEN 'acked_unattributed'
                           WHEN 'superseded_remote' THEN 'acked_by_other'
                           WHEN 'retired_after_quiescence' THEN 'not_acked' END;
    new_state := CASE p_outcome WHEN 'confirmed_attributed' THEN 'REMOTE_CONFIRMED'
                                WHEN 'retired_after_quiescence' THEN 'BLOCKED' ELSE 'ALREADY_ACKED' END;
    IF need IS NULL THEN
        RETURN 'bad_outcome';
    END IF;
    IF p_note IS NULL OR octet_length(p_note) > 1024 THEN
        RETURN 'bad_note';
    END IF;
    att := voalack._lock_attempt(p_attempt);
    IF att.attempt_id IS NULL THEN
        RETURN 'no_attempt';
    END IF;
    input := voalack._decision_input(p_attempt, p_outcome, p_reconciliation, 'operator', p_note);
    replay := voalack._decision_replay(p_decision, input);
    IF replay IS NOT NULL THEN
        RETURN replay;
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = att.attempt_id) THEN
        RETURN 'conflict';                               -- another decision already settled it
    END IF;
    SELECT * INTO rec FROM voalack.reconciliations x WHERE x.reconciliation_id = p_reconciliation FOR SHARE;
    IF NOT FOUND OR rec.attempt_id <> p_attempt
       OR (rec.instance_id, rec.target_kind, rec.target_id, rec.request_sha256, rec.original_generation,
           rec.original_incarnation)
          IS DISTINCT FROM (att.instance_id, att.target_kind, att.target_id, att.request_sha256,
                            att.owner_generation, att.incarnation) THEN
        RETURN 'wrong_reconciliation';
    END IF;
    refusal := voalack._reader_current(rec.instance_id, rec.reader_generation, rec.reader_incarnation,
                                       rec.credential_ref, rec.config_revision, rec.provider_contract);
    IF refusal IS NOT NULL THEN
        RETURN 'reader_' || refusal;
    END IF;
    IF rec.classification <> need THEN
        RETURN 'classification_mismatch';
    END IF;
    IF p_outcome <> 'confirmed_attributed' THEN
        FOR h IN SELECT * FROM voalack._target_holders(att.instance_id, att.target_kind, att.target_id) LOOP
            IF (rec.reader_generation, rec.reader_incarnation) = (h.owner_generation, h.incarnation) THEN
                RETURN 'reader_is_holder';
            END IF;
            IF EXISTS (SELECT 1 FROM voalack.session_owners o
                        WHERE (o.instance_id, o.owner_generation, o.incarnation)
                              = (att.instance_id, h.owner_generation, h.incarnation)
                          AND o.state IN ('active', 'suspended')) THEN
                RETURN 'holder_not_contained';
            END IF;
            SELECT * INTO q FROM voalack.quiescence x
             WHERE (x.instance_id, x.owner_generation, x.incarnation) = (att.instance_id, h.owner_generation, h.incarnation);
            IF NOT FOUND THEN
                RETURN 'holder_not_quiescent';
            END IF;
            IF NOT EXISTS (SELECT 1 FROM voalack.provider_sessions ps
                            WHERE (ps.instance_id, ps.owner_generation, ps.incarnation)
                                  = (att.instance_id, h.owner_generation, h.incarnation)) THEN
                RETURN 'holder_sessions_unknown';
            END IF;
            IF EXISTS (SELECT 1 FROM voalack.provider_sessions ps
                        WHERE (ps.instance_id, ps.owner_generation, ps.incarnation)
                              = (att.instance_id, h.owner_generation, h.incarnation)
                          AND NOT ps.session_ref = ANY(q.session_refs)) THEN
                RETURN 'quiescence_incomplete';
            END IF;
            holders := holders || jsonb_build_array(jsonb_build_object('generation', h.owner_generation,
                                                                       'incarnation', h.incarnation));
            qids := qids || q.quiescence_id;
            latest := greatest(latest, q.recorded_at);
        END LOOP;
        IF cardinality(qids) = 0 THEN
            RETURN 'holder_not_quiescent';
        END IF;
        IF NOT rec.reserved_at > latest THEN
            RETURN 'read_before_quiescence';
        END IF;
    END IF;
    RETURN voalack._settle(p_decision, input, p_reconciliation, p_outcome, new_state, 'operator', holders, qids,
                           p_note);
END;
$$;

-- Minimal audit result for one decision id (no request bytes, evidence or identities beyond these).
CREATE OR REPLACE FUNCTION voalack.settlement_status(p_decision uuid)
RETURNS TABLE (r_attempt_id uuid, r_outcome text, r_effect_state text, r_decided_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT s.attempt_id, s.outcome, s.effect_state, s.decided_at FROM voalack.settlements s
     WHERE s.decision_id = p_decision
$$;

-- Administrator only (no runtime grant). The evidence must cover every provider session the holder
-- registered: a successful revocation, then a successful exact-session executing = 0 observation.
CREATE OR REPLACE FUNCTION voalack.record_quiescence(p_instance text, p_generation bigint, p_incarnation uuid,
                                                     p_evidence jsonb) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    cid bigint;
    qid bigint;
    ps record;
    s jsonb;
    covered text[] := '{}';
BEGIN
    SELECT oc.containment_id INTO cid FROM voalack.owner_containment oc
     WHERE (oc.instance_id, oc.owner_generation, oc.incarnation) = (p_instance, p_generation, p_incarnation)
     ORDER BY oc.containment_id DESC LIMIT 1;
    IF cid IS NULL THEN
        RAISE EXCEPTION 'voalack: quiescence requires the holder''s containment record';
    END IF;
    IF p_evidence IS NULL OR octet_length(p_evidence::text) > 16384
       OR jsonb_typeof(p_evidence->'process') IS DISTINCT FROM 'object'
       OR coalesce(length(p_evidence->'process'->>'label'), 0) = 0
       OR coalesce(length(p_evidence->'process'->>'exit_observed_at'), 0) = 0
       OR jsonb_typeof(p_evidence->'sessions') IS DISTINCT FROM 'array'
       OR coalesce(length(p_evidence->>'basis'), 0) = 0 THEN
        RAISE EXCEPTION 'voalack: quiescence evidence must name the process exit, the sessions and a basis';
    END IF;
    FOR ps IN SELECT x.session_ref FROM voalack.provider_sessions x
               WHERE (x.instance_id, x.owner_generation, x.incarnation) = (p_instance, p_generation, p_incarnation) LOOP
        SELECT e INTO s FROM jsonb_array_elements(p_evidence->'sessions') e WHERE e->>'session_ref' = ps.session_ref
         LIMIT 1;
        IF s IS NULL
           OR s->'revoke'->'status' IS DISTINCT FROM '200'::jsonb
           OR s->'executing'->'status' IS DISTINCT FROM '200'::jsonb
           OR s->'executing'->'session_ref' IS DISTINCT FROM to_jsonb(ps.session_ref)
           OR s->'executing'->'scope' IS DISTINCT FROM '"session"'::jsonb
           OR jsonb_typeof(s->'executing'->'executing') IS DISTINCT FROM 'number'
           OR s->'executing'->'executing' <> '0'::jsonb
           OR NOT coalesce((s->'executing'->>'observed_at')::timestamptz
                           > (s->'revoke'->>'observed_at')::timestamptz, false) THEN
            RAISE EXCEPTION 'voalack: quiescence evidence must show, for every registered session, a successful revocation and then no executing request';
        END IF;
        covered := covered || ps.session_ref;
    END LOOP;
    INSERT INTO voalack.quiescence (containment_id, instance_id, owner_generation, incarnation, session_refs, evidence)
    VALUES (cid, p_instance, p_generation, p_incarnation, covered, p_evidence)
    RETURNING quiescence_id INTO qid;
    RETURN qid;
END;
$$;
ALTER TABLE voalack.provider_sessions OWNER TO voalack_admin;
ALTER TABLE voalack.reconciliation_reads OWNER TO voalack_admin;
ALTER TABLE voalack.reconciliations OWNER TO voalack_admin;
ALTER SEQUENCE voalack.reconciliations_reconciliation_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.quiescence OWNER TO voalack_admin;
ALTER SEQUENCE voalack.quiescence_quiescence_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.settlements OWNER TO voalack_admin;
ALTER SEQUENCE voalack.settlements_settlement_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack.register_session(text, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._target_holders(text, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._lock_attempt(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._reader_current(text, bigint, uuid, text, integer, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.begin_reconciliation(uuid, uuid, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._classify(uuid, jsonb, timestamptz) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_reconciliation(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._settle(uuid, text, bigint, text, text, text, jsonb, bigint[], text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._decision_input(uuid, text, bigint, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._decision_replay(uuid, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.settle_by_reconciliation(uuid, bigint, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.settlement_status(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_quiescence(text, bigint, uuid, jsonb) OWNER TO voalack_admin;

-- T04 S3c (M1): explicit bootstrap and the close barrier. Administrator only (granted to no runtime
-- role); never implicit at install, schema reapplication or acquisition. The supervisor writes the
-- anchor line first and passes its identity; SQL cannot read the anchor and trusts the supervisor
-- for it, but binds every later acquisition and gate to exactly that line.
CREATE OR REPLACE FUNCTION voalack.initialize_recovery(p_head_sha256 text, p_evidence jsonb) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
BEGIN
    LOCK TABLE voalack.recovery_epoch IN EXCLUSIVE MODE;
    SELECT * INTO r FROM voalack.recovery_epoch x;
    IF FOUND THEN
        IF (r.epoch, r.phase, r.head_seq, r.head_sha256) = (1::bigint, 'open', 1, p_head_sha256)
           AND NOT EXISTS (SELECT 1 FROM voalack.recovery_transitions t
                           WHERE t.detail->>'transition' IS DISTINCT FROM 'initialize') THEN
            RETURN 'already_initialized';
        END IF;
        RAISE EXCEPTION 'voalack: recovery epoch already initialized';
    END IF;
    IF p_head_sha256 IS NULL OR p_head_sha256 !~ '^[0-9a-f]{64}$'
       OR p_evidence IS NULL OR jsonb_typeof(p_evidence) IS DISTINCT FROM 'object'
       OR coalesce(length(p_evidence->>'basis'), 0) = 0 OR octet_length(p_evidence::text) > 16384 THEN
        RAISE EXCEPTION 'voalack: initialization needs the genesis line digest and evidence with a basis';
    END IF;
    INSERT INTO voalack.recovery_epoch (epoch, phase, head_seq, head_sha256) VALUES (1, 'open', 1, p_head_sha256);
    INSERT INTO voalack.recovery_transitions (epoch, phase, head_seq, head_sha256, detail, decided_by)
    VALUES (1, 'open', 1, p_head_sha256, jsonb_build_object('transition', 'initialize', 'evidence', p_evidence),
            session_user);
    RETURN 'initialized';
END;
$$;

-- open(e) -> closed(e), bound to the anchor's closed line (the next line after the open one). Every
-- gate refuses from this commit on. Re-running the same close returns 'already_closed'.
CREATE OR REPLACE FUNCTION voalack.close_recovery(p_epoch bigint, p_head_seq integer, p_head_sha256 text)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
BEGIN
    SELECT * INTO r FROM voalack.recovery_epoch x FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: recovery epoch is not initialized';
    END IF;
    IF (r.epoch, r.phase, r.head_seq, r.head_sha256) = (p_epoch, 'closed', p_head_seq, p_head_sha256) THEN
        RETURN 'already_closed';
    END IF;
    IF r.phase <> 'open' OR r.epoch <> p_epoch OR p_head_seq IS DISTINCT FROM r.head_seq + 1
       OR p_head_sha256 IS NULL OR p_head_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'voalack: close must follow the open line of the current epoch';
    END IF;
    UPDATE voalack.recovery_epoch x SET phase = 'closed', head_seq = p_head_seq, head_sha256 = p_head_sha256,
           changed_at = clock_timestamp();
    INSERT INTO voalack.recovery_transitions (epoch, phase, head_seq, head_sha256, detail, decided_by)
    VALUES (p_epoch, 'closed', p_head_seq, p_head_sha256, jsonb_build_object('transition', 'close'), session_user);
    RETURN 'closed';
END;
$$;
-- The live owner journal's facts for this owner's own attempts only (generation and incarnation
-- must match), including whether a settlement exists; never request bytes or other owners' rows.
CREATE OR REPLACE FUNCTION voalack.journal_facts(p_instance text, p_generation bigint, p_incarnation uuid,
                                                 p_attempts uuid[])
RETURNS TABLE (attempt_id text, state text, permit_state text, owner_generation bigint, incarnation text,
               effect_id bigint, action_id text, request_sha256 text, instance_id text, target_kind text, target_id text,
               credential_ref text, config_revision integer, provider_contract text, dispatched boolean,
               guard_attempt text, guard_state text, in_flight text, effect_state text, settled boolean,
               settlement_effect_state text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT a.attempt_id::text, a.state, a.permit_state, a.owner_generation, a.incarnation::text, a.effect_id,
           a.action_id::text, a.request_sha256, a.instance_id, a.target_kind, a.target_id, a.credential_ref,
           a.config_revision, a.provider_contract, a.dispatched_at IS NOT NULL,
           g.attempt_id::text, g.state, e.in_flight_attempt::text, e.state,
           st.attempt_id IS NOT NULL, st.effect_state
      FROM voalack.attempts a
      LEFT JOIN voalack.target_guards g
        ON (g.instance_id, g.target_kind, g.target_id) = (a.instance_id, a.target_kind, a.target_id)
      LEFT JOIN voalack.effects e ON e.effect_id = a.effect_id
      LEFT JOIN voalack.settlements st ON st.attempt_id = a.attempt_id
     WHERE a.attempt_id = ANY(p_attempts)
       AND (a.instance_id, a.owner_generation, a.incarnation) = (p_instance, p_generation, p_incarnation)
$$;
-- T04 S3c (M2): the inventory, adoption of a restored database, recovered holds, recovery reads and
-- hold settlement. Administrator functions are granted to no runtime role; recovery reads go to the
-- sender (maintenance or ordinary capability), hold settlement to the settler.
CREATE TABLE IF NOT EXISTS voalack.recovery_adoptions (
    adoption_id            bigint PRIMARY KEY,
    epoch                  bigint NOT NULL UNIQUE,
    head_seq               integer NOT NULL CHECK (head_seq >= 1),
    head_sha256            text NOT NULL CHECK (head_sha256 ~ '^[0-9a-f]{64}$'),
    input_sha256           text NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    inventory_sha256       text NOT NULL CHECK (inventory_sha256 ~ '^[0-9a-f]{64}$'),
    inventory_captured_at  timestamptz NOT NULL,
    backup_id              text NOT NULL CHECK (octet_length(backup_id) BETWEEN 1 AND 256),
    backup_sha256          text CHECK (backup_sha256 ~ '^[0-9a-f]{64}$'),
    review_sha256          text NOT NULL CHECK (review_sha256 ~ '^[0-9a-f]{64}$'),
    review_ref             text NOT NULL CHECK (octet_length(review_ref) BETWEEN 1 AND 256),
    contained_owners       integer NOT NULL,
    effect_holds           integer NOT NULL,
    key_holds              integer NOT NULL,
    prior_recovery         jsonb NOT NULL,             -- the inventory's recovery provenance (R2)
    adopted_by             text NOT NULL,
    adopted_at             timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE SEQUENCE IF NOT EXISTS voalack.recovery_adoptions_adoption_id_seq;
DROP TRIGGER IF EXISTS recovery_adoptions_immutable ON voalack.recovery_adoptions;
CREATE TRIGGER recovery_adoptions_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_adoptions
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
-- Supervisor cleanup in the closed phase (R1): a credential-wide revocation at the provider and an
-- observation that no session of the credential is live or executing, covering sessions Voalack never
-- registered (a login whose token arrived after the close). Administrator-attested.
CREATE TABLE IF NOT EXISTS voalack.recovery_cleanups (
    cleanup_id      bigserial PRIMARY KEY,
    epoch           bigint NOT NULL,
    instance_id     text NOT NULL,
    credential_ref  text NOT NULL,
    evidence        jsonb NOT NULL CHECK (octet_length(evidence::text) <= 16384),
    recorded_by     text NOT NULL,
    recorded_at     timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS recovery_cleanups_immutable ON voalack.recovery_cleanups;
CREATE TRIGGER recovery_cleanups_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_cleanups
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
-- Permanent: an effect key (or action) whose inventory and restored facts differ never sends again.
CREATE TABLE IF NOT EXISTS voalack.recovered_effects (
    effect_key       text PRIMARY KEY,
    action_id        uuid,
    adoption_id      bigint NOT NULL,
    inventory_facts  jsonb,
    restored_facts   jsonb,
    created_at       timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS recovered_effects_action ON voalack.recovered_effects (action_id);
DROP TRIGGER IF EXISTS recovered_effects_immutable ON voalack.recovered_effects;
CREATE TRIGGER recovered_effects_immutable BEFORE UPDATE OR DELETE ON voalack.recovered_effects
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
-- One per physical key per adoption: the complete set of inventory and restored attempts on the key
-- with their original identities, and the holders' inventory sessions and quiescence.
CREATE TABLE IF NOT EXISTS voalack.recovered_holds (
    hold_id                bigserial PRIMARY KEY,
    adoption_id            bigint NOT NULL,
    instance_id            text NOT NULL,
    target_kind            text NOT NULL,
    target_id              text NOT NULL,
    members                jsonb NOT NULL CHECK (jsonb_typeof(members) = 'array' AND jsonb_array_length(members) > 0),
    holders                jsonb NOT NULL CHECK (jsonb_typeof(holders) = 'array' AND jsonb_array_length(holders) > 0),
    inventory_captured_at  timestamptz NOT NULL,
    status                 text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'released')),
    created_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at            timestamptz,
    CHECK ((status = 'released') = (released_at IS NOT NULL)),
    UNIQUE (adoption_id, instance_id, target_kind, target_id)
);
CREATE INDEX IF NOT EXISTS recovered_holds_key ON voalack.recovered_holds (instance_id, target_kind, target_id)
    WHERE status = 'active';
-- A hold changes once, active -> released, and nothing else of it ever changes.
CREATE OR REPLACE FUNCTION voalack.recovered_hold_release_only() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.status <> 'active' OR NEW.status <> 'released' OR NEW.released_at IS NULL
       OR (NEW.hold_id, NEW.adoption_id, NEW.instance_id, NEW.target_kind, NEW.target_id, NEW.members, NEW.holders,
           NEW.inventory_captured_at, NEW.created_at)
          IS DISTINCT FROM (OLD.hold_id, OLD.adoption_id, OLD.instance_id, OLD.target_kind, OLD.target_id, OLD.members,
                            OLD.holders, OLD.inventory_captured_at, OLD.created_at) THEN
        RAISE EXCEPTION 'voalack: a recovered hold only changes from active to released';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS recovered_holds_release_only ON voalack.recovered_holds;
CREATE TRIGGER recovered_holds_release_only BEFORE UPDATE OR DELETE ON voalack.recovered_holds
    FOR EACH ROW EXECUTE FUNCTION voalack.recovered_hold_release_only();
CREATE TABLE IF NOT EXISTS voalack.recovery_reads (
    read_id             uuid PRIMARY KEY,
    hold_id             bigint NOT NULL REFERENCES voalack.recovered_holds (hold_id),
    instance_id         text NOT NULL,
    target_kind         text NOT NULL,
    target_id           text NOT NULL,
    reader_generation   bigint NOT NULL,
    reader_incarnation  uuid NOT NULL,
    reader_mode         text NOT NULL,
    epoch               bigint NOT NULL,
    head_sha256         text NOT NULL,
    credential_ref      text NOT NULL,
    config_revision     integer NOT NULL,
    provider_contract   text NOT NULL,
    reserved_at         timestamptz NOT NULL DEFAULT clock_timestamp()
);
DROP TRIGGER IF EXISTS recovery_reads_immutable ON voalack.recovery_reads;
CREATE TRIGGER recovery_reads_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_reads
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
CREATE TABLE IF NOT EXISTS voalack.recovery_reconciliations (
    recovery_reconciliation_id  bigserial PRIMARY KEY,
    read_id             uuid NOT NULL UNIQUE REFERENCES voalack.recovery_reads (read_id),
    hold_id             bigint NOT NULL,
    instance_id         text NOT NULL,
    target_kind         text NOT NULL,
    target_id           text NOT NULL,
    reader_generation   bigint NOT NULL,
    reader_incarnation  uuid NOT NULL,
    reader_mode         text NOT NULL,
    epoch               bigint NOT NULL,
    head_sha256         text NOT NULL,
    credential_ref      text NOT NULL,
    config_revision     integer NOT NULL,
    provider_contract   text NOT NULL,
    reserved_at         timestamptz NOT NULL,
    read_started_at     timestamptz,
    read_completed_at   timestamptz,
    recorded_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    classification      text NOT NULL CHECK (classification IN ('attributable', 'acked_by_other', 'acked_unattributed',
                                                                'not_acked', 'evidence_only')),
    matched_attempt     uuid,
    observation         jsonb NOT NULL CHECK (octet_length(observation::text) <= 16384)
);
DROP TRIGGER IF EXISTS recovery_reconciliations_immutable ON voalack.recovery_reconciliations;
CREATE TRIGGER recovery_reconciliations_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_reconciliations
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
CREATE TABLE IF NOT EXISTS voalack.recovery_settlements (
    recovery_settlement_id      bigserial PRIMARY KEY,
    decision_id                 uuid NOT NULL UNIQUE,
    decision_input_sha256       text NOT NULL CHECK (decision_input_sha256 ~ '^[0-9a-f]{64}$'),
    hold_id                     bigint NOT NULL UNIQUE REFERENCES voalack.recovered_holds (hold_id),
    outcome                     text NOT NULL CHECK (outcome IN ('recovered_attributed', 'recovered_acked_unattributed',
                                                                 'recovered_acked_by_other', 'recovered_retired')),
    recovery_reconciliation_id  bigint NOT NULL REFERENCES voalack.recovery_reconciliations (recovery_reconciliation_id),
    reader_generation           bigint NOT NULL,
    reader_incarnation          uuid NOT NULL,
    epoch                       bigint NOT NULL,
    head_sha256                 text NOT NULL,
    holders                     jsonb NOT NULL,
    released_guards             jsonb NOT NULL,
    blocked_effects             jsonb NOT NULL,
    decided_by                  text NOT NULL,
    decided_at                  timestamptz NOT NULL DEFAULT clock_timestamp(),
    note                        text NOT NULL CHECK (octet_length(note) <= 1024)
);
DROP TRIGGER IF EXISTS recovery_settlements_immutable ON voalack.recovery_settlements;
CREATE TRIGGER recovery_settlements_immutable BEFORE UPDATE OR DELETE ON voalack.recovery_settlements
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

-- The request comment of stored request bytes (NULL when the bytes are not a JSON request).
CREATE OR REPLACE FUNCTION voalack._request_comment(p_bytes bytea) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    RETURN convert_from(p_bytes, 'UTF8')::jsonb->>'comment';
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

-- An effect's delivery facts, compared by key between the inventory and a restored database (the
-- numeric effect id is not part of them: a re-promotion gets a new one).
CREATE OR REPLACE FUNCTION voalack._effect_facts(p_effect_id bigint) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT jsonb_build_object(
               'effect_key', e.effect_key, 'action_id', e.action_id, 'instance_id', e.instance_id,
               'target_id', e.target_id, 'state', e.state, 'in_flight_attempt', e.in_flight_attempt,
               'attempt_count', e.attempt_count, 'next_attempt_after', e.next_attempt_after,
               'retry_owner_generation', e.retry_owner_generation, 'retry_incarnation', e.retry_incarnation,
               'attempts', coalesce((SELECT jsonb_agg(jsonb_build_object(
                                                'attempt_id', a.attempt_id, 'state', a.state, 'permit_state', a.permit_state,
                                                'request_sha256', a.request_sha256, 'generation', a.owner_generation,
                                                'incarnation', a.incarnation, 'credential_ref', a.credential_ref,
                                                'config_revision', a.config_revision, 'provider_contract', a.provider_contract,
                                                'target_kind', a.target_kind, 'target_id', a.target_id,
                                                'dispatched', a.dispatched_at IS NOT NULL,
                                                'settlement', (SELECT jsonb_build_object('decision_id', st.decision_id,
                                                                                         'outcome', st.outcome,
                                                                                         'effect_state', st.effect_state)
                                                                 FROM voalack.settlements st WHERE st.attempt_id = a.attempt_id))
                                            ORDER BY a.attempt_id)
                                       FROM voalack.attempts a WHERE a.effect_id = e.effect_id), '[]'::jsonb))
      FROM voalack.effects e WHERE e.effect_id = p_effect_id
$$;

-- One attempt's original identities as a hold member (never its request bytes).
CREATE OR REPLACE FUNCTION voalack._attempt_member(p_attempt uuid, p_source text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT jsonb_build_object(
               'attempt_id', a.attempt_id, 'effect_id', a.effect_id, 'action_id', a.action_id,
               'effect_key', (SELECT e.effect_key FROM voalack.effects e WHERE e.effect_id = a.effect_id),
               'request_sha256', a.request_sha256, 'comment', voalack._request_comment(a.request_bytes),
               'generation', a.owner_generation, 'incarnation', a.incarnation, 'credential_ref', a.credential_ref,
               'config_revision', a.config_revision, 'provider_contract', a.provider_contract,
               'instance_id', a.instance_id, 'target_kind', a.target_kind, 'target_id', a.target_id,
               'state', a.state, 'permit_state', a.permit_state,
               'settled', EXISTS (SELECT 1 FROM voalack.settlements s WHERE s.attempt_id = a.attempt_id),
               'source', p_source)
      FROM voalack.attempts a WHERE a.attempt_id = p_attempt
$$;

-- Administrator only (closed phase): the supervisor's credential-wide cleanup evidence (R1).
CREATE OR REPLACE FUNCTION voalack.record_recovery_cleanup(p_instance text, p_credential_ref text, p_evidence jsonb)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
    cid bigint;
BEGIN
    SELECT * INTO r FROM voalack.recovery_epoch x FOR SHARE;
    IF NOT FOUND OR r.phase <> 'closed' THEN
        RAISE EXCEPTION 'voalack: cleanup is recorded in the closed phase';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM voalack.instance_config c WHERE c.instance_id = p_instance)
       OR coalesce(octet_length(p_credential_ref), 0) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'voalack: cleanup names a configured instance and a credential';
    END IF;
    IF p_evidence IS NULL OR octet_length(p_evidence::text) > 16384
       OR coalesce(length(p_evidence->>'basis'), 0) = 0
       OR p_evidence->'revoke'->'status' IS DISTINCT FROM '200'::jsonb
       OR p_evidence->'revoke'->'credential' IS DISTINCT FROM to_jsonb(p_credential_ref)
       OR p_evidence->'executing'->'status' IS DISTINCT FROM '200'::jsonb
       OR p_evidence->'executing'->'scope' IS DISTINCT FROM '"credential"'::jsonb
       OR p_evidence->'executing'->'credential' IS DISTINCT FROM to_jsonb(p_credential_ref)
       OR jsonb_typeof(p_evidence->'executing'->'live') IS DISTINCT FROM 'number'
       OR p_evidence->'executing'->'live' <> '0'::jsonb
       OR jsonb_typeof(p_evidence->'executing'->'executing') IS DISTINCT FROM 'number'
       OR p_evidence->'executing'->'executing' <> '0'::jsonb
       OR NOT coalesce((p_evidence->'executing'->>'observed_at')::timestamptz
                       > (p_evidence->'revoke'->>'observed_at')::timestamptz, false) THEN
        RAISE EXCEPTION 'voalack: cleanup evidence must show a credential-wide revocation, then no live or executing session';
    END IF;
    INSERT INTO voalack.recovery_cleanups (epoch, instance_id, credential_ref, evidence, recorded_by)
    VALUES (r.epoch, p_instance, p_credential_ref, p_evidence, session_user)
    RETURNING cleanup_id INTO cid;
    RETURN cid;
END;
$$;

-- True when recovery protects an attempt: its effect key or action is held, or an active recovered
-- hold covers its physical key. Such work is held, never freed, requeued, consumed or sent (R4).
CREATE OR REPLACE FUNCTION voalack._recovered_protected(p_attempt uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM voalack.attempts a JOIN voalack.effects e ON e.effect_id = a.effect_id
                    WHERE a.attempt_id = p_attempt
                      AND (EXISTS (SELECT 1 FROM voalack.recovered_effects r
                                    WHERE r.effect_key = e.effect_key OR r.action_id = e.action_id)
                           OR EXISTS (SELECT 1 FROM voalack.recovered_holds h
                                       WHERE (h.instance_id, h.target_kind, h.target_id)
                                             = (a.instance_id, a.target_kind, a.target_id)
                                         AND h.status = 'active')))
$$;

-- The complete delivery ledger in one snapshot (one statement), in the closed phase once every
-- owner is contained. Its digest is sha256 of this value's text rendering.
CREATE OR REPLACE FUNCTION voalack.recovery_inventory() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
    inv jsonb;
BEGIN
    SELECT * INTO r FROM voalack.recovery_epoch x FOR SHARE;
    IF NOT FOUND OR r.phase <> 'closed' THEN
        RAISE EXCEPTION 'voalack: the inventory requires the closed phase';
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.session_owners o WHERE o.state IN ('active', 'suspended')) THEN
        RAISE EXCEPTION 'voalack: the inventory requires every owner to be contained';
    END IF;
    -- One statement, one snapshot, taken after the containment barrier above (R6). Arrays are in a
    -- fixed order; the digest is sha256 of this value's text rendering.
    SELECT jsonb_build_object(
        'format', 'voalack-inventory/2', 'epoch', r.epoch, 'head_seq', r.head_seq, 'head_sha256', r.head_sha256,
        'captured_at', clock_timestamp(),
        'effects', coalesce((SELECT jsonb_agg(voalack._effect_facts(e.effect_id) ORDER BY e.effect_key)
                               FROM voalack.effects e), '[]'::jsonb),
        'attempts', coalesce((SELECT jsonb_agg(voalack._attempt_member(a.attempt_id, 'inventory') ORDER BY a.attempt_id)
                                FROM voalack.attempts a), '[]'::jsonb),
        'guards', coalesce((SELECT jsonb_agg(to_jsonb(g) ORDER BY g.instance_id, g.target_kind, g.target_id)
                              FROM voalack.target_guards g), '[]'::jsonb),
        'settlements', coalesce((SELECT jsonb_agg(jsonb_build_object('settlement_id', s.settlement_id,
                                                                     'decision_id', s.decision_id, 'attempt_id', s.attempt_id,
                                                                     'outcome', s.outcome, 'effect_state', s.effect_state)
                                                  ORDER BY s.settlement_id) FROM voalack.settlements s), '[]'::jsonb),
        'provider_sessions', coalesce((SELECT jsonb_agg(to_jsonb(ps) ORDER BY ps.session_ref)
                                         FROM voalack.provider_sessions ps), '[]'::jsonb),
        'containment', coalesce((SELECT jsonb_agg(jsonb_build_object('containment_id', c.containment_id,
                                                                     'instance_id', c.instance_id,
                                                                     'owner_generation', c.owner_generation,
                                                                     'incarnation', c.incarnation,
                                                                     'recorded_at', c.recorded_at)
                                                  ORDER BY c.containment_id) FROM voalack.owner_containment c), '[]'::jsonb),
        'quiescence', coalesce((SELECT jsonb_agg(jsonb_build_object('quiescence_id', q.quiescence_id,
                                                                    'instance_id', q.instance_id,
                                                                    'owner_generation', q.owner_generation,
                                                                    'incarnation', q.incarnation,
                                                                    'session_refs', to_jsonb(q.session_refs),
                                                                    'recorded_at', q.recorded_at)
                                                 ORDER BY q.quiescence_id) FROM voalack.quiescence q), '[]'::jsonb),
        'cleanups', coalesce((SELECT jsonb_agg(jsonb_build_object('cleanup_id', cl.cleanup_id, 'epoch', cl.epoch,
                                                                  'instance_id', cl.instance_id,
                                                                  'credential_ref', cl.credential_ref,
                                                                  'recorded_at', cl.recorded_at)
                                               ORDER BY cl.cleanup_id)
                                FROM voalack.recovery_cleanups cl WHERE cl.epoch = r.epoch), '[]'::jsonb),
        'owners', coalesce((SELECT jsonb_agg(to_jsonb(o) ORDER BY o.instance_id) FROM voalack.session_owners o), '[]'::jsonb),
        'recovered_effects', coalesce((SELECT jsonb_agg(jsonb_build_object('effect_key', re.effect_key,
                                                                           'action_id', re.action_id,
                                                                           'inventory_facts', re.inventory_facts)
                                                        ORDER BY re.effect_key) FROM voalack.recovered_effects re), '[]'::jsonb),
        'recovered_holds', coalesce((SELECT jsonb_agg(jsonb_build_object('hold_id', h.hold_id, 'adoption_id', h.adoption_id,
                                                                         'instance_id', h.instance_id,
                                                                         'target_kind', h.target_kind,
                                                                         'target_id', h.target_id, 'members', h.members,
                                                                         'holders', h.holders)
                                                      ORDER BY h.hold_id)
                                       FROM voalack.recovered_holds h WHERE h.status = 'active'), '[]'::jsonb),
        'recovery_history', jsonb_build_object(
            'adoptions', coalesce((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.adoption_id) FROM voalack.recovery_adoptions a),
                                  '[]'::jsonb),
            'holds', coalesce((SELECT jsonb_agg(to_jsonb(h) ORDER BY h.hold_id) FROM voalack.recovered_holds h), '[]'::jsonb),
            'settlements', coalesce((SELECT jsonb_agg(to_jsonb(rs) ORDER BY rs.recovery_settlement_id)
                                       FROM voalack.recovery_settlements rs), '[]'::jsonb)))
      INTO inv;
    RETURN inv;
END;
$$;

-- The exact keys of a voalack-inventory/2 document and the array each holds (R6).
CREATE OR REPLACE FUNCTION voalack._inventory_valid(p_inventory jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    k text;
BEGIN
    IF jsonb_typeof(p_inventory) IS DISTINCT FROM 'object'
       OR (SELECT array_agg(x ORDER BY x) FROM jsonb_object_keys(p_inventory) x)
          IS DISTINCT FROM ARRAY['attempts', 'captured_at', 'cleanups', 'containment', 'effects', 'epoch', 'format',
                                 'guards', 'head_seq', 'head_sha256', 'owners', 'provider_sessions', 'quiescence',
                                 'recovered_effects', 'recovered_holds', 'recovery_history', 'settlements']
       OR p_inventory->>'format' IS DISTINCT FROM 'voalack-inventory/2'
       OR jsonb_typeof(p_inventory->'epoch') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p_inventory->'head_seq') IS DISTINCT FROM 'number'
       OR jsonb_typeof(p_inventory->'head_sha256') IS DISTINCT FROM 'string'
       OR p_inventory->>'head_sha256' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(p_inventory->'captured_at') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p_inventory->'recovery_history') IS DISTINCT FROM 'object' THEN
        RETURN false;
    END IF;
    FOREACH k IN ARRAY ARRAY['attempts', 'cleanups', 'containment', 'effects', 'guards', 'owners', 'provider_sessions',
                             'quiescence', 'recovered_effects', 'recovered_holds', 'settlements'] LOOP
        IF jsonb_typeof(p_inventory->k) IS DISTINCT FROM 'array' THEN
            RETURN false;
        END IF;
    END LOOP;
    PERFORM (p_inventory->>'captured_at')::timestamptz;
    RETURN true;
EXCEPTION WHEN others THEN
    RETURN false;
END;
$$;

-- Adoption of a restored (or unchanged) database at a new epoch, bound to the anchor's recovering
-- line, the inventory, the backup (label and dump digest) and the review, in one transaction. Owners
-- of earlier epochs are logically invalidated (process containment recorded as unknown unless the
-- inventory covers it); effect holds for every key whose full facts differ, carried effect holds;
-- physical holds for every key with unresolved inventory work, a restored guard or a carried active
-- hold, keeping carried holders' frozen proof. Restored delivery rows are not rewritten.
CREATE OR REPLACE FUNCTION voalack.adopt_recovery(p_epoch bigint, p_head_seq integer, p_head_sha256 text,
                                                  p_inventory jsonb, p_inventory_sha256 text, p_backup_id text,
                                                  p_backup_sha256 text, p_review_sha256 text, p_review_ref text)
RETURNS TABLE (outcome text, r_adoption_id bigint, r_input_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
    prior voalack.recovery_adoptions%ROWTYPE;
    input text;
    aid bigint;
    captured timestamptz;
    n_contained integer;
    n_effects integer := 0;
    n_carried integer;
    n_keys integer := 0;
    k record;
    holders jsonb;
    carried jsonb;
BEGIN
    LOCK TABLE voalack.recovery_epoch, voalack.recovery_adoptions IN EXCLUSIVE MODE;
    LOCK TABLE voalack.session_owners, voalack.effects, voalack.attempts, voalack.target_guards,
               voalack.recovered_effects, voalack.recovered_holds IN SHARE ROW EXCLUSIVE MODE;
    -- T04 S4 (D5): no other writer allocates an outcome revision while the adoption runs.
    LOCK TABLE voalack.projection_actions IN SHARE ROW EXCLUSIVE MODE;
    IF NOT voalack._event_coverage_ready() THEN
        RAISE EXCEPTION 'voalack: outcome-event coverage is incomplete';
    END IF;
    IF p_inventory IS NULL OR p_inventory_sha256 IS NULL
       OR encode(sha256(convert_to(p_inventory::text, 'UTF8')), 'hex') <> p_inventory_sha256 THEN
        RAISE EXCEPTION 'voalack: inventory digest mismatch';
    END IF;
    input := encode(sha256(convert_to(jsonb_build_object(
                 'epoch', p_epoch, 'head_seq', p_head_seq, 'head_sha256', p_head_sha256,
                 'inventory_sha256', p_inventory_sha256, 'backup_id', p_backup_id, 'backup_sha256', p_backup_sha256,
                 'review_sha256', p_review_sha256, 'review_ref', p_review_ref)::text, 'UTF8')), 'hex');
    SELECT * INTO prior FROM voalack.recovery_adoptions a WHERE a.epoch = p_epoch;
    IF FOUND THEN
        IF prior.input_sha256 = input THEN
            RETURN QUERY SELECT 'already_adopted'::text, prior.adoption_id, input;
            RETURN;
        END IF;
        RAISE EXCEPTION 'voalack: this epoch was adopted with other input';
    END IF;
    IF NOT voalack._inventory_valid(p_inventory) THEN
        RAISE EXCEPTION 'voalack: the inventory is not a complete voalack-inventory/2 document';
    END IF;
    IF (p_inventory->>'epoch')::bigint IS DISTINCT FROM p_epoch - 1 THEN
        RAISE EXCEPTION 'voalack: the inventory does not belong to the previous epoch';
    END IF;
    IF p_head_seq IS NULL OR p_head_seq < 1 OR p_head_sha256 IS NULL OR p_head_sha256 !~ '^[0-9a-f]{64}$'
       OR p_review_sha256 IS NULL OR p_review_sha256 !~ '^[0-9a-f]{64}$'
       OR coalesce(octet_length(p_backup_id), 0) NOT BETWEEN 1 AND 256
       OR (p_backup_id = 'none') <> (p_backup_sha256 IS NULL)
       OR (p_backup_sha256 IS NOT NULL AND p_backup_sha256 !~ '^[0-9a-f]{64}$')
       OR coalesce(octet_length(p_review_ref), 0) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'voalack: adoption needs the recovering line, the backup and its digest, and the review';
    END IF;
    SELECT * INTO r FROM voalack.recovery_epoch x;
    IF coalesce(r.epoch, 0) >= p_epoch THEN
        RAISE EXCEPTION 'voalack: adoption needs an epoch newer than the database''s';
    END IF;
    captured := (p_inventory->>'captured_at')::timestamptz;
    aid := nextval('voalack.recovery_adoptions_adoption_id_seq');
    -- T04 S4 (C3): the database epoch moves to recovering(p_epoch) after every validation and replay
    -- check and before the owner, effect-hold and key-hold writes, so the outcome events those writes
    -- produce carry p_epoch. Same transaction: a failure below undoes it with everything else.
    INSERT INTO voalack.recovery_epoch (epoch, phase, head_seq, head_sha256, adoption_id)
    VALUES (p_epoch, 'recovering', p_head_seq, p_head_sha256, aid)
    ON CONFLICT (singleton) DO UPDATE
       SET epoch = EXCLUDED.epoch, phase = 'recovering', head_seq = EXCLUDED.head_seq,
           head_sha256 = EXCLUDED.head_sha256, adoption_id = EXCLUDED.adoption_id, changed_at = clock_timestamp();
    PERFORM voalack._pin_epoch();                    -- the row this transaction just wrote, held to COMMIT

    -- Every capability of an earlier epoch is unusable through the epoch pin (logical invalidation);
    -- the owner rows become contained so that a new owner can acquire. Whether the process was
    -- actually stopped is known only when the inventory's containment covers that exact owner (R3).
    INSERT INTO voalack.owner_containment (instance_id, owner_generation, incarnation, evidence)
    SELECT o.instance_id, o.owner_generation, o.incarnation,
           jsonb_build_object('logical_invalidation', true, 'adoption_id', aid,
                              'process_stopped', c.covered, 'no_requests_executing', c.covered,
                              'basis', CASE WHEN c.covered
                                            THEN 'recovery adoption of epoch ' || p_epoch || ': inventory containment covers this owner'
                                            ELSE 'recovery adoption of epoch ' || p_epoch || ': logical invalidation only; process containment unknown' END)
      FROM voalack.session_owners o
      CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM jsonb_array_elements(p_inventory->'containment') x
                                          WHERE x->>'instance_id' = o.instance_id
                                            AND (x->>'owner_generation')::bigint = o.owner_generation
                                            AND x->>'incarnation' = o.incarnation::text) AS covered) c
     WHERE o.state IN ('active', 'suspended');
    GET DIAGNOSTICS n_contained = ROW_COUNT;
    UPDATE voalack.session_owners o SET state = 'contained', changed_at = clock_timestamp()
     WHERE o.state IN ('active', 'suspended');

    -- Effect holds: every key whose full facts differ (missing on either side included), and the
    -- inventory's own effect holds carried forward (R2).
    FOR k IN
        WITH inv AS (SELECT x->>'effect_key' AS key, x AS facts FROM jsonb_array_elements(p_inventory->'effects') x),
             cur AS (SELECT e.effect_key AS key, voalack._effect_facts(e.effect_id) AS facts FROM voalack.effects e)
        SELECT coalesce(inv.key, cur.key) AS key, inv.facts AS inv_facts, cur.facts AS cur_facts
          FROM inv FULL JOIN cur ON inv.key = cur.key
         WHERE inv.facts IS DISTINCT FROM cur.facts
    LOOP
        INSERT INTO voalack.recovered_effects (effect_key, action_id, adoption_id, inventory_facts, restored_facts)
        VALUES (k.key, coalesce(k.inv_facts->>'action_id', k.cur_facts->>'action_id')::uuid, aid, k.inv_facts, k.cur_facts)
        ON CONFLICT (effect_key) DO NOTHING;
        IF FOUND THEN
            n_effects := n_effects + 1;
        END IF;
    END LOOP;
    INSERT INTO voalack.recovered_effects (effect_key, action_id, adoption_id, inventory_facts, restored_facts)
    SELECT x->>'effect_key', (x->>'action_id')::uuid, aid, x->'inventory_facts', NULL
      FROM jsonb_array_elements(p_inventory->'recovered_effects') x
    ON CONFLICT (effect_key) DO NOTHING;
    GET DIAGNOSTICS n_carried = ROW_COUNT;

    -- Physical holds: per key, the complete set of unresolved inventory attempts, restored guards'
    -- attempts and members of the inventory's active holds.
    FOR k IN
        WITH members AS (
            SELECT x AS m FROM jsonb_array_elements(p_inventory->'attempts') x
             WHERE x->>'state' = 'dispatched' OR (x->>'state' = 'uncertain' AND (x->>'settled')::boolean IS NOT TRUE)
            UNION ALL
            SELECT voalack._attempt_member(g.attempt_id, 'restored') FROM voalack.target_guards g
            UNION ALL
            SELECT y FROM jsonb_array_elements(p_inventory->'recovered_holds') h, jsonb_array_elements(h->'members') y),
             one AS (
            SELECT DISTINCT ON (m->>'attempt_id') m FROM members
             ORDER BY m->>'attempt_id', CASE m->>'source' WHEN 'inventory' THEN 0 WHEN 'restored' THEN 1 ELSE 2 END)
        SELECT m->>'instance_id' AS inst, m->>'target_kind' AS kind, m->>'target_id' AS target,
               jsonb_agg(m ORDER BY m->>'attempt_id') AS members
          FROM one GROUP BY 1, 2, 3
    LOOP
        -- Frozen holder proof of carried active holds on this key is kept as it was (F3); other
        -- holders are reconstructed from this inventory's records, and nothing is invented.
        SELECT coalesce(jsonb_agg(c), '[]'::jsonb) INTO carried
          FROM jsonb_array_elements(p_inventory->'recovered_holds') ih, jsonb_array_elements(ih->'holders') c
         WHERE ih->>'instance_id' = k.inst AND ih->>'target_kind' = k.kind AND ih->>'target_id' = k.target;
        SELECT jsonb_agg(coalesce(
                   (SELECT c FROM jsonb_array_elements(carried) c
                     WHERE (c->>'generation')::bigint = h.gen AND c->>'incarnation' = h.inc LIMIT 1),
                   jsonb_build_object(
                   'generation', h.gen, 'incarnation', h.inc, 'credential_ref', h.cred,
                   'sessions', coalesce((SELECT jsonb_agg(s->>'session_ref' ORDER BY s->>'session_ref')
                                           FROM jsonb_array_elements(p_inventory->'provider_sessions') s
                                          WHERE s->>'instance_id' = k.inst
                                            AND (s->>'owner_generation')::bigint = h.gen
                                            AND s->>'incarnation' = h.inc), '[]'::jsonb),
                   'quiescence', (SELECT q FROM jsonb_array_elements(p_inventory->'quiescence') q
                                   WHERE q->>'instance_id' = k.inst AND (q->>'owner_generation')::bigint = h.gen
                                     AND q->>'incarnation' = h.inc
                                   ORDER BY (q->>'quiescence_id')::bigint DESC LIMIT 1),
                   'cleanup', (SELECT cl FROM jsonb_array_elements(p_inventory->'cleanups') cl
                                WHERE cl->>'instance_id' = k.inst AND cl->>'credential_ref' = h.cred
                                ORDER BY (cl->>'cleanup_id')::bigint DESC LIMIT 1)))
                 ORDER BY h.gen, h.inc)
          INTO holders
          FROM (SELECT DISTINCT (m->>'generation')::bigint AS gen, m->>'incarnation' AS inc, m->>'credential_ref' AS cred
                  FROM jsonb_array_elements(k.members) m) h;
        INSERT INTO voalack.recovered_holds (adoption_id, instance_id, target_kind, target_id, members, holders,
                                             inventory_captured_at)
        VALUES (aid, k.inst, k.kind, k.target, k.members, holders, captured);
        n_keys := n_keys + 1;
    END LOOP;

    INSERT INTO voalack.recovery_adoptions (adoption_id, epoch, head_seq, head_sha256, input_sha256, inventory_sha256,
                                            inventory_captured_at, backup_id, backup_sha256, review_sha256, review_ref,
                                            contained_owners, effect_holds, key_holds, prior_recovery, adopted_by)
    VALUES (aid, p_epoch, p_head_seq, p_head_sha256, input, p_inventory_sha256, captured, p_backup_id, p_backup_sha256,
            p_review_sha256, p_review_ref, n_contained, n_effects + n_carried, n_keys,
            jsonb_build_object('recovery_history', p_inventory->'recovery_history',
                               'recovered_effects', p_inventory->'recovered_effects',
                               'recovered_holds', p_inventory->'recovered_holds'),
            session_user);
    INSERT INTO voalack.recovery_transitions (epoch, phase, head_seq, head_sha256, detail, decided_by)
    VALUES (p_epoch, 'recovering', p_head_seq, p_head_sha256,
            jsonb_build_object('transition', 'adopt', 'adoption_id', aid, 'input_sha256', input), session_user);
    RETURN QUERY SELECT 'adopted'::text, aid, input;
END;
$$;

-- recovering(e) -> open(e), bound to the anchor's open line (the next line after recovering), once
-- every maintenance owner is contained. Re-running the same reopen returns 'already_open'.
CREATE OR REPLACE FUNCTION voalack.open_recovery(p_epoch bigint, p_head_seq integer, p_head_sha256 text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
BEGIN
    SELECT * INTO r FROM voalack.recovery_epoch x FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: recovery epoch is not initialized';
    END IF;
    IF (r.epoch, r.phase, r.head_seq, r.head_sha256) = (p_epoch, 'open', p_head_seq, p_head_sha256) THEN
        RETURN 'already_open';
    END IF;
    IF r.phase <> 'recovering' OR r.epoch <> p_epoch OR p_head_seq IS DISTINCT FROM r.head_seq + 1
       OR p_head_sha256 IS NULL OR p_head_sha256 !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'voalack: reopen must follow the recovering line of the current epoch';
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.session_owners o WHERE o.mode = 'maintenance' AND o.state IN ('active', 'suspended')) THEN
        RAISE EXCEPTION 'voalack: every maintenance owner must be contained before reopening';
    END IF;
    UPDATE voalack.recovery_epoch x SET phase = 'open', head_seq = p_head_seq, head_sha256 = p_head_sha256,
           changed_at = clock_timestamp();
    INSERT INTO voalack.recovery_transitions (epoch, phase, head_seq, head_sha256, detail, decided_by)
    VALUES (p_epoch, 'open', p_head_seq, p_head_sha256, jsonb_build_object('transition', 'reopen'), session_user);
    RETURN 'opened';
END;
$$;

-- A recovery reader: an active owner pinned to the phase of its mode (maintenance in recovering,
-- ordinary in open), owner row FOR SHARE. Returns the owner row, or NULL fields.
CREATE OR REPLACE FUNCTION voalack._recovery_reader(p_instance text, p_generation bigint, p_incarnation uuid)
RETURNS voalack.session_owners
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    o voalack.session_owners%ROWTYPE;
BEGIN
    SELECT * INTO o FROM voalack.session_owners x
     WHERE x.instance_id = p_instance AND x.owner_generation = p_generation AND x.incarnation = p_incarnation
       AND x.state = 'active'
       FOR SHARE;
    IF NOT FOUND OR NOT voalack._epoch_pin(o.acquired_epoch, o.acquired_head_sha256, o.mode) THEN
        RETURN NULL;
    END IF;
    RETURN o;
END;
$$;

-- After any wait: the reader is still that pinned owner at the given epoch and anchor line, with
-- the configuration equal to its acquired snapshot and to the given read snapshot.
CREATE OR REPLACE FUNCTION voalack._recovery_reader_current(p_instance text, p_generation bigint, p_incarnation uuid,
                                                            p_credential text, p_revision integer, p_contract text,
                                                            p_epoch bigint, p_head_sha256 text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    o voalack.session_owners%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    o := voalack._recovery_reader(p_instance, p_generation, p_incarnation);
    IF o.instance_id IS NULL OR (o.acquired_epoch, o.acquired_head_sha256) IS DISTINCT FROM (p_epoch, p_head_sha256) THEN
        RETURN 'owner_fenced';
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF (ic.credential_ref, ic.config_revision, ic.provider_contract) IS DISTINCT FROM (p_credential, p_revision, p_contract)
       OR NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                            ic.config_revision, ic.provider_contract) THEN
        RETURN 'config_changed';
    END IF;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION voalack.begin_recovery_read(p_read uuid, p_hold bigint, p_instance text,
                                                       p_generation bigint, p_incarnation uuid)
RETURNS TABLE (outcome text, r_target_kind text, r_target_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    h voalack.recovered_holds%ROWTYPE;
    o voalack.session_owners%ROWTYPE;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    SELECT * INTO h FROM voalack.recovered_holds x WHERE x.hold_id = p_hold FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_hold'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF EXISTS (SELECT 1 FROM voalack.recovery_reads rr WHERE rr.read_id = p_read) THEN
        RETURN QUERY SELECT 'already_reserved'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF h.instance_id <> p_instance THEN
        RETURN QUERY SELECT 'wrong_instance'::text, NULL::text, NULL::text; RETURN;
    END IF;
    o := voalack._recovery_reader(p_instance, p_generation, p_incarnation);
    IF o.instance_id IS NULL THEN
        RETURN QUERY SELECT 'owner_fenced'::text, NULL::text, NULL::text; RETURN;
    END IF;
    IF h.status <> 'active' THEN
        RETURN QUERY SELECT 'not_active'::text, NULL::text, NULL::text; RETURN;
    END IF;
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF NOT voalack._owner_config_matches(p_instance, p_generation, p_incarnation, ic.credential_ref,
                                         ic.config_revision, ic.provider_contract) THEN
        RETURN QUERY SELECT 'config_changed'::text, NULL::text, NULL::text; RETURN;
    END IF;
    INSERT INTO voalack.recovery_reads (read_id, hold_id, instance_id, target_kind, target_id, reader_generation,
                                        reader_incarnation, reader_mode, epoch, head_sha256, credential_ref,
                                        config_revision, provider_contract)
    VALUES (p_read, p_hold, h.instance_id, h.target_kind, h.target_id, p_generation, p_incarnation, o.mode,
            o.acquired_epoch, o.acquired_head_sha256, ic.credential_ref, ic.config_revision, ic.provider_contract);
    RETURN QUERY SELECT 'reserved'::text, h.target_kind, h.target_id;
END;
$$;

-- Classification of one read of a hold's key against its frozen members (fake contract, as _classify).
CREATE OR REPLACE FUNCTION voalack._classify_hold(p_hold bigint, p_observation jsonb, p_reserved_at timestamptz)
RETURNS TABLE (classification text, matched_attempt uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    h voalack.recovered_holds%ROWTYPE;
    al jsonb := p_observation->'alarm';
    op jsonb;
    mem jsonb;
    started timestamptz;
BEGIN
    SELECT * INTO h FROM voalack.recovered_holds x WHERE x.hold_id = p_hold;
    BEGIN
        started := (p_observation->>'read_started_at')::timestamptz;
    EXCEPTION WHEN others THEN
        RETURN QUERY SELECT 'evidence_only'::text, NULL::uuid; RETURN;
    END;
    IF started IS NULL OR started < p_reserved_at
       OR jsonb_typeof(p_observation->'status') IS DISTINCT FROM 'number' OR p_observation->'status' <> '200'::jsonb
       OR jsonb_typeof(al) IS DISTINCT FROM 'object'
       OR jsonb_typeof(al->'target_id') IS DISTINCT FROM 'string' OR al->>'target_id' <> h.target_id
       OR jsonb_typeof(al->'kind') IS DISTINCT FROM 'string' OR al->>'kind' <> h.target_kind
       OR al ? 'children' OR jsonb_typeof(al->'acked') IS DISTINCT FROM 'boolean' THEN
        RETURN QUERY SELECT 'evidence_only'::text, NULL::uuid; RETURN;
    END IF;
    op := al->'acked_by_operation';
    IF NOT (al->>'acked')::boolean THEN
        RETURN QUERY SELECT (CASE WHEN op IS NULL OR op = 'null'::jsonb THEN 'not_acked' ELSE 'evidence_only' END)::text,
                            NULL::uuid;
        RETURN;
    END IF;
    IF op IS NULL OR op = 'null'::jsonb THEN
        RETURN QUERY SELECT (CASE WHEN jsonb_typeof(al->'comment') = 'string'
                                       AND EXISTS (SELECT 1 FROM jsonb_array_elements(h.members) m
                                                    WHERE m->>'comment' = al->>'comment')
                                  THEN 'acked_unattributed' ELSE 'evidence_only' END)::text, NULL::uuid;
        RETURN;
    END IF;
    IF jsonb_typeof(op) IS DISTINCT FROM 'string' OR op #>> '{}' !~ '^[0-9a-f]{64}$' THEN
        RETURN QUERY SELECT 'evidence_only'::text, NULL::uuid; RETURN;
    END IF;
    SELECT m INTO mem FROM jsonb_array_elements(h.members) m WHERE m->>'request_sha256' = op #>> '{}'
     ORDER BY m->>'attempt_id' LIMIT 1;
    IF mem IS NULL THEN
        RETURN QUERY SELECT 'acked_by_other'::text, NULL::uuid; RETURN;
    END IF;
    IF jsonb_typeof(al->'comment') = 'string' AND al->>'comment' = mem->>'comment'
       AND al->'operation_status' = '"completed"'::jsonb THEN
        RETURN QUERY SELECT 'attributable'::text, (mem->>'attempt_id')::uuid; RETURN;
    END IF;
    RETURN QUERY SELECT 'evidence_only'::text, NULL::uuid;
END;
$$;

CREATE OR REPLACE FUNCTION voalack.record_recovery_read(p_read uuid, p_instance text, p_generation bigint,
                                                        p_incarnation uuid, p_observation jsonb)
RETURNS TABLE (outcome text, r_recovery_reconciliation_id bigint, r_classification text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    rr voalack.recovery_reads%ROWTYPE;
    rec voalack.recovery_reconciliations%ROWTYPE;
    refusal text;
    cls text;
    matched uuid;
    rid bigint;
    started timestamptz;
    completed timestamptz;
BEGIN
    SELECT * INTO rr FROM voalack.recovery_reads x WHERE x.read_id = p_read;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'no_reservation'::text, NULL::bigint, NULL::text; RETURN;
    END IF;
    IF (rr.instance_id, rr.reader_generation, rr.reader_incarnation) IS DISTINCT FROM (p_instance, p_generation, p_incarnation) THEN
        RETURN QUERY SELECT 'not_reader'::text, NULL::bigint, NULL::text; RETURN;
    END IF;
    IF p_observation IS NULL OR octet_length(p_observation::text) > 16384 THEN
        RETURN QUERY SELECT 'bad_observation'::text, NULL::bigint, NULL::text; RETURN;
    END IF;
    PERFORM 1 FROM voalack.recovered_holds h WHERE h.hold_id = rr.hold_id FOR SHARE;
    PERFORM 1 FROM voalack.recovery_reads x WHERE x.read_id = p_read FOR UPDATE;
    SELECT * INTO rec FROM voalack.recovery_reconciliations x WHERE x.read_id = p_read;
    IF FOUND THEN
        RETURN QUERY SELECT (CASE WHEN rec.observation = p_observation THEN 'recorded' ELSE 'already_recorded' END)::text,
                            rec.recovery_reconciliation_id, rec.classification;
        RETURN;
    END IF;
    refusal := voalack._recovery_reader_current(p_instance, p_generation, p_incarnation, rr.credential_ref,
                                                rr.config_revision, rr.provider_contract, rr.epoch, rr.head_sha256);
    IF refusal IS NOT NULL THEN
        RETURN QUERY SELECT refusal, NULL::bigint, NULL::text; RETURN;
    END IF;
    SELECT c.classification, c.matched_attempt INTO cls, matched FROM voalack._classify_hold(rr.hold_id, p_observation, rr.reserved_at) c;
    BEGIN
        started := (p_observation->>'read_started_at')::timestamptz;
        completed := (p_observation->>'read_completed_at')::timestamptz;
    EXCEPTION WHEN others THEN
        started := NULL;
        completed := NULL;
    END;
    INSERT INTO voalack.recovery_reconciliations (read_id, hold_id, instance_id, target_kind, target_id,
                                                  reader_generation, reader_incarnation, reader_mode, epoch,
                                                  head_sha256, credential_ref, config_revision, provider_contract,
                                                  reserved_at, read_started_at, read_completed_at, classification,
                                                  matched_attempt, observation)
    VALUES (p_read, rr.hold_id, rr.instance_id, rr.target_kind, rr.target_id, rr.reader_generation,
            rr.reader_incarnation, rr.reader_mode, rr.epoch, rr.head_sha256, rr.credential_ref, rr.config_revision,
            rr.provider_contract, rr.reserved_at, started, completed, cls, matched, p_observation)
    RETURNING recovery_reconciliation_id INTO rid;
    RETURN QUERY SELECT 'recorded'::text, rid, cls;
END;
$$;

-- Operator settlement of one physical hold (settler only). Every holder of the set must be known,
-- with inventory sessions all covered by an inventory quiescence record taken before the inventory;
-- the read of this hold's key must be reserved after the adoption by a reader that is still pinned
-- with its configuration. Releases the hold and every restored guard of a member; restored effects
-- whose in-flight attempt is a member become BLOCKED (neutral; never QUEUED).
CREATE OR REPLACE FUNCTION voalack.settle_recovered_hold(p_decision uuid, p_hold bigint, p_outcome text,
                                                         p_recovery_reconciliation bigint, p_note text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    need text;
    input text;
    replay text;
    h voalack.recovered_holds%ROWTYPE;
    rec voalack.recovery_reconciliations%ROWTYPE;
    refusal text;
    adopted timestamptz;
    hol jsonb;
    q jsonb;
    ids uuid[];
    released jsonb;
    blocked jsonb;
BEGIN
    PERFORM voalack._pin_epoch();                    -- T04 S4 (D7.4 corrected): the epoch row first
    need := CASE p_outcome WHEN 'recovered_attributed' THEN 'attributable'
                           WHEN 'recovered_acked_unattributed' THEN 'acked_unattributed'
                           WHEN 'recovered_acked_by_other' THEN 'acked_by_other'
                           WHEN 'recovered_retired' THEN 'not_acked' END;
    IF need IS NULL THEN
        RETURN 'bad_outcome';
    END IF;
    IF p_note IS NULL OR octet_length(p_note) > 1024 THEN
        RETURN 'bad_note';
    END IF;
    input := encode(sha256(convert_to(jsonb_build_object('hold_id', p_hold, 'outcome', p_outcome,
                                                         'recovery_reconciliation_id', p_recovery_reconciliation,
                                                         'note', p_note)::text, 'UTF8')), 'hex');
    SELECT * INTO h FROM voalack.recovered_holds x WHERE x.hold_id = p_hold FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'no_hold';
    END IF;
    SELECT CASE WHEN s.decision_input_sha256 = input THEN 'already_settled' ELSE 'decision_conflict' END INTO replay
      FROM voalack.recovery_settlements s WHERE s.decision_id = p_decision;
    IF replay IS NOT NULL THEN
        RETURN replay;
    END IF;
    IF h.status <> 'active' OR EXISTS (SELECT 1 FROM voalack.recovery_settlements s WHERE s.hold_id = p_hold) THEN
        RETURN 'conflict';
    END IF;
    SELECT * INTO rec FROM voalack.recovery_reconciliations x
     WHERE x.recovery_reconciliation_id = p_recovery_reconciliation FOR SHARE;
    IF NOT FOUND OR rec.hold_id <> p_hold
       OR (rec.instance_id, rec.target_kind, rec.target_id) IS DISTINCT FROM (h.instance_id, h.target_kind, h.target_id) THEN
        RETURN 'wrong_reconciliation';
    END IF;
    refusal := voalack._recovery_reader_current(rec.instance_id, rec.reader_generation, rec.reader_incarnation,
                                                rec.credential_ref, rec.config_revision, rec.provider_contract,
                                                rec.epoch, rec.head_sha256);
    IF refusal IS NOT NULL THEN
        RETURN 'reader_' || refusal;
    END IF;
    IF rec.classification <> need THEN
        RETURN 'classification_mismatch';
    END IF;
    SELECT a.adopted_at INTO adopted FROM voalack.recovery_adoptions a WHERE a.adoption_id = h.adoption_id;
    IF adopted IS NULL OR NOT rec.reserved_at > adopted THEN
        RETURN 'read_before_adoption';
    END IF;
    FOR hol IN SELECT x FROM jsonb_array_elements(h.holders) x LOOP
        IF (rec.reader_generation, rec.reader_incarnation::text) = ((hol->>'generation')::bigint, hol->>'incarnation') THEN
            RETURN 'reader_is_holder';
        END IF;
        IF jsonb_array_length(hol->'sessions') = 0 THEN
            RETURN 'holder_sessions_unknown';
        END IF;
        q := hol->'quiescence';
        IF q IS NULL OR q = 'null'::jsonb THEN
            RETURN 'holder_not_quiescent';
        END IF;
        IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(hol->'sessions') s WHERE NOT (q->'session_refs') ? s) THEN
            RETURN 'quiescence_incomplete';
        END IF;
        IF NOT (q->>'recorded_at')::timestamptz < h.inventory_captured_at THEN
            RETURN 'quiescence_after_inventory';
        END IF;
        -- R1: a credential-wide cleanup (covering sessions never registered) before the inventory.
        IF hol->'cleanup' IS NULL OR hol->'cleanup' = 'null'::jsonb THEN
            RETURN 'holder_cleanup_unknown';
        END IF;
        IF NOT (hol->'cleanup'->>'recorded_at')::timestamptz < h.inventory_captured_at THEN
            RETURN 'cleanup_after_inventory';
        END IF;
    END LOOP;
    ids := ARRAY(SELECT (m->>'attempt_id')::uuid FROM jsonb_array_elements(h.members) m);
    PERFORM 1 FROM voalack.effects e WHERE e.in_flight_attempt = ANY(ids) FOR UPDATE;
    PERFORM 1 FROM voalack.attempts a WHERE a.attempt_id = ANY(ids) FOR UPDATE;
    PERFORM 1 FROM voalack.target_guards g
     WHERE (g.instance_id, g.target_kind, g.target_id) = (h.instance_id, h.target_kind, h.target_id) FOR UPDATE;
    -- T04 S4 (D5): the projection rows of every member action, in action order, before the first
    -- outcome event (the BLOCKED effects and the settlement's release event).
    PERFORM voalack._lock_projection_actions(ARRAY(SELECT (m->>'action_id')::uuid FROM jsonb_array_elements(h.members) m));
    -- After the locks (R3, F4): only attempts whose current rows still carry the member's complete
    -- frozen identity are released: request digest, generation, incarnation, credential, configuration
    -- revision, provider contract, action, the logical effect key (through the attempt's own effect
    -- row, never a numeric effect id) and the physical key, on both sides. A missing member field is
    -- NULL and never matches; a replaced or conflicting attempt keeps its guard and its effect.
    ids := ARRAY(SELECT a.attempt_id FROM voalack.attempts a
                   JOIN voalack.effects e ON e.effect_id = a.effect_id AND e.action_id = a.action_id
                   JOIN jsonb_array_elements(h.members) m ON a.attempt_id = (m->>'attempt_id')::uuid
                  WHERE a.request_sha256 = m->>'request_sha256'
                    AND a.owner_generation = (m->>'generation')::bigint
                    AND a.incarnation::text = m->>'incarnation'
                    AND a.credential_ref = m->>'credential_ref'
                    AND a.config_revision = (m->>'config_revision')::integer
                    AND a.provider_contract = m->>'provider_contract'
                    AND a.action_id::text = m->>'action_id'
                    AND e.effect_key = m->>'effect_key'
                    AND (a.instance_id, a.target_kind, a.target_id) = (h.instance_id, h.target_kind, h.target_id)
                    AND (m->>'instance_id', m->>'target_kind', m->>'target_id') = (h.instance_id, h.target_kind, h.target_id));
    SELECT coalesce(jsonb_agg(jsonb_build_object('attempt_id', g.attempt_id, 'state', g.state) ORDER BY g.attempt_id),
                    '[]'::jsonb) INTO released
      FROM voalack.target_guards g
     WHERE g.attempt_id = ANY(ids) AND (g.instance_id, g.target_kind, g.target_id) = (h.instance_id, h.target_kind, h.target_id);
    DELETE FROM voalack.target_guards g
     WHERE g.attempt_id = ANY(ids) AND (g.instance_id, g.target_kind, g.target_id) = (h.instance_id, h.target_kind, h.target_id);
    SELECT coalesce(jsonb_agg(jsonb_build_object('effect_id', e.effect_id, 'prior_state', e.state,
                                                 'in_flight_attempt', e.in_flight_attempt) ORDER BY e.effect_id),
                    '[]'::jsonb) INTO blocked
      FROM voalack.effects e
     WHERE e.in_flight_attempt = ANY(ids)
       AND EXISTS (SELECT 1 FROM voalack.attempts a WHERE a.attempt_id = e.in_flight_attempt AND a.effect_id = e.effect_id);
    UPDATE voalack.effects e SET state = 'BLOCKED', in_flight_attempt = NULL
     WHERE e.in_flight_attempt = ANY(ids)
       AND EXISTS (SELECT 1 FROM voalack.attempts a WHERE a.attempt_id = e.in_flight_attempt AND a.effect_id = e.effect_id);
    UPDATE voalack.recovered_holds x SET status = 'released', released_at = clock_timestamp() WHERE x.hold_id = p_hold;
    INSERT INTO voalack.recovery_settlements (decision_id, decision_input_sha256, hold_id, outcome,
                                              recovery_reconciliation_id, reader_generation, reader_incarnation,
                                              epoch, head_sha256, holders, released_guards, blocked_effects,
                                              decided_by, note)
    VALUES (p_decision, input, p_hold, p_outcome, p_recovery_reconciliation, rec.reader_generation,
            rec.reader_incarnation, rec.epoch, rec.head_sha256, h.holders, released, blocked, session_user, p_note);
    RETURN 'settled';
END;
$$;

CREATE OR REPLACE FUNCTION voalack.recovery_settlement_status(p_decision uuid)
RETURNS TABLE (r_hold_id bigint, r_outcome text, r_decided_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT s.hold_id, s.outcome, s.decided_at FROM voalack.recovery_settlements s WHERE s.decision_id = p_decision
$$;
ALTER TABLE voalack.recovery_epoch OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_transitions OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovery_transitions_transition_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack._epoch_pin(bigint, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.initialize_recovery(text, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.close_recovery(bigint, integer, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.journal_facts(text, bigint, uuid, uuid[]) OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_adoptions OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_cleanups OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovery_cleanups_cleanup_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_recovery_cleanup(text, text, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._recovered_protected(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._inventory_valid(jsonb) OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovery_adoptions_adoption_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.recovered_effects OWNER TO voalack_admin;
ALTER TABLE voalack.recovered_holds OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovered_holds_hold_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_reads OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_reconciliations OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovery_reconciliations_recovery_reconciliation_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.recovery_settlements OWNER TO voalack_admin;
ALTER SEQUENCE voalack.recovery_settlements_recovery_settlement_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack.recovered_hold_release_only() OWNER TO voalack_admin;
ALTER FUNCTION voalack._request_comment(bytea) OWNER TO voalack_admin;
ALTER FUNCTION voalack._effect_facts(bigint) OWNER TO voalack_admin;
ALTER FUNCTION voalack._attempt_member(uuid, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.recovery_inventory() OWNER TO voalack_admin;
ALTER FUNCTION voalack.adopt_recovery(bigint, integer, text, jsonb, text, text, text, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.open_recovery(bigint, integer, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._recovery_reader(text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._recovery_reader_current(text, bigint, uuid, text, integer, text, bigint, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.begin_recovery_read(uuid, bigint, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._classify_hold(bigint, jsonb, timestamptz) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_recovery_read(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.settle_recovered_hold(uuid, bigint, text, bigint, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.recovery_settlement_status(uuid) OWNER TO voalack_admin;

-- Ownership and privileges (design "Database ownership and privacy"): PUBLIC gets nothing; the
-- application role reads what the boundary checks and writes only through the functions above.
ALTER SCHEMA voalack OWNER TO voalack_admin;
ALTER TABLE voalack.bindings OWNER TO voalack_admin;
ALTER TABLE voalack.binding_revisions OWNER TO voalack_admin;
ALTER TABLE voalack.binding_generations OWNER TO voalack_admin;
ALTER TABLE voalack.authorization_policy OWNER TO voalack_admin;
ALTER TABLE voalack.authorization_policy_active OWNER TO voalack_admin;
ALTER TABLE voalack.prepared_intents OWNER TO voalack_admin;
ALTER TABLE voalack.captures OWNER TO voalack_admin;
ALTER FUNCTION voalack.capture_ack() OWNER TO voalack_admin;
ALTER FUNCTION voalack.refuse_change() OWNER TO voalack_admin;
ALTER FUNCTION voalack.lock_binding(text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.lock_grant(text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.stage_intent(uuid, text, uuid, text, jsonb, text, text, integer, timestamptz,
                                    timestamptz, timestamptz) OWNER TO voalack_admin;
ALTER FUNCTION voalack.approve_intent(uuid, bytea, text, text, text, jsonb) OWNER TO voalack_admin;
ALTER TABLE voalack.verification_claims OWNER TO voalack_admin;
ALTER TABLE voalack.verifications OWNER TO voalack_admin;
ALTER TABLE voalack.effects OWNER TO voalack_admin;
ALTER SEQUENCE voalack.verifications_verification_id_seq OWNER TO voalack_admin;
ALTER SEQUENCE voalack.effects_effect_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack.capture_fingerprint(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.claim_verification(text, integer, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._lock_original(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack._require_current_claim(uuid, bigint) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_verification(uuid, bigint, text, text, text, text, text, text, text, text)
    OWNER TO voalack_admin;
ALTER FUNCTION voalack.promote_effect(uuid, bigint, bigint) OWNER TO voalack_admin;
ALTER TABLE voalack.instance_config OWNER TO voalack_admin;
ALTER TABLE voalack.accepted_kids OWNER TO voalack_admin;
ALTER TABLE voalack.accepted_verifier_versions OWNER TO voalack_admin;
ALTER TABLE voalack.session_owners OWNER TO voalack_admin;
ALTER TABLE voalack.owner_containment OWNER TO voalack_admin;
ALTER SEQUENCE voalack.owner_containment_containment_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.attempts OWNER TO voalack_admin;
ALTER TABLE voalack.target_guards OWNER TO voalack_admin;
ALTER TABLE voalack.attempt_evidence OWNER TO voalack_admin;
ALTER SEQUENCE voalack.attempt_evidence_evidence_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack.encode_ack_request(bigint) OWNER TO voalack_admin;
ALTER FUNCTION voalack._owner_fenced(text, bigint, uuid, text[]) OWNER TO voalack_admin;
ALTER FUNCTION voalack._dispatch_eligibility(bigint) OWNER TO voalack_admin;
ALTER FUNCTION voalack.acquire_owner(text, text, uuid, bigint, integer, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.check_owner(text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.suspend_owner(text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_containment(text, bigint, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._release_no_dispatch(uuid, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._hold_uncertain(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.start_attempt(uuid, bigint, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.consume_dispatch(uuid, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.check_dispatch(uuid, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.close_already_acked(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_not_sent(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.close_unsupported_target(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._owner_config_matches(text, bigint, uuid, text, integer, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.abort_attempt(uuid, text, bigint, uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.hold_attempt(uuid, text, bigint, uuid, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_result(uuid, text, bigint, uuid, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.record_evidence(uuid, bigint, uuid, text, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack.release_stale_started(text, bigint, uuid) OWNER TO voalack_admin;
REVOKE ALL ON SCHEMA voalack FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA voalack FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA voalack FROM PUBLIC;
-- Global (not IN SCHEMA): a schema-level revoke cannot remove PostgreSQL's global default
-- EXECUTE for PUBLIC on functions created by voalack_admin (review R23).
ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE voalack_admin IN SCHEMA voalack REVOKE ALL ON TABLES FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA voalack FROM voalack_app;
GRANT USAGE ON SCHEMA voalack TO voalack_app;
GRANT SELECT ON voalack.bindings, voalack.binding_revisions, voalack.authorization_policy,
                voalack.authorization_policy_active, voalack.prepared_intents, voalack.captures
    TO voalack_app;
GRANT EXECUTE ON FUNCTION voalack.lock_binding(text), voalack.lock_grant(text, text),
    voalack.stage_intent(uuid, text, uuid, text, jsonb, text, text, integer, timestamptz, timestamptz,
                         timestamptz),
    voalack.approve_intent(uuid, bytea, text, text, text, jsonb)
    TO voalack_app;

-- T04 S1: the verifier role reads what verification needs and writes only through its functions.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA voalack FROM voalack_verifier;
GRANT USAGE ON SCHEMA voalack TO voalack_verifier;
GRANT SELECT ON voalack.prepared_intents, voalack.captures, voalack.bindings, voalack.binding_revisions,
                voalack.authorization_policy, voalack.authorization_policy_active, voalack.verifications,
                voalack.effects, voalack.verification_claims
    TO voalack_verifier;
GRANT EXECUTE ON FUNCTION voalack.capture_fingerprint(uuid), voalack.claim_verification(text, integer, uuid),
    voalack.record_verification(uuid, bigint, text, text, text, text, text, text, text, text),
    voalack.promote_effect(uuid, bigint, bigint)
    TO voalack_verifier;

-- T04 S2: the sender role reads only the delivery ledger and its configuration, and writes only
-- through the owner and attempt functions. record_containment is granted to no runtime role.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON ALL TABLES IN SCHEMA voalack FROM voalack_sender;
GRANT USAGE ON SCHEMA voalack TO voalack_sender;
GRANT SELECT ON voalack.effects, voalack.attempts, voalack.target_guards, voalack.session_owners,
                voalack.instance_config
    TO voalack_sender;
GRANT EXECUTE ON FUNCTION voalack.acquire_owner(text, text, uuid, bigint, integer, text, text),
    voalack.check_owner(text, bigint, uuid),
    voalack.suspend_owner(text, bigint, uuid), voalack.start_attempt(uuid, bigint, text, bigint, uuid),
    voalack.consume_dispatch(uuid, text, bigint, uuid), voalack.check_dispatch(uuid, text, bigint, uuid),
    voalack.abort_attempt(uuid, text, bigint, uuid), voalack.close_already_acked(uuid, text, bigint, uuid, jsonb),
    voalack.record_not_sent(uuid, text, bigint, uuid, jsonb), voalack.close_unsupported_target(uuid, text, bigint, uuid, jsonb),
    voalack.hold_attempt(uuid, text, bigint, uuid, text), voalack.record_result(uuid, text, bigint, uuid, jsonb),
    voalack.record_evidence(uuid, bigint, uuid, text, jsonb), voalack.release_stale_started(text, bigint, uuid)
    TO voalack_sender;

-- T04 S3b: the sender registers sessions, reconciles and settles only attributable reads; the
-- settler role (a trusted operator capability) settles through settle_uncertain only and reads the
-- audit ledger with an explicit column list on attempts (never request_bytes). record_quiescence,
-- like record_containment, is granted to no runtime role.
GRANT EXECUTE ON FUNCTION voalack.register_session(text, text, bigint, uuid),
    voalack.begin_reconciliation(uuid, uuid, text, bigint, uuid),
    voalack.record_reconciliation(uuid, text, bigint, uuid, jsonb),
    voalack.settle_by_reconciliation(uuid, bigint, text, bigint, uuid), voalack.settlement_status(uuid)
    TO voalack_sender;
REVOKE ALL ON ALL TABLES IN SCHEMA voalack FROM voalack_settler;
GRANT USAGE ON SCHEMA voalack TO voalack_settler;
GRANT SELECT ON voalack.effects, voalack.target_guards, voalack.session_owners, voalack.owner_containment,
                voalack.provider_sessions, voalack.quiescence, voalack.reconciliations, voalack.settlements
    TO voalack_settler;
GRANT SELECT (attempt_id, effect_id, action_id, instance_id, credential_ref, provider_contract, config_revision,
              owner_generation, incarnation, target_kind, target_id, request_sha256, permit_state, state,
              started_at, dispatched_at, settled_at)
    ON voalack.attempts TO voalack_settler;
GRANT EXECUTE ON FUNCTION voalack.settle_uncertain(uuid, uuid, text, bigint, text), voalack.settlement_status(uuid)
    TO voalack_settler;

-- T04 S3c: the sender's live journal reads its own attempts' facts through journal_facts (no new
-- table read); recovery administration is granted to no runtime role.
GRANT EXECUTE ON FUNCTION voalack.journal_facts(text, bigint, uuid, uuid[]) TO voalack_sender;
-- T04 S3c (M2): recovery reads by the sender (maintenance or ordinary capability); hold settlement and
-- the recovery audit for the settler. recovery_inventory, adopt_recovery and open_recovery are granted
-- to no runtime role.
GRANT EXECUTE ON FUNCTION voalack.begin_recovery_read(uuid, bigint, text, bigint, uuid),
    voalack.record_recovery_read(uuid, text, bigint, uuid, jsonb)
    TO voalack_sender;
GRANT SELECT ON voalack.recovered_effects, voalack.recovered_holds, voalack.recovery_reconciliations,
                voalack.recovery_settlements, voalack.recovery_adoptions
    TO voalack_settler;
GRANT EXECUTE ON FUNCTION voalack.settle_recovered_hold(uuid, bigint, text, bigint, text),
    voalack.recovery_settlement_status(uuid)
    TO voalack_settler;

-- =====================================================================================================
-- T04 S4: durable, idempotent operator projection (spec r1-r3 with D1-D7). Display only: nothing here
-- sends, settles, releases, requeues or creates an intent. An outcome event is appended, in the same
-- transaction, for every operator-visible change; the projector publishes one Alerta note per event in
-- one transaction with its protected publication record, its marker and its position.
-- =====================================================================================================

-- Protected publication provenance (C1, D2). A separate schema outside the supported Voalack-only
-- restore set (pg_dump/pg_restore -n voalack): nothing in it refers to an object in voalack, so a clean
-- restore of voalack drops, recreates and fails on nothing here. Created only if absent; schema apply
-- never drops, truncates or recreates publication history.
CREATE SCHEMA IF NOT EXISTS voalack_publication;
CREATE OR REPLACE FUNCTION voalack_publication.refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'voalack: publication rows are immutable';
END;
$$;
CREATE TABLE IF NOT EXISTS voalack_publication.publications (
    note_id          text PRIMARY KEY
                     CHECK (note_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    action_id        uuid NOT NULL,
    epoch            bigint NOT NULL CHECK (epoch >= 1),
    revision         bigint NOT NULL CHECK (revision >= 1),
    event_sha256     text NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    note_row_sha256  text NOT NULL CHECK (note_row_sha256 ~ '^[0-9a-f]{64}$'),
    alert_id         text NOT NULL,
    customer         text,
    published_at     timestamptz NOT NULL DEFAULT clock_timestamp(),   -- a transaction record time, not COMMIT
    UNIQUE (action_id, epoch, revision)
);
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = 'voalack_publication.publications'::regclass
                     AND t.tgname = 'publications_immutable') THEN
        CREATE TRIGGER publications_immutable BEFORE UPDATE OR DELETE ON voalack_publication.publications
            FOR EACH ROW EXECUTE FUNCTION voalack_publication.refuse_change();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid = 'voalack_publication.publications'::regclass
                     AND t.tgname = 'publications_no_truncate') THEN
        CREATE TRIGGER publications_no_truncate BEFORE TRUNCATE ON voalack_publication.publications
            FOR EACH STATEMENT EXECUTE FUNCTION voalack_publication.refuse_change();
    END IF;
END;
$$;

-- Per-action revision allocation (writers only, under the row lock) and the projector's own position
-- (projector only: created and locked by project_next), kept apart so a stalled projector never delays
-- a delivery writer: no writer reads, inserts or locks a position row.
CREATE TABLE IF NOT EXISTS voalack.projection_actions (
    action_id      uuid PRIMARY KEY,
    last_revision  bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0),
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS voalack.projection_positions (
    action_id                uuid PRIMARY KEY,
    last_projected_revision  bigint NOT NULL DEFAULT 0 CHECK (last_projected_revision >= 0),
    created_at               timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- Outcome events: append-only, one per operator-visible change, with the frozen destination and the
-- complete presentation fixed before hashing (R1, C2).
CREATE TABLE IF NOT EXISTS voalack.outcome_events (
    event_id         bigserial PRIMARY KEY,
    action_id        uuid NOT NULL,
    revision         bigint NOT NULL CHECK (revision >= 1),
    epoch            bigint NOT NULL CHECK (epoch >= 1),
    outcome          text NOT NULL CHECK (outcome ~ ('^(queued|confirmed|already_acked|blocked|superseded|uncertain'
                         '|recovery_held|recovery_key_held'
                         '|settled:(confirmed_attributed|confirmed_by_operator|superseded_remote|retired_after_quiescence)'
                         '|recovery_key_released:(recovered_attributed|recovered_acked_unattributed|recovered_acked_by_other|recovered_retired)'
                         '|snapshot:(queued|confirmed|already_acked|blocked|superseded|uncertain))$')),
    reason           text,
    facts            jsonb NOT NULL CHECK (jsonb_typeof(facts) = 'object' AND octet_length(facts::text) <= 2048),
    occurred_at      timestamptz NOT NULL,
    txid             bigint NOT NULL,
    alert_id         text,
    customer         text,
    note_text        text CHECK (char_length(note_text) <= 400),
    note_time        timestamp without time zone,
    note_attributes  jsonb,
    event_sha256     text NOT NULL CHECK (event_sha256 ~ '^[0-9a-f]{64}$'),
    note_id          text NOT NULL,
    UNIQUE (action_id, revision),
    CHECK ((alert_id IS NULL) = (note_text IS NULL) AND (alert_id IS NULL) = (note_time IS NULL)
           AND (alert_id IS NULL) = (note_attributes IS NULL))
);
DROP TRIGGER IF EXISTS outcome_events_immutable ON voalack.outcome_events;
CREATE TRIGGER outcome_events_immutable BEFORE UPDATE OR DELETE ON voalack.outcome_events
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();
-- Projection markers: one per event, append-only. Stops (destination_conflict, note_conflict) keep the
-- position; every other status advances it.
CREATE TABLE IF NOT EXISTS voalack.projections (
    projection_id    bigserial PRIMARY KEY,
    action_id        uuid NOT NULL,
    revision         bigint NOT NULL,
    epoch            bigint NOT NULL,
    event_sha256     text NOT NULL,
    note_id          text NOT NULL,
    note_row_sha256  text,
    status           text NOT NULL CHECK (status IN ('projected', 'reconciled', 'publication_note_missing',
                                                     'publication_note_altered', 'publication_conflict',
                                                     'superseded_by_publication', 'unprojectable',
                                                     'destination_conflict', 'note_conflict')),
    detail           text CHECK (octet_length(detail) <= 256),
    projector        text NOT NULL CHECK (octet_length(projector) BETWEEN 1 AND 128),
    projected_at     timestamptz NOT NULL DEFAULT clock_timestamp(),  -- a transaction record time, not COMMIT
    UNIQUE (action_id, revision)
);
DROP TRIGGER IF EXISTS projections_immutable ON voalack.projections;
CREATE TRIGGER projections_immutable BEFORE UPDATE OR DELETE ON voalack.projections
    FOR EACH ROW EXECUTE FUNCTION voalack.refuse_change();

-- Canonical JSON (D4): UTF-8, keys sorted by their bytes, no whitespace, to_json string escapes,
-- integers only, explicit nulls.
CREATE OR REPLACE FUNCTION voalack._canonical(p jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    kind text := jsonb_typeof(p);
    out text;
BEGIN
    IF p IS NULL OR kind = 'null' THEN
        RETURN 'null';
    ELSIF kind = 'object' THEN
        SELECT '{' || coalesce(string_agg(to_json(o.k)::text || ':' || voalack._canonical(o.v), ',' ORDER BY o.k COLLATE "C"), '') || '}'
          INTO out FROM jsonb_each(p) AS o(k, v);
        RETURN out;
    ELSIF kind = 'array' THEN
        SELECT '[' || coalesce(string_agg(voalack._canonical(x.v), ',' ORDER BY x.i), '') || ']'
          INTO out FROM jsonb_array_elements(p) WITH ORDINALITY AS x(v, i);
        RETURN out;
    ELSIF kind = 'string' THEN
        RETURN to_json(p #>> '{}')::text;
    ELSIF kind = 'number' THEN
        IF p::text !~ '^-?(0|[1-9][0-9]*)$' THEN
            RAISE EXCEPTION 'voalack: canonical JSON holds integers only';
        END IF;
        RETURN p::text;
    END IF;
    RETURN p::text;                                          -- true, false
END;
$$;
-- UTC, always six microsecond digits: YYYY-MM-DDTHH:MM:SS.ffffffZ.
CREATE OR REPLACE FUNCTION voalack._utc(p timestamptz) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT to_char(p AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;
-- Alerta's timestamp-without-time-zone columns hold UTC wall time.
CREATE OR REPLACE FUNCTION voalack._utc_wall(p timestamp) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT to_char(p, 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;
-- Note id (D7.1): RFC 9562 UUIDv8 over sha256(namespace 31964abc-7784-44a0-a81f-4a1f829a329d || event digest).
CREATE OR REPLACE FUNCTION voalack._note_id(p_event_sha256 text) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    d bytea;
    h text;
BEGIN
    d := substring(sha256(decode('31964abc778444a0a81f4a1f829a329d', 'hex') || convert_to(p_event_sha256, 'UTF8'))
                   FROM 1 FOR 16);
    d := set_byte(d, 6, (get_byte(d, 6) & 15) | 128);
    d := set_byte(d, 8, (get_byte(d, 8) & 63) | 128);
    h := encode(d, 'hex');
    RETURN substr(h, 1, 8) || '-' || substr(h, 9, 4) || '-' || substr(h, 13, 4) || '-' || substr(h, 17, 4) || '-'
           || substr(h, 21, 12);
END;
$$;
-- The complete note row as stored (D4), or NULL when there is no row; a row that cannot be put in
-- canonical form (for example a float in its attributes) is reported as '' (never equal to a digest).
CREATE OR REPLACE FUNCTION voalack._note_row_sha256(p_note_id text) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    doc jsonb;
BEGIN
    SELECT jsonb_build_object('id', n.id, 'text', n.text, 'user', n."user", 'attributes', n.attributes,
                              'type', n.type, 'create_time', voalack._utc_wall(n.create_time),
                              'update_time', voalack._utc_wall(n.update_time), 'alert', n.alert, 'customer', n.customer)
      INTO doc FROM public.notes n WHERE n.id = p_note_id;
    IF doc IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN encode(sha256(convert_to(voalack._canonical(doc), 'UTF8')), 'hex');
EXCEPTION WHEN raise_exception THEN
    RETURN '';
END;
$$;
CREATE OR REPLACE FUNCTION voalack._state_outcome(p_state text) RETURNS text
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT CASE p_state WHEN 'QUEUED' THEN 'queued' WHEN 'REMOTE_CONFIRMED' THEN 'confirmed'
                        WHEN 'ALREADY_ACKED' THEN 'already_acked' WHEN 'BLOCKED' THEN 'blocked'
                        WHEN 'SUPERSEDED' THEN 'superseded' WHEN 'UNCERTAIN' THEN 'uncertain' END
$$;
-- Fixed sentences (r1 §4): an uncertain ACK is never worded as applied; already-acked claims no
-- attribution; a recovery hold says what is held, not what happened remotely.
CREATE OR REPLACE FUNCTION voalack._outcome_sentence(p_outcome text) RETURNS text
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT CASE
        WHEN p_outcome = 'queued' THEN 'ACK queued for Veeam ONE'
        WHEN p_outcome = 'confirmed' THEN 'ACK confirmed by Veeam ONE'
        WHEN p_outcome = 'already_acked' THEN 'Veeam ONE shows the alarm as already acknowledged'
        WHEN p_outcome = 'blocked' THEN 'ACK blocked; not sent'
        WHEN p_outcome = 'superseded' THEN 'ACK superseded; not sent'
        WHEN p_outcome = 'uncertain' THEN 'ACK may have reached Veeam ONE; held, not resent'
        WHEN p_outcome = 'recovery_held' THEN 'ACK held after a database restore; not sent until reviewed'
        WHEN p_outcome = 'recovery_key_held' THEN 'Veeam ONE target held after a database restore'
        WHEN p_outcome LIKE 'settled:%' THEN 'uncertain ACK settled as ' || substr(p_outcome, 9)
        WHEN p_outcome LIKE 'recovery_key_released:%' THEN 'restore hold released as ' || substr(p_outcome, 23)
        WHEN p_outcome LIKE 'snapshot:%' THEN 'snapshot of the recorded outcome (' || substr(p_outcome, 10)
                                              || '); historical time unknown'
    END
$$;

-- The projection rows of several actions, created if absent and locked in action order (D5 Invariant B).
CREATE OR REPLACE FUNCTION voalack._lock_projection_actions(p_actions uuid[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    INSERT INTO voalack.projection_actions (action_id)
    SELECT DISTINCT x FROM unnest(p_actions) x WHERE x IS NOT NULL ORDER BY 1
    ON CONFLICT DO NOTHING;
    PERFORM 1 FROM voalack.projection_actions p WHERE p.action_id = ANY(p_actions) ORDER BY p.action_id FOR UPDATE;
END;
$$;

-- The epoch row pin (D7.4 corrected, spec D8): the singleton recovery_epoch row FOR SHARE, held
-- to COMMIT, and a transaction-local marker bound to this transaction id. Every event-producing entry
-- point calls this as its first statement, before any source lock, in every phase (a closed or
-- recovering database still records holds and refusals). A rolled-back savepoint reverts both the
-- row lock and the marker. Returns false (no marker) when the row does not exist.
CREATE OR REPLACE FUNCTION voalack._pin_epoch() RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
BEGIN
    PERFORM 1 FROM voalack.recovery_epoch r FOR SHARE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    PERFORM set_config('voalack.epoch_pin', txid_current()::text, true);
    RETURN true;
END;
$$;

-- Append one outcome event (R1, C2, C3, D4). The caller's transaction must have pinned the epoch row
-- first (_pin_epoch: the marker of this transaction); a relation lock alone is not a pin. The marker is a
-- custom setting any caller can set (PGC_USERSET): it is an internal guard against an unpinned path, not a
-- capability. The protection is the real row pin each producer takes first, and that no runtime role can
-- write an event source or call this helper directly. The epoch read
-- here is that pinned row (or the adoption's own write of it), never a stale unlocked read.
CREATE OR REPLACE FUNCTION voalack._append_event(p_action uuid, p_outcome text, p_facts jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    r voalack.recovery_epoch%ROWTYPE;
    rev bigint;
    d_alert text;
    d_customer text;
    d_issued timestamptz;
    at timestamptz := clock_timestamp();
    txt text;
    wall timestamp;
    pre jsonb;
    sha text;
    attrs jsonb;
BEGIN
    IF current_setting('voalack.epoch_pin', true) IS DISTINCT FROM txid_current()::text THEN
        -- Pre-initialization history: only with no epoch row and only for a superuser session (the schema
        -- application). No caller-settable setting selects this branch; a runtime login never does.
        IF NOT EXISTS (SELECT 1 FROM voalack.recovery_epoch)
           AND EXISTS (SELECT 1 FROM pg_roles x WHERE x.rolname = session_user AND x.rolsuper) THEN
            RETURN;
        END IF;
        RAISE EXCEPTION 'voalack: an outcome event needs a transaction that pinned the recovery epoch row first';
    END IF;
    SELECT * INTO r FROM voalack.recovery_epoch x;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: an outcome event needs an initialized recovery epoch';
    END IF;
    INSERT INTO voalack.projection_actions (action_id) VALUES (p_action) ON CONFLICT DO NOTHING;
    UPDATE voalack.projection_actions x SET last_revision = x.last_revision + 1
     WHERE x.action_id = p_action RETURNING x.last_revision INTO rev;
    -- The destination comes only from the immutable accepted intent (D3), never from current attributes.
    SELECT i.alert_id, i.customer, i.issued_at INTO d_alert, d_customer, d_issued
      FROM voalack.prepared_intents i WHERE i.action_id = p_action;
    IF d_alert IS NOT NULL THEN
        txt := format('[Voalack] %s · epoch %s · action %s · revision %s · ACK requested %s · outcome recorded %s',
                      voalack._outcome_sentence(p_outcome), r.epoch, p_action, rev,
                      coalesce(voalack._utc(d_issued), 'unknown'), voalack._utc(at));
        wall := at AT TIME ZONE 'UTC';
    END IF;
    pre := jsonb_build_object('action_id', p_action, 'epoch', r.epoch, 'revision', rev, 'outcome', p_outcome,
                              'reason', NULL, 'facts', p_facts, 'occurred_at', voalack._utc(at),
                              'alert_id', d_alert, 'customer', d_customer, 'note_text', txt,
                              'note_time', voalack._utc_wall(wall));
    sha := encode(sha256(convert_to(voalack._canonical(pre), 'UTF8')), 'hex');
    IF d_alert IS NOT NULL THEN
        attrs := jsonb_build_object('voalack', jsonb_build_object('action_id', p_action, 'epoch', r.epoch,
                                                                  'revision', rev, 'event_sha256', sha));
    END IF;
    INSERT INTO voalack.outcome_events (action_id, revision, epoch, outcome, reason, facts, occurred_at, txid,
                                        alert_id, customer, note_text, note_time, note_attributes, event_sha256, note_id)
    VALUES (p_action, rev, r.epoch, p_outcome, NULL, p_facts, at, txid_current(), d_alert, d_customer, txt, wall,
            attrs, sha, voalack._note_id(sha));
END;
$$;

-- One trigger function for every event source (R3 table, r3 C3): AFTER row triggers, so events follow
-- the actual statement order with no coalescing. A failure here rolls back the source transaction.
CREATE OR REPLACE FUNCTION voalack._outcome_event() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    a uuid;
BEGIN
    IF TG_TABLE_SCHEMA <> 'voalack' OR TG_WHEN <> 'AFTER' OR TG_LEVEL <> 'ROW' THEN
        RAISE EXCEPTION 'voalack: outcome event from an unexpected trigger';
    END IF;
    IF TG_TABLE_NAME = 'effects' AND TG_OP = 'INSERT' THEN
        PERFORM voalack._append_event(NEW.action_id, voalack._state_outcome(NEW.state),
                                      jsonb_build_object('effect_id', NEW.effect_id, 'state', NEW.state));
    ELSIF TG_TABLE_NAME = 'effects' AND TG_OP = 'UPDATE' THEN
        IF NEW.state IS DISTINCT FROM OLD.state THEN
            PERFORM voalack._append_event(NEW.action_id, voalack._state_outcome(NEW.state),
                                          jsonb_build_object('effect_id', NEW.effect_id, 'state', NEW.state,
                                                             'prior_state', OLD.state, 'attempt_id', OLD.in_flight_attempt));
        END IF;
    ELSIF TG_TABLE_NAME = 'settlements' AND TG_OP = 'INSERT' THEN
        PERFORM voalack._append_event(NEW.action_id, 'settled:' || NEW.outcome,
                                      jsonb_build_object('settlement_id', NEW.settlement_id, 'attempt_id', NEW.attempt_id,
                                                         'effect_id', NEW.effect_id, 'path', NEW.path));
    ELSIF TG_TABLE_NAME = 'recovered_effects' AND TG_OP = 'INSERT' THEN
        IF NEW.action_id IS NOT NULL THEN
            PERFORM voalack._append_event(NEW.action_id, 'recovery_held',
                                          jsonb_build_object('adoption_id', NEW.adoption_id));
        END IF;
    ELSIF TG_TABLE_NAME = 'recovered_holds' AND TG_OP = 'INSERT' THEN
        FOR a IN SELECT DISTINCT (m->>'action_id')::uuid FROM jsonb_array_elements(NEW.members) m
                  WHERE m->>'action_id' IS NOT NULL ORDER BY 1 LOOP
            PERFORM voalack._append_event(a, 'recovery_key_held',
                                          jsonb_build_object('adoption_id', NEW.adoption_id, 'hold_id', NEW.hold_id,
                                                             'target_kind', NEW.target_kind));
        END LOOP;
    ELSIF TG_TABLE_NAME = 'recovery_settlements' AND TG_OP = 'INSERT' THEN
        FOR a IN SELECT DISTINCT (m->>'action_id')::uuid
                   FROM voalack.recovered_holds h, jsonb_array_elements(h.members) m
                  WHERE h.hold_id = NEW.hold_id AND m->>'action_id' IS NOT NULL ORDER BY 1 LOOP
            PERFORM voalack._append_event(a, 'recovery_key_released:' || NEW.outcome,
                                          jsonb_build_object('hold_id', NEW.hold_id,
                                                             'recovery_settlement_id', NEW.recovery_settlement_id));
        END LOOP;
    ELSE
        RAISE EXCEPTION 'voalack: outcome event from an unexpected source %.%', TG_TABLE_NAME, TG_OP;
    END IF;
    RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS effects_outcome_insert ON voalack.effects;
CREATE TRIGGER effects_outcome_insert AFTER INSERT ON voalack.effects
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();
DROP TRIGGER IF EXISTS effects_outcome_state ON voalack.effects;
CREATE TRIGGER effects_outcome_state AFTER UPDATE OF state ON voalack.effects
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();
DROP TRIGGER IF EXISTS settlements_outcome ON voalack.settlements;
CREATE TRIGGER settlements_outcome AFTER INSERT ON voalack.settlements
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();
DROP TRIGGER IF EXISTS recovered_effects_outcome ON voalack.recovered_effects;
CREATE TRIGGER recovered_effects_outcome AFTER INSERT ON voalack.recovered_effects
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();
DROP TRIGGER IF EXISTS recovered_holds_outcome ON voalack.recovered_holds;
CREATE TRIGGER recovered_holds_outcome AFTER INSERT ON voalack.recovered_holds
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();
DROP TRIGGER IF EXISTS recovery_settlements_outcome ON voalack.recovery_settlements;
CREATE TRIGGER recovery_settlements_outcome AFTER INSERT ON voalack.recovery_settlements
    FOR EACH ROW EXECUTE FUNCTION voalack._outcome_event();

-- R4: the six event triggers exactly as installed (AFTER, FOR EACH ROW, the one function, the exact
-- event mask, no WHEN, no constraint trigger, enabled for ordinary sessions).
CREATE OR REPLACE FUNCTION voalack._event_coverage_ready() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT count(*) = 6
      FROM (VALUES ('effects', 'effects_outcome_insert', 'INSERT'), ('effects', 'effects_outcome_state', 'STATE'),
                   ('settlements', 'settlements_outcome', 'INSERT'),
                   ('recovered_effects', 'recovered_effects_outcome', 'INSERT'),
                   ('recovered_holds', 'recovered_holds_outcome', 'INSERT'),
                   ('recovery_settlements', 'recovery_settlements_outcome', 'INSERT')) req(tbl, name, mask)
     WHERE EXISTS (
        SELECT 1 FROM pg_trigger t
         WHERE t.tgrelid = to_regclass('voalack.' || req.tbl) AND t.tgname = req.name
           AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal AND t.tgconstraint = 0
           AND t.tgfoid = to_regprocedure('voalack._outcome_event()')
           AND t.tgtype & 1 = 1 AND t.tgtype & 2 = 0 AND t.tgtype & 64 = 0 AND t.tgqual IS NULL
           AND CASE req.mask
                 WHEN 'INSERT' THEN t.tgtype & 60 = 4 AND cardinality(t.tgattr::int2[]) = 0
                 ELSE t.tgtype & 60 = 16 AND cardinality(t.tgattr::int2[]) = 1      -- int2vector: subscript 0
                      AND t.tgattr[0] = (SELECT a.attnum FROM pg_attribute a
                                          WHERE a.attrelid = t.tgrelid AND a.attname = 'state')
               END)
$$;

-- The projector's one step (r1 §1, R2, R5, C1, D3, D4, D7.2). Gate first: exactly the open epoch and
-- head the projector read from the anchor, FOR SHARE until COMMIT; otherwise 'paused' before any write.
-- Then one action's position (SKIP LOCKED, oldest pending event first), its next event only
-- (revision = last projected + 1), and one disposition, all in this transaction: a note, its protected
-- publication, the marker and the position commit or roll back together.
CREATE OR REPLACE FUNCTION voalack.project_next(p_projector text, p_epoch bigint, p_head_sha256 text)
RETURNS TABLE (outcome text, action_id uuid, revision bigint, note_id text, status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    a uuid;
    cand uuid;
    seen boolean := false;
    pos voalack.projection_positions%ROWTYPE;
    e voalack.outcome_events%ROWTYPE;
    pub voalack_publication.publications%ROWTYPE;
    hw_epoch bigint;
    hw_rev bigint;
    al_customer text;
    st text;
    det text;
    row_sha text;
BEGIN
    IF p_projector IS NULL OR octet_length(p_projector) NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION 'voalack: a projector name is required';
    END IF;
    PERFORM 1 FROM voalack.recovery_epoch r
     WHERE r.epoch = p_epoch AND r.head_sha256 = p_head_sha256 AND r.phase = 'open' FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'paused'::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;
    -- Candidates, oldest pending event first (no lock), then the first whose position this projector can
    -- lock (SKIP LOCKED: another projector's action is left to it). A missing position row is created
    -- here, by projectors only. The scan has no fixed bound: actions locked by other projectors never hide
    -- a later unlocked one ('busy' when every pending action is locked elsewhere; 'idle' only when none).
    FOR cand IN
        SELECT x.action_id FROM voalack.projection_actions x
          LEFT JOIN voalack.projection_positions p ON p.action_id = x.action_id
         WHERE x.last_revision > coalesce(p.last_projected_revision, 0)
           AND NOT EXISTS (SELECT 1 FROM voalack.projections m
                            WHERE m.action_id = x.action_id AND m.revision = coalesce(p.last_projected_revision, 0) + 1)
         ORDER BY (SELECT ev.event_id FROM voalack.outcome_events ev
                    WHERE ev.action_id = x.action_id AND ev.revision = coalesce(p.last_projected_revision, 0) + 1)
    LOOP
        seen := true;
        IF NOT EXISTS (SELECT 1 FROM voalack.projection_positions p WHERE p.action_id = cand) THEN
            INSERT INTO voalack.projection_positions (action_id) VALUES (cand) ON CONFLICT DO NOTHING;
        END IF;
        SELECT p.action_id INTO a FROM voalack.projection_positions p WHERE p.action_id = cand FOR UPDATE SKIP LOCKED;
        EXIT WHEN a IS NOT NULL;
    END LOOP;
    IF a IS NULL THEN
        RETURN QUERY SELECT CASE WHEN seen THEN 'busy' ELSE 'idle' END::text, NULL::uuid, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;
    -- After the lock: the ordering fence is this re-read (revision = last projected + 1).
    SELECT * INTO pos FROM voalack.projection_positions p WHERE p.action_id = a;
    SELECT * INTO e FROM voalack.outcome_events ev WHERE ev.action_id = a AND ev.revision = pos.last_projected_revision + 1;
    IF NOT FOUND OR EXISTS (SELECT 1 FROM voalack.projections m WHERE m.action_id = a AND m.revision = e.revision) THEN
        RETURN QUERY SELECT 'retry'::text, a, NULL::bigint, NULL::text, NULL::text;
        RETURN;
    END IF;
    IF e.alert_id IS NULL THEN
        st := 'unprojectable';
        det := 'missing_original';
    ELSE
        SELECT * INTO pub FROM voalack_publication.publications x
         WHERE x.action_id = a AND x.epoch = e.epoch AND x.revision = e.revision;
        IF FOUND THEN
            -- The same (epoch, revision) was published before (another lineage of this database): an
            -- identical event reconciles only if its note is still exactly the published row.
            IF pub.event_sha256 = e.event_sha256 AND pub.note_id = e.note_id THEN
                row_sha := voalack._note_row_sha256(e.note_id);
                st := CASE WHEN row_sha IS NULL THEN 'publication_note_missing'
                           WHEN row_sha = pub.note_row_sha256 THEN 'reconciled'
                           ELSE 'publication_note_altered' END;
            ELSE
                st := 'publication_conflict';
                det := 'published ' || pub.note_id;
            END IF;
        ELSE
            SELECT x.epoch, x.revision INTO hw_epoch, hw_rev FROM voalack_publication.publications x
             WHERE x.action_id = a ORDER BY x.epoch DESC, x.revision DESC LIMIT 1;
            IF hw_epoch IS NOT NULL AND (e.epoch, e.revision) < (hw_epoch, hw_rev) THEN
                st := 'superseded_by_publication';
                det := 'high-water ' || hw_epoch || ':' || hw_rev;
            ELSE
                SELECT al.customer INTO al_customer FROM public.alerts al WHERE al.id = e.alert_id FOR SHARE;
                IF NOT FOUND THEN
                    st := 'destination_conflict';
                    det := 'alert missing';
                ELSIF al_customer IS DISTINCT FROM e.customer THEN
                    st := 'destination_conflict';
                    det := 'alert customer changed';
                ELSIF EXISTS (SELECT 1 FROM public.notes n WHERE n.id = e.note_id) THEN
                    st := 'note_conflict';
                    det := 'an unproven note holds the id';
                ELSE
                    INSERT INTO public.notes (id, text, "user", attributes, type, create_time, update_time, alert, customer)
                    VALUES (e.note_id, e.note_text, 'voalack', e.note_attributes, 'alert', e.note_time, e.note_time,
                            e.alert_id, e.customer);
                    row_sha := voalack._note_row_sha256(e.note_id);
                    INSERT INTO voalack_publication.publications (note_id, action_id, epoch, revision, event_sha256,
                                                                  note_row_sha256, alert_id, customer)
                    VALUES (e.note_id, a, e.epoch, e.revision, e.event_sha256, row_sha, e.alert_id, e.customer);
                    st := 'projected';
                END IF;
            END IF;
        END IF;
    END IF;
    INSERT INTO voalack.projections (action_id, revision, epoch, event_sha256, note_id, note_row_sha256, status,
                                     detail, projector)
    VALUES (a, e.revision, e.epoch, e.event_sha256, e.note_id,
            CASE WHEN st IN ('projected', 'reconciled') THEN row_sha END, st, det, p_projector);
    IF st NOT IN ('destination_conflict', 'note_conflict') THEN
        UPDATE voalack.projection_positions p SET last_projected_revision = e.revision WHERE p.action_id = a;
    END IF;
    RETURN QUERY SELECT 'done'::text, a, e.revision, e.note_id, st;
END;
$$;

-- What an operator or the projector may rely on for one action (D3): the latest protected publication
-- by (epoch, revision) and whether its note is still exactly the published row; "current" is that
-- publication only when its display is valid. Not a statement about the present remote state.
CREATE OR REPLACE FUNCTION voalack.projection_status(p_action uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    pub voalack_publication.publications%ROWTYPE;
    display text;
    row_sha text;
    al record;
BEGIN
    SELECT * INTO pub FROM voalack_publication.publications x
     WHERE x.action_id = p_action ORDER BY x.epoch DESC, x.revision DESC LIMIT 1;
    IF FOUND THEN
        row_sha := voalack._note_row_sha256(pub.note_id);
        display := CASE WHEN row_sha IS NULL THEN 'missing' WHEN row_sha <> pub.note_row_sha256 THEN 'altered' ELSE 'valid' END;
        IF display = 'valid' AND NOT EXISTS (SELECT 1 FROM public.notes n
                                              WHERE n.id = pub.note_id AND n.alert = pub.alert_id
                                                AND n.customer IS NOT DISTINCT FROM pub.customer) THEN
            display := 'altered';
        END IF;
    END IF;
    RETURN jsonb_build_object(
        'action_id', p_action,
        'last_revision', (SELECT x.last_revision FROM voalack.projection_actions x WHERE x.action_id = p_action),
        'last_projected_revision', coalesce((SELECT x.last_projected_revision FROM voalack.projection_positions x
                                              WHERE x.action_id = p_action), 0),
        'latest_publication', CASE WHEN pub.note_id IS NULL THEN NULL ELSE jsonb_build_object(
            'note_id', pub.note_id, 'epoch', pub.epoch, 'revision', pub.revision, 'event_sha256', pub.event_sha256,
            'published_at', voalack._utc(pub.published_at), 'display', display) END,
        'current', CASE WHEN display = 'valid' THEN jsonb_build_object('note_id', pub.note_id, 'epoch', pub.epoch,
                                                                       'revision', pub.revision) END,
        'markers', (SELECT coalesce(jsonb_object_agg(m.status, m.n), '{}'::jsonb)
                      FROM (SELECT x.status, count(*) AS n FROM voalack.projections x
                             WHERE x.action_id = p_action GROUP BY x.status) m),
        'stopped', (SELECT jsonb_build_object('revision', x.revision, 'status', x.status, 'detail', x.detail)
                      FROM voalack.projections x
                     WHERE x.action_id = p_action
                       AND x.revision = coalesce((SELECT p.last_projected_revision FROM voalack.projection_positions p
                                                   WHERE p.action_id = p_action), 0) + 1));
END;
$$;

-- Unknown-COMMIT resolution (D4, D12/F1): in a fresh transaction, the projector's remembered step is
-- compared with the stored event, its marker and, for a published disposition, the protected publication
-- and the actual note row (identity, frozen audience and complete row digest). 'not_committed' when no
-- marker exists for the revision; 'committed' only when every binding agrees; otherwise 'conflict'.
-- Read only: nothing is repaired, overwritten or retried here.
CREATE OR REPLACE FUNCTION voalack.projection_resolve(p_action uuid, p_revision bigint, p_note_id text, p_status text)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    e voalack.outcome_events%ROWTYPE;
    m voalack.projections%ROWTYPE;
    pub voalack_publication.publications%ROWTYPE;
BEGIN
    SELECT * INTO m FROM voalack.projections x WHERE x.action_id = p_action AND x.revision = p_revision;
    IF NOT FOUND THEN
        RETURN 'not_committed';
    END IF;
    SELECT * INTO e FROM voalack.outcome_events x WHERE x.action_id = p_action AND x.revision = p_revision;
    IF NOT FOUND OR (m.note_id, m.status, m.epoch, m.event_sha256) IS DISTINCT FROM (p_note_id, p_status, e.epoch, e.event_sha256)
       OR e.note_id IS DISTINCT FROM p_note_id THEN
        RETURN 'conflict';
    END IF;
    IF m.status IN ('projected', 'reconciled') THEN
        SELECT * INTO pub FROM voalack_publication.publications x
         WHERE x.note_id = p_note_id AND x.action_id = p_action AND x.epoch = e.epoch AND x.revision = e.revision
           AND x.event_sha256 = e.event_sha256 AND x.alert_id = e.alert_id
           AND x.customer IS NOT DISTINCT FROM e.customer AND x.note_row_sha256 = m.note_row_sha256;
        IF NOT FOUND OR voalack._note_row_sha256(p_note_id) IS DISTINCT FROM pub.note_row_sha256
           OR NOT EXISTS (SELECT 1 FROM public.notes n WHERE n.id = p_note_id AND n.alert = pub.alert_id
                            AND n.customer IS NOT DISTINCT FROM pub.customer) THEN
            RETURN 'conflict';
        END IF;
    END IF;
    RETURN 'committed';
END;
$$;

-- Administrator only (r1 §6): one snapshot event per existing effect whose action has no events. Epoch
-- first, then the effects table (SHARE: no effect writer in between), then projection rows in action order.
CREATE OR REPLACE FUNCTION voalack.backfill_projection_snapshot() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    n integer := 0;
    x record;
BEGIN
    IF NOT voalack._pin_epoch() THEN
        RAISE EXCEPTION 'voalack: recovery epoch is not initialized';
    END IF;
    IF NOT voalack._event_coverage_ready() THEN
        RAISE EXCEPTION 'voalack: outcome-event coverage is incomplete';
    END IF;
    LOCK TABLE voalack.effects IN SHARE MODE;
    FOR x IN SELECT e.effect_id, e.action_id, e.state FROM voalack.effects e
              WHERE NOT EXISTS (SELECT 1 FROM voalack.projection_actions p
                                 WHERE p.action_id = e.action_id AND p.last_revision > 0)
              ORDER BY e.action_id LOOP
        PERFORM voalack._append_event(x.action_id, 'snapshot:' || voalack._state_outcome(x.state),
                                      jsonb_build_object('effect_id', x.effect_id, 'state', x.state,
                                                         'historical_time', 'unknown'));
        n := n + 1;
    END LOOP;
    RETURN n;
END;
$$;

-- Alerta 9.1.0 tables (r1 §8, D7.3): the exact notes layout, and the definer's only rights on them.
DO $$
BEGIN
    IF to_regclass('public.notes') IS NOT NULL AND to_regclass('public.alerts') IS NOT NULL THEN
        IF (SELECT string_agg(a.attname || ':' || format_type(a.atttypid, a.atttypmod), ',' ORDER BY a.attnum)
              FROM pg_attribute a WHERE a.attrelid = 'public.notes'::regclass AND a.attnum > 0 AND NOT a.attisdropped)
           <> 'id:text,text:text,user:text,attributes:jsonb,type:text,create_time:timestamp without time zone,'
              'update_time:timestamp without time zone,alert:text,customer:text' THEN
            RAISE EXCEPTION 'voalack: public.notes is not the Alerta 9.1.0 layout';
        END IF;
        GRANT SELECT, INSERT ON public.notes TO voalack_admin;
        GRANT SELECT, UPDATE (id) ON public.alerts TO voalack_admin;
        IF has_table_privilege('voalack_admin', 'public.notes', 'UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
           OR has_table_privilege('voalack_admin', 'public.alerts', 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')
           OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = 'public.alerts'::regclass AND a.attnum > 0
                        AND NOT a.attisdropped AND a.attname <> 'id'
                        AND has_column_privilege('voalack_admin', a.attrelid, a.attnum, 'UPDATE, INSERT, REFERENCES'))
           OR EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = 'public.notes'::regclass AND a.attnum > 0
                        AND NOT a.attisdropped AND has_column_privilege('voalack_admin', a.attrelid, a.attnum, 'UPDATE, REFERENCES'))
           OR pg_has_role('voalack_admin', (SELECT c.relowner FROM pg_class c WHERE c.oid = 'public.notes'::regclass), 'MEMBER')
           OR pg_has_role('voalack_admin', (SELECT c.relowner FROM pg_class c WHERE c.oid = 'public.alerts'::regclass), 'MEMBER') THEN
            RAISE EXCEPTION 'voalack: voalack_admin has more than its projection rights on Alerta''s tables';
        END IF;
    END IF;
END;
$$;
DO $$
BEGIN
    IF NOT voalack._event_coverage_ready() THEN
        RAISE EXCEPTION 'voalack: outcome-event coverage is incomplete';
    END IF;
END;
$$;

-- S4 ownership and privileges. The projector reads its own tables and executes only project_next and
-- projection_status; no runtime role has any right in voalack_publication.
ALTER SCHEMA voalack_publication OWNER TO voalack_admin;
ALTER TABLE voalack_publication.publications OWNER TO voalack_admin;
ALTER FUNCTION voalack_publication.refuse_change() OWNER TO voalack_admin;
ALTER TABLE voalack.projection_actions OWNER TO voalack_admin;
ALTER TABLE voalack.projection_positions OWNER TO voalack_admin;
ALTER TABLE voalack.outcome_events OWNER TO voalack_admin;
ALTER SEQUENCE voalack.outcome_events_event_id_seq OWNER TO voalack_admin;
ALTER TABLE voalack.projections OWNER TO voalack_admin;
ALTER SEQUENCE voalack.projections_projection_id_seq OWNER TO voalack_admin;
ALTER FUNCTION voalack._canonical(jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._utc(timestamptz) OWNER TO voalack_admin;
ALTER FUNCTION voalack._utc_wall(timestamp) OWNER TO voalack_admin;
ALTER FUNCTION voalack._note_id(text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._note_row_sha256(text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._state_outcome(text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._outcome_sentence(text) OWNER TO voalack_admin;
ALTER FUNCTION voalack._lock_projection_actions(uuid[]) OWNER TO voalack_admin;
ALTER FUNCTION voalack._pin_epoch() OWNER TO voalack_admin;
ALTER FUNCTION voalack._append_event(uuid, text, jsonb) OWNER TO voalack_admin;
ALTER FUNCTION voalack._outcome_event() OWNER TO voalack_admin;
ALTER FUNCTION voalack._event_coverage_ready() OWNER TO voalack_admin;
ALTER FUNCTION voalack.project_next(text, bigint, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.projection_status(uuid) OWNER TO voalack_admin;
ALTER FUNCTION voalack.projection_resolve(uuid, bigint, text, text) OWNER TO voalack_admin;
ALTER FUNCTION voalack.backfill_projection_snapshot() OWNER TO voalack_admin;
REVOKE ALL ON SCHEMA voalack_publication FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA voalack_publication FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA voalack_publication FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA voalack FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA voalack FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA voalack FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA voalack FROM voalack_projector;
GRANT USAGE ON SCHEMA voalack TO voalack_projector;
GRANT SELECT ON voalack.outcome_events, voalack.projections, voalack.projection_actions, voalack.projection_positions
    TO voalack_projector;
GRANT EXECUTE ON FUNCTION voalack.project_next(text, bigint, text), voalack.projection_status(uuid),
    voalack.projection_resolve(uuid, bigint, text, text)
    TO voalack_projector;
