-- Voalack capture schema (T03b, development). Lives beside Alerta's tables; it never stores
-- integration state in public.alerts. Idempotent: safe to apply repeatedly.
-- Apply as a superuser. Prerequisite roles: voalack_admin (owns everything here, no login) and
-- voalack_app (no login; holds only the capture path's grants). Alerta's runtime login is a
-- member of voalack_app and never of voalack_admin; it owns Alerta's own tables (Alerta alters
-- them at startup), so it could disable the capture trigger on public.alerts: an eligible ACK then
-- finds no capture and rolls back (fail closed).
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
BEGIN
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
BEGIN
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

-- Owner fence: the caller's instance, generation and process incarnation must be current and in one
-- of the given states; locks the owner row FOR SHARE.
CREATE OR REPLACE FUNCTION voalack._owner_fenced(p_instance text, p_generation bigint, p_incarnation uuid,
                                                 p_states text[]) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT EXISTS (SELECT 1 FROM voalack.session_owners o
                    WHERE o.instance_id = p_instance AND o.owner_generation = p_generation
                      AND o.incarnation = p_incarnation AND o.state = ANY(p_states)
                      FOR SHARE)
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

CREATE OR REPLACE FUNCTION voalack.acquire_owner(p_instance text, p_owner_id text, p_incarnation uuid)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
DECLARE
    new_generation bigint;
    ic voalack.instance_config%ROWTYPE;
BEGIN
    SELECT * INTO ic FROM voalack.instance_config c WHERE c.instance_id = p_instance FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'voalack: instance is not configured';
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
           bound_provider_contract = ic.provider_contract
     WHERE o.instance_id = p_instance AND o.state IN ('free', 'contained')
    RETURNING o.owner_generation INTO new_generation;
    IF new_generation IS NULL THEN
        RAISE EXCEPTION 'voalack: instance owner is not free or contained';
    END IF;
    RETURN new_generation;
END;
$$;

-- The caller's owner state, or 'config_changed' when the instance's credential or configuration
-- revision is no longer the one this owner acquired under (its session must not be used).
CREATE OR REPLACE FUNCTION voalack.check_owner(p_instance text, p_generation bigint, p_incarnation uuid)
RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, voalack, pg_temp AS $$
    SELECT CASE WHEN (o.bound_credential_ref, o.bound_config_revision, o.bound_provider_contract)
                     IS DISTINCT FROM (ic.credential_ref, ic.config_revision, ic.provider_contract) THEN 'config_changed'
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
        PERFORM voalack._release_no_dispatch(p_attempt, 'QUEUED');
        RETURN QUERY SELECT 'aborted:owner_fenced'::text, NULL::bytea; RETURN;
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
    IF NOT voalack._owner_fenced(p_instance, p_generation, p_incarnation, ARRAY['active']) THEN
        RAISE EXCEPTION 'voalack: owner fenced';
    END IF;
    FOR att IN SELECT a.attempt_id AS id, a.effect_id, a.state FROM voalack.attempts a
                WHERE a.instance_id = p_instance AND a.owner_generation < p_generation
                  AND a.state IN ('started', 'dispatched') ORDER BY a.started_at LOOP
        PERFORM 1 FROM voalack.effects e WHERE e.effect_id = att.effect_id FOR UPDATE;
        PERFORM 1 FROM voalack.attempts a WHERE a.attempt_id = att.id FOR UPDATE;
        IF att.state = 'started' THEN
            PERFORM voalack._release_no_dispatch(att.id, 'QUEUED');
            RETURN QUERY SELECT att.id, 'aborted_before_dispatch'::text;
        ELSE
            PERFORM voalack._hold_uncertain(att.id);
            RETURN QUERY SELECT att.id, 'uncertain'::text;
        END IF;
    END LOOP;
END;
$$;

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
ALTER FUNCTION voalack.acquire_owner(text, text, uuid) OWNER TO voalack_admin;
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
GRANT EXECUTE ON FUNCTION voalack.acquire_owner(text, text, uuid), voalack.check_owner(text, bigint, uuid),
    voalack.suspend_owner(text, bigint, uuid), voalack.start_attempt(uuid, bigint, text, bigint, uuid),
    voalack.consume_dispatch(uuid, text, bigint, uuid), voalack.check_dispatch(uuid, text, bigint, uuid),
    voalack.abort_attempt(uuid, text, bigint, uuid), voalack.close_already_acked(uuid, text, bigint, uuid, jsonb),
    voalack.record_not_sent(uuid, text, bigint, uuid, jsonb), voalack.close_unsupported_target(uuid, text, bigint, uuid, jsonb),
    voalack.hold_attempt(uuid, text, bigint, uuid, text), voalack.record_result(uuid, text, bigint, uuid, jsonb),
    voalack.record_evidence(uuid, bigint, uuid, text, jsonb), voalack.release_stale_started(text, bigint, uuid)
    TO voalack_sender;
