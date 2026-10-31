"""T04 S1: verifier and effect ledger (no endpoint, credential or network access).

Captures come from real ACKs through the capture boundary; verification runs as the verifier login
(member of voalack_verifier); administrator changes use the lab superuser on separate connections.
"""
import dataclasses
import threading
import time
from datetime import timedelta

import psycopg2
import pytest

from conftest import DSN, VERIFIER_DSN, ack, new_alert, sql
from voalack import envelope as v2
from voalack import verifier


def _captured(client, **kwargs):
    alert_id = new_alert(client, **kwargs)
    assert ack(client, alert_id).status_code == 200
    action_id = sql("SELECT action_id::text FROM voalack.prepared_intents WHERE alert_id = %s", (alert_id,))[0][0]
    return alert_id, action_id


def _verify(app, action_id, keys=None, lease=60, claimant="lab-verifier-a", promoted=None):
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as conn:
        return verifier.run_once(conn, claimant, signing.ctx, keys or signing.keys, lease_seconds=lease,
                                 on_promoted=promoted, action_id=action_id)


def _effects(action_id):
    return sql("SELECT state FROM voalack.effects WHERE action_id = %s", (action_id,))


def _records(action_id):
    return sql("SELECT outcome, reason FROM voalack.verifications WHERE action_id = %s ORDER BY verification_id",
               (action_id,))


# --- positive -----------------------------------------------------------------------------

def test_committed_capture_verifies_and_promotes_exactly_one_effect(client, app):
    _, action_id = _captured(client)
    calls = []
    result = _verify(app, action_id, promoted=calls.append)
    assert result["outcome"] == "verified" and result["effect_id"]
    assert _effects(action_id) == [("QUEUED",)] and _records(action_id) == [("verified", "ok")]
    assert len(calls) == 1
    assert _verify(app, action_id) is None                       # nothing left to claim for it


# --- D1: complete original capture ----------------------------------------------------------

def _admin(statement, args):
    sql(statement, args, fetch=False)


@pytest.mark.parametrize("tamper,reason", [
    ("bytes", "digest_link_mismatch"),
    ("bytes_and_digests", "invalid_proof:bytes_not_canonical"),
    ("generation", "generation_mismatch"),
    ("capture_link", "digest_link_mismatch"),
])
def test_tampered_capture_is_refused_without_an_effect(client, app, tamper, reason):
    _, action_id = _captured(client)
    if tamper == "bytes":
        _admin("UPDATE voalack.prepared_intents SET envelope_canonical = envelope_canonical || ' '::bytea "
               "WHERE action_id = %s", (action_id,))
    elif tamper == "bytes_and_digests":
        _admin("UPDATE voalack.prepared_intents SET envelope_canonical = envelope_canonical || ' '::bytea "
               "WHERE action_id = %s", (action_id,))
        _admin("UPDATE voalack.prepared_intents SET envelope_sha256 = encode(sha256(envelope_canonical), 'hex') "
               "WHERE action_id = %s", (action_id,))
        _admin("UPDATE voalack.captures c SET envelope_sha256 = p.envelope_sha256 FROM voalack.prepared_intents p "
               "WHERE p.action_id = c.action_id AND c.action_id = %s", (action_id,))
    elif tamper == "generation":
        _admin("UPDATE voalack.captures SET generation = generation + 1 WHERE action_id = %s", (action_id,))
    else:
        _admin("UPDATE voalack.captures SET envelope_sha256 = repeat('0', 64) WHERE action_id = %s", (action_id,))
    calls = []
    result = _verify(app, action_id, promoted=calls.append)
    assert (result["outcome"], result["reason"]) == ("refused", reason), result
    assert _effects(action_id) == [] and calls == []


def test_proof_copied_from_another_action_is_refused(client, app):
    _, a = _captured(client)
    _, b = _captured(client)
    row = sql("SELECT envelope_canonical, envelope_sha256, kid, mac FROM voalack.prepared_intents WHERE action_id = %s",
              (a,))[0]
    _admin("UPDATE voalack.prepared_intents SET envelope_canonical = %s, envelope_sha256 = %s, kid = %s, mac = %s "
           "WHERE action_id = %s", (psycopg2.Binary(bytes(row[0])), row[1], row[2], row[3], b))
    _admin("UPDATE voalack.captures SET envelope_sha256 = %s WHERE action_id = %s", (row[1], b))
    result = _verify(app, b)
    assert (result["outcome"], result["reason"]) == ("refused", "identity_mismatch"), result
    assert _effects(b) == []


def test_legacy_unsigned_capture_is_refused(client, app):
    alert_id = new_alert(client)
    action_id = "21212121-2121-4121-8121-212121212121"
    _admin("INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload) "
           "VALUES (%s, %s, 7, 'operator@example.test', '{}')", (action_id, alert_id))
    _admin("INSERT INTO voalack.captures (action_id, alert_id, txid, history_user, history_time) "
           "VALUES (%s, %s, 7, 'operator@example.test', now())", (action_id, alert_id))
    result = _verify(app, action_id)
    assert (result["outcome"], result["reason"]) == ("refused", "legacy_unsigned"), result
    assert _effects(action_id) == []


def test_unknown_key_is_a_hold_not_a_refusal(client, app):
    _, action_id = _captured(client)
    signing = app.extensions["voalack_signing"]
    tup = (signing.ctx.deployment_id, signing.ctx.provider, signing.ctx.purpose)
    without_k1 = v2.KeyRing({tup + ("lab-k9",): b"k" * 32}, {tup: "lab-k9"})
    result = _verify(app, action_id, keys=without_k1, lease=1)
    assert (result["outcome"], result["reason"]) == ("hold", "key_unavailable") and _effects(action_id) == []
    time.sleep(1.2)                                               # the held capture can be claimed again
    assert _verify(app, action_id)["outcome"] == "verified" and _effects(action_id) == [("QUEUED",)]


# --- current eligibility at promotion ----------------------------------------------------

def test_policy_revoked_after_capture_is_not_promoted(client, app):
    _, action_id = _captured(client)
    _admin("UPDATE voalack.authorization_policy_active SET policy_revision = 3", ())
    try:
        result = _verify(app, action_id)
    finally:
        _admin("UPDATE voalack.authorization_policy_active SET policy_revision = 1", ())
    assert (result["outcome"], result["reason"]) == ("refused", "policy_revoked"), result
    assert _effects(action_id) == [] and _records(action_id) == [("verified", "ok"), ("refused", "policy_revoked")]


def test_binding_re_revisioned_after_capture_is_not_promoted(client, app):
    alert_id, action_id = _captured(client)
    binding = f"lab-{alert_id}"
    _admin("INSERT INTO voalack.binding_revisions SELECT binding_id, 2, customer, source_namespace, instance_id, "
           "resource, event, environment, origin, combination_id, capture_id, target_kind, target_id, alarm_template_id,"
           " object_id, repeat_count, triggered_time, occurrence_ref, occurrence_evidence_sha256, snapshot_sha256,"
           " clock_timestamp(), alert_lifetime_id FROM voalack.binding_revisions WHERE binding_id = %s AND binding_revision = 1",
           (binding,))
    _admin("UPDATE voalack.bindings SET binding_revision = 2 WHERE alert_id = %s", (alert_id,))
    result = _verify(app, action_id)
    assert (result["outcome"], result["reason"]) == ("refused", "binding_changed"), result
    assert _effects(action_id) == []


def test_execution_deadline_passed_is_refused(client, app):
    signing = app.extensions["voalack_signing"]
    short = dataclasses.replace(signing, capture_window=timedelta(seconds=1), execution_window=timedelta(seconds=1))
    app.extensions["voalack_signing"] = short
    try:
        _, action_id = _captured(client)
    finally:
        app.extensions["voalack_signing"] = signing
    time.sleep(1.2)
    result = _verify(app, action_id)
    assert (result["outcome"], result["reason"]) == ("refused", "expired"), result
    assert _effects(action_id) == []


# --- claims and concurrency ---------------------------------------------------------------

def test_stale_claimant_cannot_record_or_promote(client, app):
    _, action_id = _captured(client)
    signing = app.extensions["voalack_signing"]
    with psycopg2.connect(VERIFIER_DSN) as a:
        cur = a.cursor()
        cur.execute("SELECT * FROM voalack.claim_verification('lab-a', 1, %s)", (action_id,))
        _, gen_a = cur.fetchone()
        a.commit()
        time.sleep(1.2)                                            # A's lease expires
        assert _verify(app, action_id, claimant="lab-b")["outcome"] == "verified"
        with pytest.raises(psycopg2.errors.RaiseException, match="stale or expired"):
            verifier.process(a, action_id, gen_a, signing.ctx, signing.keys)
    assert len(_effects(action_id)) == 1


def test_competing_promotions_of_one_effect_key_yield_one_effect(client, app):
    _, first = _captured(client, occurrence_ref="lab-shared-occurrence")
    _, second = _captured(client, occurrence_ref="lab-shared-occurrence")
    results, barrier = {}, threading.Barrier(2)

    def run(action_id):
        barrier.wait(5)
        results[action_id] = _verify(app, action_id, claimant=f"lab-{action_id[:4]}")
    threads = [threading.Thread(target=run, args=(a,)) for a in (first, second)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    outcomes = sorted((r["outcome"], r["reason"]) for r in results.values())
    assert outcomes == [("hold", "effect_key_taken"), ("verified", "ok")], results
    assert len(_effects(first)) + len(_effects(second)) == 1


# --- roles ----------------------------------------------------------------------------------

@pytest.mark.parametrize("statement", [
    "INSERT INTO voalack.effects (effect_key, instance_id, target_id, action_id, verification_id, state) "
    "VALUES ('k', 'i', '1', gen_random_uuid(), 1, 'QUEUED')",
    "UPDATE voalack.effects SET state = 'REMOTE_CONFIRMED'",
    "INSERT INTO voalack.verifications (action_id, claim_epoch, verifier_version, deployment_id, provider,"
    " outcome, reason) VALUES (gen_random_uuid(), 1, 'v', 'd', 'p', 'verified', 'ok')",
    "UPDATE voalack.verification_claims SET lease_until = now()",
    "UPDATE voalack.prepared_intents SET mac = 'x'",
    "DELETE FROM voalack.captures",
    "SELECT voalack.stage_intent(gen_random_uuid(), 'a', gen_random_uuid(), 'u', '{}', 'c', 'b', 1, now(), now(), now())",
    "SELECT voalack.capture_ack()",
    "SELECT voalack._require_current_claim(gen_random_uuid(), 1)",
])
def test_verifier_role_is_denied_direct_writes_and_other_functions(app, statement):
    with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.errors.InsufficientPrivilege):
            cur.execute(statement)


def test_verification_records_are_immutable(client, app):
    _, action_id = _captured(client)
    _verify(app, action_id)
    with pytest.raises(psycopg2.errors.RaiseException, match="immutable"):
        sql("UPDATE voalack.verifications SET outcome = 'refused' WHERE action_id = %s", (action_id,), fetch=False)


def test_verifier_login_has_no_path_to_the_owner(app):
    with psycopg2.connect(VERIFIER_DSN) as conn, conn.cursor() as cur:
        cur.execute("SELECT r.rolsuper, pg_has_role(current_user, 'voalack_admin', 'MEMBER'), "
                    "pg_has_role(current_user, 'voalack_app', 'MEMBER') FROM pg_roles r WHERE r.rolname = current_user")
        assert cur.fetchone() == (False, False, False)
