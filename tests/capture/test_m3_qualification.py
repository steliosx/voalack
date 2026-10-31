"""M3: remaining local signing/capture qualification (proposal cases 1-9, with VO-ASTRA's refinements).

All requests run as Alerta's restricted runtime login; administrator writes and observers use the
lab superuser on separate connections. Synthetic fixtures and keys only.
"""
import dataclasses
import json
import logging
import threading
import time
from contextlib import contextmanager

import psycopg2
import pytest
from flask import g

from conftest import (CONFIG, DSN, OPERATOR, ack, basic, captures, intents, new_alert, sql, status,
                      user_id)
from test_c3_transaction import _Hook
from voalack import envelope as v2
from voalack import intent


def _row(alert_id):
    rows = sql("SELECT envelope_canonical, envelope_sha256, kid, mac, generation, action_id::text "
               "FROM voalack.prepared_intents WHERE alert_id = %s ORDER BY generation", (alert_id,))
    return [(bytes(r[0]) if r[0] is not None else None,) + tuple(r[1:]) for r in rows]


def _committed(alert_id, n=1):
    assert status(alert_id)[0] == "ack" and captures(alert_id) == n and intents(alert_id) == n


def _nothing(alert_id):
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


@contextmanager
def _session_hook(app, action):
    """Run ``action`` at session save: after approval, before the commit point."""
    wrapper = app.session_interface
    original = wrapper.inner

    class Hook:
        def __getattr__(self, name):
            return getattr(original, name)

        def save_session(self, app_, session, response):
            action()
            original.save_session(app_, session, response)
    wrapper.inner = Hook()
    try:
        yield
    finally:
        wrapper.inner = original


@contextmanager
def _lab_grant(statement):
    sql(f"GRANT {statement} TO voalack_app", fetch=False)
    try:
        yield
    finally:
        sql(f"REVOKE {statement} FROM voalack_app", fetch=False)


@contextmanager
def _signing(app, signing):
    original = app.extensions["voalack_signing"]
    app.extensions["voalack_signing"] = signing
    try:
        yield
    finally:
        app.extensions["voalack_signing"] = original


# --- 1. copied proof ------------------------------------------------------------------------

def test_case1_proof_copied_from_another_action_is_refused(client, app):
    control = new_alert(client)
    assert ack(client, control).status_code == 200           # B's path is reachable with these fixtures
    _committed(control)
    a = new_alert(client)
    assert ack(client, a).status_code == 200
    a_bytes, a_sha, a_kid, a_mac, _, _ = _row(a)[0]
    b = new_alert(client)

    def copy_a_proof_into_b():
        # Disclosed fields (lab-only grant): B's canonical bytes, digest, kid and MAC, and B's capture
        # digest link, so the digest/link checks pass and the action/alert binding check decides.
        cur = g.db.cursor()
        cur.execute("UPDATE voalack.prepared_intents SET envelope_canonical = %s, envelope_sha256 = %s, kid = %s,"
                    " mac = %s WHERE action_id = %s",
                    (psycopg2.Binary(a_bytes), a_sha, a_kid, a_mac, g.voalack["action_id"]))
        cur.execute("UPDATE voalack.captures SET envelope_sha256 = %s WHERE action_id = %s",
                    (a_sha, g.voalack["action_id"]))
    with _lab_grant("UPDATE ON voalack.prepared_intents, voalack.captures"), _session_hook(app, copy_a_proof_into_b):
        r = ack(client, b)
    assert r.status_code == 500, r.get_data(as_text=True)
    _nothing(b)
    _committed(a)
    assert _row(a)[0][:4] == (a_bytes, a_sha, a_kid, a_mac)    # A's proof is untouched
    signing = app.extensions["voalack_signing"]
    assert v2.verify(a_bytes, a_mac, signing.ctx, signing.keys)["alert_id"] == a   # the copy was authentic for A


# --- 2. generations ------------------------------------------------------------------------

def test_case2_generation_counts_real_ack_transitions_only(client, app):
    alert_id = new_alert(client)
    binding = f"lab-{alert_id}"

    def counter():
        rows = sql("SELECT generation FROM voalack.binding_generations WHERE binding_id = %s", (binding,))
        return rows[0][0] if rows else 0
    assert ack(client, alert_id).status_code == 200
    assert counter() == 1
    r = client.put(f"/alert/{alert_id}/action", json={"action": "unack", "text": "undo"}, headers=basic(OPERATOR))
    assert r.status_code == 200, r.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and counter() == 1 and intents(alert_id) == 1   # unACK stages nothing
    assert ack(client, alert_id).status_code == 200            # second real ACK transition
    rows = _row(alert_id)
    signing = app.extensions["voalack_signing"]
    generations = [v2.verify(r[0], r[3], signing.ctx, signing.keys)["generation"] for r in rows]
    stored = [r[4] for r in rows]
    captured = [c[0] for c in sql("SELECT generation FROM voalack.captures WHERE alert_id = %s ORDER BY generation",
                                  (alert_id,))]
    assert generations == stored == captured == [1, 2] and counter() == 2
    assert status(alert_id)[0] == "ack"


# --- 3. key rotation -----------------------------------------------------------------------

def test_case3_key_rotation_keeps_old_proofs_verifiable_while_retained(client, app):
    signing = app.extensions["voalack_signing"]
    ctx = signing.ctx
    k1 = signing.keys.key(ctx, "lab-k1")
    first = new_alert(client)
    assert ack(client, first).status_code == 200
    old = _row(first)[0]
    k2 = b"lab-only-synthetic-signing-key-k2"
    tup = (ctx.deployment_id, ctx.provider, ctx.purpose)
    rotated = dataclasses.replace(signing, kid="lab-k2",
                                  keys=v2.KeyRing({tup + ("lab-k1",): k1, tup + ("lab-k2",): k2}, {tup: "lab-k2"}))
    second = new_alert(client)
    with _signing(app, rotated):
        assert ack(client, second).status_code == 200
    new = _row(second)[0]
    assert new[2] == "lab-k2" and v2.verify(new[0], new[3], ctx, rotated.keys)["kid"] == "lab-k2"
    assert v2.verify(old[0], old[3], ctx, rotated.keys)["kid"] == "lab-k1"      # retained k1 still verifies
    assert _row(first)[0] == old                                                  # never re-signed
    without_k1 = v2.KeyRing({tup + ("lab-k2",): k2}, {tup: "lab-k2"})
    with pytest.raises(v2.KeyUnavailable):
        v2.verify(old[0], old[3], ctx, without_k1)                               # a hold, not a forgery verdict
    forged = old[3][:-1] + ("0" if old[3][-1] != "0" else "1")
    with pytest.raises(v2.EnvelopeError, match="mac_mismatch"):
        v2.verify(old[0], forged, ctx, rotated.keys)                             # distinct from a forged MAC


# --- 4. legacy unsigned rows ---------------------------------------------------------------

def test_case4_part1_shaped_unsigned_rows_are_not_verifiable(client, app):
    alert_id = new_alert(client)
    payload = {"action_id": "11111111-2222-4333-8444-555555555555", "alert_id": alert_id,
               "actor": OPERATOR[0], "note": "legacy", "binding_id": f"lab-{alert_id}", "binding_revision": 1}
    sql("INSERT INTO voalack.prepared_intents (action_id, alert_id, txid, actor_login, payload) "
        "VALUES (%s, %s, 1, %s, %s)", (payload["action_id"], alert_id, OPERATOR[0], json.dumps(payload)), fetch=False)
    try:
        row = sql("SELECT envelope_canonical, mac, payload FROM voalack.prepared_intents WHERE action_id = %s",
                  (payload["action_id"],))[0]
        assert row[0] is None and row[1] is None                                  # no proof, no backfill
        signing = app.extensions["voalack_signing"]
        with pytest.raises(v2.EnvelopeError, match="envelope_keys"):
            v2.verify(v2.canonical_json(row[2], 16384), "0" * 64, signing.ctx, signing.keys)
    finally:
        sql("DELETE FROM voalack.prepared_intents WHERE action_id = %s", (payload["action_id"],), fetch=False)


# --- 5. route-level message bounds ---------------------------------------------------------

@pytest.mark.parametrize("note,accepted", [
    ("é" * 4096, True),                 # 8192 UTF-8 bytes: at the limit
    ("\U0001F600" * 2048, True),             # 8192 bytes of supplementary characters
    ("é" * 4096 + "x", False),          # 8193 bytes: just over
])
def test_case5_note_limits_are_utf8_bytes_and_message_utf16_units(client, app, note, accepted):
    alert_id = new_alert(client)
    r = ack(client, alert_id, text=note)
    if not accepted:
        assert r.status_code == 500, r.get_data(as_text=True)
        _nothing(alert_id)
        return
    assert r.status_code == 200, r.get_data(as_text=True)
    canonical, _, _, mac, _, _ = _row(alert_id)[0]
    signing = app.extensions["voalack_signing"]
    env = v2.verify(canonical, mac, signing.ctx, signing.keys)
    history = sql("SELECT (history[1]).text FROM alerts WHERE id = %s", (alert_id,))[0][0]
    assert history == note                                                        # authorised history keeps it
    assert env["message"] == v2.build_message(env["action_id"], OPERATOR[0], env["issued_at"], alert_id, history)
    assert len(env["message"].encode("utf-16-le")) // 2 <= 1024
    assert not any(0xD800 <= ord(c) <= 0xDFFF for c in env["message"])


def test_case5_controls_are_normalised_once_and_not_repaired_on_verify(client, app):
    alert_id = new_alert(client)
    assert ack(client, alert_id, text="first\r\nsecond\tthird").status_code == 200
    canonical, _, _, mac, _, _ = _row(alert_id)[0]
    signing = app.extensions["voalack_signing"]
    env = v2.verify(canonical, mac, signing.ctx, signing.keys)
    assert env["message"].endswith("note=first second third")
    assert sql("SELECT (history[1]).text FROM alerts WHERE id = %s", (alert_id,))[0][0] == "first\r\nsecond\tthird"
    raw = json.loads(canonical)
    raw["message"] = raw["message"].replace("first second", "first\nsecond")
    with pytest.raises(v2.EnvelopeError, match="message_invalid"):
        v2.verify(v2.canonical_json(raw, 16384), mac, signing.ctx, signing.keys)


# --- 9. window configuration (complete fixtures, so 503 means unsupported configuration) ---

@pytest.mark.parametrize("capture,execution,supported", [
    (60, 14400, True), (61, 14400, False), (30, 20, False), (60, 14401, False), (1, 1, True),
])
def test_case9_window_configuration_limits(client, app, capture, execution, supported):
    config = dict(CONFIG, VOALACK_CAPTURE_WINDOW_SECONDS=capture, VOALACK_EXECUTION_WINDOW_SECONDS=execution)
    loaded = intent.load_signing(config)
    assert (loaded is not None) is supported
    alert_id = new_alert(client)
    with _signing(app, loaded):
        r = ack(client, alert_id)
    if supported:
        assert r.status_code == 200, r.get_data(as_text=True)
        canonical, _, _, mac, _, _ = _row(alert_id)[0]
        env = v2.verify(canonical, mac, loaded.ctx, loaded.keys)
        issued = v2.parse_utc(env["issued_at"])
        assert v2.parse_utc(env["capture_expires_at"]) - issued == loaded.capture_window
        assert v2.parse_utc(env["execution_expires_at"]) - issued == loaded.execution_window
    else:
        assert r.status_code == 503, r.get_data(as_text=True)
        _nothing(alert_id)


# --- 6 and 7. serialisation of policy and binding changes ----------------------------------

def _blocked_by(pid, timeout=5.0):
    """The PIDs blocking ``pid`` once it waits on a lock (from pg_blocking_pids)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = sql("SELECT wait_event_type, pg_blocking_pids(%s) FROM pg_stat_activity WHERE pid = %s", (pid, pid))
        if rows and rows[0][0] == "Lock" and rows[0][1]:
            return rows[0][1]
        time.sleep(0.02)
    return []


def _held_ack(app, faults, alert_id):
    """Start an ACK that holds its transaction open after staging; returns (thread, results, release)."""
    entered, release, results = threading.Event(), threading.Event(), {}

    def hold(alert, action, text):
        cur = g.db.cursor()
        cur.execute("SELECT pg_backend_pid()")
        results["pid"] = cur.fetchone()[0]
        entered.set()
        release.wait(10)
    faults("hold", _Hook("hold", post_action=hold))

    def run():
        with app.test_client() as c:
            results["status"] = ack(c, alert_id).status_code
    thread = threading.Thread(target=run)
    thread.start()
    assert entered.wait(10)
    return thread, results, release


def _writer(statement, args, results):
    def run():
        conn = psycopg2.connect(DSN)
        try:
            with conn.cursor() as cur:
                cur.execute("SET statement_timeout = '10s'")
                cur.execute("SELECT pg_backend_pid()")
                results["writer_pid"] = cur.fetchone()[0]
                cur.execute(statement, args)
            conn.commit()
            results["writer"] = "committed"
        except psycopg2.Error as exc:
            results["writer"] = type(exc).__name__
            conn.rollback()
        finally:
            conn.close()
    thread = threading.Thread(target=run)
    thread.start()
    return thread


def test_case6_policy_change_waits_for_the_ack(client, app, faults):
    alert_id = new_alert(client)
    ack_thread, results, release = _held_ack(app, faults, alert_id)
    writer = _writer("UPDATE voalack.authorization_policy_active SET policy_revision = 2", (), results)
    try:
        deadline = time.monotonic() + 5
        while "writer_pid" not in results and time.monotonic() < deadline:
            time.sleep(0.01)
        assert results["pid"] in _blocked_by(results["writer_pid"]), results
        assert "writer" not in results                         # still waiting on the ACK's FOR SHARE
    finally:
        release.set()
        ack_thread.join(10)
        writer.join(15)
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert results["status"] == 200 and results["writer"] == "committed", results
    canonical, _, _, mac, _, _ = _row(alert_id)[0]
    signing = app.extensions["voalack_signing"]
    assert v2.verify(canonical, mac, signing.ctx, signing.keys)["actor"]["authorization_policy_revision"] == 1
    _committed(alert_id)


def test_case6_revocation_before_the_gate_refuses(client):
    alert_id = new_alert(client)
    sql("UPDATE voalack.authorization_policy_active SET policy_revision = 3", fetch=False)   # no grants
    try:
        r = ack(client, alert_id)
    finally:
        sql("UPDATE voalack.authorization_policy_active SET policy_revision = 1", fetch=False)
    assert r.status_code == 403, r.get_data(as_text=True)
    _nothing(alert_id)


def test_case7_binding_deactivation_waits_for_the_ack(client, app, faults):
    alert_id = new_alert(client)
    ack_thread, results, release = _held_ack(app, faults, alert_id)
    writer = _writer("UPDATE voalack.bindings SET active = false WHERE alert_id = %s", (alert_id,), results)
    try:
        deadline = time.monotonic() + 5
        while "writer_pid" not in results and time.monotonic() < deadline:
            time.sleep(0.01)
        assert results["pid"] in _blocked_by(results["writer_pid"]), results
        assert "writer" not in results
    finally:
        release.set()
        ack_thread.join(10)
        writer.join(15)
    assert results["status"] == 200 and results["writer"] == "committed", results
    _committed(alert_id)
    assert sql("SELECT active FROM voalack.bindings WHERE alert_id = %s", (alert_id,))[0][0] is False


def test_case7_deactivation_before_the_gate_leaves_the_alert_unbound(client):
    alert_id = new_alert(client)
    sql("UPDATE voalack.bindings SET active = false WHERE alert_id = %s", (alert_id,), fetch=False)
    r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)                       # upstream ACK
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 0 and intents(alert_id) == 0


# --- 8. Voalack log records and ACK-route bodies -------------------------------------------

CANARY_NOTE = "lab-canary-note-7f3a9c"
CANARY_PASSWORD = "lab-canary-password-bad"


def _canaries(app, alert_id=None):
    signing = app.extensions["voalack_signing"]
    key = signing.keys.key(signing.ctx, "lab-k1")
    values = {"key": key.decode("latin-1"), "key-hex": key.hex(), "note": CANARY_NOTE,
              "password": CANARY_PASSWORD}
    if alert_id:
        for canonical, sha, _, mac, _, _ in _row(alert_id):
            values.update({"mac": mac, "digest": sha, "envelope": canonical.decode("utf-8")[:120]})
    return values


@pytest.mark.parametrize("case", ["committed", "source-mismatch", "no-grant", "bad-password", "tampered-commit"])
def test_case8_voalack_records_and_ack_bodies_carry_no_secrets(client, app, caplog, case):
    caplog.set_level(logging.DEBUG, logger="voalack")
    alert_id = new_alert(client, customer="lab-no-grant" if case == "no-grant" else "lab-customer")
    if case == "source-mismatch":
        sql("UPDATE alerts SET value = 'Info' WHERE id = %s", (alert_id,), fetch=False)
    headers = basic((OPERATOR[0], CANARY_PASSWORD)) if case == "bad-password" else basic(OPERATOR)

    def send():
        return client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": CANARY_NOTE}, headers=headers)
    rolled_back_proof = {}
    if case == "tampered-commit":
        def tamper():
            cur = g.db.cursor()
            # Review note N1: keep this request's own opaque proof (it never commits) as canaries.
            cur.execute("SELECT envelope_canonical, envelope_sha256, mac FROM voalack.prepared_intents "
                        "WHERE action_id = %s", (g.voalack["action_id"],))
            canonical, sha, mac = cur.fetchone()
            rolled_back_proof.update({"rolled-back-mac": mac, "rolled-back-digest": sha,
                                      "rolled-back-envelope": bytes(canonical).decode("utf-8")[:120]})
            cur.execute("UPDATE voalack.prepared_intents SET mac = repeat('0', 64) WHERE action_id = %s",
                        (g.voalack["action_id"],))
        with _lab_grant("UPDATE ON voalack.prepared_intents"), _session_hook(app, tamper):
            r = send()
    else:
        r = send()
    expected = {"committed": 200, "source-mismatch": 503, "no-grant": 403, "bad-password": 401,
                "tampered-commit": 500}[case]
    assert r.status_code == expected, r.get_data(as_text=True)
    records = [rec for rec in caplog.records if rec.name.startswith("voalack")]
    probe = logging.getLogger("voalack.boundary")
    print("VOALACK_LOGGER", case, "disabled=", probe.disabled, "level=", probe.getEffectiveLevel(), "records=", len(records))
    probe.debug("canary capture check")                                          # records are really captured
    assert any(rec.getMessage() == "canary capture check" for rec in caplog.records)
    if case in ("source-mismatch", "tampered-commit"):
        assert records, "the refusal is expected to be logged by voalack"
    texts = [rec.getMessage() for rec in records] + [r.get_data(as_text=True)]
    if case == "tampered-commit":
        assert len(rolled_back_proof) == 3 and all(rolled_back_proof.values()), rolled_back_proof
        _nothing(alert_id)
    canaries = dict(_canaries(app, alert_id if case == "committed" else None), **rolled_back_proof)
    for name, value in canaries.items():
        assert not any(value and value in text for text in texts), name
    if case == "committed":
        assert r.get_json() == {"status": "ok"}
