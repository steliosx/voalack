"""B2: the capture gate runs after authentication and customer filtering, inside the action route.

Denied requests must not query the binding registry or wait on locks, whether or not the alert
is bound. The registry query is counted (deterministic); elapsed time only corroborates it.
"""
import inspect
import threading
import time
import uuid

import psycopg2
import pytest
from flask import Flask

import voalack.boundary as boundary
from conftest import DSN, OPERATOR, OPERATOR2, READER, ack, basic, captures, intents, new_alert, sql, status
from test_c3_transaction import _Hook


@pytest.fixture
def lookups(monkeypatch):
    calls = []
    original = boundary._lookup_binding

    def counted(cur, alert_id, lock=False):
        calls.append((alert_id, lock))
        return original(cur, alert_id, lock)
    monkeypatch.setattr(boundary, "_lookup_binding", counted)
    return calls


def _api_key(client):
    r = client.post("/key", json={"scopes": ["write:alerts", "read:alerts"], "text": "lab"}, headers=basic(OPERATOR))
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["key"]


class _Held:
    """Separate connections holding both alert rows and the whole binding registry."""

    def __init__(self, *alert_ids, registry=True):
        self.rows = psycopg2.connect(DSN)
        self.rows.cursor().execute("SELECT id FROM alerts WHERE id = ANY(%s) FOR UPDATE", (list(alert_ids),))
        self.registry = None
        if registry:
            self.registry = psycopg2.connect(DSN)
            self.registry.cursor().execute("LOCK TABLE voalack.bindings IN ACCESS EXCLUSIVE MODE")

    def release(self):
        for conn in (self.rows, self.registry):
            if conn is not None:
                conn.rollback()
                conn.close()


def test_gate_placement_in_pinned_alerta_source():
    import alerta.views.alerts as views
    from alerta.version import __version__
    assert __version__ == boundary.PINNED_ALERTA
    source = inspect.getsource(views)
    start = source.index("@api.route('/alert/<alert_id>/action'")
    body = source[start:source.index("\n@api.route", start + 1)]
    assert body.index("@permission(Scope.write_alerts)") < body.index("def action_alert(alert_id):")
    assert body.index("customers = g.get('customers', None)") < body.index("alert = Alert.find_by_id(alert_id, customers)")
    assert body.index("alert = Alert.find_by_id(alert_id, customers)") < body.index("process_action(alert, action, text, timeout)")
    assert body.count("find_by_id") == 1
    from alerta.models.alert import Alert
    assert getattr(Alert.find_by_id, "_voalack_gate", False)


@pytest.mark.parametrize("who", ["missing", "bad-password", "bad-key", "reader", "api-key"])
def test_denied_requests_never_reach_the_registry(client, app, lookups, who):
    bound, unbound = new_alert(client), new_alert(client, bound=False)
    key = _api_key(client) if who == "api-key" else None
    headers = {"missing": {}, "bad-password": basic((OPERATOR[0], "wrong")), "bad-key": {"Authorization": "Key nope"},
               "reader": basic(READER), "api-key": {"Authorization": f"Key {key}"}}[who]
    expected = {"missing": 401, "bad-password": 401, "bad-key": 401, "reader": 403, "api-key": 403}[who]
    held = _Held(bound, unbound)
    results = []
    try:
        for alert_id in (unbound, bound):
            start = time.monotonic()
            r = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"}, headers=headers)
            results.append((r.status_code, time.monotonic() - start))
    finally:
        held.release()
    assert [code for code, _ in results] == [expected, expected], results
    assert lookups == [], lookups
    assert all(elapsed < 1 for _, elapsed in results), results
    for alert_id in (bound, unbound):
        assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


@pytest.fixture
def customer_views(app):
    mapping = str(uuid.uuid4())
    sql("INSERT INTO customers (id, match, customer) VALUES (%s, %s, 'lab-A')", (mapping, OPERATOR[0]), fetch=False)
    app.config["CUSTOMER_VIEWS"] = True
    yield
    app.config["CUSTOMER_VIEWS"] = False
    sql("DELETE FROM customers WHERE id = %s", (mapping,), fetch=False)


def _set_customer(alert_id, customer):
    sql("UPDATE alerts SET customer = %s WHERE id = %s", (customer, alert_id), fetch=False)


def test_wrong_customer_is_denied_before_the_registry(client, app, lookups):
    bound, unbound = new_alert(client), new_alert(client, bound=False)
    for alert_id in (bound, unbound):
        _set_customer(alert_id, "lab-B")
    mapping = str(uuid.uuid4())
    sql("INSERT INTO customers (id, match, customer) VALUES (%s, %s, 'lab-A')", (mapping, OPERATOR[0]), fetch=False)
    app.config["CUSTOMER_VIEWS"] = True
    held = _Held(bound, unbound)
    try:
        codes = [ack(client, alert_id).status_code for alert_id in (unbound, bound)]
    finally:
        held.release()
        app.config["CUSTOMER_VIEWS"] = False
        sql("DELETE FROM customers WHERE id = %s", (mapping,), fetch=False)
    assert codes == [404, 404], codes
    assert lookups == []
    assert status(bound)[0] == "open" and captures(bound) == 0 and intents(bound) == 0


def test_own_customer_ack_is_captured(client, customer_views):
    alert_id = new_alert(client, customer="lab-A")   # M2 fixture: bound for lab-A (was: re-set after binding)
    r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1 and intents(alert_id) == 1


def _waiting_on_lock(timeout=5.0):
    """Wait until some backend is blocked on a lock (deterministic, from pg_stat_activity)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = sql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock'")
        if rows[0][0] > 0:
            return True
        time.sleep(0.02)
    return False


def _in_thread(app, who, alert_id, results, key):
    def run():
        with app.test_client() as c:
            results[key] = c.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": key},
                                 headers=basic(who)).status_code
    t = threading.Thread(target=run)
    t.start()
    return t


def test_scope_change_while_waiting_is_refused(client, app, customer_views):
    alert_id = new_alert(client, customer="lab-A")   # M2 fixture: bound for lab-A (was: re-set after binding)
    holder = psycopg2.connect(DSN)
    holder.cursor().execute("SELECT id FROM alerts WHERE id = %s FOR UPDATE", (alert_id,))
    results = {}
    t = _in_thread(app, OPERATOR, alert_id, results, "b")
    try:
        assert _waiting_on_lock()
        holder.cursor().execute("UPDATE alerts SET customer = 'lab-B' WHERE id = %s", (alert_id,))
        holder.commit()
    finally:
        holder.close()
        t.join(10)
    assert results.get("b") == 404, results
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_authorized_lock_timeout_is_refused(client):
    alert_id = new_alert(client)
    holder = psycopg2.connect(DSN)
    holder.cursor().execute("SELECT id FROM alerts WHERE id = %s FOR UPDATE", (alert_id,))
    try:
        r = ack(client, alert_id)
    finally:
        holder.rollback()
        holder.close()
    assert r.status_code == 503, r.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_racing_acks_use_the_reloaded_alert(client, app, faults):
    alert_id = new_alert(client)
    entered, release = threading.Event(), threading.Event()
    first = []

    seen_by_actions = {}

    def record(alert, action, text):
        # What process_action passes to action hooks: must be the alert reloaded under the lock.
        seen_by_actions[text] = alert.status

    def hold(alert, action, text):
        if not first:
            first.append(text)
            entered.set()
            release.wait(10)
    faults("hold", _Hook("hold", take_action=record, post_action=hold))
    results = {}
    a = _in_thread(app, OPERATOR, alert_id, results, "a")
    assert entered.wait(10)
    b = _in_thread(app, OPERATOR2, alert_id, results, "b")
    try:
        assert _waiting_on_lock()
    finally:
        release.set()
        a.join(10)
        b.join(10)
    assert results == {"a": 200, "b": 409}, results
    assert seen_by_actions == {"a": "open", "b": "ack"}, seen_by_actions
    assert status(alert_id) == ("ack", "ack", OPERATOR[0])
    assert captures(alert_id) == 1 and intents(alert_id) == 1


def test_binding_removed_while_waiting_continues_upstream(client, app):
    alert_id = new_alert(client)
    holder = psycopg2.connect(DSN)
    holder.cursor().execute("SELECT id FROM alerts WHERE id = %s FOR UPDATE", (alert_id,))
    results = {}
    t = _in_thread(app, OPERATOR, alert_id, results, "b")
    try:
        assert _waiting_on_lock()
        sql("UPDATE voalack.bindings SET active = false WHERE alert_id = %s", (alert_id,), fetch=False)
    finally:
        holder.rollback()
        holder.close()
        t.join(10)
    assert results.get("b") == 200, results
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_install_refuses_another_alerta_version(monkeypatch):
    import alerta.version
    monkeypatch.setattr(alerta.version, "__version__", "9.2.0")
    with pytest.raises(RuntimeError, match="9.1.0"):
        boundary.install(Flask(__name__))
