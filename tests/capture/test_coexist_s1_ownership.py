"""Coexistence 3a S1 (contract r8 sections 1-2): the public ownership class and the foreign pass-through.

An ACK of an alert outside the public Veeam ONE class is upstream Alerta behaviour, untouched: no Voalack
state, registry lookup, lock, signing or refusal, whoever sends it. Alerts of the class keep the whole
existing gate, with the human-authentication refusal uniform for bound and unbound members."""
import copy
import json
import logging
import threading
import uuid

import pytest

import voalack.boundary as boundary
from conftest import OPERATOR, ack, basic, captures, intents, new_alert, sql, status
from test_c3_gate import _api_key, _Held, lookups  # noqa: F401
from voalack import intent

GOLDEN = [
    (("VeeamOneAlarm", "veeamone:x"), "veeam_one"),
    (("VeeamOneAlarm", "veeamone:lab-0123"), "veeam_one"),
    (("VeeamOneAlarm", "veeamone: "), "veeam_one"),
    (("VeeamOneAlarm", "veeamone:x "), "veeam_one"),
    (("VeeamOneAlarm", "veeamone:_"), "veeam_one"),
    (("VeeamOneAlarm", "veeamone:%"), "veeam_one"),
    (("VeeamOneAlarm", "veeamone:"), "none"),
    (("VeeamOneAlarm", "Veeamone:x"), "none"),
    (("VeeamOneAlarm", " veeamone:x"), "none"),
    (("VeeamOneAlarm ", "veeamone:x"), "none"),
    (("veeamonealarm", "veeamone:x"), "none"),
    (("VeeamOneAlarm", None), "none"),
    ((None, "veeamone:x"), "none"),
    ((None, None), "none"),
    (("ZabbixTrigger", "zabbix:host-1"), "none"),
    (("VeeamOneAlarm", "veeamoneı:x"), "none"),
    (("VeeamOneAlarm", "veeamone：x"), "none"),
    (("VeeamOneАlarm", "veeamone:x"), "none"),
    (("VeeamOneAlarm", "veeamone:é"), "veeam_one"),
]


@pytest.mark.parametrize("args,expected", GOLDEN, ids=[repr(g[0]) for g in GOLDEN])
def test_one_classifier_in_python_and_sql(app, args, expected):
    assert intent.alert_class(*args) == expected
    assert sql("SELECT voalack.alert_class(%s, %s)", args)[0][0] == expected


def test_non_string_inputs_are_none_in_python():
    for value in (1, b"veeamone:x", ["veeamone:x"], object()):
        assert intent.alert_class("VeeamOneAlarm", value) == "none"
        assert intent.alert_class(value, "veeamone:x") == "none"


def foreign_alert(client):
    """An alert of another provider (Zabbix-shaped), outside the public Veeam ONE class."""
    r = client.post("/alert", json={"resource": f"zabbix:host-{uuid.uuid4().hex[:8]}", "event": "ZabbixTrigger",
                                     "environment": "Development", "severity": "major", "service": ["lab"],
                                     "text": "synthetic foreign", "attributes": {"source_system": "zabbix"}},
                    headers=basic(OPERATOR))
    assert r.status_code == 201, r.get_data(as_text=True)
    return r.get_json()["id"]


def key_ack(client, alert_id, key):
    return client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "synthetic"},
                      headers={"Authorization": f"Key {key}"})


def _body(response):
    return {k: v for k, v in response.get_json().items() if k != "requestId"}


def _no_voalack_effect(alert_id):
    assert (captures(alert_id), intents(alert_id)) == (0, 0)


HAWK = {"key": "lab-hawk-key", "secret": "lab-only-synthetic-hawk-secret", "algorithm": "sha256"}


def hawk_ack(client, app, monkeypatch, alert_id):
    """An ACK signed with Alerta's pinned Hawk HMAC scheme (alerta/auth/decorators.py): user_id None, admin scopes."""
    from mohawk import Sender
    monkeypatch.setitem(app.config, "HMAC_AUTH_CREDENTIALS", [HAWK])
    url = f"http://localhost/alert/{alert_id}/action"
    content = json.dumps({"action": "ack", "text": "synthetic"})
    sender = Sender({"id": HAWK["key"], "key": HAWK["secret"], "algorithm": HAWK["algorithm"]}, url, "PUT",
                    content=content, content_type="application/json")
    return client.put(f"/alert/{alert_id}/action", data=content, content_type="application/json",
                      headers={"Authorization": sender.request_header})


def _ack_as(who, client, app, monkeypatch, alert_id):
    if who == "human":
        return ack(client, alert_id)
    if who == "api-key":
        return key_ack(client, alert_id, _api_key(client))
    return hawk_ack(client, app, monkeypatch, alert_id)


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def private_work(monkeypatch):
    """Observes the gate's owned-path work directly: Voalack request state (the deferred-commit wrapper behind
    g.voalack), the callback and receiver catalog checks, gate fact processing (which reads the signing
    configuration), registry lookups, and every record of the voalack loggers."""
    seen = []
    for name in ("_lookup_binding", "_unreviewed_response_callbacks", "_foreign_receivers", "_freeze_gate_facts",
                 "DeferredCommitConnection"):
        original = getattr(boundary, name)

        def observed(*args, _name=name, _original=original, **kwargs):
            seen.append(_name)
            return _original(*args, **kwargs)
        monkeypatch.setattr(boundary, name, observed)
    handler = _Records()
    logger = logging.getLogger("voalack")
    logger.addHandler(handler)
    previous = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        yield seen, handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)


@pytest.mark.parametrize("who", ["human", "api-key", "hawk"])
def test_a_foreign_ack_is_upstream_and_untouched(client, app, monkeypatch, private_work, who):
    alert_id = foreign_alert(client)
    seen, records = private_work
    response = _ack_as(who, client, app, monkeypatch, alert_id)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack"
    # No owned-path work: no registry lookup, no Voalack request state, no catalog check, no gate fact processing
    # or signing read, and no Voalack log record. (The inherited public capture trigger still runs on the ACK
    # UPDATE and reads prepared intents; that database-side read is an S1 limitation carried to S2/S3.)
    assert seen == [] and [r.getMessage() for r in records] == []
    _no_voalack_effect(alert_id)


def test_a_foreign_ack_needs_no_readable_registry(client, app):
    alert_id = foreign_alert(client)
    sql("REVOKE SELECT ON voalack.bindings FROM voalack_app", fetch=False)
    try:
        response = ack(client, alert_id)
    finally:
        sql("GRANT SELECT ON voalack.bindings TO voalack_app", fetch=False)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack"
    _no_voalack_effect(alert_id)


BLOCK_BOUND = 10.0   # seconds; an unblocked ACK takes well under one


def test_a_foreign_ack_is_not_blocked_by_a_locked_registry(client, app):
    """Bounded: the ACK runs in a thread; if it is still waiting after BLOCK_BOUND the lock is released so the
    request (and pytest) always completes, and the test then fails on the observed wait."""
    alert_id = foreign_alert(client)
    held = _Held(new_alert(client), registry=True)          # the registry table held exclusively
    result = {}
    worker = threading.Thread(target=lambda: result.setdefault("response", ack(client, alert_id)), daemon=True)
    try:
        worker.start()
        worker.join(BLOCK_BOUND)
        blocked = worker.is_alive()
    finally:
        held.release()
    worker.join(60)
    assert not blocked, "the foreign ACK waited on the held binding registry"
    response = result["response"]
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack"


def test_a_foreign_ack_needs_no_signing_configuration(client, app, monkeypatch):
    alert_id = foreign_alert(client)
    monkeypatch.setitem(app.extensions, "voalack_signing", None)
    response = ack(client, alert_id)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack"
    _no_voalack_effect(alert_id)


@pytest.mark.parametrize("who", ["api-key", "hawk"])
def test_one_class_api_key_refusal_is_uniform_for_bound_and_unbound(client, app, monkeypatch, lookups, who):  # noqa: F811,E501
    bound, unbound = new_alert(client), new_alert(client, bound=False)
    responses = [_ack_as(who, client, app, monkeypatch, alert_id) for alert_id in (bound, unbound)]
    assert [r.status_code for r in responses] == [403, 403]
    assert _body(responses[0]) == _body(responses[1])           # identical apart from the request id
    assert lookups == []                                     # membership never looked up for a key
    for alert_id in (bound, unbound):
        assert status(alert_id)[0] == "open"
        _no_voalack_effect(alert_id)


def test_an_absent_id_gets_upstream_behaviour(client, app, lookups):  # noqa: F811
    response = key_ack(client, str(uuid.uuid4()), _api_key(client))
    assert response.status_code == 404, response.get_data(as_text=True)
    assert lookups == []


def test_a_class_change_before_the_lock_refuses_without_switching_lane(client, app, monkeypatch):
    alert_id = new_alert(client)
    original = boundary._original_find_by_id
    calls = []

    def reload_changed(id, customers=None):
        calls.append(id)
        alert = original(id, customers)
        if len(calls) == 2 and alert is not None:          # the reload under the lock sees another class
            alert = copy.copy(alert)
            alert.event = "ZabbixTrigger"
        return alert
    monkeypatch.setattr(boundary, "_original_find_by_id", reload_changed)
    frozen = []
    freeze = boundary._freeze_gate_facts

    def observed_freeze(state, cur, alert, revision, customers):
        frozen.append(alert.event)
        return freeze(state, cur, alert, revision, customers)
    monkeypatch.setattr(boundary, "_freeze_gate_facts", observed_freeze)
    response = ack(client, alert_id)
    assert response.status_code == 503, response.get_data(as_text=True)
    # The explicit class check refuses the changed reload before any gate fact processing (and so before
    # signing or source checks); without it, the source checks would still refuse later, with another message.
    assert frozen == []
    assert "alert changed" in response.get_json()["message"]
    assert status(alert_id)[0] == "open"
    _no_voalack_effect(alert_id)


def test_a_bound_one_alert_is_still_captured(client, app):
    alert_id = new_alert(client)
    response = ack(client, alert_id)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert (status(alert_id)[0], captures(alert_id)) == ("ack", 1)


def test_the_sql_classifier_is_an_owner_definer_not_executable_by_the_runtime_roles(app):
    """voalack.alert_class follows the schema's function invariant: owner voalack_admin, SECURITY DEFINER,
    search_path with pg_temp last, IMMUTABLE, and no EXECUTE for PUBLIC or any runtime role."""
    import psycopg2
    from conftest import APP_DSN, SENDER_DSN, VERIFIER_DSN
    row = sql("SELECT pg_get_userbyid(p.proowner), p.prosecdef, p.proconfig, p.provolatile, "
              "p.proacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(p.proacl) x WHERE x.grantee = 0) "
              "FROM pg_proc p WHERE p.oid = 'voalack.alert_class(text, text)'::regprocedure")[0]
    owner, definer, config, volatility, public_execute = row
    assert (owner, definer, volatility, public_execute) == ("voalack_admin", True, "i", False), row
    assert list(config or []) == ["search_path=pg_catalog, voalack, pg_temp"], config   # the readiness definer rule
    for dsn in (APP_DSN, SENDER_DSN, VERIFIER_DSN):
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT has_function_privilege('voalack.alert_class(text, text)', 'EXECUTE')")
            assert cur.fetchone()[0] is False, dsn
