"""Audit 2026-11-08 finding 2: an alias of a ONE-class alert never acknowledges it.

Alerta's action view also resolves an id prefix, the id in another letter case and an alert's
last_receive_id. Before the fix such a request skipped the gate and acknowledged a bound alert
without a capture. Now a human is refused with 400 and an API key with 403, for bound and unbound
alerts alike, before any binding lookup and with no change to the alert. Non-ONE alerts and
unknown ids keep upstream behaviour. The alias matrix and the rewrite case follow the reviewer's
revised guest acceptance tests; real customer-filtered Alerta lookup and database state, no
product-source monkeypatches.
"""
import json

import pytest
from alerta.exceptions import ApiError

from conftest import OPERATOR, ack, basic, bind, captures, intents, new_alert, sql, status
from test_coexist_s1_ownership import foreign_alert


def _snapshot(aid):
    # Compare the complete stored history, not only its newest event.
    return (sql("SELECT status, history FROM alerts WHERE id = %s", (aid,)),
            captures(aid), intents(aid))


def _observe(response, before, after, lookups=None):
    # Retain all observations before a failed status assertion can stop the case.
    # Raw history/customer contents and API keys are deliberately not exported.
    return {"http_status": response.status_code,
            "binding_lookups": lookups,
            "state_and_history_unchanged": after[0] == before[0],
            "captures_before": before[1], "captures_after": after[1],
            "intents_before": before[2], "intents_after": after[2]}


def _alias(client, aid, kind):
    if kind == "prefix":
        value = aid[:8]
        assert sql("SELECT count(*) FROM alerts WHERE id ~* %s", ("^" + value,))[0][0] == 1
    elif kind == "uppercase":
        value = aid.upper()
        assert value != aid, "fixture UUID must contain letters"
    else:
        # Receive the same alert again through the application to create a real
        # last_receive_id alias, rather than modifying protected source fields.
        fields = ("resource", "event", "environment", "severity", "value", "service", "text", "attributes")
        row = sql("SELECT resource, event, environment, severity, value, service, text, attributes "
                  "FROM alerts WHERE id = %s", (aid,))[0]
        customer_before = sql("SELECT customer FROM alerts WHERE id = %s", (aid,))
        response = client.post("/alert", json=dict(zip(fields, row)), headers=basic(OPERATOR))
        assert response.status_code == 201, response.get_data(as_text=True)
        assert response.get_json()["id"] == aid, "second receive must update the original alert"
        assert sql("SELECT customer FROM alerts WHERE id = %s", (aid,)) == customer_before
        value = sql("SELECT last_receive_id FROM alerts WHERE id = %s", (aid,))[0][0]
        assert value and value != aid, "duplicate receive must establish a distinct alias"
    return value


@pytest.mark.parametrize("kind", ["prefix", "uppercase", "last_receive"])
@pytest.mark.parametrize("bound", [True, False])
@pytest.mark.parametrize("human", [True, False])
def test_one_alias_refuses_without_binding_or_ack(
        client, monkeypatch, record_property, kind, bound, human):
    from voalack import boundary
    # Both receives use the same authenticated customer context. Only then use
    # the existing binding fixture, which assigns the synthetic lab customer.
    aid = new_alert(client, bound=False)
    alias = _alias(client, aid, kind)
    if bound:
        bind(aid)
    assert client.get(f"/alert/{alias}", headers=basic(OPERATOR)).get_json()["alert"]["id"] == aid
    before = _snapshot(aid)
    headers = basic(OPERATOR)
    if not human:
        r = client.post("/key", json={"scopes": ["read:alerts", "write:alerts"],
                                      "text": "synthetic alias refusal"}, headers=headers)
        assert r.status_code == 201
        headers = {"Authorization": "Key " + r.get_json()["key"]}
    lookups = []
    original = boundary._lookup_binding

    def observe_lookup(*args, **kwargs):
        lookups.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(boundary, "_lookup_binding", observe_lookup)
    response = client.put(f"/alert/{alias}/action",
                          json={"action": "ack", "text": "synthetic alias"}, headers=headers)
    after = _snapshot(aid)
    observation = _observe(response, before, after, len(lookups))
    record_property("alias_observation", json.dumps(observation, sort_keys=True))
    assert response.status_code == (400 if human else 403), observation
    assert not lookups, observation
    assert after == before, observation


def test_canonical_human_ack_still_captures(client):
    aid = new_alert(client)
    assert ack(client, aid).status_code == 200
    assert status(aid)[0] == "ack" and captures(aid) == intents(aid) == 1


def test_alias_refusal_cannot_be_rewritten_to_success(client, app, record_property):
    aid = new_alert(client)
    alias = _alias(client, aid, "prefix")
    before = _snapshot(aid)
    handlers = app.error_handler_spec[None].setdefault(None, {})
    previous = dict(handlers)
    called = []

    def rewrite(exc):
        called.append(type(exc).__name__)
        return {"status": "ok", "handled": True}, 200

    handlers[ApiError] = rewrite
    try:
        response = ack(client, alias)
    finally:
        handlers.clear()
        handlers.update(previous)
    after = _snapshot(aid)
    observation = _observe(response, before, after)
    observation["error_handler_calls"] = len(called)
    record_property("rewrite_observation", json.dumps(observation, sort_keys=True))
    # A direct refusal can safely bypass the handler. Zero calls do not qualify
    # an exercised rewrite path; the report must retain that distinction.
    assert response.status_code >= 400, observation
    assert after == before, observation


def _count_lookups(monkeypatch):
    from voalack import boundary
    lookups = []
    original = boundary._lookup_binding

    def observe_lookup(*args, **kwargs):
        lookups.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(boundary, "_lookup_binding", observe_lookup)
    return lookups


def test_foreign_alert_alias_keeps_upstream_behaviour(client, monkeypatch):
    aid = foreign_alert(client)
    assert sql("SELECT count(*) FROM alerts WHERE id ~* %s", ("^" + aid[:8],))[0][0] == 1
    lookups = _count_lookups(monkeypatch)
    response = ack(client, aid[:8])
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(aid)[0] == "ack"
    assert (captures(aid), intents(aid)) == (0, 0)
    assert not lookups


def test_unknown_id_keeps_upstream_not_found(client, monkeypatch):
    new_alert(client)
    lookups = _count_lookups(monkeypatch)
    response = ack(client, "not-an-alert-id")
    assert response.status_code == 404, response.get_data(as_text=True)
    assert not lookups
