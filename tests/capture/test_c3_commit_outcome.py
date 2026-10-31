"""Automated review of 5d80169: the gated snapshot at commit, an interrupted COMMIT, API-key existence."""
import uuid

import psycopg2
import pytest

from conftest import OPERATOR, ack, basic, captures, intents, new_alert, status
from test_c3_transaction import _Hook
from voalack.txn import DeferredCommitConnection


def _in_transaction(statement):
    def hook(alert, action, text):
        from flask import g
        g.db.cursor().execute(statement, (alert.id,))
    return hook


@pytest.mark.parametrize("statement", [
    "UPDATE alerts SET customer = 'lab-Z' WHERE id = %s",
    "UPDATE voalack.bindings SET binding_revision = binding_revision + 1 WHERE alert_id = %s",
])
def test_customer_or_binding_changed_after_the_gate_rolls_back(client, faults, statement):
    alert_id = new_alert(client)
    faults("mutate", _Hook("mutate", post_action=_in_transaction(statement)))
    response = ack(client, alert_id)
    assert response.status_code == 500, response.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_interrupted_commit_that_completed_reports_saved(client, monkeypatch):
    alert_id = new_alert(client)

    def commit_then_lose_connection(self):
        self._conn.commit()
        raise psycopg2.OperationalError("connection lost after COMMIT")
    monkeypatch.setattr(DeferredCommitConnection, "commit_now", commit_then_lose_connection)
    response = ack(client, alert_id)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1 and intents(alert_id) == 1


def test_interrupted_commit_without_evidence_is_unknown(client, monkeypatch):
    alert_id = new_alert(client)

    def lose_connection(self):
        raise psycopg2.OperationalError("connection lost before COMMIT completed")
    monkeypatch.setattr(DeferredCommitConnection, "commit_now", lose_connection)
    response = ack(client, alert_id)
    assert response.status_code == 503, response.get_data(as_text=True)
    body = response.get_json()
    assert "unknown" in body["message"] and body["outcome"] == "unknown" and body["code"] == 503
    assert body["action_id"] and "rolled back" not in body["message"]
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_server_reported_commit_failure_is_a_rollback(client):
    from conftest import sql
    alert_id = new_alert(client)
    sql("""CREATE OR REPLACE FUNCTION voalack.lab_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$""", fetch=False)
    sql("""CREATE CONSTRAINT TRIGGER lab_fail_at_commit AFTER INSERT ON voalack.captures
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION voalack.lab_fail_at_commit()""", fetch=False)
    try:
        response = ack(client, alert_id)
    finally:
        sql("DROP TRIGGER lab_fail_at_commit ON voalack.captures", fetch=False)
    assert response.status_code == 500 and "unknown" not in response.get_json()["message"]
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0


def test_api_key_refusal_does_not_reveal_existence(client):
    """Coexistence 3a (r8 B2 amendment): within the public Veeam ONE class the refusal is uniform and reveals no
    binding membership; an absent id gets upstream Alerta behaviour (404), as for every non-ONE alert."""
    bound, unbound = new_alert(client), new_alert(client, bound=False)
    r = client.post("/key", json={"scopes": ["write:alerts"], "text": "lab"}, headers=basic(OPERATOR))
    key = r.get_json()["key"]
    codes = [client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                        headers={"Authorization": f"Key {key}"}).status_code
             for alert_id in (bound, unbound, str(uuid.uuid4()))]
    assert codes == [403, 403, 404], codes


@pytest.mark.parametrize("field,value", [("action_id", "other-action"), ("alert_id", "other-alert"),
                                         ("actor", "someone-else@example.test")])
def test_intent_payload_identity_changed_after_staging_rolls_back(client, faults, field, value):
    import json

    def rewrite(alert, action, text):
        from flask import g
        g.db.cursor().execute("UPDATE voalack.prepared_intents SET payload = payload || %s::jsonb WHERE action_id = %s",
                              (json.dumps({field: value}), g.voalack["action_id"]))
    alert_id = new_alert(client)
    faults("rewrite", _Hook("rewrite", post_action=rewrite))
    response = ack(client, alert_id)
    assert response.status_code == 500, response.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
