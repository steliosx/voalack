"""C3: the commit is made after every request_finished receiver has run, and only when
Voalack's is the only receiver (receiver order is not guaranteed).

Receiver order is not guaranteed, so each foreign receiver records, from a separate
connection, whether the ACK was already committed when it ran.
"""
import psycopg2
import pytest
from flask import request_finished

from conftest import DSN, ack, captures, intents, new_alert, status


def _committed_status(alert_id):
    with psycopg2.connect(DSN) as other, other.cursor() as cur:
        cur.execute("SELECT status FROM alerts WHERE id = %s", (alert_id,))
        return cur.fetchone()[0]


def _with_receiver(app, receiver, call):
    request_finished.connect(receiver, app, weak=False)
    try:
        return call()
    finally:
        request_finished.disconnect(receiver, app)


def test_receiver_changing_the_response_finds_nothing_committed(client, app):
    alert_id = new_alert(client)
    seen = []

    def change(sender, response=None, **extra):
        seen.append(_committed_status(alert_id))
        response.status_code = 500

    response = _with_receiver(app, change, lambda: ack(client, alert_id))
    assert seen == ["open"], seen
    assert response.status_code >= 400
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_raising_receiver_finds_nothing_committed(client, app):
    alert_id = new_alert(client)
    seen = []

    def fail(sender, response=None, **extra):
        seen.append(_committed_status(alert_id))
        raise RuntimeError("injected request_finished receiver failure")

    previous = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False
    try:
        response = _with_receiver(app, fail, lambda: ack(client, alert_id))
    finally:
        app.config["PROPAGATE_EXCEPTIONS"] = previous
    assert seen and set(seen) == {"open"}, seen
    assert response.status_code >= 400
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_passive_foreign_receiver_is_rejected(client, app):
    alert_id = new_alert(client)
    seen = []

    def observe(sender, response=None, **extra):
        seen.append(_committed_status(alert_id))

    response = _with_receiver(app, observe, lambda: ack(client, alert_id))
    assert seen == ["open"], seen
    assert response.status_code >= 400, response.get_data(as_text=True)     # refused at the gate (B1)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_without_foreign_receivers_the_ack_commits(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1 and intents(alert_id) == 1
