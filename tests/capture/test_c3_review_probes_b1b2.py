"""Independent B1/B2 regressions for exact a3e8590; synthetic guest only."""
import time
import psycopg2
from flask import request_finished
from conftest import DSN, ack, captures, intents, new_alert, status


def test_foreign_receiver_never_observes_provisional_ack_success(client, app):
    alert_id = new_alert(client)
    seen = []
    def receiver(sender, response=None, **extra):
        # This in-memory record stands for an irreversible external effect; no network I/O.
        seen.append(response.status_code)
    request_finished.connect(receiver, app, weak=False)
    try:
        response = ack(client, alert_id)
    finally:
        request_finished.disconnect(receiver, app)
    assert response.status_code >= 400
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
    assert all(code >= 400 for code in seen), seen


def test_self_disconnecting_foreign_receiver_cannot_allow_ack_commit(client, app):
    alert_id = new_alert(client)
    seen = []
    def receiver(sender, response=None, **extra):
        seen.append(response.status_code)
        request_finished.disconnect(receiver, app)
    request_finished.connect(receiver, app, weak=False)
    try:
        response = ack(client, alert_id)
    finally:
        request_finished.disconnect(receiver, app)
    actual = (response.status_code, status(alert_id)[0], captures(alert_id), intents(alert_id), seen)
    assert response.status_code >= 400 and actual[1:4] == ("open", 0, 0), actual
    assert all(code >= 400 for code in seen), seen


def test_unauthenticated_contention_cannot_reveal_binding(client, app):
    bound = new_alert(client)
    unbound = new_alert(client, bound=False)
    previous = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False
    outcomes = []
    try:
        with psycopg2.connect(DSN) as locker:
            with locker.cursor() as cur:
                cur.execute("SELECT id FROM alerts WHERE id IN (%s, %s) FOR UPDATE", (bound, unbound))
            for alert_id in (unbound, bound):
                start = time.monotonic()
                response = ack(client, alert_id, who=None)
                outcomes.append((response.status_code, time.monotonic() - start, response.get_json()))
    finally:
        app.config["PROPAGATE_EXCEPTIONS"] = previous
    assert status(bound)[0] == "open" and captures(bound) == 0 and intents(bound) == 0
    assert [code for code, elapsed, body in outcomes] == [401, 401], outcomes
    # Generous local bound detects a 2s row-lock wait; this is not statistical timing qualification.
    assert all(elapsed < 1 for code, elapsed, body in outcomes), outcomes
