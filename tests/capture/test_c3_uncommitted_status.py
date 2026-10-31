"""A5: an uncommitted eligible ACK never leaves with a success status a receiver chose."""
import pytest
from alerta.exceptions import ForwardingLoop
from flask import request_finished

from conftest import capture_does_nothing, ack, captures, intents, new_alert, sql, status
from test_c3_transaction import _Hook, _raise


def _set_status(code):
    def receiver(sender, response=None, **extra):
        response.status_code = code
    return receiver


@pytest.mark.parametrize("code", [200, 201, 204])
def test_failed_capture_cannot_become_success(client, app, code):
    # Review of 27f02c4 (automated): a failed postcondition rolled back in _finish.
    alert_id = new_alert(client)
    receiver = _set_status(code)
    request_finished.connect(receiver, app, weak=False)
    try:
        with capture_does_nothing():      # 3a S3a: a lab capture-skip fault; disabling the trigger is refused DDL
            response = ack(client, alert_id)
    finally:
        request_finished.disconnect(receiver, app)
    assert response.status_code >= 400, response.status_code
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


@pytest.mark.parametrize("code", [None, 200, 201])
def test_forwarding_loop_202_is_kept_only_unchanged(client, app, faults, code):
    alert_id = new_alert(client)
    faults("loop", _Hook("loop", post_action=_raise(ForwardingLoop("injected loop"))))
    receiver = _set_status(code) if code else None
    if receiver:
        request_finished.connect(receiver, app, weak=False)
    try:
        response = ack(client, alert_id)
    finally:
        if receiver:
            request_finished.disconnect(receiver, app)
    assert response.status_code == (202 if code is None else 500), response.status_code
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0


def test_error_handler_202_is_not_the_genuine_forwarding_loop(client, app, faults):
    # Automated review of dfef40d: a handled view exception answered with 202.
    from alerta.exceptions import ApiError
    alert_id = new_alert(client)
    previous = dict(app.error_handler_spec[None][None])
    app.error_handler_spec[None][None][ApiError] = lambda exc: ({"status": "ok"}, 202)
    faults("fail", _Hook("fail", post_action=_raise(RuntimeError("failed chain"))))
    try:
        response = ack(client, alert_id)
    finally:
        app.error_handler_spec[None][None].clear()
        app.error_handler_spec[None][None].update(previous)
    assert response.status_code == 500, response.status_code
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
