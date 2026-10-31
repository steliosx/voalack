"""C3: the commit happens after the session is saved; a failing session save leaves nothing."""
import pytest
from werkzeug.exceptions import InternalServerError

from conftest import ack, captures, intents, new_alert, status


class _FailingSave:
    def __init__(self, inner):
        self.inner = inner

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def save_session(self, app, session, response):
        raise RuntimeError("injected session store failure")


@pytest.mark.parametrize("handler_status", [None, 200])
def test_failing_session_save_does_not_commit(client, app, handler_status):
    alert_id = new_alert(client)
    wrapper = app.session_interface                      # voalack's CommitAfterSessionSave
    original_inner = wrapper.inner
    previous_handlers = dict(app.error_handler_spec[None].get(500, {}))
    previous_propagate = app.config.get("PROPAGATE_EXCEPTIONS")
    app.config["PROPAGATE_EXCEPTIONS"] = False
    if handler_status:
        app.error_handler_spec[None].setdefault(500, {})[InternalServerError] = \
            lambda exc: ({"status": "ok", "handled": True}, handler_status)
    wrapper.inner = _FailingSave(original_inner)
    try:
        response = ack(client, alert_id)
    finally:
        wrapper.inner = original_inner
        app.error_handler_spec[None].setdefault(500, {}).clear()
        app.error_handler_spec[None][500].update(previous_handlers)
        app.config["PROPAGATE_EXCEPTIONS"] = previous_propagate
    assert status(alert_id)[0] == "open", (response.status_code, status(alert_id), captures(alert_id))
    assert captures(alert_id) == 0 and intents(alert_id) == 0


def test_commit_happens_after_session_save(client, app):
    alert_id = new_alert(client)
    wrapper = app.session_interface
    original_inner = wrapper.inner
    seen = {}

    class _Observe:
        def __getattr__(self, name):
            return getattr(original_inner, name)

        def save_session(self, app_, session, response):
            import psycopg2
            from conftest import DSN
            with psycopg2.connect(DSN) as other, other.cursor() as cur:
                cur.execute("SELECT status FROM alerts WHERE id = %s", (alert_id,))
                seen["status_during_save"] = cur.fetchone()[0]      # not yet committed
            original_inner.save_session(app_, session, response)

    wrapper.inner = _Observe()
    try:
        assert ack(client, alert_id).status_code == 200
    finally:
        wrapper.inner = original_inner
    assert seen["status_during_save"] == "open"
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1
