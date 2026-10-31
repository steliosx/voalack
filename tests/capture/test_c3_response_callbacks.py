"""R11: response callbacks run before the commit decision; only reviewed ones allow capture.

Reviewed callbacks are the actual callable objects frozen at install (the pinned factory's own,
identified by code and binding, plus explicitly configured ones); names never qualify.
"""
import logging

import pytest
from flask import Flask, after_this_request, request

import voalack.boundary as boundary
from conftest import CONFIG, ack, captures, intents, new_alert, status

seen_by_reviewed = []


def reviewed_local(response):
    """A local callback an operator has reviewed (records only, no external effect)."""
    if request.endpoint == "api.action_alert":
        seen_by_reviewed.append(response.status_code)
    return response


def _refused(client, alert_id, seen):
    response = ack(client, alert_id)
    assert response.status_code == 503, response.get_data(as_text=True)
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
    assert all(code >= 400 for code in seen), seen


def _observer(seen):
    def publish(response):
        if request.endpoint == "api.action_alert":
            seen.append(response.status_code)
        return response
    return publish


def test_native_callbacks_are_frozen_by_identity(app):
    from alerta.utils.logging import Logger
    labels = sorted(boundary._label(f) for f in app.extensions["voalack_reviewed_callbacks"])
    assert labels == ["alerta.utils.tracing.Tracing.set_request_id",
                      "flask_compress.flask_compress.Compress.after_request",
                      "flask_cors.extension.make_after_request_function.<locals>.cors_after_request"], labels
    assert app.extensions["voalack_request_logger"] is Logger.log_response


def test_compress_with_a_cache_backend_is_not_native(app, monkeypatch):
    import alerta.app
    monkeypatch.setattr(alerta.app.compress, "cache", object())   # would store response bodies
    reviewed, _ = boundary._native_response_callbacks(app)
    assert "flask_compress.flask_compress.Compress.after_request" not in [boundary._label(f) for f in reviewed]


@pytest.mark.parametrize("scope", [None, "api"])
def test_unknown_application_or_blueprint_callback_is_refused(client, app, scope):
    alert_id = new_alert(client)
    seen = []
    callbacks = app.after_request_funcs.setdefault(scope, [])
    callbacks.append(_observer(seen))
    try:
        _refused(client, alert_id, seen)
    finally:
        callbacks.pop()


def test_request_local_callback_is_refused(client, app):
    alert_id = new_alert(client)
    seen = []

    def register():
        if request.endpoint == "api.action_alert":
            after_this_request(_observer(seen))
    app.before_request_funcs.setdefault(None, []).append(register)
    try:
        _refused(client, alert_id, seen)
    finally:
        app.before_request_funcs[None].remove(register)


def test_same_name_replacement_of_a_native_callback_is_refused(client, app):
    from alerta.utils.tracing import Tracing
    alert_id = new_alert(client)
    seen = []
    publish = _observer(seen)

    def set_request_id(response):
        return publish(response)
    set_request_id.__module__, set_request_id.__qualname__ = "alerta.utils.tracing", "Tracing.set_request_id"
    callbacks = app.after_request_funcs[None]
    index = next(i for i, f in enumerate(callbacks) if f is Tracing.set_request_id)
    callbacks[index] = set_request_id
    try:
        _refused(client, alert_id, seen)
    finally:
        callbacks[index] = Tracing.set_request_id


def test_request_logger_emitting_info_is_refused(client, app):
    alert_id = new_alert(client)
    previous = app.logger.level
    app.logger.setLevel(logging.INFO)          # log_response would record the provisional 200
    try:
        _refused(client, alert_id, [])
    finally:
        app.logger.setLevel(previous)


def test_operator_selectors_must_match_exactly_one_callback():
    bare = Flask(__name__)
    with pytest.raises(RuntimeError, match="not found"):
        boundary._operator_reviewed_callbacks(bare, ["test_c3_response_callbacks:missing"])
    with pytest.raises(RuntimeError, match="matches 0"):
        boundary._operator_reviewed_callbacks(bare, ["test_c3_response_callbacks:reviewed_local"])
    bare.after_request(reviewed_local)
    bare.after_request(reviewed_local)
    with pytest.raises(RuntimeError, match="matches 2"):
        boundary._operator_reviewed_callbacks(bare, ["test_c3_response_callbacks:reviewed_local"])


def test_reviewed_local_callback_allows_capture(app, monkeypatch):
    import alerta.app
    from voalack.boundary import create_app
    original_factory = alerta.app.create_app

    def factory(*args, **kwargs):
        target = original_factory(*args, **kwargs)
        target.after_request(reviewed_local)
        return target
    config = dict(CONFIG, VOALACK_REVIEWED_RESPONSE_CALLBACKS=["test_c3_response_callbacks:reviewed_local"])
    with monkeypatch.context() as patch:
        patch.setattr(alerta.app, "create_app", factory)
        target = create_app(config_override=config)
    seen_by_reviewed.clear()
    with target.test_client() as client:
        alert_id = new_alert(client)
        response = ack(client, alert_id)
    assert response.status_code == 200, response.get_data(as_text=True)
    assert status(alert_id)[0] == "ack" and captures(alert_id) == 1 and intents(alert_id) == 1
    assert seen_by_reviewed == [200]


def _cors_closure():
    from flask_cors.extension import make_after_request_function
    return make_after_request_function([])


def test_cors_identity_needs_the_real_module_and_one_closure():
    import types
    real = _cors_closure()
    forged = types.FunctionType(real.__code__, {"__name__": "flask_cors.extension"}, real.__name__,
                                real.__defaults__, real.__closure__)
    for registered, native in (([real], True), ([forged], False), ([real, _cors_closure()], False)):
        bare = Flask(__name__)
        for func in registered:
            bare.after_request(func)
        reviewed, _ = boundary._native_response_callbacks(bare)
        assert (len(reviewed) == 1) is native, (registered, reviewed)


def test_error_after_compression_drops_the_encoding(client, app):
    # Automated review of bd35994: the provisional 200 was gzipped before the commit failed.
    from conftest import sql
    alert_id = new_alert(client)
    previous = app.config.get("COMPRESS_MIN_SIZE")
    app.config["COMPRESS_MIN_SIZE"] = 0
    sql("""CREATE OR REPLACE FUNCTION voalack.lab_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$""", fetch=False)
    sql("""CREATE CONSTRAINT TRIGGER lab_fail_at_commit AFTER INSERT ON voalack.captures
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION voalack.lab_fail_at_commit()""", fetch=False)
    try:
        from conftest import OPERATOR, basic
        response = client.put(f"/alert/{alert_id}/action", json={"action": "ack", "text": "x"},
                              headers={**basic(OPERATOR), "Accept-Encoding": "gzip"})
    finally:
        sql("DROP TRIGGER lab_fail_at_commit ON voalack.captures", fetch=False)
        app.config["COMPRESS_MIN_SIZE"] = previous
    assert response.status_code == 500
    assert "Content-Encoding" not in response.headers, dict(response.headers)
    assert response.get_json()["status"] == "error"
    assert int(response.headers["Content-Length"]) == len(response.get_data())
    assert status(alert_id)[0] == "open" and captures(alert_id) == 0 and intents(alert_id) == 0
