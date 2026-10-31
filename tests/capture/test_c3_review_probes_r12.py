"""Independent native callback identity witness; synthetic guest, no external I/O."""
import types
import pytest
from flask import request
from conftest import capture_does_nothing, CONFIG, ack, captures, intents, new_alert, sql, status


@pytest.mark.parametrize("failure", ["missing-capture", "commit-failure"])
def test_new_cors_callback_with_unreviewed_globals_is_refused(app, monkeypatch, failure):
    import alerta.app
    from voalack.boundary import create_app
    original_factory = alerta.app.create_app
    seen = []

    def factory(*args, **kwargs):
        target = original_factory(*args, **kwargs)
        native = next(f for f in target.after_request_funcs[None]
                      if f.__module__ == "flask_cors.extension")
        real_set_headers = native.__globals__["set_cors_headers"]
        def publish(response, options):
            if request.endpoint == "api.action_alert":
                seen.append(response.status_code)
            return real_set_headers(response, options)
        # Genuine reviewed code object, but a NEW unreviewed callable with a different
        # global helper: register before install, without changing the installed module.
        namespace = dict(native.__globals__, set_cors_headers=publish,
                         ACL_ORIGIN="X-Voalack-Synthetic-Unset-Cors")
        # Alerta action views already set the real CORS header. This private replacement
        # global makes this NEW callback reach its helper rather than return early.
        forged = types.FunctionType(native.__code__, namespace, native.__name__,
                                    native.__defaults__, native.__closure__)
        target.after_request(forged)
        return target

    with monkeypatch.context() as patch:
        patch.setattr(alerta.app, "create_app", factory)
        target = create_app(config_override=CONFIG)
    with target.test_client() as client:
        alert_id = new_alert(client)
        noop = capture_does_nothing()       # 3a S3a: a lab capture-skip fault; disabling the trigger is refused DDL
        if failure == "missing-capture":
            noop.__enter__()
        else:
            sql("""CREATE OR REPLACE FUNCTION voalack.lab_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS
                   $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$""", fetch=False)
            sql("""CREATE CONSTRAINT TRIGGER lab_fail_at_commit AFTER INSERT ON voalack.captures
                   DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION voalack.lab_fail_at_commit()""", fetch=False)
        try:
            response = ack(client, alert_id)
        finally:
            if failure == "missing-capture":
                noop.__exit__(None, None, None)
            else:
                sql("DROP TRIGGER lab_fail_at_commit ON voalack.captures", fetch=False)
    actual = (response.status_code, status(alert_id)[0], captures(alert_id), intents(alert_id), seen)
    assert response.status_code >= 400 and actual[1:4] == ("open", 0, 0), actual
    assert seen, actual
    assert all(code >= 400 for code in seen), actual
