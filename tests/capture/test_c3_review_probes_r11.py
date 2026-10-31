"""Independent response-side-effect probes; synthetic smolvm only, no external I/O."""
import pytest
from flask import request
from conftest import capture_does_nothing, CONFIG, ack, captures, intents, new_alert, sql, status


@pytest.mark.parametrize("failure", ["missing-capture", "commit-failure"])
def test_unreviewed_existing_response_callback_never_announces_uncommitted_ack(app, monkeypatch, failure):
    # Initialize synthetic users/schema via the submitted session fixture first.
    # Register this callback in the real Alerta factory BEFORE Voalack installs its boundary.
    import alerta.app
    from voalack.boundary import create_app
    original_factory = alerta.app.create_app
    seen = []

    def factory(*args, **kwargs):
        target = original_factory(*args, **kwargs)
        @target.after_request
        def publish(response):
            if request.method == "PUT" and request.endpoint == "api.action_alert":
                # A durable external notification would already have escaped here.
                # This in-memory observer makes the same ordering visible without network I/O.
                seen.append(response.status_code)
            return response
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
