"""C3: the eligible local ACK and its capture commit together or not at all."""
import psycopg2
import pytest
from alerta.exceptions import ForwardingLoop
from alerta.plugins import PluginBase

from conftest import DSN, OPERATOR, READER, ack, captures, intents, new_alert, sql, status


class _Hook(PluginBase):
    def __init__(self, name, **hooks):
        super().__init__(name)
        self._hooks = hooks

    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return None

    def status_change(self, alert, status, text, **kwargs):
        return self._hooks.get("status_change", lambda *a: None)(alert, status, text)

    def take_action(self, alert, action, text, **kwargs):
        return self._hooks.get("take_action", lambda *a: None)(alert, action, text)

    def post_action(self, alert, action, text, **kwargs):
        return self._hooks.get("post_action", lambda *a: None)(alert, action, text)


def _raise(exc):
    def hook(*args):
        raise exc
    return hook


def test_eligible_ack_commits_with_exactly_one_capture(client):
    alert_id = new_alert(client)
    r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert status(alert_id) == ("ack", "ack", OPERATOR[0])
    assert intents(alert_id) == 1 and captures(alert_id) == 1


def test_unbound_alert_keeps_upstream_behaviour(client):
    alert_id = new_alert(client, bound=False)
    assert ack(client, alert_id).status_code == 200
    assert status(alert_id)[0] == "ack"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_post_action_failure_rolls_back_ack_and_capture(client, faults):
    alert_id = new_alert(client)
    faults("fault", _Hook("fault", post_action=_raise(RuntimeError("injected after set_alert"))))
    r = ack(client, alert_id)
    assert r.status_code == 500
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_forwarding_loop_202_rolls_back(client, faults):
    # Upstream keeps the ACK on 202; for an eligible alert only 200 may commit (A5).
    alert_id = new_alert(client)
    faults("loop", _Hook("loop", post_action=_raise(ForwardingLoop("injected loop"))))
    r = ack(client, alert_id)
    assert r.status_code == 202
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_disabled_trigger_fails_closed(client):
    # Coexistence 3a S3a (amended openly): disabling the capture trigger is refused DDL under the enabled guard. Under
    # the disclosed lab bypass (a disabled trigger and disabled event triggers), the gate refuses before staging (503).
    from conftest import guard_bypassed
    alert_id = new_alert(client)
    with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg2.Error) as exc:
            cur.execute("ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack")
    assert "protected inventory" in str(exc.value), exc.value
    with guard_bypassed("legacy disabled-trigger witness: the gate refuses before staging"):
        sql("ALTER TABLE public.alerts DISABLE TRIGGER voalack_capture_ack", fetch=False)
        r = ack(client, alert_id)
    assert r.status_code == 503 and "protections not intact" in r.get_data(as_text=True)
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_capture_insert_failure_rolls_back(client):
    alert_id = new_alert(client)
    sql("ALTER TABLE voalack.captures ADD CONSTRAINT lab_reject CHECK (false) NOT VALID", fetch=False)
    try:
        r = ack(client, alert_id)
    finally:
        sql("ALTER TABLE voalack.captures DROP CONSTRAINT lab_reject", fetch=False)
    assert r.status_code == 500
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_commit_failure_is_reported_and_nothing_persists(client):
    alert_id = new_alert(client)
    sql("""CREATE OR REPLACE FUNCTION voalack.lab_fail_at_commit() RETURNS trigger LANGUAGE plpgsql AS
           $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$""", fetch=False)
    sql("""CREATE CONSTRAINT TRIGGER lab_fail_at_commit AFTER INSERT ON voalack.captures
           DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION voalack.lab_fail_at_commit()""", fetch=False)
    try:
        r = ack(client, alert_id)
    finally:
        sql("DROP TRIGGER lab_fail_at_commit ON voalack.captures", fetch=False)
    assert r.status_code == 500
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_tag_and_attribute_writes_add_no_second_capture(client, faults):
    # A3: status_change tags/attributes (before set_alert) and post_action updates (after it)
    # issue extra UPDATEs on the same row; only the ACK history change captures, once.
    alert_id = new_alert(client)

    def tag(alert, *rest):
        alert.tags.append("lab-tag")
        alert.attributes["labNote"] = "x"
        return alert, rest[0], rest[1]
    faults("writer", _Hook("writer", status_change=tag, post_action=lambda a, act, t: (a, act, t)))
    r = ack(client, alert_id)
    assert r.status_code == 200, r.get_data(as_text=True)
    assert captures(alert_id) == 1 and intents(alert_id) == 1
    assert "lab-tag" in sql("SELECT tags FROM alerts WHERE id = %s", (alert_id,))[0][0]


def test_unauthenticated_request_rolls_back_and_releases_the_lock(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id, who=None).status_code == 401
    assert status(alert_id)[0] == "open" and intents(alert_id) == 0
    r = ack(client, alert_id)                              # lock released: the real ACK proceeds
    assert r.status_code == 200 and captures(alert_id) == 1


def test_read_only_user_is_denied_without_capture(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id, who=READER).status_code == 403
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def test_second_ack_of_an_acked_alert_does_not_capture_again(client):
    alert_id = new_alert(client)
    assert ack(client, alert_id).status_code == 200
    ack(client, alert_id)                                  # already acked: no new ACK history entry
    assert captures(alert_id) == 1


def test_a_capture_that_records_nothing_fails_the_postcondition(client):
    """The pre-3a disabled-trigger witness, kept on the postcondition path: the trigger is present and frozen but its
    function records nothing, so the gate passes and the missing capture fails closed (500), nothing kept."""
    from conftest import LATE_POSTCONDITION, capture_does_nothing
    alert_id = new_alert(client)
    with capture_does_nothing() as logs:
        r = ack(client, alert_id)
    assert r.status_code == 500 and "capture could not be recorded" in r.get_data(as_text=True)
    assert LATE_POSTCONDITION in logs, logs
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0
