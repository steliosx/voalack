"""T05a: reverse-state assessment witnesses over the T04 S3b read-only reconciliation.

No product change. Every witness runs under an attempt that is ``uncertain`` (the attempt-keyed
reconciliation reads nothing otherwise) and states its baselines: setup counters are taken after the
uncertain attempt exists, so a delta of zero ACKs belongs to the reads, and whole-test counts are
asserted as well. Labels: [get] a real fake-provider GET counted by the fake; [sql] a direct
record/reservation call with a constructed observation (no network read); [inject] synthetic fake
state set by the test, not a provider call. See ``design/T05_REVERSE_STATE.md``.
"""

import pytest

from conftest import sql
from test_t04_s2_sender import _effect, _guards, _owner, fake, instance  # noqa: F401
from test_t04_s3b_settlement import (_comment, _effect_row, _now, _reconciliation, _record, _reserve,
                                     _settlements, _successor, _uncertain)


def _alert_of(effect_id):
    return sql("SELECT p.alert_id FROM voalack.prepared_intents p JOIN voalack.effects e USING (action_id) "
               "WHERE e.effect_id = %s", (effect_id,))[0][0]


def _alert(alert_id):
    """The Alerta alert row exactly (status and history included), and its status."""
    return sql("SELECT md5(a::text), a.status FROM alerts a WHERE a.id = %s", (alert_id,))[0]


def _ledger():
    """Rows that an echo would create: intents, captures, effects, attempts."""
    return sql("SELECT (SELECT count(*) FROM voalack.prepared_intents), (SELECT count(*) FROM voalack.captures), "
               "(SELECT count(*) FROM voalack.effects), (SELECT count(*) FROM voalack.attempts)")[0]


def _events(effect_id):
    return [r[0] for r in sql("SELECT o.outcome FROM voalack.outcome_events o JOIN voalack.effects e "
                              "USING (action_id) WHERE e.effect_id = %s ORDER BY o.revision", (effect_id,))]


def _display(action_id):
    """What only the projector may write for the action: its projection markers, protected publications and
    Alerta notes, as exact row fingerprints (count plus an ordered digest of the full rows)."""
    return sql("SELECT (SELECT count(*) || ':' || coalesce(md5(string_agg(p::text, '|' ORDER BY p::text)), '') "
               "FROM voalack.projections p WHERE p.action_id = %s), "
               "(SELECT count(*) || ':' || coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') "
               "FROM voalack_publication.publications x WHERE x.action_id = %s), "
               "(SELECT count(*) || ':' || coalesce(md5(string_agg(n::text, '|' ORDER BY n::text)), '') "
               "FROM public.notes n WHERE n.attributes->'voalack'->>'action_id' = %s)",
               (action_id, action_id, action_id))[0]


def _transport(owner, fake):
    return {"ack_writes": owner.transport.counts["ack_writes"], "receipts": fake.counts["receipts"],
            "effects": fake.counts["effects"], "reads": fake.counts["reads"]}


def _evidence(attempt_id, kind):
    return sql("SELECT count(*) FROM voalack.attempt_evidence WHERE attempt_id = %s AND kind = %s",
               (attempt_id, kind))[0][0]


def _reconciliation_rows(attempt_id):
    return sql("SELECT reconciliation_id, md5(r::text) FROM voalack.reconciliations r WHERE attempt_id = %s "
               "ORDER BY reconciliation_id", (attempt_id,))


# --- E1 (decisive): reading back our own ACK is not a new event ------------------------------------

def test_e1_reading_back_our_own_ack_never_echoes(client, app, instance, fake):
    """[get] The ACK reached the fake but its response was lost; the read sees our own ACK (with the
    [AlertaAck:<uuid>] comment), settles once, and creates nothing outbound."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake, mode="close_after_body")
    alert_id = _alert_of(effect_id)
    action = sql("SELECT action_id::text FROM voalack.attempts WHERE attempt_id = %s", (attempt_id,))[0][0]
    assert "[AlertaAck:" in _comment(attempt_id) and fake.alarms["4711"]["acked"] is True
    setup, ledger, alert, events = _transport(owner, fake), _ledger(), _alert(alert_id), _events(effect_id)
    display = _display(action)                                                  # the projector does not run
    assert (setup["ack_writes"], setup["receipts"], setup["effects"]) == (1, 1, 1)      # whole setup: one ACK

    result = owner.reconcile(attempt_id)
    after = _transport(owner, fake)
    assert after == {**setup, "reads": setup["reads"] + 1}                      # one GET, zero ACK delta
    assert (result["outcome"], result["classification"], result.get("settlement")) == \
        ("settled", "attributable", "settled"), result
    assert _ledger() == ledger                                                  # no intent/capture/effect/attempt
    assert _alert(alert_id) == alert and alert[1] == "ack"                      # Alerta status/history unchanged
    # exactly one settlement, and the two events the delivered S4 triggers derive from it in the settlement
    # transaction: the settlement row's event, then the effect's state change (voalack._outcome_event)
    assert _settlements(attempt_id) == [("confirmed_attributed", "automatic", "REMOTE_CONFIRMED", "lab_sender")]
    settlement_id, action_id = sql("SELECT settlement_id, action_id::text FROM voalack.settlements "
                                   "WHERE attempt_id = %s", (attempt_id,))[0]
    new = sql("SELECT revision, outcome, facts, txid FROM voalack.outcome_events WHERE action_id = %s "
              "AND revision > %s ORDER BY revision", (action_id, len(events)))
    assert [(r[0], r[1]) for r in new] == [(len(events) + 1, "settled:confirmed_attributed"),
                                          (len(events) + 2, "confirmed")]
    assert new[0][2] == {"settlement_id": settlement_id, "attempt_id": attempt_id, "effect_id": effect_id,
                         "path": "automatic"}
    assert new[1][2] == {"effect_id": effect_id, "state": "REMOTE_CONFIRMED", "prior_state": "UNCERTAIN",
                         "attempt_id": attempt_id}
    assert new[0][3] == new[1][3]                                               # one transaction
    assert _display(action) == display                                          # nothing published by the read
    assert _events(effect_id) == events + ["settled:confirmed_attributed", "confirmed"]
    assert _effect_row(effect_id) == ("REMOTE_CONFIRMED", False) and _guards(instance) == []

    for _ in range(2):                                                          # later calls: no read at all
        again = owner.reconcile(attempt_id)
        assert _transport(owner, fake) == after                                 # no read, no ACK
        assert (again["outcome"], again.get("reason")) == ("refused", "not_uncertain"), again
        # after each refusal individually: nothing outbound, displayed, recorded or settled
        assert _ledger() == ledger and _alert(alert_id) == alert and _display(action) == display
        assert _events(effect_id) == events + ["settled:confirmed_attributed", "confirmed"]
        assert len(_reconciliation_rows(attempt_id)) == 1 and len(_settlements(attempt_id)) == 1
    assert owner.transport.counts["ack_writes"] == 1                            # whole test: one ACK


# --- E2/E5: foreign ACK, unattributed ACK, typed marker without our operation ---------------------

OTHER_HASH = "0123456789abcdef" * 4                     # canonical 64-hex request hash of another operation


@pytest.mark.parametrize("alarm, expected", [
    ("foreign_operation", "acked_by_other"),            # E2: a valid other operation identity
    ("original_comment_no_operation", "acked_unattributed"),
    ("foreign_comment_no_operation", "evidence_only"),
    ("typed_marker_no_operation", "evidence_only"),     # E5: our marker typed into another comment
    ("original_comment_foreign_operation", "acked_by_other"),   # E5: our exact comment, another operation
    ("malformed_operation", "evidence_only"),
])
def test_e2_e5_foreign_or_unproven_acks_are_observed_never_attributed(client, app, instance, fake, alarm,
                                                                      expected):
    """[get] + [inject] The fake never processed our ACK (close_before_body); the test then sets ONE's
    state as acknowledged by someone or something else. The read records it; nothing settles."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake, mode="close_before_body")
    alert_id = _alert_of(effect_id)
    ours = _comment(attempt_id)
    action = sql("SELECT action_id::text FROM voalack.attempts WHERE attempt_id = %s", (attempt_id,))[0][0]
    base = {"target_id": "4711", "kind": "triggered_alarm", "acked": True}
    fake.alarms["4711"] = {**base, **{                                          # [inject]
        "foreign_operation": {"acked_by_operation": OTHER_HASH, "comment": "acknowledged in ONE"},
        "original_comment_no_operation": {"comment": ours},
        "foreign_comment_no_operation": {"comment": "acknowledged in ONE"},
        "typed_marker_no_operation": {"comment": f"[AlertaAck:{action}] typed by someone"},
        "original_comment_foreign_operation": {"acked_by_operation": OTHER_HASH, "comment": ours},
        "malformed_operation": {"acked_by_operation": "not-a-hash", "comment": ours},
    }[alarm]}
    setup, ledger, alert, events = _transport(owner, fake), _ledger(), _alert(alert_id), _events(effect_id)
    assert (setup["ack_writes"], setup["receipts"], setup["effects"]) == (1, 0, 0)      # setup sent one, unprocessed

    result = owner.reconcile(attempt_id)
    assert _transport(owner, fake) == {**setup, "reads": setup["reads"] + 1}   # the GET happened; zero ACK delta
    assert (result["outcome"], result["classification"]) == ("recorded", expected), result
    assert _ledger() == ledger and _alert(alert_id) == alert and _events(effect_id) == events
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _settlements(attempt_id) == []
    assert owner.transport.counts["ack_writes"] == 1


# --- E3: replaying a reservation or a record never grants a fresh read ------------------------------

def test_e3_replayed_reservation_and_record_keep_the_first_result(client, app, instance, fake):
    """[get] one real first read through the owner; then [sql] replays of its reservation and record."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake, mode="close_before_body")
    setup, ledger = _transport(owner, fake), _ledger()                         # before the first read
    first = owner.reconcile(attempt_id, settle=False)
    transport = _transport(owner, fake)
    assert transport == {**setup, "reads": setup["reads"] + 1}                 # exactly one GET, zero ACK delta
    assert (first["outcome"], first["classification"]) == ("recorded", "not_acked"), first
    assert _ledger() == ledger                                                  # the read created no outbound row
    read_id, rid = first["read_id"], first["reconciliation_id"]
    rows = _reconciliation_rows(attempt_id)
    assert len(rows) == 1
    stored = sql("SELECT observation FROM voalack.reconciliations WHERE reconciliation_id = %s", (rid,))[0][0]

    assert _reserve(owner, attempt_id, read_id)[1]["outcome"] == "already_reserved"
    same = _record(owner, read_id, stored)
    assert (same["outcome"], same["r_reconciliation_id"], same["r_classification"]) == ("recorded", rid, "not_acked")
    conflict = _record(owner, read_id, {**stored, "alarm": {**stored["alarm"], "acked": True}})
    assert (conflict["outcome"], conflict["r_reconciliation_id"], conflict["r_classification"]) == \
        ("already_recorded", rid, "not_acked")
    assert _evidence(attempt_id, "conflicting_reconciliation") == 1
    assert _reconciliation_rows(attempt_id) == rows                             # one immutable record
    assert _transport(owner, fake) == transport and _ledger() == ledger         # no read, no outbound row
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _settlements(attempt_id) == []


# --- E4: a stale reader's late record cannot overwrite or settle ------------------------------------

def test_e4_late_record_from_a_fenced_reader_is_evidence_only(client, app, instance, fake):
    """[sql] the original owner reserves a read and is then replaced; [get] the successor reads and
    records; [sql] the original's late record is refused and kept as evidence only."""
    effect_id, attempt_id, original = _uncertain(client, app, instance, fake, mode="close_after_body")
    stale_read, row = _reserve(original, attempt_id)
    assert row["outcome"] == "reserved"
    successor = _successor(instance, fake, original, quiesce=False)
    alert_id = _alert_of(effect_id)
    provider = dict(fake.counts)
    writes = (original.transport.counts["ack_writes"], successor.transport.counts["ack_writes"])
    ledger, alert, events = _ledger(), _alert(alert_id), _events(effect_id)    # before the successor read
    assert _reconciliation_rows(attempt_id) == []
    newer = successor.reconcile(attempt_id, settle=False)
    expected = {**provider, "reads": provider["reads"] + 1, "logins": provider["logins"] + 1}
    assert fake.counts == expected                              # only the intended GET and the successor's login
    assert writes == (1, 0) and successor.transport.counts["ack_writes"] == 0
    assert (newer["outcome"], newer["classification"]) == ("recorded", "attributable"), newer
    rows = _reconciliation_rows(attempt_id)
    assert len(rows) == 1 and rows[0][0] == newer["reconciliation_id"]          # the one new reconciliation
    assert _ledger() == ledger and _alert(alert_id) == alert and _events(effect_id) == events

    late = _record(original, stale_read, {"kind": "reconciliation_read", "status": 200,
                                          "alarm": {"target_id": "4711", "kind": "triggered_alarm", "acked": False},
                                          "read_started_at": _now(), "read_completed_at": _now()})
    assert (late["outcome"], late["r_reconciliation_id"], late["r_classification"]) == ("owner_fenced", None, None)
    assert _evidence(attempt_id, "late_reconciliation") == 1
    assert _reconciliation_rows(attempt_id) == rows                             # the newer record is unchanged
    assert _reconciliation(newer["reconciliation_id"])[3:5] == (successor.generation, successor.incarnation)
    assert _settlements(attempt_id) == [] and _effect_row(effect_id) == ("UNCERTAIN", True)
    assert _ledger() == ledger and _alert(alert_id) == alert and _events(effect_id) == events
    assert fake.counts == expected                                              # the SQL record made no call
    assert original.transport.counts["ack_writes"] == 1 and successor.transport.counts["ack_writes"] == 0


# --- E6: an unacknowledgement in ONE keeps the hold and never re-ACKs ------------------------------

@pytest.mark.parametrize("unack", ["operation_cleared", "operation_kept"])
def test_e6_unack_before_the_read_keeps_the_hold(client, app, instance, fake, unack):
    """[get] + [inject] Our ACK reached the fake (close_after_body); ONE is then unacknowledged before
    the read. The read sees it; the effect stays held; nothing is sent again."""
    effect_id, attempt_id, owner = _uncertain(client, app, instance, fake, mode="close_after_body")
    alert_id = _alert_of(effect_id)
    alarm = dict(fake.alarms["4711"])
    alarm["acked"] = False                                                      # [inject]
    if unack == "operation_cleared":
        alarm.pop("acked_by_operation", None)
        alarm.pop("operation_status", None)
    fake.alarms["4711"] = alarm
    setup, ledger, alert, events = _transport(owner, fake), _ledger(), _alert(alert_id), _events(effect_id)

    result = owner.reconcile(attempt_id)
    assert _transport(owner, fake) == {**setup, "reads": setup["reads"] + 1}   # the GET happened; zero ACK delta
    expected = "not_acked" if unack == "operation_cleared" else "evidence_only"
    assert (result["outcome"], result["classification"]) == ("recorded", expected), result
    assert _effect_row(effect_id) == ("UNCERTAIN", True) and _guards(instance) == [("4711", "uncertain")]
    assert _settlements(attempt_id) == [] and _events(effect_id) == events
    assert _ledger() == ledger and _alert(alert_id) == alert
    assert owner.transport.counts["ack_writes"] == 1 and fake.counts["effects"] == 1
