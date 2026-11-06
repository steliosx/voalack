#!/usr/bin/env python3
"""Finite synthetic lab demonstration; never a production worker or installer.

Run only in a fresh approved disposable guest after setup_guest.sh and installation
of the exact candidate wheels. Uses real Alerta/PostgreSQL, Alerta's in-process
HTTP test client, and the existing loopback fake ONE server. No live endpoint,
credential, database, instance or provider override is accepted.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import closing
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys
import uuid


ADMIN = "postgres://lab_admin:lab-only-admin@127.0.0.1/alerta"
APP = "postgres://alerta:lab-only-synthetic@127.0.0.1/alerta"
VERIFY = "postgres://lab_verifier:lab-only-verifier@127.0.0.1/alerta"
SEND = "postgres://lab_sender:lab-only-sender@127.0.0.1/alerta"
PROJECT = "postgres://lab_projector:lab-only-projector@127.0.0.1/alerta"
HUMAN = ("operator@example.test", "synthetic-demo-password")
CUSTOMER = "synthetic-beta-customer"


class DemoFailure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DemoFailure(message)


def sql(query, params=()):
    import psycopg2
    with closing(psycopg2.connect(ADMIN, connect_timeout=2,
                                 options="-c statement_timeout=15000 -c lock_timeout=5000")) as conn:
        with conn, conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall() if cur.description else []


def basic():
    token = base64.b64encode(":".join(HUMAN).encode()).decode()
    return {"Authorization": "Basic " + token}


def enroll(client, instance, target):
    from voalack.envelope import SNAPSHOT_FIELDS, snapshot_digest
    suffix = uuid.uuid4().hex
    response = client.post("/alert", headers=basic(), json={
        "resource": "veeamone:synthetic-" + suffix, "event": "VeeamOneAlarm",
        "environment": "Development", "severity": "major", "value": "Error",
        "service": ["synthetic-beta"], "text": "Synthetic beta demonstration",
        "attributes": {"veeamAlarmCombinationId": "comb-" + suffix, "captureId": "cap-" + suffix}})
    require(response.status_code == 201, "synthetic alert creation failed")
    alert = response.get_json()["id"]
    # Synthetic administrator enrollment, not trust in an incoming mutable customer field.
    sql("UPDATE public.alerts SET customer = %s WHERE id = %s", (CUSTOMER, alert))
    row = sql("SELECT id,customer,resource,event,environment,origin,attributes FROM public.alerts WHERE id=%s",
              (alert,))[0]
    fields = dict(zip(("id", "customer", "resource", "event", "environment", "origin"), row[:6]))
    binding = "synthetic-" + alert
    sql("""INSERT INTO voalack.binding_revisions
        (binding_id,binding_revision,customer,source_namespace,instance_id,resource,event,environment,origin,
         combination_id,capture_id,target_kind,target_id,alarm_template_id,object_id,repeat_count,triggered_time,
         occurrence_ref,occurrence_evidence_sha256,snapshot_sha256,alert_lifetime_id)
        VALUES (%s,1,%s,'synthetic-demo',%s,%s,%s,%s,%s,%s,%s,'triggered_alarm',%s,7,9,0,
                '2026-10-02T00:00:00Z',%s,%s,%s,voalack.alert_open_lifetime(%s))""",
        (binding, CUSTOMER, instance, fields["resource"], fields["event"], fields["environment"], fields["origin"],
         row[6]["veeamAlarmCombinationId"], row[6]["captureId"], target, "synthetic-occurrence-" + alert,
         "e" * 64, snapshot_digest({k: fields[k] for k in SNAPSHOT_FIELDS}), alert))
    require(sql("SELECT voalack.enroll_binding(%s,%s,1)", (alert, binding))[0][0] == binding,
            "binding enrollment failed")
    return alert


def projection_witness(action, anchor, expected):
    import psycopg2
    from voalack import projector
    before = sql("SELECT count(*) FROM voalack.prepared_intents")[0][0]
    delivery = sql("SELECT state,in_flight_attempt FROM voalack.effects WHERE action_id=%s", (action,))
    events = sql("SELECT revision,outcome,epoch,note_id,note_text FROM voalack.outcome_events "
                 "WHERE action_id=%s ORDER BY revision", (action,))
    require([(e[0], e[1]) for e in events] == [(1, "queued"), (2, expected)],
            "outcome events do not match queued and expected terminal state")
    result = projector.run(PROJECT, str(anchor), "synthetic-beta-projector", max_steps=20)
    require(result and result[-1]["outcome"] == "idle", "projection did not drain to idle")
    with closing(psycopg2.connect(PROJECT)) as conn:
        status = projector.status(conn, action)
    require(status["latest_publication"]["display"] == "valid", "projected note is not valid")
    require(status["current"] == {"note_id": events[-1][3], "epoch": events[-1][2], "revision": 2},
            "current projection does not name the terminal event")
    notes = sql("SELECT id,text FROM public.notes WHERE attributes->'voalack'->>'action_id'=%s ORDER BY create_time,id",
                (action,))
    require(notes == [(e[3], e[4]) for e in events], "notes do not match the recorded outcome events")
    publications = sql("SELECT epoch,revision,note_id FROM voalack_publication.publications "
                       "WHERE action_id=%s ORDER BY epoch,revision", (action,))
    require(publications == [(e[2], e[0], e[3]) for e in events], "publication identities do not match events")
    require(sql("SELECT count(*) FROM voalack.prepared_intents")[0][0] == before,
            "projection created an intent")
    require(sql("SELECT state,in_flight_attempt FROM voalack.effects WHERE action_id=%s", (action,)) == delivery,
            "projection changed delivery state")
    require(projector.run(PROJECT, str(anchor), "synthetic-beta-projector", max_steps=20)[-1]["outcome"] == "idle",
            "repeat projection was not idle")
    require(sql("SELECT id,text FROM public.notes WHERE attributes->'voalack'->>'action_id'=%s "
                "ORDER BY create_time,id", (action,)) == notes, "repeat projection changed the notes")
    return [row[1] for row in notes]


def demonstrate(work, report):
    import psycopg2
    import voalack
    from voalack import recovery, schema, verifier
    from voalack.boundary import create_app
    from voalack.sender import FakeOneTransport, OwnerSession
    require(Path(voalack.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()),
            "Voalack must be imported from the installed guest environment")
    require(sql("SELECT current_database(),current_user")[0] == ("alerta", "lab_admin"),
            "wrong synthetic database identity")
    require(sql("SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()")[0][0]
            == "alerta_dbowner", "wrong synthetic database owner")
    require(sql("SELECT to_regnamespace('voalack'),to_regclass('public.alerts')")[0] == (None, None),
            "demo requires a fresh provisioned guest; existing installations are refused")
    fake_path = Path(__file__).resolve().parents[1] / "tests/capture/fake_one.py"
    spec = importlib.util.spec_from_file_location("voalack_beta_fake", fake_path)
    fake_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fake_module)
    report["fake_provider_sha256"] = hashlib.sha256(fake_path.read_bytes()).hexdigest()
    report["versions"] = {name: importlib.metadata.version(name)
                          for name in ("voalack", "alerta-ack-core", "alerta-server", "psycopg2-binary")}
    key = work / "synthetic-signing-key.bin"
    with open(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(secrets.token_bytes(32))
    config = {
        "VOALACK_DEPLOYMENT_ID": "synthetic-beta", "VOALACK_SIGNING_KEY_FILES": {"lab-k1": str(key)},
        "VOALACK_ACTIVE_KID": "lab-k1", "VOALACK_ALLOWED_AUTH_PROVIDERS": ["basic"],
        "VOALACK_MESSAGE_POLICY_REVISION": 1, "TESTING": True, "DATABASE_URL": APP,
        "AUTH_REQUIRED": True, "SECRET_KEY": secrets.token_hex(32), "ADMIN_USERS": [],
        "PLUGINS": ["voalack"], "PLUGINS_RAISE_ON_ERROR": True, "ALLOWED_ENVIRONMENTS": ["Development"]}
    app = create_app(config_override=config)
    with closing(psycopg2.connect(ADMIN)) as conn:
        schema.apply(conn)
    anchor_dir = work / "anchor"
    recovery.bootstrap(str(anchor_dir), ADMIN, {"basis": "fresh disposable synthetic beta demo"})
    with app.app_context():
        from alerta.auth.utils import generate_password_hash
        from alerta.models.user import User
        User(name="Synthetic operator", login=HUMAN[0], password=generate_password_hash(HUMAN[1]),
             email=HUMAN[0], roles=["user"], text="synthetic", email_verified=True).create()
    uid = sql("SELECT id FROM public.users WHERE login=%s", (HUMAN[0],))[0][0]
    sql("INSERT INTO voalack.authorization_policy VALUES (1,%s,%s)", (uid, CUSTOMER))
    sql("INSERT INTO voalack.authorization_policy_active VALUES (true,1)")
    sql("INSERT INTO voalack.accepted_kids VALUES ('lab-k1')")
    sql("INSERT INTO voalack.accepted_verifier_versions VALUES ('voalack-verifier/s1')")
    client = app.test_client()
    report["stages"].append("fresh_schema_anchor_policy_installed")
    for name, mode, expected in (("confirmed", "success", "confirmed"),
                                 ("uncertain", "close_after_body", "uncertain")):
        instance = "synthetic-beta-" + name
        sql("INSERT INTO voalack.instance_config VALUES (%s,%s,'fake-one/v1',1)",
            (instance, "synthetic-credential-" + name))
        require(sql("SELECT observer_enabled FROM voalack.instance_config WHERE instance_id=%s", (instance,))[0][0]
                is False, "observer must remain disabled")
        alert = enroll(client, instance, "4711")
        response = client.put("/alert/" + alert + "/action", headers=basic(),
                              json={"action": "ack", "text": "synthetic beta operator note"})
        require(response.status_code == 200, "human ACK failed")
        local_ack = sql('SELECT status,(history[1]).type,(history[1])."user" FROM public.alerts WHERE id=%s',
                        (alert,))[0]
        require(local_ack == ("ack", "ack", HUMAN[0]), "persisted local human ACK does not match")
        rows = sql("SELECT p.action_id::text FROM voalack.prepared_intents p JOIN voalack.captures c "
                   "ON c.action_id=p.action_id WHERE p.alert_id=%s", (alert,))
        require(len(rows) == 1, "ACK did not leave exactly one committed intent and capture")
        action = rows[0][0]
        signing = app.extensions["voalack_signing"]
        with closing(psycopg2.connect(VERIFY)) as conn:
            verified = verifier.run_once(conn, "synthetic-beta-verifier", signing.ctx, signing.keys, action_id=action)
        require(verified and verified["outcome"] == "verified", "restricted verification failed")
        effect = verified["effect_id"]
        with fake_module.FakeOne() as fake:
            fake.script["ack"] = mode
            owner = OwnerSession(SEND, instance, "synthetic-beta-owner", FakeOneTransport(fake.url),
                                 anchor=recovery.Anchor(str(anchor_dir)))
            try:
                owner.acquire()
                sent = owner.apply_once(effect)
                require(sent["outcome"] == expected, "unexpected delivery result")
                counts = [owner.counts["dispatch_entries"], owner.transport.counts["ack_writes"],
                          fake.counts["receipts"], fake.counts["effects"]]
                require(counts == [1, 1, 1, 1], "dispatch/transport/receipt/effect counts differ")
                again = owner.apply_once(effect)
                require(again.get("reason") == "effect_not_queued", "repeated delivery was not refused")
                require(counts == [owner.counts["dispatch_entries"], owner.transport.counts["ack_writes"],
                                   fake.counts["receipts"], fake.counts["effects"]], "repeated delivery sent again")
                ledger = sql("SELECT state,in_flight_attempt IS NOT NULL FROM voalack.effects WHERE effect_id=%s",
                             (effect,))[0]
                require(ledger == (("REMOTE_CONFIRMED", False) if name == "confirmed" else ("UNCERTAIN", True)),
                        "unexpected durable effect state")
                guards = sql("SELECT state FROM voalack.target_guards WHERE instance_id=%s", (instance,))
                require(guards == ([] if name == "confirmed" else [("uncertain",)]), "unexpected target guard")
                notes = projection_witness(action, anchor_dir, expected)
                report["scenarios"].append({"name": name, "outcome": sent["outcome"], "state": ledger[0],
                    "counts": counts, "repeat_reason": again["reason"], "operator_notes": notes,
                    "local_ack": {"status": local_ack[0], "history_type": local_ack[1], "human": local_ack[2]},
                    "scope": "real Alerta/PostgreSQL; in-process HTTP client; loopback fake ONE"})
            finally:
                owner.stop("synthetic_demo_complete")
                owner._drop_connection()  # finite lab process; does not clear durable holds or claim containment
        fake.thread.join(timeout=2)
        require(not fake.thread.is_alive(), "fake provider did not stop")
        report["stages"].append(name + "_complete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-synthetic-guest", action="store_true", required=True)
    parser.add_argument("--work", type=Path, required=True, help="new private directory; refuses reuse")
    parser.add_argument("--report", type=Path, required=True, help="new sanitized JSON evidence file")
    args = parser.parse_args()
    args.work.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Reserve the report without overwriting earlier evidence, before database mutations.
    with open(os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        report = {"status": "FAILED", "qualification": "synthetic_only", "stages": [], "scenarios": []}
        result = 1
        try:
            demonstrate(args.work.resolve(), report)
            report["status"] = "PASS"
            result = 0
        except Exception as exc:
            # Do not serialize driver exceptions, DSNs, configuration, tokens or SQL parameters.
            report["error_type"] = type(exc).__name__
            if isinstance(exc, DemoFailure):
                report["failure"] = str(exc)
        finally:
            json.dump(report, output, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    print("Synthetic beta demo: " + report["status"] + "; report: " + str(args.report))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
