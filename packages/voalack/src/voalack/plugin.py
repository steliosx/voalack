"""Alerta plugin: stages an intent for an eligible human ACK inside the request transaction."""
from __future__ import annotations

import json

from alerta.plugins import PluginBase
from flask import g, has_request_context


class VoalackCapture(PluginBase):
    """Stages one prepared intent per eligible ACK; never does network I/O (design A1)."""

    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return None

    def status_change(self, alert, status, text, **kwargs):
        return None

    def take_action(self, alert, action, text, **kwargs):
        state = g.get("voalack") if has_request_context() else None
        if action != "ack" or not state or state["alert_id"] != alert.id or not state.get("gate_passed"):
            return None                      # only an alert the gate locked and reloaded
        if alert.status == "ack":
            return None                      # already acknowledged: no transition, no intent
        login = g.get("login")
        if not g.get("user_id") or not isinstance(login, str) or not login:
            return None                      # not a server-authenticated human (API keys and Hawk set no user ID)
        from .intent import private
        priv = private()
        frozen = priv.get("frozen")
        if frozen is None or state.get("frozen") != dict(frozen) or "generation" in priv:
            return None                      # no original facts, a changed copy, or already staged
        if login != frozen["login"] or str(g.get("user_id")) != frozen["user_id"]:
            return None                      # identity changed after the gate: nothing staged
        action_id = frozen["action_id"]
        binding_id, binding_revision = state["binding"]
        payload = {"action_id": action_id, "alert_id": alert.id, "actor": login, "note": text or "",
                   "binding_id": binding_id, "binding_revision": binding_revision}
        cur = state["conn"].cursor()
        # Owner function: allocates the binding's next generation once and stages the intent in this
        # transaction (the application role has no direct write on voalack tables).
        # Timestamps go in as the exact signed ISO strings: Alerta registers a global psycopg2
        # datetime adapter that keeps only milliseconds (T04 S1 finding).
        cur.execute("SELECT voalack.stage_intent(%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s::timestamptz, "
                    "%s::timestamptz, %s::timestamptz)",
                    (action_id, alert.id, frozen["request_id"], login, json.dumps(payload, sort_keys=True),
                     frozen["customer"], binding_id, binding_revision, frozen["issued_at"],
                     frozen["capture_expires_at"], frozen["execution_expires_at"]))
        priv["generation"] = state["generation"] = cur.fetchone()[0]
        state["action_id"] = action_id
        return None

    def post_action(self, alert, action, text, **kwargs):
        return None                          # nothing after set_alert; no remote I/O

    def take_note(self, alert, text, **kwargs):
        return None

    def delete(self, alert, **kwargs):
        return True
