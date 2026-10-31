"""Operator-facing outcomes of an acknowledgement write-back (design: "Provider interface")."""
from __future__ import annotations

from enum import Enum


class Outcome(str, Enum):
    LOCAL_ACK = "local_ack"                # Alerta changed locally; never implies remote success
    QUEUED = "queued"                      # captured; verification and policy still precede remote access
    REMOTE_CONFIRMED = "remote_confirmed"  # expected ACK observed on the exact target; no new send
    ALREADY_ACKED = "already_acked"        # source was already acknowledged; no attribution claim
    BLOCKED = "blocked"                    # named policy/identity/configuration reason; no send
    SUPERSEDED = "superseded"              # invalidated before send by a newer binding/generation
    UNCERTAIN = "uncertain"                # may have reached the provider; read-only reconciliation only

    @property
    def terminal(self) -> bool:
        """Whether the outcome ends delivery for this action. UNCERTAIN is not terminal."""
        return self in {Outcome.REMOTE_CONFIRMED, Outcome.ALREADY_ACKED, Outcome.BLOCKED, Outcome.SUPERSEDED}
