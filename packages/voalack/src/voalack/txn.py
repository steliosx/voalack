"""Request-local deferral of Alerta's database commits (design amendment A2).

Alerta 9.1 keeps one psycopg2 connection per request in ``flask.g.db`` and commits through it
after every write. Wrapping that connection for one eligible request turns those commits into
no-ops, so every write in the request belongs to a single transaction that the request
boundary commits or rolls back. Nothing process-global is patched.
"""
from __future__ import annotations


class DeferredCommitConnection:
    """Delegates to a psycopg2 connection; ``commit()`` is recorded, not executed."""

    def __init__(self, conn):
        self._conn = conn
        self.deferred_commits = 0

    def commit(self) -> None:
        self.deferred_commits += 1

    def rollback(self) -> None:
        self._conn.rollback()

    def commit_now(self) -> None:
        """The single real commit, made only at the request boundary."""
        self._conn.commit()

    def __getattr__(self, name):
        return getattr(self._conn, name)
