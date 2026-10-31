"""C3: a process killed after set_alert and before commit leaves neither the ACK nor the capture."""
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import psycopg2

from conftest import DSN, OPERATOR, basic, captures, intents, new_alert, status

PORT = 18765


def _wait_for(predicate, seconds):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


def _row_lockable(alert_id):
    try:
        with psycopg2.connect(DSN) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM alerts WHERE id = %s FOR UPDATE NOWAIT", (alert_id,))
            return True
    except psycopg2.errors.LockNotAvailable:
        return False


def test_kill_after_set_alert_before_commit_leaves_nothing(client, tmp_path):
    alert_id = new_alert(client)
    marker = tmp_path / "stalled"
    server = subprocess.Popen([sys.executable, str(Path(__file__).with_name("crash_server.py")), str(PORT), str(marker)],
                              cwd=Path(__file__).parent, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert _wait_for(lambda: _port_open(PORT), 30), "server did not start"
        request = urllib.request.Request(f"http://127.0.0.1:{PORT}/alert/{alert_id}/action", method="PUT",
                                         data=b'{"action": "ack", "text": "crash test"}',
                                         headers={"Content-Type": "application/json", **basic(OPERATOR)})
        outcome = {}

        def send():
            try:
                outcome["status"] = urllib.request.urlopen(request, timeout=60).status
            except (urllib.error.URLError, ConnectionError, OSError) as exc:
                outcome["error"] = type(exc).__name__
        sender = threading.Thread(target=send)
        sender.start()
        assert _wait_for(marker.exists, 30), "request never reached the stall"
        # Inside the stall: the ACK row is written but uncommitted, and the row is locked.
        assert status(alert_id)[0] == "open"
        assert not _row_lockable(alert_id)
        os.kill(server.pid, signal.SIGKILL)
        server.wait(timeout=10)
        sender.join(timeout=30)
        assert "status" not in outcome                     # the client never saw success
    finally:
        if server.poll() is None:
            server.kill()
    # PostgreSQL rolls the transaction back when the backend notices the dead client.
    assert _wait_for(lambda: _row_lockable(alert_id), 30), "transaction still holds the row"
    assert status(alert_id)[0] == "open"
    assert intents(alert_id) == 0 and captures(alert_id) == 0


def _port_open(port):
    import socket
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0
