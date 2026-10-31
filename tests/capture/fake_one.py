"""Loopback fake ONE provider for T04 S2 (contract fake-one/v1). Synthetic: it qualifies Voalack's
state machine, not ONE's behaviour. It counts what it receives independently of the adapter.

T04 S3b contract additions (frozen with S3b):
* Authentication and executing registration of an ACK are one step under the provider lock, and
  revocation takes the same lock: once a session is revoked, no request of that session can begin
  executing, so a later executing = 0 for the session means no request of it can still mutate.
* An ACK's alarm mutation is one atomic publication, under the lock, of acked, the operation id,
  the comment and ``operation_status: "completed"``; it is the request's last mutation (afterwards
  it only decrements counters and replies).
* Lab-only administrator endpoints by session digest (sha256 of the token), never counted as reads:
  ``GET /lab/sessions/{ref}/executing`` -> {"session_ref", "scope": "session", "live", "executing"}
  and ``POST /lab/sessions/{ref}/revoke`` -> {"session_ref", "revoked"}.

T04 S3c contract additions (supervisor cleanup, R1): by credential, covering every session ever
issued under it whether or not Voalack registered it (a login whose token arrived after a close):
``POST /lab/credentials/{cred}/revoke`` -> {"credential", "revoked"} and
``GET /lab/credentials/{cred}/executing`` -> {"credential", "scope": "credential", "live",
"executing"}. Script ``login_delay`` issues a token only after that many seconds.
"""
import hashlib
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeOne:
    def __init__(self):
        self.lock = threading.Lock()
        # read: "normal" | "error" (HTTP 500) | "ambiguous" (no acked flag) | "wrong_target";
        # read_delay: seconds before a read answers
        self.script = {"ack": "success", "read_back": "normal", "delay": 0.0, "read": "normal", "read_delay": 0.0}
        self.sessions = {}                 # token -> credential
        self.issued = {}                   # T04 S3c: token -> credential, for every session ever issued
        self.max_concurrent = {}           # credential -> max live sessions
        self.counts = {"logins": 0, "reads": 0, "revokes": 0, "receipts": 0, "effects": 0}
        self.receipts = []                 # (token, body bytes)
        self.read_targets = []             # target id of every alarm read, in order
        self.alarms = {}                   # target id -> {"acked_by_operation", "comment"}
        self.executing = 0                 # ACK requests currently being processed
        self.executing_by_session = {}     # token -> ACK requests currently being processed (lab view)
        self.pre_auth = None               # lab hook: called after an ACK body is read, before auth
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def _handler(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def _session(self):
                with fake.lock:
                    return fake.sessions.get(self.headers.get("X-Session"))

            def do_POST(self):
                if self.path == "/login":
                    credential = json.loads(self._body())["credential"]
                    if fake.script.get("login") == "fail":
                        with fake.lock:
                            fake.counts["logins"] += 1
                        return self._reply(500, {"error": "lab: login refused"})
                    if fake.script.get("login_delay"):
                        time.sleep(fake.script["login_delay"])   # T04 S3c: the token is issued late
                    with fake.lock:
                        fake.counts["logins"] += 1
                        token = uuid.uuid4().hex
                        fake.sessions[token] = credential
                        fake.issued[token] = credential
                        live = sum(1 for c in fake.sessions.values() if c == credential)
                        fake.max_concurrent[credential] = max(fake.max_concurrent.get(credential, 0), live)
                    return self._reply(200, {"token": token})
                if self.path.startswith("/lab/sessions/") and self.path.endswith("/revoke"):
                    ref = self.path.split("/")[3]
                    self._body()
                    with fake.lock:
                        tokens = [t for t in fake.sessions if hashlib.sha256(t.encode()).hexdigest() == ref]
                        for t in tokens:
                            fake.sessions.pop(t)
                        fake.counts["revokes"] += len(tokens)
                    return self._reply(200, {"session_ref": ref, "revoked": len(tokens)})
                if self.path.startswith("/lab/credentials/") and self.path.endswith("/revoke"):
                    # T04 S3c (supervisor cleanup): revoke every live session of one credential,
                    # registered with Voalack or not.
                    credential = self.path.split("/")[3]
                    self._body()
                    with fake.lock:
                        tokens = [t for t, c in fake.sessions.items() if c == credential]
                        for t in tokens:
                            fake.sessions.pop(t)
                        fake.counts["revokes"] += len(tokens)
                    return self._reply(200, {"credential": credential, "revoked": len(tokens)})
                if self.path == "/revoke":
                    self._body()
                    with fake.lock:
                        fake.counts["revokes"] += 1
                        fake.sessions.pop(self.headers.get("X-Session"), None)
                    return self._reply(200, {})
                if self.path == "/ack":
                    mode = fake.script["ack"]
                    if mode == "close_before_body":
                        self.close_connection = True
                        self.connection.close()
                        return
                    body = self._body()
                    if fake.pre_auth is not None:
                        fake.pre_auth()
                    token = self.headers.get("X-Session")
                    with fake.lock:                      # authenticate and register as executing at once
                        if token not in fake.sessions:
                            authenticated = False
                        else:
                            authenticated = True
                            fake.counts["receipts"] += 1
                            fake.receipts.append(body)
                            fake.executing += 1
                            fake.executing_by_session[token] = fake.executing_by_session.get(token, 0) + 1
                    if not authenticated:
                        return self._reply(401, {"error": "no session"})
                    try:
                        if fake.script.get("delay"):
                            time.sleep(fake.script["delay"])
                        request = json.loads(body)
                        operation = hashlib.sha256(body).hexdigest()
                        target = request["target"]["id"]
                        with fake.lock:
                            fake.counts["effects"] += 1
                            fake.alarms[target] = {"target_id": target, "kind": "triggered_alarm", "acked": True,
                                                   "acked_by_operation": operation, "comment": request["comment"],
                                                   "operation_status": "completed"}
                        if fake.script.get("post_publish_delay"):
                            time.sleep(fake.script["post_publish_delay"])   # cleanup still pending; no mutation
                    finally:
                        with fake.lock:
                            fake.executing -= 1
                            fake.executing_by_session[token] -= 1
                    if mode == "close_after_body":
                        self.close_connection = True
                        self.connection.close()
                        return
                    if mode == "no_operation_id":
                        return self._reply(200, {"target_id": target, "result": "acked"})
                    return self._reply(200, {"operation_id": operation, "target_id": target, "result": "acked"})
                return self._reply(404, {})

            def do_GET(self):
                if self.path.startswith("/lab/sessions/") and self.path.endswith("/executing"):
                    ref = self.path.split("/")[3]
                    with fake.lock:
                        known = {hashlib.sha256(t.encode()).hexdigest(): t
                                 for t in set(fake.sessions) | set(fake.executing_by_session)}
                        token = known.get(ref)
                        payload = {"session_ref": ref, "scope": "session", "live": token in fake.sessions,
                                   "executing": fake.executing_by_session.get(token, 0) if token else 0}
                    return self._reply(200, payload)
                if self.path.startswith("/lab/credentials/") and self.path.endswith("/executing"):
                    # T04 S3c: credential scope: live sessions and ACK requests executing for every
                    # session ever issued under this credential.
                    credential = self.path.split("/")[3]
                    with fake.lock:
                        tokens = [t for t, c in fake.issued.items() if c == credential]
                        payload = {"credential": credential, "scope": "credential",
                                   "live": sum(1 for t in tokens if t in fake.sessions),
                                   "executing": sum(fake.executing_by_session.get(t, 0) for t in tokens)}
                    return self._reply(200, payload)
                if self.path.startswith("/alarms/"):
                    target = self.path.rsplit("/", 1)[1]
                    if fake.script.get("read_delay"):
                        time.sleep(fake.script["read_delay"])
                    with fake.lock:
                        fake.counts["reads"] += 1
                        fake.read_targets.append(target)
                        # Explicit synthetic state: an unacknowledged alarm says so.
                        alarm = dict(fake.alarms.get(target, {"target_id": target, "kind": "triggered_alarm",
                                                               "acked": False}))
                    mode = fake.script.get("read", "normal")
                    if mode == "error":
                        return self._reply(500, alarm)
                    if mode == "ambiguous":
                        alarm.pop("acked", None)
                    if mode == "wrong_target":
                        alarm["target_id"] = "9999"
                    if mode == "grouped":
                        alarm.update(kind="grouped_alarm", children=["4712", "4713"])
                    if mode == "no_kind":
                        alarm.pop("kind", None)
                    if mode == "no_completion":
                        alarm.pop("operation_status", None)
                    if fake.script["read_back"] == "mismatch":
                        alarm["comment"] = "something else"
                    return self._reply(200, alarm)
                return self._reply(404, {})

        return Handler
