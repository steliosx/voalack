#!/bin/sh
# T03b capture tests in a disposable VM: real Alerta 9.1.0 + PostgreSQL 18 + the voalack package.
# /src = repository (read-only), /out = evidence.
set -eu
SRC="${SRC:-/src}"; OUT="${OUT:-/out}"; WORK="${WORK:-/work}"
mkdir -p "$OUT"
exec > "$OUT/run.log" 2>&1
set -x
OUT="$OUT" WORK="$WORK" sh "$SRC/lab/setup_guest.sh"
cp -a "$SRC/packages/ack-core" "$WORK/ack-core-src"
cp -a "$SRC/packages/voalack" "$WORK/voalack-src"
# The local projects' dependencies resolve under the same reviewed constraints; the final freeze must equal the
# qualified final profile (the setup pins plus exactly these two local projects) before pytest runs.
"$WORK/venv/bin/pip" install -q -c "$SRC/lab/profiles/qualified-setup.txt" "$WORK/ack-core-src"
"$WORK/venv/bin/pip" install -q -c "$SRC/lab/profiles/qualified-setup.txt" "$WORK/voalack-src"
"$WORK/venv/bin/pip" freeze > "$OUT/pip-freeze.txt"
python3 -I "$SRC/lab/check_profile.py" "$SRC/lab/profiles/qualified-final.txt" "$OUT/pip-freeze.txt" \
  "$OUT/profile-check-final.txt"
cp -a "$SRC/tests/capture" "$WORK/tests"
cd "$WORK/tests"
status=0
# [lab] diagnostic instrumentation (reviews 53fd486f and 3d30c299, after s3c2b4g1-test-1's unrecorded deadlock):
# lock waits are logged by the server, the setting's effective value is read back from a new session, and a bounded
# private copy of the server log is kept in /out after pytest with its completeness stated, so a deadlock's other
# backend and query are recorded (PostgreSQL logs a deadlock's process and query detail by default). Diagnosis only:
# it changes no test or product path and masks no failure; its own failure is recorded, never fatal.
su postgres -c "psql -q -v ON_ERROR_STOP=1 -c 'ALTER SYSTEM SET log_lock_waits = on' -c 'SELECT pg_reload_conf()'" \
  > "$OUT/pg-instrumentation.txt" 2>&1 || echo "instrumentation failed (exit $?)" >> "$OUT/pg-instrumentation.txt"
sleep 1
show=$(su postgres -c "psql -At -c 'SHOW log_lock_waits'" 2>&1) && show_rc=0 || show_rc=$?
echo "log_lock_waits effective in a new session: $show (psql exit $show_rc)" >> "$OUT/pg-instrumentation.txt"
"$WORK/venv/bin/python" -m pytest -p no:cacheprovider -rA --junitxml="$OUT/test-results.xml" . > "$OUT/pytest.txt" 2>&1 || status=$?
"$WORK/venv/bin/python" -c "import voalack; print(voalack.__file__)" > "$OUT/import-path.txt"
echo "pytest exit: $status" > "$OUT/pytest-exit.txt"
SERVER_LOG=/var/log/postgresql/postgresql-18-main.log
LOG_LIMIT=4194304                                       # the bounded copy: at most the last 4 MiB
# One copy path, byte-capped by tail -c whatever the log grows to (review 900afe47 F2); the status states the captured
# bytes and the server log's size before and after the copy. Under set -e every step only records its own failure: the
# pytest status is never changed.
if [ -r "$SERVER_LOG" ]; then
  before=$(wc -c < "$SERVER_LOG" 2>/dev/null) || before=unknown
  if (umask 077; tail -c "$LOG_LIMIT" "$SERVER_LOG" > "$OUT/postgresql-server.log"); then
    got=$(wc -c < "$OUT/postgresql-server.log" 2>/dev/null) || got=unknown
    after=$(wc -c < "$SERVER_LOG" 2>/dev/null) || after=unknown
    if [ "$got" = "$before" ] && [ "$got" = "$after" ]; then
      state=complete
    elif [ "$got" = "$LOG_LIMIT" ]; then
      state="truncated (the last $LOG_LIMIT bytes)"
    else
      state="changed during the copy (completeness unknown)"
    fi
    echo "$state: captured $got bytes (cap $LOG_LIMIT); server log $before bytes before and $after after the copy" \
      > "$OUT/postgresql-server-log-status.txt"
  else
    echo "copy failed: server log $before bytes, nothing kept" > "$OUT/postgresql-server-log-status.txt"
  fi
else
  echo "missing: $SERVER_LOG is not readable" > "$OUT/postgresql-server-log-status.txt"
fi
tail -5 "$OUT/pytest.txt"
exit "$status"
