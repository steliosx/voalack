#!/bin/sh
# Launcher tests against fake gh/smolvm, in a disposable VM. SRC/OUT/WORK as in run_core_tests.sh.
set -eu
SRC="${SRC:-/src}"; OUT="${OUT:-/out}"; WORK="${WORK:-/work}"
mkdir -p "$OUT"
exec > "$OUT/run.log" 2>&1
set -x
command -v flock bash python3 jq
mkdir -p "$WORK" && cp -a "$SRC/ci" "$SRC/tests" "$WORK/"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "pytest==9.0.3"
cd "$WORK"
status=0
"$WORK/venv/bin/python" -m pytest -p no:cacheprovider -rA --junitxml="$OUT/test-results.xml" tests/ci > "$OUT/pytest.txt" 2>&1 || status=$?
echo "pytest exit: $status" > "$OUT/pytest-exit.txt"
tail -5 "$OUT/pytest.txt"
exit "$status"
