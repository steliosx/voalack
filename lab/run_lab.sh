#!/bin/sh
# T03b lab run in a disposable VM. /src = repository (read-only), /out = evidence.
set -eu
SRC="${SRC:-/src}"; OUT="${OUT:-/out}"; WORK="${WORK:-/work}"
mkdir -p "$OUT"
exec > "$OUT/run.log" 2>&1
set -x
OUT="$OUT" WORK="$WORK" sh "$SRC/lab/setup_guest.sh"
cp -a "$SRC/tests/lab" "$WORK/tests"
cd "$WORK/tests"
status=0
"$WORK/venv/bin/python" -m pytest -p no:cacheprovider -rA --junitxml="$OUT/test-results.xml" . > "$OUT/pytest.txt" 2>&1 || status=$?
echo "pytest exit: $status" > "$OUT/pytest-exit.txt"
tail -5 "$OUT/pytest.txt"
exit "$status"
