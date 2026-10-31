#!/bin/sh
# Build the ack-core wheel and run its tests against the installed wheel, in a disposable VM.
# The same script runs locally (smolvm with mounts) and in CI (on a single-use runner VM).
#   SRC  repository checkout, read-only     (default /src)
#   OUT  evidence directory, read-write     (default /out)
#   WORK scratch directory                  (default /work)
set -eu
SRC="${SRC:-/src}"; OUT="${OUT:-/out}"; WORK="${WORK:-/work}"
mkdir -p "$OUT"
exec > "$OUT/run.log" 2>&1
set -x
python3 --version
mkdir -p "$WORK"
cp -a "$SRC/packages/ack-core" "$WORK/ack-core"
python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
pip install -q --upgrade pip
pip install -q "build==1.3.0" "pytest==9.0.3"
python -m build --wheel --outdir "$OUT/dist" "$WORK/ack-core"
sha256sum "$OUT"/dist/*.whl
pip install -q "$OUT"/dist/*.whl
pip freeze > "$OUT/pip-freeze.txt"
cp -a "$WORK/ack-core/tests" "$WORK/tests"
cd "$WORK"
status=0
python -m pytest -p no:cacheprovider -rA --junitxml="$OUT/test-results.xml" "$WORK/tests" > "$OUT/pytest.txt" 2>&1 || status=$?
python -c "import alerta_ack_core; print(alerta_ack_core.__file__)" > "$OUT/import-path.txt"
echo "pytest exit: $status" > "$OUT/pytest-exit.txt"
tail -3 "$OUT/pytest.txt"
exit "$status"
