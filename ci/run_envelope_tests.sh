#!/bin/sh
# Build the ack-core and voalack wheels and run the pure envelope tests against them, in a
# disposable VM. Same parameters as ci/run_core_tests.sh.
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
cp -a "$SRC/packages/voalack" "$WORK/voalack"
python3 -m venv "$WORK/venv"
. "$WORK/venv/bin/activate"
pip install -q --upgrade pip
pip install -q "build==1.3.0" "pytest==9.0.3"
python -m build --wheel --outdir "$OUT/dist" "$WORK/ack-core"
python -m build --wheel --outdir "$OUT/dist" "$WORK/voalack"
sha256sum "$OUT"/dist/*.whl
pip install -q --no-index --find-links "$OUT/dist" voalack
pip freeze > "$OUT/pip-freeze.txt"
cp -a "$SRC/tests/envelope" "$WORK/tests"
cd "$WORK"
status=0
python -m pytest -p no:cacheprovider -rA --junitxml="$OUT/test-results.xml" "$WORK/tests" > "$OUT/pytest.txt" 2>&1 || status=$?
python -c "import voalack.envelope, alerta_ack_core; print(voalack.envelope.__file__); print(alerta_ack_core.__file__)" > "$OUT/import-path.txt"
echo "pytest exit: $status" > "$OUT/pytest-exit.txt"
tail -3 "$OUT/pytest.txt"
exit "$status"
