#!/bin/sh
# Run only through the approved disposable-guest route. Not a host launcher.
# SRC: exact read-only source; OUT: new evidence directory; WORK: new scratch directory.
set -eu
test "${VOALACK_DISPOSABLE_GUEST:-}" = 1 || {
    echo 'Refused: use the approved disposable synthetic guest route.' >&2
    exit 2
}
SRC="${SRC:-/src}"
OUT="${OUT:-/out/beta-demo}"
WORK="${WORK:-/work/beta-demo}"
case "${SOURCE_COMMIT:-}" in ''|*[!0-9a-f]*) echo 'A reviewed full source commit is required.' >&2; exit 2;; esac
test "${#SOURCE_COMMIT}" = 40
test -d "$SRC"
test ! -e "$OUT"
test ! -e "$WORK"
umask 077
mkdir "$OUT" "$WORK"
exec > "$OUT/run.log" 2>&1
trap 'rc=$?; printf "%s\n" "$rc" > "$OUT/exit-status.txt"' EXIT
python3 --version
# This is a declaration from the enclosing exact-source handoff, not independent Git proof.
printf '%s\n' "$SOURCE_COMMIT" > "$OUT/declared-source-commit.txt"
OUT="$OUT" WORK="$WORK" sh "$SRC/lab/setup_guest.sh"

# Keep build dependencies separate from the qualified application environment.
python3 -m venv "$WORK/builder"
"$WORK/builder/bin/pip" install -q 'build==1.3.0'
"$WORK/builder/bin/pip" freeze > "$OUT/builder-freeze.txt"
mkdir "$OUT/dist"
cp -a "$SRC/packages/ack-core" "$WORK/ack-core-src"
cp -a "$SRC/packages/voalack" "$WORK/voalack-src"
# The default build operation makes an sdist, then builds the wheel from that sdist.
"$WORK/builder/bin/python" -m build --outdir "$OUT/dist" "$WORK/ack-core-src"
"$WORK/builder/bin/python" -m build --outdir "$OUT/dist" "$WORK/voalack-src"
(cd "$OUT/dist" && sha256sum ./*.whl ./*.tar.gz > SHA256SUMS && sha256sum --check --strict SHA256SUMS)
"$WORK/venv/bin/pip" install -q --no-index --no-deps "$OUT"/dist/*.whl
"$WORK/venv/bin/pip" freeze > "$OUT/pip-freeze.txt"
python3 -I "$SRC/lab/check_profile.py" "$SRC/lab/profiles/qualified-final.txt" "$OUT/pip-freeze.txt" \
    "$OUT/profile-check-final.txt"
# The exact source, artifact manifest, profiles and logs remain part of the enclosing review packet.
# -I prevents the source checkout or PYTHONPATH from substituting for installed product imports.
"$WORK/venv/bin/python" -I "$SRC/lab/demo_beta.py" --disposable-synthetic-guest \
    --work "$WORK/demo-state" --report "$OUT/demo.json" && status=0 || status=$?
exit "$status"
