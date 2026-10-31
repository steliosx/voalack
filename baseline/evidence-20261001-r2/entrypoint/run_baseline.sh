#!/bin/sh
# T03a: reproduce the ACK MVP 0.1.0 baseline inside a disposable microVM.
# Mounts: /src  = original MVP extraction (read-only)
#         /out  = evidence directory for this run (read-write)
# Synthetic config only; no ONE/Alerta endpoint is contacted. Network is used
# only for Debian/PyPI package downloads.
#
# Exit status: 0 only if the inner manifest verifies, every rebuilt wheel member
# equals the shipped wheel, the entry point loads, and the MVP's tests pass.
#
# Test-only fault injection, used to prove that failures propagate:
#   VOALACK_FAULT=wheel       change one source file before the wheel is built
#   VOALACK_FAULT=entrypoint  remove the installed plugin module before loading it
#   VOALACK_FAULT=pytest      add one failing test to the copied test suite
# The frozen inputs are never modified; faults apply to guest-local copies.
set -eu
FAULT="${VOALACK_FAULT:-}"
exec > /out/run.log 2>&1
set -x

echo "== platform"; uname -a; head -3 /etc/os-release; python3 --version
echo "fault injection: ${FAULT:-none}"
command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl; }
openssl version

echo "== copy source (inputs stay read-only)"
cp -a /src /work
cd /work
sha256sum -c SHA256SUMS.txt
if [ "$FAULT" = wheel ]; then echo "# injected fault" >> /work/src/alerta_veeam_one/core.py; fi

echo "== environment"
python3 -m venv /venv
. /venv/bin/activate
pip install -q --upgrade pip
pip install -q "alerta-server==9.1.0" "pytest==9.1.1" build
pip freeze > /out/pip-freeze-before-install.txt

echo "== build wheel from source"
python -m build --wheel --outdir /out/dist /work
for w in /out/dist/*.whl /work/dist/alerta_veeam_one_ack_lab-0.1.0-py3-none-any.whl; do
  echo "$(sha256sum "$w" | cut -d' ' -f1)  $(stat -c %s "$w")  $w"
done > /out/wheel-archives.txt
cat /out/wheel-archives.txt

echo "== compare rebuilt wheel with shipped wheel (members)"
# Exits 1 on any member that is missing or differs.
python - <<'EOF' > /out/wheel-compare.txt
import glob, hashlib, sys, zipfile
built = zipfile.ZipFile(glob.glob("/out/dist/*.whl")[0])
shipped = zipfile.ZipFile("/work/dist/alerta_veeam_one_ack_lab-0.1.0-py3-none-any.whl")
def digests(z):
    return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}
b, s = digests(built), digests(shipped)
bad = 0
for n in sorted(set(b) | set(s)):
    state = "same" if b.get(n) == s.get(n) else ("only-built" if n not in s else "only-shipped" if n not in b else "DIFFERS")
    bad += state != "same"
    print(f"{state:12} {n}")
print(f"members: {len(set(b) | set(s))}, differing: {bad}")
sys.exit(1 if bad else 0)
EOF
cat /out/wheel-compare.txt

echo "== install the rebuilt wheel (not editable) and load the entry point"
pip install -q /out/dist/*.whl
pip freeze > /out/pip-freeze-after-install.txt
if [ "$FAULT" = entrypoint ]; then rm /venv/lib/python3.12/site-packages/alerta_veeam_one/plugin.py; fi
cd /tmp
python - > /out/entry-point.txt <<'EOF'
from importlib.metadata import entry_points
import alerta_veeam_one
eps = [e for e in entry_points(group="alerta.plugins") if e.name == "veeam_one_ack"]
print("module file:", alerta_veeam_one.__file__)
print("entry point:", eps[0].value, "->", eps[0].load())
EOF
cat /out/entry-point.txt

echo "== run the MVP's own tests against the installed wheel"
cp -a /work/tests /tmp/tests
if [ "$FAULT" = pytest ]; then printf 'def test_injected_failure():\n    assert False\n' > /tmp/tests/test_injected_fault.py; fi
cd /tmp
status=0
python -m pytest -p no:cacheprovider -rA --junitxml=/out/test-results.xml /tmp/tests > /out/pytest.txt 2>&1 || status=$?
echo "pytest exit: $status" > /out/pytest-exit.txt
tail -5 /out/pytest.txt
exit "$status"
