#!/bin/sh
# T03a: reproduce the ACK MVP 0.1.0 baseline inside a smolvm guest.
# Mounts: /src  = original MVP extraction (read-only)
#         /out  = evidence directory (read-write)
# Synthetic config only; no ONE/Alerta endpoint is contacted. Network is used
# only for Debian/PyPI package downloads.
set -eu
exec > /out/run.log 2>&1
set -x

echo "== platform"; uname -a; cat /etc/os-release | head -3; python3 --version
command -v openssl >/dev/null || { apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl; }
openssl version

echo "== copy source (inputs stay read-only)"
cp -a /src /work
cd /work
sha256sum -c SHA256SUMS.txt

echo "== environment"
python3 -m venv /venv
. /venv/bin/activate
pip install -q --upgrade pip
pip install -q "alerta-server==9.1.0" "pytest==9.1.1" build
pip freeze > /out/pip-freeze.txt

echo "== build wheel from source"
python -m build --wheel --outdir /out/dist /work
ls -l /out/dist

echo "== compare rebuilt wheel with shipped wheel (content level)"
python - <<'EOF' > /out/wheel-compare.txt
import hashlib, zipfile, glob
built = zipfile.ZipFile(glob.glob("/out/dist/*.whl")[0])
shipped = zipfile.ZipFile("/work/dist/alerta_veeam_one_ack_lab-0.1.0-py3-none-any.whl")
def digests(z):
    return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}
b, s = digests(built), digests(shipped)
for n in sorted(set(b) | set(s)):
    state = "same" if b.get(n) == s.get(n) else ("only-built" if n not in s else "only-shipped" if n not in b else "DIFFERS")
    print(f"{state:12} {n}")
EOF
cat /out/wheel-compare.txt

echo "== install the rebuilt wheel (not editable) and load the entry point"
pip install -q /out/dist/*.whl
cd /tmp
python - <<'EOF' | tee /out/entry-point.txt
from importlib.metadata import entry_points
import alerta_veeam_one
eps = [e for e in entry_points(group="alerta.plugins") if e.name == "veeam_one_ack"]
print("module file:", alerta_veeam_one.__file__)
print("entry point:", eps[0].value, "->", eps[0].load())
EOF

echo "== run the MVP's own tests against the installed wheel"
cp -a /work/tests /tmp/tests
cd /tmp
set +e
python -m pytest -p no:cacheprovider -rA --junitxml=/out/test-results.xml /tmp/tests > /out/pytest.txt 2>&1
echo "pytest exit: $?" | tee /out/pytest-exit.txt
set -e
tail -5 /out/pytest.txt
