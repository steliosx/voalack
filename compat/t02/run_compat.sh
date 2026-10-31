#!/bin/sh
# T02 Zabalack v1 compatibility proof, in a disposable VM.
# Mounts: /src = staging (read-only): ack-core/, zabalack/ (patched checkout), orig/crypto_494768d.py,
#         differential.py, compare_junit.py;  /out = evidence (read-write).
#
# Exit status is 0 only if ALL of these pass: the original Zabalack suites, the patched suites,
# the case-by-case comparison of both runs, and the differential check.
#
# Test-only fault injection (proves each failure propagates; staging is never modified):
#   COMPAT_FAULT=orig          add one failing test to the original checkout's copy
#   COMPAT_FAULT=new           add one failing test to the patched checkout's copy
#   COMPAT_FAULT=differential  make the patched signer disagree inside the differential run
set -eu
FAULT="${COMPAT_FAULT:-}"
exec > /out/run.log 2>&1
set -x
python3 --version
echo "fault injection: ${FAULT:-none}"
cp -a /src /work
cd /work
python3 -m venv /core-build && /core-build/bin/pip install -q "build==1.3.0"
/core-build/bin/python -m build --wheel --outdir /out/dist /work/ack-core
sha256sum /out/dist/*.whl
# Original Zabalack (494768d, unpatched) and patched Zabalack + core wheel, side by side.
mkdir /orig && cp -a /work/zabalack /orig/zabalack && cp /work/orig/crypto_494768d.py /orig/zabalack/src/zabalack/crypto.py
FAILING='def test_injected_fault():\n    assert False\n'
[ "$FAULT" = orig ] && printf "$FAILING" > /orig/zabalack/tests/unit/test_injected_fault.py
[ "$FAULT" = new ] && printf "$FAILING" > /work/zabalack/tests/unit/test_injected_fault.py
for v in orig new; do python3 -m venv /venv-$v; /venv-$v/bin/pip install -q --upgrade pip; done
/venv-orig/bin/pip install -q "/orig/zabalack[alerta,test]" "hypothesis==6.168.0"
/venv-new/bin/pip install -q /out/dist/*.whl "/work/zabalack[alerta,test]" "hypothesis==6.168.0"
/venv-orig/bin/pip freeze > /out/pip-freeze-orig.txt
/venv-new/bin/pip freeze > /out/pip-freeze-new.txt
TESTS="tests/unit tests/security tests/property"
s_orig=0; s_new=0; s_cmp=0; s_diff=0
(cd /orig/zabalack && /venv-orig/bin/python -m pytest -p no:cacheprovider -q -rs --junitxml=/out/junit-orig.xml $TESTS > /out/pytest-orig.txt 2>&1) || s_orig=$?
(cd /work/zabalack && /venv-new/bin/python -m pytest -p no:cacheprovider -q -rs --junitxml=/out/junit-new.xml $TESTS > /out/pytest-new.txt 2>&1) || s_new=$?
tail -n 2 /out/pytest-orig.txt /out/pytest-new.txt
python3 /work/compare_junit.py /out/junit-orig.xml /out/junit-new.xml > /out/compare.txt 2>&1 || s_cmp=$?
cat /out/compare.txt
/venv-new/bin/python -c "import zabalack.crypto as c, alerta_ack_core as a; print(c.__file__); print(a.__file__)" > /out/import-paths.txt
mkdir -p /tmp/origpkg && cp -a /orig/zabalack/src/zabalack /tmp/origpkg/zabalack_orig
DIFF_FAULT=0; [ "$FAULT" = differential ] && DIFF_FAULT=1
VOALACK_DIFF_FAULT=$DIFF_FAULT PYTHONPATH=/tmp/origpkg /venv-new/bin/python /work/differential.py > /out/differential.txt 2>&1 || s_diff=$?
cat /out/differential.txt
printf 'original suites: %s\npatched suites: %s\ncomparison: %s\ndifferential: %s\n' "$s_orig" "$s_new" "$s_cmp" "$s_diff" > /out/statuses.txt
cat /out/statuses.txt
[ "$s_orig" = 0 ] && [ "$s_new" = 0 ] && [ "$s_cmp" = 0 ] && [ "$s_diff" = 0 ]
