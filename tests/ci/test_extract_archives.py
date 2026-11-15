"""The secret scan's archive extractor (audit 2026-11-08, finding 17): small crafted archives.

Each case runs ci/extract_archives.py as the scan does (python3 -I, a manifest of archive paths)
and checks what it writes and what it refuses. A change that stopped writing members where the
scanner reads them, or that let an unsafe archive through, fails here.
"""
import json
import stat
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXTRACTOR = ROOT / "ci" / "extract_archives.py"


def _zip_bytes(members):
    """members: list of (name, data) or ZipInfo-ready (ZipInfo, data) pairs."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _run(tmp_path, archives):
    """archives: {relative path: zip bytes}. Returns (exit code, report, output dir)."""
    root = tmp_path / "repo"
    for rel, data in archives.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    manifest = tmp_path / "manifest.txt"
    manifest.write_text("".join(f"{rel}\n" for rel in archives))
    out, report = tmp_path / "out", tmp_path / "report.json"
    result = subprocess.run([sys.executable, "-I", str(EXTRACTOR), str(root), str(out), "--report", str(report),
                             "--manifest", str(manifest)], capture_output=True, text=True, timeout=60)
    data = json.loads(report.read_text()) if report.exists() else None
    return result.returncode, data, out


def test_members_and_a_nested_wheel_are_written_where_the_scanner_reads(tmp_path):
    wheel = _zip_bytes([("pkg/__init__.py", b"SECRET_IN_WHEEL = 1\n"), ("pkg-1.0.dist-info/RECORD", b"x\n")])
    outer = _zip_bytes([("README.txt", b"hello\n"), ("dist/pkg-1.0-py3-none-any.whl", wheel), ("sub/", b"")])
    rc, report, out = _run(tmp_path, {"inputs/bundle.zip": outer})
    assert rc == 0, report
    assert report["refused"] is None and report["archives"] == ["inputs/bundle.zip"]
    base = out / "inputs" / "bundle.zip.d"                  # ".d": a directory ending in .zip is allowlisted away
    assert (base / "README.txt").read_bytes() == b"hello\n"
    inner = base / "dist" / "pkg-1.0-py3-none-any.whl.d"
    assert (inner / "pkg" / "__init__.py").read_bytes() == b"SECRET_IN_WHEEL = 1\n"
    assert not (out / "inputs" / "bundle.zip").exists()
    depths = sorted((m["member"], m["depth"]) for m in report["members"])
    assert ("pkg/__init__.py", 2) in depths and ("README.txt", 1) in depths
    assert sum(m["bytes"] for m in report["members"]) == sum(
        len(b) for b in (b"hello\n", wheel, b"SECRET_IN_WHEEL = 1\n", b"x\n"))


@pytest.mark.parametrize("name", ["../escape.txt", "/abs.txt", "a\\b.txt", "C:drive.txt", "a/./b.txt",
                                  "a/../b.txt"])   # (zipfile itself truncates a name at NUL when writing)
def test_unsafe_member_names_are_refused(tmp_path, name):
    rc, report, out = _run(tmp_path, {"a.zip": _zip_bytes([(name, b"x")])})
    assert rc == 2 and "unsafe member name" in report["refused"], report
    assert not (tmp_path / "escape.txt").exists() and not Path("/abs.txt").exists()


def test_a_symlink_member_is_refused(tmp_path):
    info = zipfile.ZipInfo("link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(info, "/etc/passwd")
    rc, report, _ = _run(tmp_path, {"a.zip": buf.getvalue()})
    assert rc == 2 and "symlink member" in report["refused"], report


def test_duplicate_and_case_colliding_members_are_refused(tmp_path):
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("same.txt", b"1")
        with pytest.warns(UserWarning):
            zf.writestr("same.txt", b"2")
    rc, report, _ = _run(tmp_path, {"a.zip": buf.getvalue()})
    assert rc == 2 and "duplicate member" in report["refused"], report
    rc, report, _ = _run(tmp_path / "case", {"b.zip": _zip_bytes([("Key.txt", b"1"), ("key.txt", b"2")])})
    assert rc == 2 and "output collision" in report["refused"], report


def test_a_third_nesting_level_is_refused(tmp_path):
    level3 = _zip_bytes([("deep.txt", b"x")])
    level2 = _zip_bytes([("inner.zip", level3)])
    rc, report, _ = _run(tmp_path, {"outer.zip": _zip_bytes([("middle.zip", level2)])})
    assert rc == 2 and "nested deeper" in report["refused"], report


def test_an_oversized_member_is_refused(tmp_path):
    rc, report, _ = _run(tmp_path, {"a.zip": _zip_bytes([("big.bin", b"\0" * (5 * 1024 * 1024 + 1))])})
    assert rc == 2 and "member over" in report["refused"], report


def test_too_many_members_are_refused(tmp_path):
    rc, report, _ = _run(tmp_path, {"a.zip": _zip_bytes([(f"f{i}.txt", b"") for i in range(2001)])})
    assert rc == 2 and "more than 2000 members" in report["refused"], report


def test_an_unreadable_nested_archive_is_refused(tmp_path):
    rc, report, _ = _run(tmp_path, {"a.zip": _zip_bytes([("broken.whl", b"not a zip")])})
    assert rc == 2 and "nested archive not readable" in report["refused"], report


def test_an_existing_output_directory_stops_the_run(tmp_path):
    (tmp_path / "out").mkdir()
    rc, report, _ = _run(tmp_path, {"a.zip": _zip_bytes([("x.txt", b"x")])})
    assert rc != 0 and report is None
