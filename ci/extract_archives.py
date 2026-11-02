#!/usr/bin/env python3
"""Extract the members of the repository's zip and wheel archives for the secret scan, inertly and within bounds.

Nothing extracted is executed, imported or installed: members are only written as files under the output directory,
so the scanner can read them. A wheel inside an archive is opened in memory and extracted one level deeper (the input
zips carry one). Any bound or name violation stops the run with a non-zero exit, so the scan fails closed.

Usage: python3 -I ci/extract_archives.py ROOT OUT --report REPORT.json [--manifest FILE]

ROOT is the repository checkout. Without --manifest the archives are the tracked *.zip and *.whl files
(git ls-files); with --manifest they are the paths listed in FILE, one per line, relative to ROOT (used by the
trial fixtures, whose planted archives are not tracked). OUT must not exist. Each member is written to
OUT/<archive path>.d/<member>, and a nested archive's members to OUT/<archive path>.d/<nested member>.d/<member>.
The ".d" suffix matters: the default gitleaks path allowlist skips anything ending in ".zip", including a directory,
so a directory named after the archive would silently remove every member from the scan.
"""

import argparse
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import zipfile
from io import BytesIO

MAX_DEPTH = 2                      # outer archive (1), archive inside it (2); a third level is refused
MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 50 * 1024 * 1024  # over all archives and levels
MAX_MEMBERS = 2000                  # over all archives and levels
ARCHIVE_SUFFIXES = (".zip", ".whl")
DRIVE = re.compile(r"^[A-Za-z]:")


class Refused(Exception):
    pass


class Budget:
    def __init__(self):
        self.members = 0
        self.total = 0
        self.outputs = {}           # casefolded output path -> archive and member that claimed it

    def claim(self, out_path, origin):
        key = out_path.casefold()
        if key in self.outputs:
            raise Refused(f"output collision: {origin} and {self.outputs[key]} map to {out_path}")
        self.outputs[key] = origin


def safe_name(name):
    """Return the member name as a relative POSIX path, or refuse it."""
    if "\x00" in name or "\\" in name or name.startswith("/") or DRIVE.match(name):
        raise Refused(f"unsafe member name: {name!r}")
    parts = name.split("/")
    if any(p in ("..", ".") for p in parts):
        raise Refused(f"unsafe member name: {name!r}")
    clean = posixpath.normpath(name)
    if clean in ("", ".") or clean.startswith("../"):
        raise Refused(f"unsafe member name: {name!r}")
    return clean


def read_bounded(zf, info, label):
    if info.flag_bits & 0x1:
        raise Refused(f"encrypted member: {label}")
    if info.file_size > MAX_MEMBER_BYTES:
        raise Refused(f"member over {MAX_MEMBER_BYTES} bytes (declared): {label}")
    with zf.open(info) as fh:
        data = fh.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise Refused(f"member over {MAX_MEMBER_BYTES} bytes (actual): {label}")
    return data


def extract(zf, label, out_dir, depth, budget, report):
    seen = set()
    for info in zf.infolist():
        member = f"{label}!{info.filename}"
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise Refused(f"symlink member: {member}")
        if info.is_dir():
            continue
        name = safe_name(info.filename)
        if name in seen:
            raise Refused(f"duplicate member: {member}")
        seen.add(name)
        budget.members += 1
        if budget.members > MAX_MEMBERS:
            raise Refused(f"more than {MAX_MEMBERS} members in all archives")
        data = read_bounded(zf, info, member)
        budget.total += len(data)
        if budget.total > MAX_TOTAL_BYTES:
            raise Refused(f"more than {MAX_TOTAL_BYTES} bytes in all archives")
        target = os.path.join(out_dir, *name.split("/"))
        budget.claim(target, member)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "xb") as fh:
            fh.write(data)
        report.append({"archive": label, "member": name, "depth": depth, "bytes": len(data)})
        if name.lower().endswith(ARCHIVE_SUFFIXES):
            if depth >= MAX_DEPTH:
                raise Refused(f"archive nested deeper than {MAX_DEPTH} levels: {member}")
            try:
                inner = zipfile.ZipFile(BytesIO(data))
            except zipfile.BadZipFile as exc:
                raise Refused(f"nested archive not readable: {member}: {exc}")
            extract(inner, f"{label}!{name}", target + ".d", depth + 1, budget, report)


def archives_from_git(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z", "--", "*.zip", "*.whl"],
                         check=True, capture_output=True).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def archives_from_manifest(path):
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root")
    ap.add_argument("out")
    ap.add_argument("--report", required=True)
    ap.add_argument("--manifest")
    args = ap.parse_args(argv)
    paths = archives_from_manifest(args.manifest) if args.manifest else archives_from_git(args.root)
    os.makedirs(args.out)                      # must not exist yet
    budget, report = Budget(), []
    status = {"archives": paths, "members": report, "refused": None}
    try:
        for rel in paths:
            rel_clean = safe_name(rel)
            with zipfile.ZipFile(os.path.join(args.root, *rel_clean.split("/"))) as zf:
                extract(zf, rel_clean, os.path.join(args.out, *rel_clean.split("/")) + ".d", 1, budget, report)
    except (Refused, zipfile.BadZipFile, OSError) as exc:
        status["refused"] = str(exc)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(status, fh, indent=2, sort_keys=True)
    if status["refused"]:
        print(f"extract_archives: refused: {status['refused']}", file=sys.stderr)
        return 2
    print(f"extract_archives: {len(paths)} archives, {len(report)} members, {budget.total} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
