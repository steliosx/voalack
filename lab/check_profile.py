"""Compare a guest pip freeze with a reviewed lab dependency profile; exit 1 on any difference.

Usage: python3 -I check_profile.py PROFILE FREEZE REPORT

Both files hold pip freeze lines: "name==version" or "name @ url". Comment and blank lines are ignored. Names are
compared normalized (PEP 503: lower case, runs of "-", "_" and "." as one "-"); a duplicate normalized name in either
file is an error, never a choice. The report lists every missing, extra and differing distribution and ends with
"RESULT: profile match" or "RESULT: profile MISMATCH". Standard library only; nothing from the product is imported.
"""
import re
import sys


def _norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _entries(path):
    out, errors = {}, []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(==\s*\S+|@\s*\S+)", line)
            if not m:
                errors.append(f"{path}:{n}: not a pin or a direct reference: {line!r}")
                continue
            key, spec = _norm(m.group(1)), m.group(2)
            spec = "==" + spec[2:].strip() if spec.startswith("==") else "@ " + spec[1:].strip()
            if key in out:
                errors.append(f"{path}:{n}: duplicate distribution {key}")
                continue
            out[key] = spec
    return out, errors


def main(argv):
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        return 2
    profile_path, freeze_path, report_path = argv[1:]
    want, e1 = _entries(profile_path)
    have, e2 = _entries(freeze_path)
    lines = [f"profile {profile_path}", f"freeze {freeze_path}"] + e1 + e2
    for key in sorted(set(want) | set(have)):
        if key not in have:
            lines.append(f"missing {key} {want[key]}")
        elif key not in want:
            lines.append(f"extra {key} {have[key]}")
        elif want[key] != have[key]:
            lines.append(f"differs {key} want {want[key]} have {have[key]}")
    ok = len(lines) == 2 and bool(want)
    lines.append(f"distributions profile {len(want)} freeze {len(have)}")
    lines.append("RESULT: profile match" if ok else "RESULT: profile MISMATCH")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(lines[-1])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
