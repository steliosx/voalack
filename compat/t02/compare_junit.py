"""Fail unless two JUnit files hold the same test cases with the same results.

Random UUIDs inside parametrised test IDs are normalised before comparing.
"""
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def cases(path):
    result = Counter()
    for case in ET.parse(path).getroot().iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            state = "failed"
        elif case.find("skipped") is not None:
            state = "skipped"
        else:
            state = "passed"
        result[(UUID.sub("<uuid>", f'{case.get("classname")}::{case.get("name")}'), state)] += 1
    return result


orig, new = cases(sys.argv[1]), cases(sys.argv[2])
totals = lambda c: dict(Counter(state for (_, state), n in c.items() for _ in range(n)))  # noqa: E731
print("original:", totals(orig))
print("patched: ", totals(new))
if orig != new:
    for key in sorted(set(orig) | set(new)):
        if orig[key] != new[key]:
            print("differs:", key, "original", orig[key], "patched", new[key])
    sys.exit(1)
print("identical case sets and results")
