#!/usr/bin/env python3
"""Fake `gh` and `smolvm` for launcher tests. State lives in $FAKE_STATE/state.json.

FAKE_FAIL is a comma list of steps to fail: runs (any status), runs_queued, runs_in_progress, jobs, runners, delete_runner, token,
create, start, provision, configure, run, stop, delete_vm, ls. FAKE_MALFORMED=runs|jobs returns
garbage. FAKE_STICKY=1 keeps the runner registered after its job (as if not ephemeral).
"""
import json
import os
import sys
from pathlib import Path

STATE = Path(os.environ["FAKE_STATE"]) / "state.json"
FAIL = set(filter(None, os.environ.get("FAKE_FAIL", "").split(",")))
MALFORMED = os.environ.get("FAKE_MALFORMED", "")


def load():
    return json.loads(STATE.read_text()) if STATE.exists() else {"queued": 0, "vms": [], "runners": {}, "next_id": 1, "calls": []}


def save(state):
    STATE.write_text(json.dumps(state))


def fail(step):
    if step in FAIL:
        print(f"fake {step} failure", file=sys.stderr)
        sys.exit(9)


def gh(args, state):
    url = next((a for a in args if a.startswith("repos/")), "")
    repo = "/".join(url.split("/")[1:3])
    owners = state.setdefault("runner_repos", {})
    method = args[args.index("-X") + 1] if "-X" in args else "GET"
    if "/actions/runs?" in url:
        status = url.split("status=", 1)[1].split("&", 1)[0]
        fail("runs"); fail(f"runs_{status}")
        if MALFORMED == "runs":
            print("not-a-number")
        elif state["queued"] and state.get("run_status", "queued") == status:
            print("4242")
    elif "/jobs" in url:
        fail("jobs")
        print("garbage" if MALFORMED == "jobs" else state["queued"])
    elif url.endswith("/registration-token"):
        fail("token")
        print("FAKE-REGISTRATION-TOKEN-0123456789")
    elif method == "DELETE" and "/actions/runners/" in url:
        fail("delete_runner")
        rid = url.rsplit("/", 1)[1]
        state["runners"] = {n: i for n, i in state["runners"].items()
                            if not (str(i) == rid and owners.get(n, "steliosx/voalack") == repo)}
    elif "/actions/runners" in url:
        fail("runners")
        jq = args[args.index("--jq") + 1]
        name = jq.split('.name=="', 1)[1].split('"', 1)[0]
        if name in state["runners"] and owners.get(name, "steliosx/voalack") == repo:
            print(state["runners"][name])
    else:
        sys.exit(f"unexpected gh call {args}")


def smolvm(args, state):
    name = args[args.index("--name") + 1] if "--name" in args else None
    cmd = args[1]
    if cmd == "create":
        fail("create"); state["vms"].append(name)
    elif cmd == "start":
        fail("start")
    elif cmd == "exec":
        script = " ".join(args)
        if "sh -s" in script:
            sys.stdin.read(); fail("provision")
        elif "config.sh" in script:
            fail("configure")
            if os.environ.get("VO_REG_TOKEN") != "FAKE-REGISTRATION-TOKEN-0123456789":
                sys.exit("token not passed via environment")
            runner = script.split("--name ", 1)[1].split()[0]
            state["runners"][runner] = state["next_id"]; state["next_id"] += 1
        elif "run.sh" in script:
            fail("run")
            state["queued"] = max(0, state["queued"] - 1)
            state["run_status"] = "in_progress" if state["queued"] else "completed"
            if os.environ.get("FAKE_STICKY") != "1":
                state["runners"] = {n: i for n, i in state["runners"].items() if n != name}
        else:
            sys.exit(f"unexpected exec {args}")
    elif cmd == "stop":
        fail("stop")
    elif cmd == "delete":
        fail("delete_vm"); state["vms"] = [v for v in state["vms"] if v != name]
    elif cmd == "ls":
        fail("ls"); print("\n".join(state["vms"]))
    else:
        sys.exit(f"unexpected smolvm call {args}")


if __name__ == "__main__":
    tool, args = sys.argv[1], sys.argv[2:]
    state = load()
    state["calls"].append([tool] + [a.replace("FAKE-REGISTRATION-TOKEN-0123456789", "<TOKEN-VALUE>") for a in args])
    save(state)
    try:
        (gh if tool == "gh" else smolvm)(args, state)
    finally:
        save(state)
