#!/usr/bin/env python3
"""Fake `gh` and `smolvm` for launcher tests. State lives in $FAKE_STATE/state.json.

The fake `gh api` answers the runs and jobs endpoints with JSON shaped like GitHub's REST
responses and applies the caller's --jq expression with the real `jq` (as `gh` applies it), so
the launcher's own filters are exercised, not canned counts. The default run (id 4242) is a push
of steliosx/voalack holding `queued` queued voalack jobs; `event` and `head_repo` override its
metadata (null: missing), and `extra_runs` adds runs: {id, status, event, head_repo, jobs:
[{status, labels}]}.

FAKE_FAIL is a comma list of steps to fail: runs (any status), runs_queued, runs_in_progress, jobs, runners, delete_runner, token,
create, start, provision, configure, run, stop, delete_vm, ls. FAKE_MALFORMED=runs|jobs returns
garbage. FAKE_STICKY=1 keeps the runner registered after its job (as if not ephemeral).
"""
import json
import os
import subprocess
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


LABELS = ["self-hosted", "Linux", "X64", "voalack"]


def runs(state):
    """Every run in the fake repository, GitHub-shaped."""
    default = {"id": 4242, "status": state.get("run_status", "queued"),
               "event": state.get("event", "push"), "head_repo": state.get("head_repo", "steliosx/voalack"),
               "jobs": [{"status": "queued", "labels": LABELS}] * state["queued"]}
    result = [default] if state["queued"] else []
    for run in result + state.get("extra_runs", []):
        shaped = {"id": run["id"], "status": run["status"], "head_branch": "main", "head_sha": "0" * 40}
        if run.get("event") is not None:
            shaped["event"] = run["event"]
        if run.get("head_repo") is not None:
            shaped["head_repository"] = {"full_name": run["head_repo"]}
        shaped["jobs"] = [{"id": run["id"] * 100 + i, "run_id": run["id"], "status": j["status"],
                           "labels": j["labels"]} for i, j in enumerate(run["jobs"])]
        yield shaped


def answer(args, payload):
    """Print the payload as `gh api` would: through --jq if given (raw strings), else as JSON."""
    if "--jq" not in args:
        print(json.dumps(payload))
        return
    out = subprocess.run(["jq", "-r", args[args.index("--jq") + 1]], input=json.dumps(payload),
                         capture_output=True, text=True)
    if out.returncode:
        sys.exit(f"jq failed: {out.stderr}")
    sys.stdout.write(out.stdout)


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
        else:
            listed = [{k: v for k, v in r.items() if k != "jobs"} for r in runs(state) if r["status"] == status]
            answer(args, {"total_count": len(listed), "workflow_runs": listed})
    elif "/jobs" in url:
        fail("jobs")
        if MALFORMED == "jobs":
            print("garbage")
        else:
            run_id = int(url.split("/runs/", 1)[1].split("/", 1)[0])
            jobs = next((r["jobs"] for r in runs(state) if r["id"] == run_id), [])
            answer(args, {"total_count": len(jobs), "jobs": jobs})
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
