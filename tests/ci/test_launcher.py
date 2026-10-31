"""Launcher behaviour against fake gh/smolvm: polling, cleanup verification and failure paths."""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "ci" / "launcher" / "launch.sh"
FAKES = Path(__file__).with_name("fakes.py")
TOKEN = "FAKE-REGISTRATION-TOKEN-0123456789"


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("gh", "smolvm"):
        stub = bin_dir / tool
        stub.write_text(f'#!/bin/sh\nexec python3 {FAKES} {tool} "$@"\n')
        stub.chmod(0o755)
    (tmp_path / "fake").mkdir()
    return {**os.environ, "STATE": str(tmp_path / "state"), "FAKE_STATE": str(tmp_path / "fake"),
            "GH": str(bin_dir / "gh"), "SMOLVM": str(bin_dir / "smolvm"), "MAX_JOBS": "3"}


def setup(env, queued=0, vms=(), runners=None, run_status="queued"):
    Path(env["FAKE_STATE"], "state.json").write_text(json.dumps(
        {"queued": queued, "vms": list(vms), "runners": runners or {}, "next_id": 1, "calls": [],
         "run_status": run_status}))


def state(env):
    return json.loads(Path(env["FAKE_STATE"], "state.json").read_text())


def launch(env, *args, **extra):
    result = subprocess.run(["bash", str(LAUNCHER), *args], env={**env, **extra}, capture_output=True, text=True, timeout=60)
    log = Path(env["STATE"], "launcher.log")
    result.log = log.read_text() if log.exists() else ""
    assert TOKEN not in result.log + result.stdout + result.stderr
    return result


def unresolved(env):
    d = Path(env["STATE"], "unresolved")
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def calls(env, tool, word):
    return [c for c in state(env)["calls"] if c[0] == tool and word in " ".join(c)]


def test_idle_only_after_a_successful_query(env):
    setup(env, queued=0)
    r = launch(env)
    assert r.returncode == 0 and "no queued voalack jobs (query succeeded)" in r.log
    assert not calls(env, "smolvm", "create") and not calls(env, "gh", "registration-token")


@pytest.mark.parametrize("fault", [{"FAKE_FAIL": "runs"}, {"FAKE_FAIL": "runs_queued"},
                                   {"FAKE_FAIL": "runs_in_progress"}, {"FAKE_FAIL": "jobs"},
                                   {"FAKE_MALFORMED": "runs"}, {"FAKE_MALFORMED": "jobs"}])
def test_poll_failure_is_unavailable_not_idle(env, fault):
    setup(env, queued=1)
    r = launch(env, **fault)
    assert r.returncode == 2 and "GitHub unavailable" in r.log
    assert not calls(env, "smolvm", "create") and not calls(env, "gh", "registration-token")


def test_one_job_runs_and_everything_is_verified_gone(env):
    setup(env, queued=1)
    r = launch(env)
    assert r.returncode == 0, r.log
    s = state(env)
    assert s["vms"] == [] and s["runners"] == {} and s["queued"] == 0
    assert "absent (verified)" in r.log and unresolved(env) == []


def test_leftover_registration_is_deleted_and_verified(env):
    setup(env, queued=1)
    r = launch(env, FAKE_STICKY="1")
    assert r.returncode == 0, r.log
    assert state(env)["runners"] == {} and "runner" in r.log and "absent (verified)" in r.log


def test_stop_failure_alone_is_fine_when_delete_is_verified(env):
    setup(env, queued=1)
    r = launch(env, FAKE_FAIL="stop")
    assert r.returncode == 0 and state(env)["vms"] == []


@pytest.mark.parametrize("fault", ["delete_vm", "ls"])
def test_unverified_vm_removal_is_unresolved_and_blocks_launches(env, fault):
    setup(env, queued=2)
    r = launch(env, FAKE_FAIL=fault)
    assert r.returncode == 4 and "cleanup UNRESOLVED" in r.log
    assert len(unresolved(env)) == 1 and len(calls(env, "smolvm", "create")) == 1   # stopped launching
    again = launch(env, FAKE_FAIL=fault)
    assert again.returncode == 4 and "not launching" in again.log
    assert len(calls(env, "smolvm", "create")) == 1
    fixed = launch(env, "--cleanup")
    assert fixed.returncode == 0 and unresolved(env) == [] and state(env)["vms"] == []


@pytest.mark.parametrize("fault,sticky", [("runners", "0"), ("delete_runner", "1")])
def test_unverified_runner_removal_is_unresolved(env, fault, sticky):
    setup(env, queued=1)
    r = launch(env, FAKE_FAIL=fault, FAKE_STICKY=sticky)
    assert r.returncode == 4 and len(unresolved(env)) == 1
    assert launch(env, "--cleanup").returncode == 0 and unresolved(env) == []


@pytest.mark.parametrize("fault", ["create", "start", "provision", "token", "configure"])
def test_failed_launch_step_cleans_up_and_exits_3(env, fault):
    setup(env, queued=1)
    r = launch(env, FAKE_FAIL=fault)
    assert r.returncode == 3, r.log
    assert f"launch step failed: {fault}" in r.log
    assert state(env)["vms"] == [] and state(env)["runners"] == {} and unresolved(env) == []


def test_token_reaches_only_the_configuration_command(env):
    setup(env, queued=1)
    assert launch(env).returncode == 0
    assert not any("<TOKEN-VALUE>" in " ".join(c) for c in state(env)["calls"])   # never on a command line
    assert len(calls(env, "smolvm", "config.sh")) == 1


def test_second_job_of_an_in_progress_run_is_served(env):
    # Two jobs; after the first finishes the run is in_progress with one job still queued.
    setup(env, queued=2)
    r = launch(env)
    assert r.returncode == 0, r.log
    s = state(env)
    assert s["queued"] == 0 and s["run_status"] == "completed"
    assert len(calls(env, "smolvm", "create")) == 2 and s["vms"] == [] and s["runners"] == {}


def test_queued_job_in_an_already_in_progress_run_is_found(env):
    setup(env, queued=1, run_status="in_progress")
    r = launch(env)
    assert r.returncode == 0, r.log
    assert state(env)["queued"] == 0 and len(calls(env, "smolvm", "create")) == 1


def test_runner_process_failure_is_not_success(env):
    setup(env, queued=1)
    r = launch(env, FAKE_FAIL="run")
    assert r.returncode == 3, r.log
    assert "launch step failed: runner process" in r.log
    assert state(env)["vms"] == [] and state(env)["runners"] == {} and unresolved(env) == []


def test_unresolved_retry_uses_the_recorded_repository(env):
    # A runner left behind in another repository by an earlier launch.
    setup(env, runners={"vm-old": 7})
    s = state(env); s["runner_repos"] = {"vm-old": "other/repo"}
    Path(env["FAKE_STATE"], "state.json").write_text(json.dumps(s))
    d = Path(env["STATE"], "unresolved"); d.mkdir(parents=True)
    (d / "vm-old").write_text("vm=vm-old\nrunner=vm-old\nrepo=other/repo\nat=2026-10-01T00:00:00Z\n")
    r = launch(env, "--cleanup")                      # invoked with the default repository
    assert r.returncode == 0, r.log
    assert state(env)["runners"] == {} and unresolved(env) == []
    assert calls(env, "gh", "repos/other/repo/actions/runners")
    assert not calls(env, "gh", "repos/steliosx/voalack/actions/runners")


def test_malformed_unresolved_record_is_kept_and_blocks(env):
    setup(env, queued=1)
    d = Path(env["STATE"], "unresolved"); d.mkdir(parents=True)
    (d / "vm-bad").write_text("vm=vm-bad\nrunner=vm-bad\n")
    r = launch(env)
    assert r.returncode == 4 and "malformed" in r.log and unresolved(env) == ["vm-bad"]
    assert not calls(env, "smolvm", "create")
