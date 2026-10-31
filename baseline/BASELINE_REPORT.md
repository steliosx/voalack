# T03a — ACK MVP 0.1.0 baseline reproduction

2026-10-01 · VO-LEAD (claude-voalack) · task T03a, generation 4 · base `e859d65`

**Result: REPRODUCED.** The MVP's own 32 tests (53 JUnit cases including 21
subtests) pass against the rebuilt, installed wheel, and the rebuilt wheel's
contents are identical to the shipped wheel. Both match the historical claims in
`VALIDATION.md`. Synthetic configuration only; no Veeam ONE or Alerta endpoint was
contacted.

## Environment (actual)

| Item | Value |
|---|---|
| Runner | smolvm 1.22.1 ephemeral microVM, `--cpus 2 --mem 1536 --net --net-backend virtio-net` |
| Guest | Linux 6.12.95 x86_64, Debian 12, image `python:3.12.14-slim-bookworm` |
| Python | 3.12.14 (historical run: 3.12.14) |
| Key packages | `alerta-server==9.1.0`, `Flask==3.1.3`, `Werkzeug==3.1.9`, `pytest==9.1.1`; full list in run 1 `pip-freeze.txt` (captured before the rebuilt wheel was installed; run 2 records both before and after) |
| OpenSSL CLI | 3.0.20 (needed only for the test's ephemeral HTTPS certificate) |
| Mounts | MVP extraction read-only at `/src`; evidence read-write at `/out` |
| Network use | Debian/PyPI package downloads only |

Script: `run_baseline.sh`, corrected in run 2 (see below); each evidence folder keeps the
exact copy it ran. Command on the host:

    smolvm machine run --net --net-backend virtio-net --cpus 2 --mem 1536 --timeout 20m \
      --image python:3.12.14-slim-bookworm \
      -v <inputs>/veeam-one-ack-lab:/src:ro -v <evidence>:/out:rw -- sh /out/run_baseline.sh

The runner exits non-zero if any check fails; the VM's exit status is the run's result.

## Results

| Check | Result | Evidence |
|---|---|---|
| Inner `SHA256SUMS.txt` of the MVP | 12/12 OK | `run.log` |
| Rebuilt wheel vs shipped wheel | 9/9 members identical (including `RECORD`). Only members were compared; the archives themselves differ (run 1 rebuilt `b1f44f9b57bceee834eed7658990b0a3d26ceff619e66ce613d6de025c98fc33`, run 2 rebuilt `575e676ffaa6465c32fdd2f59e559e8bf404a09c1893659312eb9a9bdabcddb6`, shipped `2c83798484f0e465e160a55c02869a2515064af337e08b9e265145489b5863c5`, all 9145 bytes); the cause of the archive difference was not diagnosed | `wheel-compare.txt`, run 2 `wheel-archives.txt` |
| Entry point | `veeam_one_ack` → `alerta_veeam_one.plugin:VeeamOneAckPlugin`, loaded from site-packages, not source | `entry-point.txt` |
| MVP tests | **32 passed**, 0 failed, 0 skipped; JUnit 53 cases, 0 errors/failures | `pytest.txt`, `test-results.xml`, `pytest-exit.txt` (exit 0) |
| Warnings | 1: upstream `datetime.utcnow()` deprecation in `alerta/models/note.py` (same as the historical run) | `pytest.txt` |

**Historical vs reproduced:** counts, Python version and pytest version match the
2026-09-26 run. Not reproduced, because the historical run did not do them either:
real PostgreSQL (the tests mock the database boundary), real Veeam ONE, deployed
Duo/OIDC, and the Windows PowerShell feed (`pwsh` is not available; **NOT_RUN**).

## Run 2: runner correction (review finding R1)

VO-ASTRA's review of run 1 found that the runner could report success after a failed
check: wheel differences were printed but not enforced, the entry-point probe's status was
masked by a pipe, and the pytest status was printed but not returned. Run 1's script and
evidence are kept unchanged in `evidence-20261001/`.

The corrected `run_baseline.sh` exits non-zero on any wheel-member difference, a failed
entry-point load or failing tests, and records full wheel archive hashes and sizes and the
environment before and after installing the rebuilt wheel. Run 2 (`evidence-20261001-r2/`)
proves the failure paths with test-only fault injection on guest-local copies; the frozen
inputs were not modified:

| Run | Injected fault | Where it failed | VM exit |
|---|---|---|---|
| `none` | — | — (32 passed, 9/9 members equal, entry point loaded) | 0 |
| `pytest` | one failing test added to the copied suite | pytest: 1 failed, 32 passed | 1 |
| `wheel` | one line appended to a copied source file | wheel comparison: 2 of 9 members differ | 1 |
| `entrypoint` | installed plugin module removed | entry-point load: `ModuleNotFoundError` | 1 |

Exit statuses are in `evidence-20261001-r2/RUNS.txt`; each run folder holds its log and the
script it ran.

## What the MVP does

An Alerta `post_action` hook (`plugin.py:44-105`) runs after Alerta has committed a
human ACK or the explicit `veeam-ack-retry` action. It requires an authenticated
`g.user_id`/`g.login` and never reads actor attributes (`plugin.py:53-58`). It
snapshots selected alert fields (`plugin.py:67-73`) and calls `run_ack`
(`core.py:199-251`), which:

1. loads the administrator-owned JSON config and binding (`core.py:48-63`, `153-174`);
2. derives `operation_id` from the alert ID and binding, and builds the bounded
   comment `[AlertaAck:<id>] Alerta=<uuid> operator=<login>; <text>` (`core.py:208-212`, `185-197`);
3. under a per-host `flock` (`core.py:66-77`, `213`), logs in, reads the alarm, checks
   identity, grouping, trigger time, repeat count and status, then in live mode posts
   one `resolveType=Acknowledge` and reads back (`core.py:214-240`);
4. classifies the result and records it with `Note.from_alert` (`plugin.py:87-99`).

## Conservative defaults to preserve

- `dry_run` defaults to true and must be a JSON boolean (`core.py:54-56`).
- Fixed HTTPS origin without credentials or path; redirects refused (`core.py:25-28`, `50-53`).
- Default TLS verification with an optional CA file (`core.py:85-88`).
- Timeout bounded to 1–15 s (`core.py:57-60`); response status, size, content type and JSON shape checked (`core.py:103-121`).
- Grouped or child alarms refused (`core.py:181-182`).
- Trigger time checked before marker recognition and after the write; repeat count and status checked (`core.py:219-229`, `236-239`).
- An already-acknowledged alarm keeps its comment (`core.py:226-227`).
- Once a write was attempted, every failure is `uncertain`; no automatic retry (`core.py:243-251`).
- Control characters stripped and the comment bounded to 1024 UTF-16 units (`core.py:185-197`).
- Failures log only the exception type and keep the local ACK (`plugin.py:77-85`).
- Outcome notes avoid `Alert.add_note`, which would add stale status history (`plugin.py:94-99`).

## Gaps for T03b/T04 (findings, not fixes)

| ID | Gap | Source | Where T01 addresses it |
|---|---|---|---|
| G1 | ONE is called after Alerta's commit, in the request: a crash in between leaves a local ACK with no intent or note. | `plugin.py:44-74`, `core.py:199-240` | Atomic capture (C3), A1–A5 |
| G2 | Remote I/O in the request thread: three alarm calls (preflight GET, ACK POST, read-back GET) plus login and revoke, each with its own timeout of up to 15 s and no whole-operation deadline. | `core.py:57-60`, `214-240` | Worker, no request-path I/O |
| G3 | `flock` is per host; the four-node tier needs one ONE session owner. | `core.py:66-77` | Session owner (C8) |
| G4 | `operation_id` comes from alert ID + binding, so repeated human actions share one marker; no per-action identity. | `core.py:208-210` | Server-generated `action_id` (C2, C7) |
| G5 | Any `write:alerts` human can trigger it; no customer/role policy. | `plugin.py:53-58` | Authorization policy (C5) |
| G6 | Bindings live in a JSON file with no revision or audit trail. | `core.py:48-63`, `153-174` | Protected binding registry |
| G7 | Retry re-runs the whole flow; it relies on marker read-back after `uncertain`. | `plugin.py:23`, `core.py:221-222` | Durable attempts, UNCERTAIN hold (C7) |
| G8 | The comment has no request timestamp or "via Voalack" attribution. | `core.py:211-212` | Comment format in T01 (C10) |
| G9 | `status_change` deliberately does nothing; MVP has no transaction adapter. | `plugin.py:40-42` | Adapter (A2) |

## Not run

Real PostgreSQL, real Alerta server process, Veeam ONE, Duo/OIDC, Windows PowerShell feed.
