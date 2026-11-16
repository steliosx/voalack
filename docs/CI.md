# Continuous integration

CI is a **check, not an approval**: `main` moves only by a merge commit of an exact head that has been reviewed.
The full capture suite must have passed on a push of that exact head; a skipped pull request instance of the job
does not count.

## Hosted CI (pushes to main and vo/**; pull requests to main)

Since 2026-10-30 (owner direction), the CI jobs run on GitHub-hosted `ubuntu-24.04` runners:

| Job | Script | Notes |
|---|---|---|
| `core` | `ci/run_core_tests.sh` | Builds the ack-core wheel and runs its tests against the installed wheel |
| `envelope` | `ci/run_envelope_tests.sh` | Builds the wheels and runs the signed-envelope tests against the installed `voalack` wheel |
| `launcher` | `ci/run_launcher_tests.sh` | Launcher polling, cleanup verification and failure paths, against fake `gh` and `smolvm` |
| `secrets` | `ci/run_secret_scan.sh` | Pinned gitleaks 8.24.3 over the history, the current tree and the members of the current archives (see Secret scan) |
| `capture` | `lab/run_capture.sh` | The full capture suite with PostgreSQL 18.7 and Alerta 9.1.0, in a pinned container; pushes only (see Capture suite) |

## Capture suite

The `capture` job runs `lab/run_capture.sh` unchanged, in a `python:3.12.14-slim-bookworm` container pinned by digest
(the image the microVM runs use). The job runs as root inside the container, as the lab guest does: it installs
PostgreSQL 18.7 from PGDG, with the version and repository key checked by `lab/setup_guest.sh`, and Alerta from the
pinned profile, then runs every test in `tests/capture`.

- **Pushes of this repository only.** It runs for pushes to `main` and `vo/**`, which test the exact head a review
  names, and only when the repository ID is this repository's, so a copy of the workflow in a fork does not run it. It
  never runs for pull requests: the push of the same branch already covers it, and a run on GitHub's merge commit
  would repeat about an hour of work. A skipped pull request instance of this job is not evidence for anything.
- **Container options.** `--shm-size=1g`, because Docker's default 64 MiB `/dev/shm` is smaller than a guest's and
  PostgreSQL keeps its dynamic shared memory there. `--cap-add SYS_ADMIN` with AppArmor unconfined, because the anchor
  full-disk test mounts a 64 KiB tmpfs and would otherwise skip. Every step of the job runs with this widened
  container, not only that test, so the whole hosted VM is treated as expendable: the job takes synthetic inputs only
  and holds no secrets, OIDC or credentials beyond the read-only token. Other jobs do not get these options.
- **No skips.** After the suite, the job reads every suite in the JUnit report and fails unless there is at least one
  test, the testcase count matches the suites' totals, and no testcase failed, errored or was skipped. A skipped test
  is not a pass. The number of tests is not fixed; a change to it is part of the reviewed change.
- **Evidence.** The job records its repository ID, event, commit, workflow, run, attempt, runner and declared image in
  `ci-environment.txt`, and uploads the files in `/out` matching `*.txt`, `*.json`, `*.jsonl`, `*.log` and
  `test-results.xml` (that file, pytest output, JUnit report, profile checks, dependency freezes, probe witnesses,
  PostgreSQL version and a bounded server log) as `capture-evidence-<sha>-run<id>-attempt<n>`, kept for 90 days. Other
  kinds of file are not published, and finding no files fails the upload. When a review relies on a run, its artifact is downloaded, checked
  against the API digest, and hashed into the project's record, because GitHub expires artifacts. A green job does
  not replace the exact-head review. Matching versions and results are comparable observed suite results; they do not
  make a container and a microVM equivalent in isolation, kernel, filesystem or timing, or establish untested behaviour.

- **Fork pull requests: a guard, not a boundary.** In every job that runs for pull requests, the first step fails a
  pull request from a fork before checkout. The `capture` job never runs for pull requests (its job-level condition
  admits only pushes of this repository's ID), so it has no such step. A fork pull request can edit this workflow, guard included, so the guard only stops an unmodified
  workflow. The boundary is elsewhere: jobs run on GitHub's disposable hosted runners (never a maintainer machine),
  the token is read-only and no repository secrets are used. Since 15 November 2026 the repository requires approval
  before workflows run for any outside contributor (`all_external_contributors`; it was `first_time_contributors`).
  This mutable repository setting is separate from the source guard and exact-head code review.
- **Repository settings (read 15 November 2026).** Only GitHub-owned actions are allowed, and every action must be
  pinned to a full commit SHA. Private vulnerability reporting and Dependabot alerts are on. A ruleset protects `main`:
  changes arrive only through a pull request, the `core`, `envelope`, `launcher` and `secrets` checks must pass, force
  pushes and deletion are blocked, and nobody can bypass it. The `capture` job is not a required check, because a
  skipped pull request instance of a job satisfies a required check; its push result is checked before a merge
  instead. These are mutable settings, recorded here as read, not guarantees of the source.
- **Published evidence.** Every job uploads an explicit list of files or patterns, never a whole directory, so a new
  file a job writes is not published until the list is changed and reviewed. The patterns limit what is published; they
  do not sanitise contents.
- **Least privilege.** The workflow token is read-only (`contents: read`), checkouts do not persist credentials, and
  every action is pinned to a full commit SHA.
- **No self-hosted workflow.** The dispatch-only `forgehold-smoke` workflow has been removed from this
  candidate. All remaining workflows target hosted runners. Keep maintainer-host and shared-lane runners
  disconnected from this public repository; source guards do not safely isolate an attached runner from
  contributor-controlled workflows. Adding a runner or dispatch route requires its own review and authority.

## Security scans (informational)

A separate workflow, `.github/workflows/security.yml`, runs on the same events as CI, with the same fork guard,
read-only token and SHA-pinned actions. It is **not a required check**: for at least its first month a finding is
recorded and reviewed, but it does not block a merge by itself.

| Job | Tool | What it reads |
| --- | --- | --- |
| `pip-audit` | pip-audit 2.10.1, installed into its own venv at that exact version (its own dependencies resolve unpinned at run time) | The three locked lab profiles in `lab/profiles/`, audited as listed (`--no-deps --disable-pip`; nothing is installed). The two local projects in the final profiles are not on PyPI and are reported as skipped. |
| `zizmor` | zizmor 1.31.1, installed from its dependency-free wheel pinned by SHA-256 (`--require-hashes`) | The files in `.github/workflows/`, offline: no GitHub API calls and no token. |

Each job publishes only its own `*.txt` reports, for 30 days. CodeQL default setup also runs, as a repository
setting (read 16 November 2026: configured, `actions` and `python`, default query suite); its results are in the
Security tab, visible to maintainers only.

What a finding means:
- A known advisory against a **lab profile dependency** is a public advisory about a test dependency, not a Voalack
  vulnerability. It is recorded. The profile changes only through its qualification route, with a new pinned profile
  and a full capture run, never by a silent version bump.
- A **zizmor** finding in this repository's workflows is fixed, or recorded with the reason it is judged a false
  alarm. It is not hidden with an ignore file.
- A hole in **Voalack's own code or trust boundaries**, from CodeQL or anything else, is reported through private
  vulnerability reporting (`SECURITY.md`), never in an issue or a pull request.

## Secret scan

The `secrets` job downloads gitleaks 8.24.3, checks its SHA-256 against the release checksum file, and runs three
scans with the default rule set (`.gitleaks.toml` keeps every default rule):

1. the text of every reachable commit (`history.json`);
2. the current tree, archives as stored bytes (`tree.json`);
3. the members of the current `*.zip` and `*.whl` files, extracted by `ci/extract_archives.py` (`archives.json`).

The extractor writes members as plain files and never runs, imports or installs them. It opens an archive inside an
archive one level deep (an input zip carries a wheel), and refuses unsafe names, symlinks, duplicates, more than
5 MiB per member, 50 MiB or 2,000 members in all, or deeper nesting. Every scan runs; the job fails if any scan finds
something, fails, or leaves no report, and also if the archive scan covers zero bytes although members were
extracted. The default path allowlist applies to archive members as it does to the tree (so, for example, a wheel's
`*.dist-info/` files are skipped). Exceptions are added only for values a scan actually reported, each bound to
one exact path and one exact value.

Not covered: archive versions that exist only in history, binary formats other than zip and wheel (images included),
and anything the gitleaks rules do not describe.

## Disposable microVM runs (local)

Targeted test subsets, the beta demonstration (`lab/run_beta_demo.sh`) and recorded qualification runs still run in
disposable microVMs on a maintainer host, with recorded evidence. The full capture suite can also run there, with the
same script. These are local qualification runs, not CI.

**The launcher is dormant.** The on-demand self-hosted launcher described below is suspended for this public
repository: no workflow targets the `voalack` label, and it is not run. Its code and its tests (the `launcher` job,
against fakes) remain. The rest of this section describes how it would behave.

### How a launcher job runs

```text
a job labelled [self-hosted, Linux, X64, voalack] is queued (no workflow uses this label now)
                                │
launcher (ci/launcher/launch.sh, on demand) ── sees the queued job
                                │
   fresh microVM (Ubuntu 24.04, 2 CPU, 2 GiB) ── checksum-verified runner, one-hour token
                                │
   --ephemeral runner takes exactly one job, runs it, deregisters
                                │
   launcher deletes any leftover registration and the VM, and verifies both are gone
```

- **One job, one VM.** Every job gets a new disposable microVM with a single-use runner.
  Nothing persists between jobs.
- **The launcher is on demand, not a service.** It runs after the lead's pushes and from the
  lead's periodic check while a session is open; it starts runners only when a job labelled
  `voalack` is queued, one VM at a time, at most `MAX_JOBS` per invocation. A permanent
  host service would be a separate owner decision.
- **Credentials in the VM.** Exactly three kinds, all short-lived and scoped to this
  repository:
  1. the **registration token**, minted on the host just before use (it expires after one
     hour) and passed only to the runner's configuration command as a secret environment
     variable; never printed, logged or put on a command line;
  2. the **runner identity** that configuration creates (the runner stores its own
     credentials in the VM); it is single-use, removed by GitHub when the ephemeral runner
     finishes, and the VM holding it is deleted;
  3. the **job token**, read-only (`contents: read`).

  Never in the VM: the host's GitHub credential, Veeam ONE or Alerta credentials, and
  credentials for any other repository.
- **Cleanup is verified, not assumed.** After each job the launcher deletes any remaining
  registration and the VM, then checks that both are gone. If it cannot confirm that, it
  records the VM and runner under its state directory as **unresolved**, exits with status 4,
  and launches nothing more until `launch.sh --cleanup` succeeds.
- **A failed GitHub query is not "idle".** If the queue query fails or returns something
  malformed, the launcher exits with status 2 without minting a token or creating a VM.
- **Only pushes of this repository are admitted.** Every run that holds a queued `voalack` job
  must be a `push` event whose head repository is exactly this repository. If any such run is a
  pull request, comes from a fork, or lacks its event or head repository, the launcher exits with
  status 5 and starts nothing, not even for the trusted jobs in the same queue. Jobs that do not
  need a `voalack` runner are ignored. This vets the queue as polled: it does not bind a runner to
  a particular job, and a job queued after the poll is not vetted. The launcher stays suspended
  for this public repository.
- **Actions.** The checked-in workflows use GitHub-owned actions pinned to full commit SHAs.
  This describes the source, not an assertion that the repository's mutable allowed-actions setting enforces it.

**Rejected:** a runner on the host itself. It would execute workflow content from any pushed
branch with the host's access.

### Scripts

Each job records the commit it tested (`GITHUB_SHA`); on pull requests that is GitHub's
merge commit, not the branch head.

The CI scripts are the same scripts used for local runs; each takes `SRC`, `OUT` and `WORK`
directories. Later suites (the T03a baseline, T03b capture tests with Alerta and PostgreSQL
inside the VM) are added as they are written.

**Not in CI:** the Zabalack compatibility proof (`compat/t02`). It needs the private Zabalack
source, and a credential for another repository is not allowed in CI. It stays a local
microVM run with recorded evidence; a green CI run does not mean compatibility was proven.

The launcher inspects both queued and in-progress workflow runs, because a run whose first job
is running can still hold queued jobs. Known limitation: it reads at most 100 runs per status
and 100 jobs per run.

## Reading results

- A job that stayed queued, was cancelled or never started is **not** validation.
- Test evidence is uploaded as run artifacts kept for 90 days; secrets reports are kept for 3 days.
  Anything a review relies on is also
  recorded with the project, because GitHub expires logs and artifacts.
- Reviewers can inspect runs directly through the GitHub API, independently of the lead's
  reports.
