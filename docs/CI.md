# Continuous integration

CI is a **check, not an approval**: `main` still moves only after VO-ASTRA has reviewed the exact head.

## Hosted CI (every push and pull request)

Since 2026-10-30 (owner direction), the CI jobs run on GitHub-hosted `ubuntu-24.04` runners:

| Job | Script | Notes |
|---|---|---|
| `core` | `ci/run_core_tests.sh` | Builds the ack-core wheel and runs its tests against the installed wheel |
| `envelope` | `ci/run_envelope_tests.sh` | Builds the wheels and runs the signed-envelope tests against the installed `voalack` wheel |
| `launcher` | `ci/run_launcher_tests.sh` | Launcher polling, cleanup verification and failure paths, against fake `gh` and `smolvm` |
| `secrets` | `ci/run_secret_scan.sh` | Pinned gitleaks 8.24.3 over the history, the current tree and the members of the current archives (see Secret scan) |

- **Fork pull requests: a guard, not a boundary.** The first step of every job fails a pull request from a fork
  before checkout. A fork pull request can edit this workflow, guard included, so the guard only stops an unmodified
  workflow. The boundary is elsewhere: jobs run on GitHub's disposable hosted runners (never a maintainer machine),
  the token is read-only, no repository secrets are used, and a repository setting requires a maintainer's
  approval before workflows run for a pull request from an outside contributor.
- **Least privilege.** The workflow token is read-only (`contents: read`), checkouts do not persist credentials, and
  every action is pinned to a full commit SHA.
- **No self-hosted workflow.** Every workflow in this repository runs on GitHub-hosted runners; none uses a
  self-hosted label, and no self-hosted runner is registered for the repository. A pull request that adds
  a self-hosted job still needs the maintainer approval above before anything runs.

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

The full capture suite (PostgreSQL 18.6 and Alerta 9.1.0) and recorded qualification runs do not run on hosted
runners. They run in disposable microVMs on a maintainer host, with recorded evidence. The on-demand launcher
below is kept for those runs and for its own tests; no workflow targets the `voalack` label any more.

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
- **Actions.** The repository allows only GitHub-owned actions, pinned to full commit SHAs.

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
- Evidence is uploaded as a run artifact (kept 90 days). Anything a review relies on is also
  recorded with the project, because GitHub expires logs and artifacts.
- Reviewers can inspect runs directly through the GitHub API, independently of the lead's
  reports.
