# Contributing

Start with README.md and `packages/voalack/README.md`.

- Keep changes narrow. In the pull request, explain the problem, the resulting behaviour, the validation you ran and
  any compatibility effect.
- Changes to signing, authority, SQL grants, the DDL guard, delivery state or migrations need review by a maintainer
  who knows that boundary. Never weaken a test or broaden a grant to get a green run.
- Every change to `main` arrives through a pull request, and four checks must pass on it:
  - `ack-core tests (installed wheel)`
  - `voalack envelope tests (installed wheels)`
  - `CI launcher failure paths (fake gh and smolvm)`
  - `secret scan (gitleaks 8.24.3; history, tree, archive members)`

  Force pushes and deletion of `main` are blocked (`docs/CI.md`).
- The full capture suite (PostgreSQL 18.7 and Alerta 9.1.0) runs in CI only on pushes to this repository, and CI
  refuses pull requests from forks. So for an outside contribution, say in the pull request whether you ran
  `lab/run_capture.sh` yourself, in a disposable virtual machine or container.
- New tests should show a real behaviour or failure boundary, not mirror an implementation detail. A skipped test is
  not a pass.
- Never include real credentials, hostnames, addresses or customer data, even in test fixtures.

Submit only material you have the right to contribute. Contributions are accepted under the Apache License,
Version 2.0 (see LICENSE).
