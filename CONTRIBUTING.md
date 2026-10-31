# Contributing

Start with README.md and `packages/voalack/README.md`.

- Keep changes narrow. In the pull request, explain the problem, the resulting behaviour, the validation you ran and
  any compatibility effect.
- Changes to signing, authority, SQL grants, the DDL guard, delivery state or migrations need review by a maintainer
  who knows that boundary. Never weaken a test or broaden a grant to get a green run.
- CI runs the package and launcher tests (`docs/CI.md`). The full capture suite needs PostgreSQL 18.6 and
  Alerta 9.1.0 and runs in a disposable virtual machine; say in the pull request whether you ran it.
- New tests should show a real behaviour or failure boundary, not mirror an implementation detail. A skipped test is
  not a pass.
- Never include real credentials, hostnames, addresses or customer data, even in test fixtures.

Submit only material you have the right to contribute. Contributions are accepted under the Apache License,
Version 2.0 (see LICENSE).
