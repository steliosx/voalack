# Beta evidence update — 13 November 2026

**Recorded synthetic trial: PASS. Full cleanup acceptance incomplete. NOT_LIVE_VALIDATED.**
The 8 November trial used `ec989ec8b9238b417a1a6e94b00fd9cfcb633713`.
GitHub main still resolved to that commit on 13 November, with no open PRs observed.
This is a dated observation, not a statement about future branch state.

| Work | Evidence and remaining limit |
| --- | --- |
| Installed-artifact synthetic demonstration | Saved wrapper, driver and VM exit records are zero; demo JSON is `PASS` / `synthetic_only`. Both confirmed and lost-response scenarios report one dispatch/write/receipt/effect, and repeat delivery is refused. Real Alerta/PostgreSQL with an in-process HTTP client and loopback fake ONE only. |
| Trial distributions | Two wheels and two sdists are retained; all four hashes match their manifest. The wrapper builds wheels from the sdists and installs the resulting wheels. These artifacts are not a published release. |
| Source and profiles | Archive independently matches the exact commit; setup/final profiles report 39/39 and 41/41 matches. A matching profile does not establish byte-reproducible builds. |
| Hosted CI | Four named jobs passed on rerun in run [42476358118](https://github.com/steliosx/voalack/actions/runs/42476358118) at this source. They do not execute the native demo or full PostgreSQL suites. |
| Operator preparation | [Operations notes](BETA_OPERATIONS.md) describe the finite bootstrap and lifecycle limits. Full independent guest cleanup and installed-site lifecycle acceptance remain unverified. |

See the [trial record](BETA_TRIAL_20261108.md) for artifact identities and
[readiness checklist](BETA_READINESS.md) for remaining acceptance work. The next
work is to close the cleanup evidence gap and review/test the existing audit
corrections at their actual candidate heads. A new trial is not needed merely to
replace stale NOT_RUN wording with the accurately scoped historical result.

Installed-beta gates still include the real ONE occurrence/conditional-ACK contract
and adapter, installed Alerta authorization/plugin behavior, platform/failover
containment, Windows feed, two-product installed coexistence and supported
lifecycle tests. The current coexistence layout has no supported restore.

The self-hosted launcher remains suspended; metadata filtering alone does not
qualify live runner isolation. Integration retains independent review, exact-head
validation and the existing advisor gate. No release, deployment, live endpoint,
repository-setting change or recurring work follows from this documentation.

Scope remains narrow human ACK write-back with write-back disabled by default.
Reverse ACK/unack mirroring is not offered; the optional observer is ledger-only
and off by default.
