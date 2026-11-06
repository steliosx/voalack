# Public beta preparation — 6 November 2026

**Status: preparation candidate; native demo NOT_RUN; NOT_LIVE_VALIDATED.**
No candidate wheel/sdist bundle, installed-site acceptance or supported live
write-back is claimed. The intended first beta still preserves the feed and
delivers authorized human Alerta ACKs to the exact approved ONE alarm with honest
failure semantics and write-back disabled by default.

| Prepared work | Evidence and remaining limit |
| --- | --- |
| Public guidance and protected-schema installation corrections | [Draft PR #4](https://github.com/steliosx/voalack/pull/4), head `383fee8e4f3c07458daa40dfd05567f600fc7d3b`. Four scoped hosted jobs passed in [run 42224186956](https://github.com/steliosx/voalack/actions/runs/42224186956); draft, not merged at this snapshot. |
| Installed-artifact synthetic demonstration | [Draft PR #5](https://github.com/steliosx/voalack/pull/5), stacked on #4. Runtime payload/profile reviewed at `e2158e5c4a2870dafa3ef3f8cb3c82e1f8671844`. Its four hosted jobs passed in [run 42225665420](https://github.com/steliosx/voalack/actions/runs/42225665420); that run did not execute the new demo. Later documentation does not extend this exact-head CI result. |
| Operator preparation | [Installation and lifecycle notes](BETA_OPERATIONS.md), [demo invocation and acceptance](../lab/BETA_DEMO.md), [full readiness checklist](BETA_READINESS.md). Source-derived instructions, not evidence of installation or removal. |

The finite demo is designed to build and install checksummed core/Voalack sdists
and wheels, capture a persisted human ACK, verify it under a restricted role,
deliver once to the loopback fake ONE provider and project the exact recorded
outcome. A second scenario holds a possibly-applied request `UNCERTAIN` and refuses
resend. Both scenarios and the artifact route still need native execution.

The next actionable gate is one fresh, exact-source trial through the existing
coordinated disposable-guest lane, followed by independent review of artifacts,
profiles, scenario witnesses and cleanup. Integration retains the existing
writer/reviewer/advisor agreement and exact-head gates. No new owner decision is
requested merely to review these draft preparations.

Before an installed beta, outstanding evidence also includes the real ONE
occurrence/conditional-ACK contract and adapter, installed Alerta authorization
and plugin behavior, platform/failover containment, Windows feed validation,
two-product installed coexistence, and the required lifecycle tests. The current
coexistence layout has no supported restore. These gates cannot be replaced by
green hosted CI, a synthetic result or an old private-development test count.

Scope remains narrow ACK write-back. Reverse ACK/unack mirroring is not offered;
the optional observer is ledger-only and off by default. No live endpoint,
deployment, release or repository-setting change is included in this preparation.
