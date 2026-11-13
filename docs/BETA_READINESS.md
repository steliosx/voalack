# Beta readiness

Evidence reconciliation: 13 November 2026, public repository `steliosx/voalack`
(repository ID `1442050691`). The synthetic trial on 8 November used exact source
`ec989ec8b9238b417a1a6e94b00fd9cfcb633713` and reported wrapper exit `0` and
`PASS` with qualification `synthetic_only`. Its archive, distribution hashes and
saved results were independently inspected; this documentation refresh does not
claim a new execution. See the [trial evidence record](BETA_TRIAL_20261108.md).
Complete guest-cleanup acceptance and installed/live qualification remain open.

The intended outcome remains the [first candidate requirements](REQUIREMENTS.md#4-first-candidate):
preserve the feed, capture an authorized human ACK durably, deliver it to the
approved ONE target with honest failure semantics, and supply installable,
checksummed artifacts and operator instructions. Write-back stays disabled by
default. A synthetic demonstration is a step toward that outcome, not a substitute
for the live-provider and installed-environment gates.

## What is already available

- The shared ACK core, signed capture, verifier, durable attempt/uncertainty
  handling, projection, optional ledger-only observer and coexistence protections
  are implemented. See the [package notes](../packages/voalack/README.md) for
  historical test evidence and limitations.
- Public hosted CI runs installed ACK-core and envelope tests, mocked-launcher
  tests and bounded secret scans. Exact-source run
  [42476358118](https://github.com/steliosx/voalack/actions/runs/42476358118)
  passed on rerun at the trial commit. It does not run the PostgreSQL capture,
  sender, observer, coexistence or recovery suites. The synthetic native trial
  is separate evidence; see its record below.
- `lab/setup_guest.sh`, the qualified dependency profiles and
  `lab/run_capture.sh` provide a synthetic PostgreSQL/Alerta test environment.
  They are guest provisioning/test scripts, not a deployable worker service.
- `schema.apply(conn)` verifies the packaged SQL expectations and installs the
  complete protected schema in order. Applying `schema.sql` by itself is not the
  current installation route.

## Remaining software and artifact work

| Work | Current evidence | Smallest useful completion evidence |
| --- | --- | --- |
| Runnable synthetic assembly | The two saved native scenarios report PASS at the trial commit; source/artifact bindings were independently checked. This is not a persistent deployment service. | Complete independent guest/lane cleanup evidence. Preserve the exact trial result; run affected critical regressions for any later implementation candidate. |
| Candidate distribution bundle | Both wheel/sdist pairs exist for the trial. All four hashes match the saved manifest. The wrapper builds wheels from sdists and installs them without dependency resolution. | Use the retained exact artifacts and profiles for candidate review. Verify packaged resources and installed lifecycle as required; these privately retained files are not a published release or reproducible-build claim. |
| Installation/lifecycle runbook | The finite synthetic bootstrap ran successfully. The operations notes describe role/anchor separation and unsupported removal/restore; there is no qualified persistent installed delivery system. | Test the supported installed lifecycle, including removal/rollback where offered. Preserve unsupported downgrade/restore limits; never reset a real protected installation to imitate a fresh demo. |
| Candidate regression evidence | Two synthetic scenarios passed at the exact trial head. Historical native suites and named hosted jobs retain their original scope. | At the next integration candidate, run directly affected critical regressions and record source/overlay identities, environment/profile, raw cases and exit statuses. Reuse unaffected evidence only with a source/scope comparison. |
| Operator and owner handoff | The owner summary and trial record now identify observed synthetic results, artifact hashes and remaining gates. | Obtain independent review of this documentation change and complete outstanding cleanup/site/lifecycle evidence before broader readiness claims. |

Use targeted critical checks during development and a batch review at the
integration candidate. Do not require exhaustive new negative-control matrices
for each small change. Failed, cancelled, skipped or unexecuted cases remain
failed or unqualified; a larger pass count does not replace the required behavior.

## Synthetic assembly acceptance sequence

This is the acceptance contract for the [demo command](../lab/BETA_DEMO.md). The recorded trial passed its two scenarios; full acceptance also requires the cleanup evidence described below.
Run only in the existing approved disposable guest with synthetic data. Do not
turn the test fixtures into deployment credentials or point them at a real site.

1. Start from a fresh approved guest and exact source. Verify the dependency
   profile; use a separate database owner and restricted Alerta/runtime roles.
   Install the exact candidate artifacts, create Alerta's tables, apply the full
   packaged schema and bootstrap the external recovery anchor.
2. Configure a synthetic human and one exact customer/alert/instance binding.
   Use the loopback fake ONE transport only. Preserve the `fake-one/v1` provider
   restriction and the default-off observer.
3. Submit a human ACK through the Alerta application boundary. Independently
   observe the local ACK and its committed capture/intent. Run verification under
   the verifier role and delivery under the sender role; do not use the bootstrap
   superuser for those operations.
4. Record a successful fake delivery and independently counted dispatch, ACK
   transport, receipt and effect. A repeated delivery attempt must not add an
   effect. Drain projection under its own role and verify the operator note
   without changing delivery state or creating another intent.
5. On a separate synthetic target, simulate a response lost after possible
   transmission. Require `UNCERTAIN` and retained guards; another delivery must
   not send again. Report reconciliation/containment limits honestly.
6. Stop the demo and retain sanitized evidence. Follow the approved guest cleanup
   route. A new disposable demonstration may start from a fresh guest; destroying
   a real protected database or rolling back its anchor is not a reset procedure.

## Gates that still require environment evidence

| Gate | Status and needed evidence |
| --- | --- |
| ONE occurrence and write contract (U1/U2) | Open. The shipped sender transport is fake and loopback-only. Pin the deployed ONE build/API, occurrence/conditional-write behavior, narrow ACK operation, session/auth/privilege behavior, comment bound and read-back semantics before implementing/enabling a live adapter. A GET-to-POST race is not closed by timestamps, a marker or a database generation. |
| Installed Alerta and identity (U3/U4) | Open. Verify the actual plugin chain, transaction boundary, human identity/customer claims and role matrix without changing existing visibility or granting delete permission. |
| Platform and failover (U5) | Open. Record the actual PostgreSQL/Patroni/PgBouncer configuration, transaction-pooling behavior, RPO and independent old-sender containment. Do not infer safe takeover from lease expiry. |
| Windows feed (U7) | Open. The archived feed and Linux tests do not establish native PowerShell/DPAPI behavior, live ingestion lineage or missed-transition recovery. |
| Two-product installed coexistence | Open. The compatibility experiment and separately scoped source/native evidence do not establish an installed Voalack/Zabalack deployment. Use the existing coordinated test route and exact artifacts. |

These gates remain distinct from repository settings or green hosted CI. No live
endpoints, new credentials, runner attachment, deployment, or release is authorized
by this checklist. Without the required live evidence, label the outcome at most
`READY_FOR_LAB_REVIEW` / `NOT_LIVE_VALIDATED`.

## Explicit current limitations

- Coexistence 3a S1–S3b is present. There is no supported coexistence-3a restore;
  the supervised recovery route refuses that installed layout. Historical T04
  restore evidence is not current coexistence restore acceptance.
- ONE-origin ACK/unack/comment mirroring is outside scope. The optional observer
  records ledger evidence only; it cannot send, project, settle or release holds.
- The public repository's contributor-approval policy was
  `first_time_contributors` at the readback above. It does not mean every outside
  contributor's workflow requires approval. Workflow code guards are not a
  security boundary for an attached maintainer-host runner.
