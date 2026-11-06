# Beta readiness

Source assessment: 6 November 2026, public repository `steliosx/voalack`
(repository ID `1442050691`), application source at
`3ca8bb6bd3cb5e86023d65540b85fee011e6c28d`.
The documentation/workflow cleanup and synthetic demo preparation do not change
application code or turn historical evidence into new qualification. The new
[demo payload](../lab/BETA_DEMO.md) is implemented but its native execution is
**NOT_RUN**; it is not accepted beta evidence.

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
  tests and bounded secret scans. Run
  [41501760593](https://github.com/steliosx/voalack/actions/runs/41501760593)
  is evidence for the exact public main above; it does not run the PostgreSQL
  capture, sender, observer, coexistence or recovery suites.
- `lab/setup_guest.sh`, the qualified dependency profiles and
  `lab/run_capture.sh` provide a synthetic PostgreSQL/Alerta test environment.
  They are guest provisioning/test scripts, not a deployable worker service.
- `schema.apply(conn)` verifies the packaged SQL expectations and installs the
  complete protected schema in order. Applying `schema.sql` by itself is not the
  current installation route.

## Remaining software and artifact work

| Work | Current evidence | Smallest useful completion evidence |
| --- | --- | --- |
| Runnable synthetic assembly | The finite `lab/demo_beta.py` driver and guest wrapper are prepared and statically reviewed; native execution is NOT_RUN. This is not a persistent deployment service. | Run the exact reviewed payload in the coordinated fresh guest. Require its persisted human ACK, exact intent/capture, restricted verification, single fake delivery, projection and uncertainty/no-resend witnesses to pass, and independently verify source/artifact bindings and cleanup. |
| Candidate distribution bundle | CI builds test wheels. The new demo wrapper prepares both sdist/wheel pairs, but has not run and has produced no candidate bundle. | Build both distributions in the approved guest, retain wheel and sdist bytes and SHA-256 manifest, record exact source/tree and dependency profile, install those exact artifacts in a clean environment and verify imports and packaged SQL/JSON resources. Rebuild from the sdists before asserting their usability. |
| Installation/lifecycle runbook | Current setup notes describe capture and individual runtime components, not a complete installed delivery system. | Explicit dependency/bootstrap order, restricted runtime credentials separate from administrator bootstrap, anchor persistence/ownership, fail-closed startup, supported uninstall/rollback behavior and evidence for the supported fresh-install lifecycle. Document unsupported downgrade/restore rather than improvising a destructive reset of an existing deployment. |
| Candidate regression evidence | Historical native results exist; public CI covers only its named jobs. | At the actual integration candidate, record the approved native suite and directly affected critical regressions, exact artifact/source identities, environment/profile, exit statuses and raw case results. Reuse unaffected evidence only with an explicit source/scope comparison. |
| Operator and owner handoff | Design and historical reports are present. | One-page summary links exact artifacts, installation instructions, observed outcomes, unresolved gates and known limitations. No release/live-ready label until the relevant evidence exists. |

Use targeted critical checks during development and a batch review at the
integration candidate. Do not require exhaustive new negative-control matrices
for each small change. Failed, cancelled, skipped or unexecuted cases remain
failed or unqualified; a larger pass count does not replace the required behavior.

## Synthetic assembly acceptance sequence

This is the acceptance contract for the prepared, unexecuted [demo command](../lab/BETA_DEMO.md).
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
