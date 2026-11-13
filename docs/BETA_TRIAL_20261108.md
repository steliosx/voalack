# Synthetic trial evidence — 8 November 2026

Reviewed saved evidence; rechecked on 13 November 2026. This record distinguishes
execution by the trial operator from subsequent independent evidence inspection.
No new product execution was performed for this documentation update.

- Source commit: `ec989ec8b9238b417a1a6e94b00fd9cfcb633713`.
- Source tree: `a05e24f2400d1ec31e3b86a6ae7fdddedc849446`.
- Source archive SHA-256: `d5ff3052f8a5f874385b2ef5d6cb7ca88eae93cb501668af7073803ddcf784cb` (6,082,560 bytes). Its bytes match `git archive` of the commit.
- Saved VM, driver and wrapper exit records: `0`.
- Demo JSON: `PASS`, qualification `synthetic_only`; SHA-256 `5da9dd819777450986da429a10160bbc7dd2d4a68f7cbf1ecae15d42d8a97f8e`.
- Setup dependency profile: 39/39 match; installed application profile: 41/41 match.
- Fake-provider source SHA-256: `dafc644d55ccba71cc9d180c0fe4e07c7c6b64098463aaa950bd5f4af56c466a`.

| Scenario | Recorded outcome | Dispatch / ACK write / provider receipt / provider effect | Repeated delivery |
| --- | --- | --- | --- |
| Confirmed | `REMOTE_CONFIRMED`, local human ACK, queued then confirmed projection notes | 1 / 1 / 1 / 1 | Refused: `effect_not_queued`; no extra effect |
| Response lost after possible transmission | `UNCERTAIN`, retained guard, local human ACK, queued then uncertainty projection notes | 1 / 1 / 1 / 1 | Refused: `effect_not_queued`; no resend |

The driver uses real PostgreSQL and Alerta's in-process HTTP test client, restricted
runtime roles, and a loopback fake ONE provider. It does not exercise a deployed
HTTP service or live ONE. The wrapper builds each wheel from its sdist, installs
the wheels without dependency resolution and runs the demo with isolated Python.

## Retained trial distributions

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `alerta_ack_core-0.1.0.dev0-py3-none-any.whl` | 10705 | `32abee3a9e49418301bc44d4a1df19e077f2fd6397bb5a961de571a680c5f497` |
| `voalack-0.1.0.dev0-py3-none-any.whl` | 179374 | `c7e3d640958a4c15b44cf32aa27eacd974e966693e321e23734c31c57e1c60b3` |
| `alerta_ack_core-0.1.0.dev0.tar.gz` | 11225 | `e9d6be35fe77112721402ddccbee25ac27b570bed9e0ef122b613fa3795d5b18` |
| `voalack-0.1.0.dev0.tar.gz` | 186944 | `06f2c4b31c92ad9f24c2e41556a597f8fb0d3222cf6ce330bd3f1a82dd2e0816` |

All four files were read and checked against the retained manifest. Version
`0.1.0.dev0` alone does not identify these bytes. This record does not publish the
artifacts or claim byte-reproducible builds, artifact signing, or a release.

## Remaining limits

The earlier trial at `cbb0e20bf34e038b53d0142b4b974acf9183a780` failed during
provisioning under the restrictive umask, before product execution. The successful
result belongs to the later exact source above. Provisioning still inherits the
caller's umask; explicitly setting the intended provisioning permissions remains
a separate robustness follow-up.

The exit records and the driver's local stop do not independently prove guest,
runner or shared-lane cleanup. Full cleanup acceptance remains unverified. No
full capture regression run, live-provider qualification, installed lifecycle,
Windows feed, failover containment or two-product installed acceptance is implied.
Existing audit findings remain separate work. A later documentation-only revision
can cite this historical result; it cannot relabel these artifacts as built from
that later revision.

Retain the original evidence privately. Do not publish the guest work directory,
synthetic signing key, anchor, credentials or raw logs with this summary.
