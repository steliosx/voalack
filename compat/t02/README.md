# T02: Zabalack v1 compatibility with ack-core

Proof that Zabalack can consume the exact core artifact without any change in behaviour.
Requirement: a separate compatibility checkout, never merged into Zabalack's `main`
automatically, with deployed Zabalack unchanged.

## What was done

1. Built the core wheel from `packages/ack-core`
   (`alerta_ack_core-0.1.0.dev0-py3-none-any.whl`; run 3 clean build SHA-256
   `7cbabb0acf705ad62a4e51e47675f8b2145b9e1bb156e629cc4017bb37a25e2e`).
2. In a separate, local-only checkout of Zabalack at
   `494768d8c41c230a124b7c748ebaec10e7d4b6ad`, changed only `src/zabalack/crypto.py`
   (26 changed lines; diff SHA-256 `e5f03898b23cc81c7188eea0b2b96f50778a6f6d31b7099fb33a8f1994b53696`, kept with the project, not published):
   - `canonical_bytes` keeps Zabalack's `validate_intent`, then takes the encoding and the
     v1 domain from `ZABALACK_V1.signing_bytes`; core `oversized`/`encoding` errors map to
     Zabalack's `intent_oversized`/`intent_encoding`.
   - `sign_intent` keeps Zabalack's key-ID and key checks and its validation, then uses the
     core MAC.
   - `verify_capture` keeps its marker, binding and key checks, then uses the core's
     constant-time verification under the v1 profile, whose verification key rule is v1's
     own (at least 32 bytes, no upper bound).
3. Ran Zabalack's `tests/unit`, `tests/security` and `tests/property` in a disposable VM
   twice, against the original code and against the patched code with the core wheel
   (`run_compat.sh`), with Zabalack's pinned extras plus `hypothesis==6.168.0` from its lock.
4. Compared both JUnit results case by case (`compare_junit.py`, random UUIDs in test IDs
   normalised) and ran `differential.py`: original and patched crypto side by side.

`run_compat.sh` exits non-zero if the original suites, the patched suites, the comparison or
the differential fails. Test-only switches prove each path (`COMPAT_FAULT=orig|new|differential`;
staging is never modified):

| Run | Original suites | Patched suites | Comparison | Differential | VM exit |
|---|---|---|---|---|---|
| clean | 0 | 0 | 0 | 0 | 0 |
| failing test added to the original copy | 1 | 0 | 1 | 0 | 1 |
| failing test added to the patched copy | 0 | 1 | 1 | 0 | 1 |
| patched signer made to disagree | 0 | 0 | 0 | 1 | 1 |

(`RUNS.txt`.)

## Results

| Check | Original 494768d | Patched + core |
|---|---|---|
| Zabalack unit/security/property tests | 299 passed, 1 skipped | 299 passed, 1 skipped |
| Same test cases, same results | — | yes (one test ID contains a random UUID; identical once normalised) |
| Crypto, binding and proof-redaction cases | 70 pass | 70 pass |
| Differential, 500 random intents | — | identical intents, canonical bytes and markers; cross-verification passes; tampered MACs rejected by both with `mac_invalid` |
| Error parity (signing) | — | identical exception type and reason for oversized and non-encodable intents, bad versions, bad key IDs, 31- and 129-byte signing keys |
| Verification-key parity | — | identical for 32, 128, 129, 200 and 1024-byte keys (valid proofs accepted, tampered rejected as `mac_invalid`), and for 31-byte, missing and non-byte keys (`verification_key_unavailable`) |

The skip is Zabalack's own (`test_deployment_collectors.py`: Node unavailable). The patched
`zabalack` and `alerta_ack_core` were both imported from site-packages, not source.
Full logs and JUnit files are kept with the project.

## Scope

The run-2 core treated verification keys over 128 bytes as unavailable, unlike v1; review
finding R2. The v1 profile now keeps v1's verification key rule, and the differential checks it.
Signing keys stay 32..128 bytes for both profiles, and v2 verification keys stay bounded.
Not covered: PostgreSQL-backed, real Alerta and real Zabbix suites.
