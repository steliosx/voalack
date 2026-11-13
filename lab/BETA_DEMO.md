# Synthetic beta demonstration candidate

**Recorded native execution: PASS, synthetic_only, on 8 November 2026.**
The exact source was `ec989ec8b9238b417a1a6e94b00fd9cfcb633713`. See the
[trial evidence record](../docs/BETA_TRIAL_20261108.md) for source/artifact identities
and independently inspected results. This is historical trial evidence, not a new
run of a later documentation head. Complete guest-cleanup acceptance remains open.
The driver and wrapper do not provide a live adapter, a persistent service, or
installed-site acceptance.

`run_beta_demo.sh` is a guest payload, not a host launcher. Use the existing approved
disposable microVM lane, its fresh source checks, timing agreement and cleanup route.
Do not run it on a maintainer host or attach another runner. It provisions a new
synthetic database and refuses reused work/evidence directories. The environment
acknowledgment is an operator guard, not proof of virtualization or an access boundary.

Within that already approved fresh guest, supply the exact source at `/src` read-only
and an empty writable `/out` and `/work` parent. The invocation is:

```sh
VOALACK_DISPOSABLE_GUEST=1 SRC=/src OUT=/out/beta-demo WORK=/work/beta-demo \
  SOURCE_COMMIT='<reviewed-full-commit>' sh /src/lab/run_beta_demo.sh
```

`SOURCE_COMMIT` is recorded as a declaration; the enclosing source handoff must
independently bind the actual mounted bytes to the reviewed commit/tree. It is not
a replacement for the shared lane's source checks. Use a fresh guest after any
failure; do not attempt a protected-database restore or rerun the fixture on a
deployed installation.

The wrapper uses the existing qualified lab profile, builds both wheel/sdist pairs
in a separate build environment, installs the resulting wheels without resolving
additional dependencies, verifies the final application profile, and invokes the
demo with isolated Python. `profiles/beta-demo-final.txt` preserves every third-party
entry from the existing qualified final profile and changes only the two local
project source-directory references to their exact installed wheel versions. The
original profile remains unchanged for its existing source-install runner.
The wrapper records distribution SHA-256 sums, build output,
dependency freezes, import version identities, demo JSON and an explicit exit code.
Build dependency resolution and version constraints are not byte-reproducibility
claims. Retain and review the actual artifact hashes and enclosing source evidence.

The finite demonstration uses real PostgreSQL and Alerta's in-process HTTP test
client, with the existing loopback fake ONE server. It creates synthetic human
access, exact lifetime-bound bindings, full protected schema, accepted signing and
verifier versions, and the external recovery anchor. Restricted verifier, sender
and projector roles perform their respective actions; the lab-only administrator
is confined to bootstrap/enrollment and independent state observations.

Two scenarios must pass:

1. A human ACK commits one intent/capture, verifies, sends one fake ACK and records
   `REMOTE_CONFIRMED`. Repeating delivery must refuse without another effect.
   Projection must produce the queued and confirmed notes, leave delivery and
   intent count unchanged, and then become idle.
2. A separate fake instance applies the ACK but loses its response. The ledger must
   remain `UNCERTAIN` with its target guard. Repeating delivery must not resend.
   Projection must report the actual recorded state without altering delivery.

The JSON includes independent dispatch/transport/provider receipt/effect counters
and synthetic operator notes. It excludes credentials, tokens, signing keys,
configuration and raw driver exceptions. The private work directory includes a
synthetic signing key and recovery anchor: do not publish it with the evidence.
The driver locally stops each owner, closes its connection and stops the fake
server. It does not clear holds, assert provider containment, or prove guest/lane
cleanup; the existing launcher must record cleanup separately.

Acceptance requires both a zero wrapper exit and JSON `PASS`, reviewed exact
source/artifact/profile bindings, and verified guest cleanup. This is two finite
synthetic scenarios, not the full capture regression suite, real HTTP deployment
of Alerta, live ONE behavior, multi-node failover or two-product qualification.
