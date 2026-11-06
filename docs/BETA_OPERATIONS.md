# Candidate installation and lifecycle notes

**Prepared for lab review; native demo NOT_RUN; no installed-site qualification.**
This runbook describes the finite [synthetic demonstration](../lab/BETA_DEMO.md)
and the shipped component boundaries. It is not a production installer or a
persistent worker service. The current transport accepts only the loopback fake
provider. Live write-back remains unavailable; the feed is unchanged.

## Obtain and identify a candidate

Use a reviewed source commit and tree, the exact source archive digest, and the
existing coordinated disposable-guest route. Record those identities before
mounting source at `/src` read-only. A branch name, version string or the wrapper's
`SOURCE_COMMIT` declaration does not identify the actual bytes on its own.

Both distributions currently declare version `0.1.0.dev0` and Python
`>=3.12,<3.13`: `alerta-ack-core` and `voalack`. Their versions alone cannot
distinguish candidate builds. The Voalack wheel depends on the core but does not
declare the complete Alerta/PostgreSQL environment. Use the exact
[setup profile](../lab/profiles/qualified-setup.txt) and
[demo final profile](../lab/profiles/beta-demo-final.txt); the wrapper refuses
profile differences. It records the PostgreSQL and Python versions actually used.

The guest wrapper builds each sdist, then its wheel from that sdist, in a separate
build environment. It installs the two wheels by exact version from its local
artifact directory with dependency resolution disabled. Retain all four artifacts
and `dist/SHA256SUMS`, and verify the sums before transferring or installing them.
Those hashes bind an observed build; they are not a reproducible-build claim.
There is no candidate distribution bundle until this route has actually run.

## Bootstrap order and ownership

The executable example is [demo_beta.py](../lab/demo_beta.py), with roles created
by [setup_guest.sh](../lab/setup_guest.sh). Both are disposable-lab inputs; their
synthetic administrator credentials and HTTP test client are not site settings.

| Boundary | Shipped lab arrangement |
| --- | --- |
| Database | `alerta_dbowner` owns the database; Alerta's runtime login owns its own tables, not the database or Voalack schema. |
| Capture | Alerta is a member of the no-login `voalack_app` role. `voalack_admin` owns the integration objects and is not a runtime login. |
| DDL protection | `voalack_guard_owner` is a no-login owner without members; the setup grants it `pg_read_all_stats` for the protector's coordinator checks. |
| Workers | Separate verifier, sender, settler and projector logins inherit only their respective no-login roles. Bootstrap administration is not a worker credential. |
| Recovery anchor | A supervisor writes the external anchor; worker APIs read it. Deployment must enforce that separation with filesystem ownership and permissions; Python API separation alone is not an OS access boundary. |

The fresh synthetic bootstrap performs these steps before submitting any ACK:

1. Provision the guest dependencies, database and separate roles. Install the exact
   wheels. The demo refuses an existing `voalack` schema or `public.alerts` table,
   a different database/user or a different database owner.
2. Construct the pinned Alerta application and its tables without exposing a
   listener or serving requests. Configure the Voalack factory with synthetic
   Basic authentication, a signing-key file and `PLUGINS = ['voalack']`.
3. Apply `voalack.schema.apply(conn)` using the installation administrator.
   It verifies packaged SQL expectation hashes, takes the early alerts-table lock
   and executes the complete ordered SQL transaction. `schema.sql` alone omits
   the protection and admission layers. An integrity or admission refusal stops
   setup; retain the error and investigate the exact source/catalog difference.
4. Bootstrap a new external recovery anchor with `recovery.bootstrap`, binding its
   genesis head to the database's recovery epoch. The anchor lives outside the
   database; its log and linked documents are durable authority state, not a
   disposable cache. Preserve them separately from database rollback. Bootstrap
   writes the anchor before initializing the database: a partial failure is not
   permission to delete the anchor or blindly bootstrap again. The hash chain
   detects malformed or spliced content but cannot detect replacement with an
   earlier valid prefix. Independent protection against anchor rollback remains
   a deployment requirement.
5. Create the synthetic human user and its customer authorization grant and active policy,
   accepted signing key ID and verifier version, and the `fake-one/v1` instance.
   Trusted signing configuration comes from service configuration/key files, not
   alert attributes. The observer remains disabled.
6. Create the synthetic alert and its immutable binding revision, including the
   current open alert lifetime, then call `voalack.enroll_binding`. Current binding
   pointers and generations are not manually assigned. Synthetic occurrence
   labels do not establish the real ONE occurrence contract.
7. Submit the authorized human ACK. Verification, sending and projection use their
   own restricted connections; the administrator is used only for setup and
   independent observations. Follow the two scenarios and witnesses in the
   [demo acceptance contract](../lab/BETA_DEMO.md).

For a real installed application, preserve the existing identity provider,
customer visibility and action chain. The lab's one-plugin chain is not a site
migration recommendation. The [capture setup notes](../packages/voalack/README.md#operator-setup-development-not-qualified-for-production)
describe required trusted configuration and callback/plugin constraints. Merely
adding a name to a reviewed-plugin list does not review its side effects.

## Refusal and uncertain outcomes

Startup/capture checks reject unsupported Alerta or authentication code, privileged
runtime roles and unreviewed action hooks. Worker readiness checks their role
paths, grants and required catalog objects; drift is refused, not repaired by
granting administrator privileges. Anchor read/validation failures close provider
authority. These checks do not establish whole-system attestation or site readiness.

A local ACK is separate from remote confirmation. After a possibly transmitted
request, retain `UNCERTAIN`, its attempt and guards; do not requeue or resend it.
Read-only reconciliation and settlement have their own evidence/containment
requirements. A missing or conflicting projection note does not authorize another
ACK, manual publication-marker edits or clearing an immutable projection stop.

## Stop, removal and rollback

For this demonstration, the driver stops its local owner, closes its connection
and stops the fake server. The enclosing approved launcher must independently
record guest/lane cleanup. Driver exit, a lease expiry or a locally stopped owner
does not prove containment of an already in-flight provider operation.

On failure, retain the exact source/artifact identities, exit status and sanitized
evidence for review. A subsequent demonstration uses a new disposable guest.
Deleting a guest is only disposal of that synthetic environment, not an uninstall
test or a supported rollback of an installed system.

The current coexistence-3a layout has **no supported restore**, and observer
downgrade is unsupported. There is no qualified installed-site removal/rollback
procedure in this candidate. `pip uninstall` cannot remove the database objects,
capture trigger, anchor, holds or publication state safely. Preserve those records;
do not use the historical pre-3a recovery sequence or destructive SQL as a reset.
Install/remove/rollback and installed two-product coexistence tests remain explicit
[first-candidate requirements](REQUIREMENTS.md#4-first-candidate).

## Evidence to retain and review

Keep the source commit/tree/archive identity; four distribution files and their
checksums; setup/final profile checks and dependency freezes; recorded interpreter
and PostgreSQL versions; wrapper exit status; demo JSON; and independent launcher
cleanup evidence. Inspect installed package locations and packaged SQL/JSON
resources as part of candidate review. A profile match is not an artifact hash.

Both wrapper exit `0` and demo JSON `PASS` are necessary, together with the exact
bindings and cleanup evidence. Neither has been observed for this prepared demo.
The existing hosted jobs do not run it. Do not publish the private work directory
(synthetic signing key and anchor) or raw logs without checking for sensitive data.
The [owner summary](BETA_OWNER_SUMMARY.md) separates prepared work, observed CI and
the native/site gates still open.
