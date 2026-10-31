# Inputs

The two original inputs, as supplied by the owner on 2026-09-28. Do not edit them; verify
their hashes before use.

| File | SHA-256 | Bytes | Contents |
|---|---|---|---|
| `original/Alerta_Veeam_ONE_Ack_Lab_MVP_2026-09-26.zip` | `bcb91cb5a60dd2cfc9fb894c37081995b07c56712c089aa6dc2de4cd98e57ee0` | 37675 | ACK MVP 0.1.0: Alerta plugin, ONE client, tests, historical validation report, shipped wheel; inner `SHA256SUMS.txt` (12 files) |
| `original/VeeamONE_13.1_Alerta_9.1_Script_Integration_2026-09-24.zip` | `8b9610dd1698387a4473eb3ca09e323921c1756f0fb57b6640976256d340f9c0` | 25743 | PowerShell feed from Veeam ONE to Alerta, its independent review, example config; inner `SHA256SUMS.txt` (8 files). **Redacted**, see below |

Verify with `sha256sum` against the table, then each archive's inner `SHA256SUMS.txt`.

## Handling rules

- The MVP's `VALIDATION.md` and `test-results.xml` are historical claims. The reproduction
  done here is in [`../baseline/`](../baseline/).
- Never run the feed with its example configuration: it is labelled Production. Use a
  synthetic configuration with outbound delivery disabled.
- Windows PowerShell behaviour cannot be tested on Linux; it is `NOT_RUN` until a Windows
  run exists.

## Redaction (2026-10-01)

On the owner's direction, environment-specific details in the feed were replaced with
placeholders, in two steps:

1. The production Alerta hostname became `<your-alerta-fqdn>` (so
   `https://<your-alerta-fqdn>/api/alert`).
2. Internal IP addresses became placeholders such as `<site-A-app-node-ips>` and
   `<site-B-writer-vip>`; the database writer VIP's internal DNS name became
   `<db-writer-vip-name>`; site names became `site-A`, `site-B` and `site-C`; and the example
   instance name became `one-site-a`.

| | SHA-256 | Bytes |
|---|---|---|
| Feed ZIP as originally supplied | `9cc2ecdb8eacf49d339377cdbda61227f8127b4b409698bf0b5068d213fa957a` | 25732 |
| After step 1 | `077067b25960b951e9cc262073c1cea7051238fcd4f1adf58afff5685d533acc` | 25737 |
| After step 2 (pinned here) | `8b9610dd1698387a4473eb3ca09e323921c1756f0fb57b6640976256d340f9c0` | 25743 |

Changed members: `README.md`, `config.example.json` and the inner `SHA256SUMS.txt`,
regenerated for those two. The other six members are byte-identical, and member order,
timestamps and attributes are preserved. The MVP ZIP is unchanged.

## Zabalack reference

Reuse decisions refer to Zabalack (`steliosx/zab-al-ack`):

| Pin | Commit | Note |
|---|---|---|
| Product snapshot (selected) | `494768d8c41c230a124b7c748ebaec10e7d4b6ad`, tree `d47d4c0e1f30d1f6f6a885ae8d4f198dcd9749f5` | Recovered from the owner's hash-verified qualification bundles; not published on GitHub |
| `main` at preparation time | `a3317dc41890ef56411e7597b32c44c70b878416` | Ancestor of `494768d`; comparison only |

The core files considered for reuse (crypto, worker, reconciler, rpc, migration 008,
trigger) are byte-identical at both pins; `plugins.py` and some documents differ.

## Known gaps

- The lab guide and the architecture document cited by the original source register were
  not supplied.
- Zabalack requires Python 3.12; builds here pin 3.12 (`mise.toml`).
