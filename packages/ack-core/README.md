# alerta-ack-core

Provider-neutral primitives for signed Alerta acknowledgement intents, shared by Zabalack
(Zabbix) and Voalack (Veeam ONE). Package name provisional.

| Module | Contents |
|---|---|
| `canonical` | Canonical JSON (sorted keys, compact, UTF-8, no NaN) and a strict loader that refuses duplicate keys, floats, NaN/Infinity, invalid UTF-8, lone surrogates and non-canonical spellings |
| `profiles` | Fixed signing profiles with domain-separated HMAC-SHA256: `ZABALACK_V1` (`zabalack\0v1\0`, byte-identical to Zabalack 494768d) and `INTENT_V2` (`alerta-ack-core\0intent\0v2\0`); constant-time verification; key ID and key-length checks |
| `validate` | Canonical UUIDs, bounded text, UTC timestamps |
| `outcomes` | `LOCAL_ACK`, `QUEUED`, `REMOTE_CONFIRMED`, `ALREADY_ACKED`, `BLOCKED`, `SUPERSEDED`, `UNCERTAIN` |

It has no runtime dependencies and imports no Alerta, database, HTTP or provider code. It
owns no database objects, threads or credentials. Provider-specific intent shapes, policy,
binding and delivery stay in each plugin.

Tests: `ci/run_core_tests.sh` builds the wheel and runs `tests/` against the installed wheel
in a disposable VM. Zabalack compatibility: [`../../compat/t02/README.md`](../../compat/t02/README.md).
