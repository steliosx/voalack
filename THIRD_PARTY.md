# Third-party software

Voalack is distributed as two Python packages (`packages/ack-core`, `packages/voalack`) whose only runtime
dependency is each other; they run inside an Alerta server that the operator installs separately.

## Derived source

`packages/ack-core` contains portions derived from Zabalack (Zab-al-ack contributors, Apache-2.0): canonical
encoding, domain-separated HMAC and field validators from `src/zabalack/crypto.py` at commit
`494768d8c41c230a124b7c748ebaec10e7d4b6ad` (blob `05203f738b4a4e649992409b81f5244f08f7acd1`). The attribution is
kept in `packages/ack-core/NOTICE`. No other third-party source code is included.

## Runtime environment (installed separately, not distributed here)

| Component | Version tested | License |
|---|---|---|
| Alerta server (`alerta-server`) | 9.1.0 | Apache-2.0 |
| PostgreSQL | 18.6 | PostgreSQL License |

## Test and lab environment (installed from PyPI; exact pins in `lab/profiles/`)

The lab installs Alerta 9.1.0 with its own dependencies, plus `pytest` (MIT) and `psycopg2-binary` (LGPL-3.0 with
exceptions). `lab/profiles/qualified-setup.txt` and `lab/profiles/qualified-final.txt` list every pinned
distribution; each keeps its own license.

## CI

GitHub Actions `actions/checkout` and `actions/upload-artifact` (MIT), pinned to full commit SHAs in
`.github/workflows/`.

## Original inputs

`inputs/original/` holds the project's two original inputs (an earlier ACK prototype and a Veeam ONE to Alerta
PowerShell feed). The maintainer reports them as their own work; they are published under this repository's Apache-2.0 license.
