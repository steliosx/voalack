# Security policy

## Status

Voalack is a beta-stage project. It is implemented and tested against a fake Veeam ONE provider only; live use is
not qualified (see README.md). No version is endorsed for production, and no response-time commitment exists yet.

## Reporting a vulnerability

Use **Security → Report a vulnerability** on this repository (private vulnerability reporting). If that option is
not available, open an issue asking only for a private contact, without any details.

Include the affected commit or version, a minimal synthetic reproduction, the expected and the actual behaviour, and
the impact. Never include live credentials, tokens, customer data, hostnames or addresses of real systems.

## Security boundaries

The most sensitive paths are: human authority and the capture gate; signed intents and their keys; the verifier and
the one-time dispatch permit; `SECURITY DEFINER` functions and grants; the DDL guard over protected objects; and
uncertain remote writes, which must never be retried automatically. See `docs/` and the package README.
