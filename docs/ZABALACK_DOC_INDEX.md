# Zabalack documentation index

Zabalack documents that the T01 design (reuse row R8) treats as reference contracts. Read at
the selected pin `494768d8c41c230a124b7c748ebaec10e7d4b6ad` and compared with `main` at
preparation time, `a3317dc41890ef56411e7597b32c44c70b878416`. Blob IDs are Git object IDs.
Contents are not copied here; Zabalack's gates and amendments stay Zabalack's.

| Document | Blob at `494768d` | At `a3317dc` | What it defines (section headings) |
|---|---|---|---|
| `docs/DESIGN.md` (722 lines) | `0d2697c184da48dee440b9a066ff803263f246ca` | same | Release-one design baseline: §3 inbound contract and tenant gate; §4 eligibility, actor authority and transition table; §5 acknowledgement capture (plugin stages, intent and proof, trigger predicate, lifetimes, failure policy, replay protection, capture-health gate, emergency bypass); §6 delivery worker (states, sequence, retry classification, limits, expiry/pause/leases); §8 result projection; §9 reconciliation; §12 security and data; §13 packaging and rollback; §14 acceptance catalogue; §15 deployment gates G1–G8 |
| `docs/WORKER_IMPLEMENTATION.md` (98 lines) | `95ebf7f13ca02a27749f095162a994140d8d46b8` | same | Worker, RPC and reconciliation implementation; explicit settlement of an unresolved remote attempt; evidence boundaries; monitoring export |
| `docs/final_review_notes.md` (10 lines) | `a046ed19eb3d0db040a0233c0986409ba757059f` | same | Final-review interpretations applied to design revision 1.2 |
| `docs/security_and_data.md` (58 lines) | `a9ec315dcd485f78eb015f564ac373df090686c8` | differs (`b109dd8a…`) | Cryptographic/effect boundary, privilege boundary, data inventory, deployment safety checklist. The `494768d` version adds the log-route analysis: which access logs can carry query strings and how to configure path-only formats |
| `docs/SPEC_AMENDMENTS.md` (820 lines) | `16c402ba8f157dfa675d7bd0507697c5faff8c51` | differs (`c5977281…`) | Source-backed amendments A1–A6 (below). The `494768d` version adds a candidate TLS remedy note under A2 and whole-name matching for restricted query keys under A5 |

## Zabalack amendments relevant to Voalack

| Amendment | Subject | Relevance |
|---|---|---|
| A1 | Reference Alerta logs provisional SQL and returns database error detail | Log/response privacy for the capture adapter |
| A2 | Reference Zabbix webhook transport does not authenticate TLS peers | Zabbix-specific; Voalack keeps TLS verification on (requirements §3.10) |
| A3 | Zabbix renders an absent cause event as `*UNKNOWN*` | Zabbix-specific |
| A4 | Zabbix role defaults do not revoke omitted action rules | Zabbix-specific |
| A5 | Reference Alerta commits staged plugin attributes and serves them to every reader | Directly relevant: why Voalack stages intents in a sidecar schema, not alert attributes (design, capture section) |
| A6 | Ambiguous Zabbix API errors preserve uncertainty and suspend writes | Pattern carried into Voalack's UNCERTAIN handling (requirements §3.6) |

## Zabalack deployment gates (DESIGN §15)

G1 version and configuration inventory · G2 live ingestion contract · G3 update-operation
inventory · G4 pilot cohort inventory · G5 tenant permission coverage · G6 implementation and
batch acceptance · G7 operational ownership · G8 records-policy mapping. These are Zabalack's;
Voalack will need its own equivalents before any live pilot.
