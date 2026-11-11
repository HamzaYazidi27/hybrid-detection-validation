# ADR-0010: Detections and scenarios as schema-validated YAML

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Detections need deployment parameters (KQL, schedule, entities), engineering metadata (MITRE,
data sources, licensing, false positives) and validation metadata (scenarios, correlation,
timeouts, incident expectation). Scenarios need execution and **safety** metadata. Kept in
different places, these drift apart.

## Decision

- One YAML file per detection (`detections/**/DET-*.yml`) and per scenario
  (`scenarios/**/SCN-*.yml`). The file name is exactly `<ID>.yml` or `<ID>-<lowercase-slug>.yml`.
- Contracts: [`schemas/detection.schema.json`](../../schemas/detection.schema.json) and
  [`schemas/scenario.schema.json`](../../schemas/scenario.schema.json) (JSON Schema 2020-12).
- Pinned reference data: [`tools/data/attack-enterprise.json`](../../tools/data/attack-enterprise.json)
  (MITRE ATT&CK Enterprise 20.1, generated from the official STIX bundle by
  `tools/update_attack_data.py`) and [`tools/data/licensing-matrix.yml`](../../tools/data/licensing-matrix.yml).
- Semantic rules are enforced by [`tools/validate_content.py`](../../tools/validate_content.py)
  on every pull request: exact file naming, durations, bidirectional references, placeholders
  vs. declared inputs, licensing and licensing gates, ATT&CK existence, revocation and
  tactic consistency, incident-expectation consistency.
- **Content is untrusted input.** The loader rejects symlinks, files over 256 KiB, invalid
  UTF-8, YAML anchors/aliases, custom tags, duplicate keys and excessive nesting (bounded before
  parsing). Malicious fixtures test each case.
- Safety invariants live in the schema itself:
  - lab only;
  - approval required for destructive, irreversible or high-impact scenarios;
  - cleanup plus sweep, or a written justification;
  - no defaults for sensitive inputs;
  - no shell metacharacters in arguments;
  - run markers restricted to `HDV-` plus safe characters;
  - pinned Atomic Red Team commit.
- **Maturity is never declared in YAML** ([ADR-0014](0014-maturity-derived-from-evidence.md)).
- Schema changes are versioned via `schema_version`.

## Consequences

- Sentinel rule definitions will be generated from YAML; the portal is never the source of truth.
- Real hostnames, IPs, tenant IDs and secrets never appear in content files; they come from an
  untracked local inventory and a secret store at run time.
- KQL syntax is not checked yet: there is no offline Log Analytics engine. Phase 3 adds
  `Kusto.Language` parsing; Phase 4 adds L2 execution against the workspace.
- ATT&CK v20 split Defense Evasion into *Stealth* and *Defense Impairment*. Sentinel's tactic
  list still uses `DefenseEvasion`, so the generator maps both to it. This mapping is an
  **unverified assumption** about Sentinel's current API, to be checked in Phase 3.
