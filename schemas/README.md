# Schemas

JSON Schema (Draft 2020-12) contracts for repository content
([ADR-0010](../docs/adr/0010-content-as-code-yaml-schemas.md)).

| Schema | Validates | Key guarantees |
|---|---|---|
| [`detection.schema.json`](detection.schema.json) | `detections/**/DET-*.yml` | Sentinel-compatible severity, tactics, entities; scheduled vs NRT parameters; authoring status only (no declared maturity); licensing and licensing gates; mandatory false-positive notes; correlation strategy, with a justification for `time_window_only`; explicit incident creation and a separate incident expectation; WEF collection path |
| [`scenario.schema.json`](scenario.schema.json) | `scenarios/**/SCN-*.yml` | Lab only; approval for risky scenarios; cleanup + sweep or justification; no defaults on sensitive inputs; reserved placeholder names; safe run-marker template (`HDV-` + `{run_id}`); shell-safe arguments; repository-confined script paths; pinned Atomic Red Team commit |

Rules JSON Schema cannot express are enforced by
[`tools/validate_content.py`](../tools/validate_content.py):
- exact file naming;
- duration ranges;
- query length;
- bidirectional references;
- placeholders vs inputs;
- licensing matrix;
- ATT&CK existence, revocation and tactics;
- shared techniques between scenario and detection;
- unique IDs;
- input hardening (size, encoding, anchors and aliases, tags, nesting, symlinks).

## Versioning

`schema_version` is `"1.0"`. Phase 0 is the first published version. After the first commit,
backward-compatible additions keep the version; breaking changes need a new version, a
migration note and an ADR.
