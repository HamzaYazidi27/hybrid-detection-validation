# Detections

Microsoft Sentinel detection content, one YAML file per detection.

- File name: exactly `DET-<AD|ENTRA|HYB|AZ>-<nnn>.yml` or `DET-...-<nnn>-<lowercase-slug>.yml`.
- Contract: [`schemas/detection.schema.json`](../schemas/detection.schema.json).
- Validated in CI by [`tools/validate_content.py`](../tools/validate_content.py), including:
  - licensing against [`tools/data/licensing-matrix.yml`](../tools/data/licensing-matrix.yml)
    (declare `licensing_gates` for unresolved tables);
  - MITRE consistency against pinned ATT&CK 20.1.
- `status` is the authoring lifecycle (`draft`, `ready`, `deprecated`). **Maturity is derived
  from verdict evidence and is never declared here** ([ADR-0014](../docs/adr/0014-maturity-derived-from-evidence.md)).
- Incident creation (`rule.incident.create`) is explicit per rule. Incident validation is
  separate (`validation.incident.expected`) and never affects the alert verdict.

**Phase 0:** intentionally empty. Detections are authored in Phase 3. Schema examples live in
`tests/fixtures/valid/detections/`; they are not real or validated detections.
