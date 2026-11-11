# Scenarios

Controlled adversary-emulation scenarios, one YAML file per scenario, plus executor, cleanup
and sweep scripts under `scenarios/scripts/`.

- File name: exactly `SCN-<AD|ENTRA|HYB|AZ>-<nnn>.yml` or `SCN-...-<nnn>-<lowercase-slug>.yml`.
- Contract: [`schemas/scenario.schema.json`](../schemas/scenario.schema.json).
- Safety invariants enforced by the schema and validator:
  - lab only;
  - approval for high-impact, destructive or irreversible scenarios;
  - cleanup **plus an idempotent sweep**, or a written justification;
  - no defaults for sensitive inputs;
  - placeholders must reference declared inputs or `{run_id}` / `{run_marker}`;
  - no shell metacharacters in arguments;
  - scripts confined to `scenarios/scripts/`;
  - run markers start with `HDV-`;
  - rate limits for brute force;
  - pinned Atomic Red Team commit.
- A failed cleanup marks the lab **DIRTY** and blocks further runs until a verified sweep or a
  recorded manual recovery ([ADR-0013](../docs/adr/0013-lab-state-cleanup-sweeper.md)).
- **Read [docs/safety.md](../docs/safety.md) before writing or running a scenario.**

**Phase 0:** intentionally empty. Nothing has been executed. Scenarios are authored in Phase 4.
Schema examples live in `tests/fixtures/valid/scenarios/`; hostile examples in
`tests/fixtures/malicious/`.
