# ADR-0005: MVP stack — Python CLI, SQLite, Markdown/HTML reports

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

The value of the project is the correctness of the validation loop (execute → observe →
verdict), not a web interface. Every extra service adds deployment, authentication and
maintenance cost before the core is proven.

## Decision

- Orchestration is a **Python CLI** (Python ≥ 3.12).
- Results persist in **SQLite** behind a small repository interface so a later move to
  PostgreSQL is a storage-adapter change, not a rewrite.
- Reports are **Markdown** (for PRs/GitHub) and **static HTML** (for demos), plus an
  ATT&CK Navigator layer JSON for coverage.
- CI is **GitHub Actions**.
- **Out of the MVP:** FastAPI, PostgreSQL, React or any hosted UI.

## Implementation status

Phase 0 implements only the offline, safety-critical engine parts under `validator/hdv/`:
lab state, sweeper and maturity derivation (ADR-0013/0014). The CLI, executors, evaluation,
SQLite persistence and reports are **planned** (Phase 4).

## Consequences

- Positive: zero hosting cost; runs on a laptop or CI runner; easy to demo.
- Negative: no multi-user access or live dashboard in the MVP.
- SQLite files may contain tenant IDs, UPNs and hostnames: they are git-ignored and never
  uploaded as public CI artefacts.
