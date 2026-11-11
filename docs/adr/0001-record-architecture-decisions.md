# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

The project spans on-premises AD DS, Entra ID, Azure monitoring, detection engineering and
CI/CD. Many choices (where the DC runs, which sync engine, how alerts are read) are costly to
reverse and will be questioned by reviewers and recruiters. The reasoning must be traceable.

## Decision

We will record architecturally significant decisions as ADRs in `docs/adr/` using the
template in `0000-template.md`, and reference the governing ADR from code and docs.

## Consequences

- Positive: decisions are reviewable in pull requests; trade-offs are explicit.
- Negative: small documentation overhead per decision.
