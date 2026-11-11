# ADR-0009: Scenario execution path into the on-premises lab

- **Status:** **Proposed**. The owner must decide before Phase 4.
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

DC01, SYNC01, WS01 and WEC01 run on an isolated VMware network behind FW01
([ADR-0012](0012-lab-network-isolation.md)), so GitHub-hosted runners cannot reach them.
Entra ID and Azure scenarios can run from anywhere with credentials. Windows scenarios need a
path into the lab, and every such path is also an attack path towards Tier 0.

## Options

| Option | How | Pros | Cons / risks |
|---|---|---|---|
| **A. Operator-run CLI (recommended for MVP)** | The owner runs the CLI on a management host (MGMT) inside the lab. Windows scenarios run over WinRM inside the lab; Entra scenarios run over Graph. CI does static checks and, in Phase 5, evaluation-only jobs | No inbound path; no new privileged cloud path | Not fully unattended |
| B. Self-hosted GitHub runner in the lab | A runner VM inside the lab picks up jobs | Fully automated regression | On a **public** repository, pull requests from forks can be used to run code in the lab. Requires a private repo or strict environment restrictions; the runner becomes Tier 0-adjacent |
| C. Azure Arc Run Command | CI uses OIDC to invoke Run Command on Arc machines | No inbound path | Gives CI **SYSTEM on the target**. **Incompatible with ADR-0011** on DC01/SYNC01, because Run Command is blocked by the lockdown allowlist and CI must stay out of the Tier 0 scope. It also executes as SYSTEM, changing the telemetry |

## Recommendation

Adopt **A** for the MVP. Re-evaluate **B** (private repository, ephemeral runner, environment
approval) after the MVP. **C** is excluded for Tier 0 machines and discouraged elsewhere.

## Information needed from the owner

- Will the repository be public or private?
- Is there, or can there be, a management host inside the lab network?
