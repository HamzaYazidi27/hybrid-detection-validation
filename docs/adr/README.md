# Architecture Decision Records

Significant, hard-to-reverse decisions are recorded here so the reasoning survives
beyond the moment it was made. Format: lightweight [MADR](https://adr.github.io/madr/).

## Rules

- One decision per file: `NNNN-short-title.md`, numbered sequentially, never renumbered.
- Status lifecycle: `Proposed` → `Accepted` → (`Deprecated` | `Superseded by ADR-NNNN`).
- Accepted ADRs are immutable **once committed to the repository**. To change a decision, write
  a new ADR that supersedes it. (ADRs 0001–0010 were revised in place during the Phase 0 review,
  before the first commit.)
- A `Proposed` ADR blocks any implementation that depends on it.
- Unverified claims about vendor behaviour must be marked **(verify)** and listed under
  *Open questions* until confirmed against current documentation or observed in the lab.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted |
| [0002](0002-on-prem-dc-vmware-azure-arc-ama.md) | On-premises DC01 on VMware; telemetry through AMA | Accepted (refined by 0011) |
| [0003](0003-entra-connect-sync-dedicated-member-server.md) | Entra Connect Sync ≥ 2.6.84.0 with application-based authentication on a dedicated member server | Accepted |
| [0004](0004-terraform-azure-powershell-windows.md) | Terraform for Azure, PowerShell for Windows Server and AD DS | Accepted |
| [0005](0005-mvp-stack-python-cli-sqlite.md) | MVP stack: Python CLI, SQLite, Markdown/HTML reports | Accepted |
| [0006](0006-portal-independent-validation-engine.md) | Portal-independent validation; incidents validated separately | Accepted |
| [0007](0007-licensing-and-cost-guardrails.md) | Licensing baseline, empirical licensing gates, cost guardrails | Accepted |
| [0008](0008-three-layer-verdict-model.md) | Three-layer verdict model with run-marker correlation | Accepted |
| [0009](0009-scenario-execution-path.md) | Scenario execution path into the on-premises lab | **Proposed** |
| [0010](0010-content-as-code-yaml-schemas.md) | Detections and scenarios as schema-validated YAML | Accepted |
| [0011](0011-tier0-arc-isolation-wef-fallback.md) | Tier 0 boundary for Azure Arc, with a WEF collector fallback | Accepted |
| [0012](0012-lab-network-isolation.md) | Host-only lab network with a dedicated firewall VM | Accepted |
| [0013](0013-lab-state-cleanup-sweeper.md) | Fail-closed lab state, mandatory cleanup and an idempotent sweeper | Accepted |
| [0014](0014-maturity-derived-from-evidence.md) | Detection maturity is derived from evidence, never declared | Accepted |

Template: [0000-template.md](0000-template.md)
