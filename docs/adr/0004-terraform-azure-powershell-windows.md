# ADR-0004: Terraform for Azure, PowerShell for Windows Server and AD DS

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Two configuration planes exist: Azure resources (workspace, Sentinel, DCRs, diagnostic
settings, RBAC) and the on-premises Windows estate (AD DS objects, audit policy, Arc
onboarding, Entra Connect prerequisites). Using two Azure IaC languages would split state and
review effort.

## Decision

- **Terraform** manages all Azure resources. `azurerm` is the primary provider; `azapi` is
  allowed for resources or properties not yet exposed by `azurerm` (this is still Terraform,
  not Bicep).
- **PowerShell** (Windows PowerShell 5.1 compatible unless a module requires 7.x) manages
  Windows Server and AD DS configuration. Scripts are idempotent and support `-WhatIf`.
- **Bicep is not used** unless a future ADR documents a requirement Terraform cannot meet.
- Sentinel analytics rules are generated from the YAML content model
  ([ADR-0010](0010-content-as-code-yaml-schemas.md)); the mechanism (Terraform resource vs.
  API call from the deployment tool) is decided in Phase 3, keeping YAML as the single source of truth.

## Alternatives considered

| Option | Why not chosen |
|---|---|
| Bicep | Azure-only; Terraform is more transferable and more frequently requested in job postings |
| Terraform + Bicep | Two state models and two review paths for one plane |
| PowerShell DSC for AD | Adds a framework with limited benefit at lab scale; may be revisited |

## Consequences

- Terraform state contains resource IDs and possibly sensitive values: state is never
  committed (`.gitignore`) and the backend choice (local vs. Azure Storage) is made in Phase 1.
- `terraform apply` is always a manual, reviewed action in this project. CI only runs
  `fmt`, `validate` and, later, `plan`.
- If a dedicated Tier 0 subscription exists ([ADR-0011](0011-tier0-arc-isolation-wef-fallback.md)),
  its resources live in a **separate Terraform root module** with its own state and provider
  configuration, applied only by the owner. No CI identity can plan or apply it.
- Windows-side scripts are idempotent, support `-WhatIf` where they change anything, and are
  checked in CI by AST parsing and behaviour tests with fakes. PSScriptAnalyzer is not yet in CI:
  no version could be pinned from the build environment.

## Open questions

- Remote state backend and its own cost/security trade-off — decide in Phase 1.
