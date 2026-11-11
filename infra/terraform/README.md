# Terraform: Azure infrastructure

**Phase 1.** Empty in Phase 0 by design: no Terraform code exists, and nothing has been planned
or applied.

## Planned layout

| Root module | Subscription | Content | Who applies |
|---|---|---|---|
| `workload/` | Workload (lab) subscription | Resource groups, Log Analytics workspace, Sentinel, DCRs, Activity log and Entra diagnostic settings, Arc resource group for **WEC01**, budgets, tags, workspace-scoped CI role assignments | Owner, manually, after review |
| `tier0/` (optional) | **Dedicated Tier 0 subscription**, only if it exists ([ADR-0011](../../docs/adr/0011-tier0-arc-isolation-wef-fallback.md)) | Arc resource group for DC01/SYNC01, Activity log export, no policy assignments with remediation | Owner only. **No CI identity can plan or apply it** |

## Rules

- `terraform apply` is a manual action and runs only after explicit approval.
- State and `*.tfvars` are never committed (see `.gitignore`); the backend is decided in Phase 1.
- CI role assignments are scoped to the **workspace resource**, never to a resource group,
  subscription or Arc resource.
- CI will run `fmt`, `validate`, `tflint` and an IaC security scan, never `apply`.
