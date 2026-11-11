# PowerShell: Windows Server and AD DS configuration

Conventions:
- Windows PowerShell 5.1 compatible;
- idempotent;
- `-WhatIf` support wherever something changes;
- read-only by default;
- never overwrites existing GPOs or SACLs (creates or adds only);
- fails closed.

CI parses every script and runs behaviour tests with fakes when `pwsh` is available
(`tests/test_powershell.py`). **No script has been run in the lab.**

| Folder / script | Purpose | Status |
|---|---|---|
| [`arc-onboarding/Set-HdvArcAgentLockdown.ps1`](arc-onboarding/Set-HdvArcAgentLockdown.ps1) | Applies or verifies Microsoft's Tier 0 agent lockdown (incoming connections off, machine configuration off, allowlist = AMA) **before** `azcmagent connect`; refuses script-execution extensions | **Implemented**; tested against a fake `azcmagent` only |
| [`isolation/Test-HdvVmxNetworking.ps1`](isolation/Test-HdvVmxNetworking.ps1) | Host-side, read-only `.vmx` check: no bridged NICs, lab-only networks, FW01 NIC layout, no host adapter | **Implemented**; tested against synthetic `.vmx` files |
| [`isolation/Test-HdvLabIsolation.ps1`](isolation/Test-HdvLabIsolation.ps1) | Guest-side, read-only check: default route = FW01, lab DNS, RFC1918 targets time out, Microsoft endpoints reachable | **Implemented**; only fail-closed paths tested (no lab) |
| `discovery/` | Read-only inventory (D1–D16) | Planned (Phase 2) |
| `audit-policy/` | Dedicated GPO with Advanced Audit Policy + additive SACLs | Planned (Phase 2) |
| `wef/` | WEF subscription to WEC01 | Planned (Phase 2) |
| `entra-connect/` | Prerequisite checks, connector account permissions | Planned (Phase 2) |
| `lab-objects/` | Lab OU, test users, SPN account | Planned (Phase 2) |
