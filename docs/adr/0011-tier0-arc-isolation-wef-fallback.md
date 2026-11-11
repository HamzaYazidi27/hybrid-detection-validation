# ADR-0011: Tier 0 boundary for Azure Arc, with a WEF collector fallback

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner
- **Refines:** [ADR-0002](0002-on-prem-dc-vmware-azure-arc-ama.md)

## Context

Microsoft's Azure Arc guidance for Tier 0 assets (domain controllers, CA servers) says to
*"treat any subscription or management group admin as equivalent to a local administrator on
Tier 0 assets"*, recommends a **dedicated Azure subscription** that is closely monitored with as
few persistent administrators as possible, and recommends local agent controls: disable
incoming connections, disable machine configuration and set an extension allowlist
([Arc security overview](https://learn.microsoft.com/azure/azure-arc/servers/security-overview),
[extension security](https://learn.microsoft.com/azure/azure-arc/servers/security-extensions)).
Microsoft also states that the Entra Connect server must be treated as Tier 0 / control plane
([Connect prerequisites](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)).

## Decision

1. **Arc for Tier 0 only inside a dedicated Tier 0 subscription.** DC01 and SYNC01 may be
   connected to Azure Arc only if a dedicated subscription exists that meets all of:
   - only the owner holds persistent privileged roles (PIM if available);
   - **no CI or automation identity has any role assignment** in it;
   - no Azure Policy assignment with `DeployIfNotExists` or `Modify` effects applies to it,
     directly or inherited from a management group;
   - its Activity log is exported to the project workspace.
2. **Lockdown before connect.** On every Arc machine (Tier 0 or not),
   [`Set-HdvArcAgentLockdown.ps1`](../../lab/powershell/arc-onboarding/Set-HdvArcAgentLockdown.ps1)
   is applied and verified **before** `azcmagent connect`: incoming connections disabled,
   machine configuration disabled, extension allowlist = Azure Monitor Agent only.
3. **Default when no dedicated subscription is available: do not connect DC01 or SYNC01 to
   Arc.** Use **Windows Event Forwarding (WEF)** instead:
   - DC01 and SYNC01 forward the required events (source-initiated subscription) to **WEC01**,
     a domain-joined member server that is **not** Tier 0;
   - WEC01 is Arc-connected (workload subscription), locked down, and runs AMA with the
     Windows Forwarded Events collection;
   - forwarded events land in the **`WindowsEvent`** table (Sentinel "Windows Forwarded Events"
     connector, `Azure/Azure-Sentinel` solution definition), not in `SecurityEvent`.
4. CI identities never receive roles in the Tier 0 subscription, under any option.

## Alternatives considered

| Option | Why not chosen |
|---|---|
| Arc for DC01 in the shared lab subscription | Contradicts Microsoft's Tier 0 guidance: every subscription admin and policy becomes a DC admin path |
| No telemetry from DC01 | Defeats the purpose of the project |
| Custom forwarder to the Logs Ingestion API | More code and secrets on a Tier 0 host; no benefit over WEF + AMA |

## Consequences

- **Two telemetry shapes:** direct AMA (`SecurityEvent`) or WEF (`WindowsEvent`). Detections
  must handle the chosen path; Phase 3 adds a normalising KQL function so rules stay
  path-independent. The detection schema records the path (`collection: ama_wef_forwarded_events`).
- **WEC01 sees Tier 0 security logs.** It cannot control DCs, but it can read or drop their
  events. It is hardened, monitored for forwarding gaps (verdict layer L1 / INCONCLUSIVE), and
  its compromise is in the threat model (TM-18).
- WEF requires a GPO on DCs (subscription manager) and read access to the Security log for the
  forwarding service. Exact steps **(verify)** in Phase 2.
- Arc onboarding of WEC01 and the lockdown script must be validated on a real agent. The
  `azcmagent config get --json` output shape is undocumented; the script fails closed.

## Open questions

- Does the owner have, or can they create, a dedicated Tier 0 subscription? (Blocks the choice
  between direct AMA and WEF.)
- WEF latency and `WindowsEvent` row size versus `SecurityEvent` **(measure in Phase 2)**.
