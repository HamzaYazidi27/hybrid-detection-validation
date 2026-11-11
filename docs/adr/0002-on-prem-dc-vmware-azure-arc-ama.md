# ADR-0002: On-premises DC01 on VMware; telemetry through Azure Monitor Agent

- **Status:** Accepted (refined by [ADR-0011](0011-tier0-arc-isolation-wef-fallback.md))
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

The project must demonstrate *hybrid* detection: identity attacks that start on-premises and
continue into Entra ID. The owner already runs an AD DS laboratory on VMware. Azure Monitor
Agent (AMA) is Microsoft's supported collection agent. For machines outside Azure it is
delivered as an extension of an **Azure Arc-enabled server**. Arc does not support Azure VMs,
so Arc is relevant only because the DC runs outside Azure. Microsoft states there is no cost
to use AMA itself ([AMA overview](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)).

## Decision

- DC01 runs on the existing VMware lab. No Azure VM is created for the domain controller.
- Telemetry is collected by **AMA** and defined by **Data Collection Rules** managed with Terraform.
- **How AMA reaches DC01's events depends on the Tier 0 subscription decision ([ADR-0011](0011-tier0-arc-isolation-wef-fallback.md)):**
  - with a dedicated Tier 0 subscription: DC01 and SYNC01 are Arc-connected (locked down) and run AMA directly;
  - otherwise (the **default**): DC01 and SYNC01 are **not** Arc-connected and forward events via
    WEF to the collector WEC01, which runs Arc and AMA.
- Existing lab configuration is reused; nothing is assumed. IPs, names and OS versions are
  discovered and recorded locally ([lab-requirements.md](../lab-requirements.md)).
- The lab network is isolated by a host-only network and a firewall VM ([ADR-0012](0012-lab-network-isolation.md)).

## Alternatives considered

| Option | Pros | Cons | Why not chosen |
|---|---|---|---|
| DC as Azure VM + AMA (no Arc) | Simpler | Not hybrid; compute cost | Owner decision |
| Legacy Log Analytics agent (MMA) | Familiar | Retired by Microsoft | Unsupported |

## Consequences

- An Arc-enabled DC makes the Azure control plane part of Tier 0. This is the reason for
  ADR-0011's conditions and lockdown.
- The lab depends on outbound HTTPS through FW01. Outages produce INCONCLUSIVE verdicts, not
  false FAILs ([ADR-0008](0008-three-layer-verdict-model.md)).
- Telemetry latency from on-premises must be measured, not assumed.
