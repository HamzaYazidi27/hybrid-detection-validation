# ADR-0006: Portal-independent validation engine (Defender portal transition)

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Microsoft states that after **31 March 2027** Microsoft Sentinel will no longer be supported in
the Azure portal and will be available only in the Microsoft Defender portal. The date was moved
from July 2026. Public reporting states that newly onboarded workspaces are already directed to
the Defender portal **(verify for our tenant at creation time)**.

From Microsoft Learn pages, seen only through search excerpts because learn.microsoft.com was
blocked in the build environment, so they still need direct confirmation:

- after onboarding to the Defender portal, Sentinel *incident creation rules* are not supported;
  incident creation happens in Defender;
- analytics-rule alert grouping settings are only advisory there; the Defender correlation
  engine may group alerts differently;
- alerts from analytics rules with incident creation **disabled** are not shown in the Defender
  portal, but they are still written to `SecurityAlert`.

## Decision

1. The engine never depends on any portal UI: no scraping, no UI automation.
2. **Alert validation (verdict layer L3) is independent of incident creation.** It is satisfied
   by the rule's alert in `SecurityAlert`, read through the Log Analytics query API (data plane).
3. **Incident creation is an explicit per-rule property** (`rule.incident.create`). It is not
   required for every detection.
4. **Incident validation is a separate check**, run only when `validation.incident.expected: true`.
   Its result (PASS/FAIL/INCONCLUSIVE/NOT_EXPECTED) is reported next to the verdict and never
   changes it. `expected: true` requires `rule.incident.create: true` (validator rule).
5. Alert and incident access sits behind an `AlertSource` interface (planned, Phase 4):
   - `LogAnalyticsAlertSource` (MVP, primary): KQL over `SecurityAlert` / `SecurityIncident`;
   - `SentinelArmIncidentSource` (MVP, optional): `Microsoft.SecurityInsights` REST API;
   - `GraphSecurityAlertSource` (post-MVP): Microsoft Graph security API (`alerts_v2`,
     `incidents`), the Defender-portal API surface. Coverage of custom Sentinel analytics alerts
     in this API is **unverified**.
6. Each verdict records which adapter produced the evidence.

## Consequences

- The engine survives the portal transition; behaviour changes are visible in history.
- Detections that intentionally skip incidents remain valid, but their alerts are not visible
  to analysts in the Defender portal. This is documented in the detection schema.
- `SecurityAlert` ingestion adds latency; timeouts include it.

## Open questions

- Confirm the three Defender-portal behaviours above on Microsoft Learn directly, and observe them
  in Phase 2.
- Graph permissions for the Graph adapter (least privilege), post-MVP.
