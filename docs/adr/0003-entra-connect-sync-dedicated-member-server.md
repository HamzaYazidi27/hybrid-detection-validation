# ADR-0003: Microsoft Entra Connect Sync on a dedicated member server

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

Hybrid identity requires synchronising lab identities from AD DS to Entra ID. Microsoft offers
**Entra Connect Sync** (a full sync engine on a Windows Server) and **Entra Cloud Sync** (a
lightweight provisioning agent with cloud-managed configuration).

Microsoft's prerequisites page states (read 2026-11-11): *"Mandatory upgrade required: Upgrade
Microsoft Entra Connect Sync to version 2.6.84.0 or later and configure application-based
authentication by April 7, 2027. Legacy authentication is being retired, and synchronization
services will stop working after this date if these requirements aren't met."*
([source](https://learn.microsoft.com/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)).
The project runs through 2027, so this requirement applies from day one.

## Decision

- We use **Microsoft Entra Connect Sync, version ≥ 2.6.84.0**, installed on **SYNC01**, a
  dedicated domain-joined member server. It is never installed on DC01.
- **Application-based authentication is configured at installation**, not as a later migration.
  The default mode ("managed by Microsoft Entra Connect": the application and certificate are
  created and rotated automatically) is used unless a later ADR chooses BYOC/BYOA.
- **TPM protection is recommended:** Microsoft recommends a TPM for the certificate's private
  key ([source](https://learn.microsoft.com/entra/identity/hybrid/connect/authenticate-application-id)).
  SYNC01 gets a **virtual TPM** if the VMware platform supports it. Without a TPM, the key sits
  in the software key storage provider, marked non-exportable, and the residual risk is recorded.
- **Certificates and private keys are never stored in Git** (enforced by `.gitignore` patterns
  and gitleaks rules).
- SYNC01 is treated as **Tier 0**, as Microsoft requires.
- Installation is a documented, PowerShell-assisted runbook. Configuration is captured with
  the supported JSON export and kept **outside Git**.
- Entra **Cloud Sync** is documented as an alternative ([hybrid-identity.md](../hybrid-identity.md#7-alternative-microsoft-entra-cloud-sync-not-selected))
  and is **not** silently substituted.

## Alternatives considered

| Option | Why not chosen |
|---|---|
| Entra Cloud Sync | Owner decision: Connect Sync is still common in enterprises, and its attack surface (connector account with replication rights, Tier 0 sync server, application certificate) is what SOC teams must defend |
| Connect Sync on DC01 | Supported but discouraged; mixes Tier 0 roles; breaks detection tuning |
| Legacy `Sync_*` account authentication | Being retired by April 7, 2027 |

## Consequences

- The AD DS connector account has *Replicating Directory Changes (All)* when Password Hash Sync
  is enabled. The DCSync design allow-lists it **by SID and only from SYNC01's IP addresses**
  ([dcsync-detection-design.md](../dcsync-detection-design.md)).
- The Entra-side identity is an **application / service principal**. Its sign-ins appear in
  service principal sign-in logs, whose export licensing on Free tenants is **unresolved**
  (gate LIC-003).
- The Connect certificate (90-day default lifetime, rotated automatically) complicates snapshot
  restores of SYNC01 ([safety.md](../safety.md#4-snapshot-restoration-risks)).

## Open questions

- Does the VMware platform in use support vTPM for SYNC01? (Owner to confirm.)
- Enable Password Hash Sync (recommended for realistic scenarios)? Confirm in Phase 2.
