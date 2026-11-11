# Safety and Rules of Engagement

> **Phase 0 statement:** no attack simulation has been executed, no Azure resource has been
> created, no credential has been issued and nothing has been installed in the lab.

These rules apply to every scenario, every run and every contributor, including AI assistants.

## 1. Authorised scope

| Target | Allowed | Identification |
|---|---|---|
| Lab Entra tenant | Yes | Tenant ID in the untracked local inventory |
| Lab Azure subscription(s) | Yes | Subscription IDs in the local inventory |
| VMware lab VMs on the isolated lab network | Yes | Hostnames + AD domain in the local inventory |
| University, employer, personal-productivity or any third-party tenant | **Never** | — |
| Host LAN, home or university network, any address outside the lab network | **Never** | Enforced by FW01 ([lab-network.md](lab-network.md)) |

Before any Entra or Azure scenario, read and comply with Microsoft's **Cloud Penetration
Testing Rules of Engagement**. Re-check the current text before Phase 4.

## 2. Hard guardrails (enforced in code)

| Guardrail | Enforcement | Status |
|---|---|---|
| Only the `lab` environment | Scenario schema | ✅ Implemented |
| Approval for destructive / irreversible / high-impact | Scenario schema | ✅ Implemented |
| Cleanup + idempotent sweep, or a written justification | Scenario schema | ✅ Implemented |
| No defaults for sensitive inputs (no secrets in YAML) | Scenario schema | ✅ Implemented |
| No shell metacharacters in arguments; scripts confined to `scenarios/scripts/` | Schema + validator | ✅ Implemented |
| Rate limit for brute force (T1110.*) | Validator | ✅ Implemented |
| Pinned Atomic Red Team commit | Scenario schema | ✅ Implemented |
| Secret scanning of history and working tree | CI (gitleaks) | ✅ Implemented (not yet run on GitHub) |
| Lab must be CLEAN before any scenario; failed cleanup → DIRTY | `validator/hdv/lab_state.py` | ✅ Core implemented; runner integration planned |
| Idempotent, verified sweep with dry run by default | `validator/hdv/sweeper.py` | ✅ Core implemented; real executors planned |
| Network isolation readiness (I1–I5) | `lab/powershell/isolation/` | ✅ Scripts implemented; run in lab planned |
| Tenant / domain match the local inventory (fail closed) | Runner pre-flight | ⏳ Phase 4 |
| Dry run by default, explicit `--execute` | Runner CLI | ⏳ Phase 4 |
| Kill switch (a `STOP` file aborts runs) | Runner | ⏳ Phase 4 |

## 3. Lab hygiene

1. **Isolation:** host-only lab network, FW01 the only egress, never bridged. Isolation checks
   must PASS before any campaign and after any network change ([ADR-0012](adr/0012-lab-network-isolation.md)).
2. **Dedicated objects:** scenarios act only on objects in a dedicated lab OU or on tagged lab
   applications, never on the owner's administrative accounts.
3. **Sync scope:** Entra Connect syncs only the lab OU(s), never privileged on-premises accounts.
4. **Antivirus:** never disable Defender on DC01, SYNC01 or WEC01. On WS01, use path-scoped
   exclusions declared in the scenario, removed in cleanup and verified by the sweep.
5. **Credentials:** test accounts use unique passwords. Certificates and private keys never
   leave their certificate store and are never committed.
6. **Lab state:** the lab starts `UNINITIALISED`. The owner initialises it with a written
   attestation (snapshots taken, isolation checks passed). Only a verified sweep or a recorded
   manual recovery returns it from `DIRTY` to `CLEAN` ([ADR-0013](adr/0013-lab-state-cleanup-sweeper.md)).

## 4. Snapshot restoration risks

VM snapshots are a recovery tool, not a cleanup tool. **Snapshots never revert Entra ID or Azure
changes**, so after any restore, run the cloud sweep before marking the lab CLEAN.

| Restored | Risk | Required action |
|---|---|---|
| DC01 (single-DC forest) | AD reverts: objects and passwords changed since the snapshot are lost; member machine passwords rotated since the snapshot break the secure channel; krbtgt state rolls back | Restore DC01 together with the member VMs from the **same** campaign snapshot set; repair secure channels (`Test-ComputerSecureChannel -Repair`) where needed |
| One DC in a multi-DC forest | **USN rollback**: replication silently breaks | Never restore a single DC alone. Restore all DCs from the same point, or use a supported AD restore procedure |
| DC01 without SYNC01 | Connect's import watermarks are ahead of AD, so changes can be missed | Run a full import and full synchronisation on SYNC01 before resuming |
| SYNC01 | Sync database older than AD/Entra; stale configuration could export old state; **the Connect application certificate may have been rotated since the snapshot** (90-day default lifetime) and no longer be valid for the application | After restore, keep SYNC01 in **staging mode** (no exports) until verified; re-establish the application credential with the Connect wizard if authentication fails **(verify procedure)**; full import + full sync |
| Any Arc-connected VM (WEC01; DC01/SYNC01 only with a Tier 0 subscription) | Agent identity state may be older than Azure expects **(verify)** | Check `azcmagent show`; reconnect following Microsoft's procedure if disconnected; re-run the lockdown verification |
| WEC01 | Forwarded events buffered after the snapshot are lost | Expect L1 gaps; mark affected runs INCONCLUSIVE |

## 5. Pre-run checklist (manual until Phase 4 automates it)

- [ ] Isolation checks I1–I5 PASS (results attached to the lab-state attestation).
- [ ] Correct tenant: Graph `organization` ID equals the lab tenant ID.
- [ ] Correct domain: `(Get-ADDomain).DNSRoot` equals the lab domain.
- [ ] Lab state is `CLEAN`.
- [ ] Snapshots taken within the last 24 hours.
- [ ] Scenario status is `reviewed`; `safety` block read; licensing gates closed.
- [ ] Budget not exceeded; workspace not at the daily cap.

## 6. If something goes wrong

1. **Stop:** create the kill-switch file or interrupt the CLI. The lab is marked DIRTY.
2. **Contain:** disable affected test accounts; revoke scenario identity credentials and sessions.
3. **Clean up:** run the sweeper (dry run first, then real). If uncertain, restore snapshots
   (see §4) **and** run the cloud sweep.
4. **Verify:** confirm no changes outside lab objects (AuditLogs, AD replication metadata, FW01 logs).
5. **Record:** a manual-recovery entry in the lab state with justification. If a rule was broken,
   add an ADR or a fix.

## 7. AI assistant boundaries

AI assistants working on this repository must not deploy Azure resources, run `terraform apply`,
create credentials, execute scenarios, install software in the lab or modify it, commit or push
without explicit per-action approval from the owner, and must not report results that were not
actually observed.
