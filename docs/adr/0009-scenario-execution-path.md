# ADR-0009: Scenario execution path into the on-premises lab

- **Status:** **Proposed**. The owner must decide before Phase 4.
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

DC01, SYNC01, WS01 and WEC01 run on an isolated host-only network behind FW01
([ADR-0012](0012-lab-network-isolation.md)). Nothing outside the lab can open a connection into
it, and lab VMs can only reach the internet over TCP 443. Entra ID and Azure scenarios can run
from anywhere with credentials. Windows scenarios, cleanup and sweeps need code running **inside**
the lab. Whatever runs that code holds the most dangerous credentials in the project: scenario
identities, Graph permissions and workspace read access. It is therefore the main attack path
towards Tier 0 after the Arc path closed by [ADR-0011](0011-tier0-arc-isolation-wef-fallback.md).

Azure Arc Run Command is **excluded**: it gives the caller SYSTEM on the target, is blocked on
Tier 0 by the lockdown allowlist, and would put CI identities into the Tier 0 scope.

## Options

| | **A. Dedicated management VM (MGMT), operator-run** | **B. Self-hosted GitHub Actions runner in the lab** | **C. Manual CLI from an existing lab machine** |
|---|---|---|---|
| What it is | A purpose-built, domain-joined Tier 1 VM that only hosts the CLI, its dependencies, SQLite results and the lab state. The owner logs in through the VMware console and runs the CLI | A runner service (on MGMT or a separate VM) that polls GitHub and executes workflow jobs inside the lab | The owner runs the CLI on whatever lab machine is convenient (for example WS01) |
| Network compatibility with FW01 | Full: needs only outbound 443 (GitHub clone, PyPI, Graph, Log Analytics) | Full: the runner only makes **outbound** HTTPS connections to GitHub; no inbound port | Full |
| Who can cause code to run in the lab | Only the operator at the console | **Anyone who can get a workflow job onto the runner.** On a public repository, pull requests from forks are the classic risk; GitHub advises against self-hosted runners on public repositories | Only the operator |
| Credential exposure | Credentials sit on one hardened VM, used interactively | Credentials must be available to unattended jobs, so they persist on the runner host or are delivered per job; runner registration is a new secret | Credentials end up on a general-purpose machine that is also a **scenario target** |
| Telemetry pollution | None on targets: tooling runs on MGMT | None if the runner is not a target | **High:** the CLI's own Graph calls, KQL queries and Python processes appear in the target's logs, confusing L1 evidence and negative (`no_alert`) tests |
| Blast radius if compromised | Lab credentials and results; no Tier 0 rights | Same as A, **plus** remote code execution driven from GitHub | Same as A, plus a scenario target |
| Automation / regression | Manual runs. Local scheduling (Task Scheduler) is possible later without new exposure | Fully unattended, scheduled regression with GitHub-native history | Manual only |
| Repository visibility constraint | None | Effectively requires a **private** repository, or strict environment rules with required reviewers and no fork PRs reaching the runner | None |
| Lab resources | One extra VM (about 2 vCPU / 4 GB) | One extra VM (or MGMT), plus runner maintenance and updates | None extra |
| Auditability | Lab-state history + run records; console access | Plus GitHub workflow logs (must not contain lab data if the repository is public) | Weakest: runs mixed with target activity |
| Demonstration value | Clear separation of duties; easy to explain | Strongest "continuous" story | Weakest |
| Fit with the MVP | **Good** | Post-MVP only | Bootstrap only |

## Recommendation

1. **MVP: Option A.** A dedicated MGMT VM, operated through the VMware console. It satisfies the
   isolation design without new trust relationships and keeps credentials off scenario targets.
2. **Bootstrap only: Option C**, until MGMT exists, and only for static checks or read-only
   queries, never for scenario execution against the same host.
3. **Post-MVP, optional: Option B**, only if all of these hold: private repository (or no fork
   PRs can reach the runner); an ephemeral or just-in-time runner on its own VM, not on a
   scenario target; jobs gated by a protected GitHub environment with required reviewers;
   runner host never Tier 0; workflow logs sanitised.

Each MVP decision path is compatible with the host-only network without a host adapter: see
[lab-network.md §5](../lab-network.md#5-operating-the-isolated-lab-manageability).

## Information needed from the owner

- Will the repository be public or private? (Decides whether Option B is ever viable.)
- Can the host spare resources for a dedicated MGMT VM (about 2 vCPU / 4 GB)?
