# ADR-0012: Host-only lab network with a dedicated firewall VM

- **Status:** Accepted
- **Date:** 2026-11-11
- **Deciders:** Project owner

## Context

The Phase 0 review found that VMware NAT does not isolate guests from the host's LAN. The lab
runs adversary-emulation scenarios and must never reach the owner's home or university network.
It still needs HTTPS egress to Microsoft cloud endpoints (Arc, AMA, Entra Connect, Graph).

## Decision

- All lab VMs attach only to a **custom host-only VMware network** with no host virtual adapter
  and no VMware DHCP.
- A **dedicated firewall VM (FW01)** is the only path out: WAN on VMware NAT, LAN on the lab
  network. It drops all traffic to RFC1918, CGNAT and link-local ranges and allows TCP 443
  egress, plus explicitly named DNS/NTP for DC01. Everything else is denied and logged.
- **Bridged networking is never used.**
- **Isolation readiness checks I1–I5** must pass before any scenario (gate G-NET). They are
  implemented as read-only, fail-closed scripts where possible
  ([lab-network.md](../lab-network.md)).

## Alternatives considered

| Option | Why not chosen |
|---|---|
| VMware NAT only | Guests can reach the host LAN |
| Host firewall rules only | Hard to verify from inside the lab; differs per host OS; no logging of lab traffic |
| Fully offline lab | Arc, AMA, Entra Connect and Graph scenarios require cloud egress |

## Consequences

- One extra VM (FW01) and its configuration to maintain; its configuration export is kept out
  of Git (contains addresses).
- The guest check treats only a timeout as "blocked", so FW01 must **drop**, not reject.
- An FQDN allow-list is an optional hardening step, not an MVP requirement.
