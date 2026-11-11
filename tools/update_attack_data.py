#!/usr/bin/env python3
"""Generate tools/data/attack-enterprise.json from an official MITRE ATT&CK STIX bundle.

The content validator needs an offline, pinned technique -> tactic mapping to check MITRE
consistency without network access in CI. This script is the only supported way to refresh
it, so the provenance of the data stays reproducible.

Usage (bundle from https://github.com/mitre-attack/attack-stix-data, enterprise-attack/):

    python tools/update_attack_data.py path/to/enterprise-attack-<version>.json \
        --source-commit <attack-stix-data git commit SHA>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "data" / "attack-enterprise.json"

# ATT&CK kill-chain phase name -> Microsoft Sentinel tactic name.
PHASE_TO_SENTINEL = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "ResourceDevelopment",
    "initial-access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "PrivilegeEscalation",
    "defense-evasion": "DefenseEvasion",
    "stealth": "DefenseEvasion",
    "defense-impairment": "DefenseEvasion",
    "credential-access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral-movement": "LateralMovement",
    "collection": "Collection",
    "command-and-control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}
TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def build(bundle: dict) -> dict:
    version = None
    released = None
    collection_markings: list[str] = []
    markings: dict[str, str] = {}
    techniques: dict[str, dict] = {}
    unknown_phases: set[str] = set()

    for obj in bundle.get("objects", []):
        if obj.get("type") == "marking-definition":
            statement = (obj.get("definition") or {}).get("statement")
            if statement:
                markings[obj["id"]] = statement
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            released = obj.get("modified")
            collection_markings = obj.get("object_marking_refs") or []
        if obj.get("type") != "attack-pattern":
            continue
        ext = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext or not TECHNIQUE_ID.match(ext.get("external_id", "")):
            continue
        tactics = set()
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            mapped = PHASE_TO_SENTINEL.get(phase["phase_name"])
            if mapped is None:
                unknown_phases.add(phase["phase_name"])
            else:
                tactics.add(mapped)
        techniques[ext["external_id"]] = {
            "name": obj["name"],
            "tactics": sorted(tactics),
            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "revoked": bool(obj.get("revoked", False)),
        }

    # Record the replacement of revoked techniques ("revoked-by" relationships).
    stix_to_id = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext and TECHNIQUE_ID.match(ext.get("external_id", "")):
                stix_to_id[obj["id"]] = ext["external_id"]
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "revoked-by":
            source, target = stix_to_id.get(obj.get("source_ref")), stix_to_id.get(obj.get("target_ref"))
            if source in techniques and target:
                techniques[source]["revoked_by"] = target

    if unknown_phases:
        raise SystemExit(f"unmapped ATT&CK phases (update PHASE_TO_SENTINEL): {sorted(unknown_phases)}")
    if not version or not techniques:
        raise SystemExit("bundle does not look like an ATT&CK Enterprise STIX bundle")
    copyright_statements = [markings[m] for m in collection_markings if m in markings]
    if not copyright_statements:
        raise SystemExit("bundle has no copyright marking on the collection; refusing to generate unattributed data")

    # Sub-technique display name "Parent: Child", as shown on attack.mitre.org.
    for tid, data in techniques.items():
        if "." in tid:
            parent = techniques.get(tid.split(".")[0])
            if parent:
                data["display_name"] = f"{parent['name']}: {data['name']}"
    return {
        "attack_version": version,
        "attack_released": released,
        "copyright": " ".join(copyright_statements),
        "license": "MITRE ATT&CK license; see THIRD_PARTY_NOTICES.md at the repository root",
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--source-commit", required=True, help="attack-stix-data commit SHA the bundle came from")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        print("--source-commit must be a 40-character git SHA", file=sys.stderr)
        return 2
    with args.bundle.open("r", encoding="utf-8") as handle:
        data = build(json.load(handle))
    data = {
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "source_commit": args.source_commit,
        "source_file": f"enterprise-attack/{args.bundle.name}",
        **data,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT} (ATT&CK {data['attack_version']}, {len(data['techniques'])} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
