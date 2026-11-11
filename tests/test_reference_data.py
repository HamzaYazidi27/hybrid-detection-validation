"""Integrity of the pinned reference data and its consistency with the documentation."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import validate_content as vc
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK = json.loads((REPO_ROOT / "tools" / "data" / "attack-enterprise.json").read_text(encoding="utf-8"))
LICENSING_DOC = (REPO_ROOT / "docs" / "cost-and-licensing.md").read_text(encoding="utf-8")


def test_attack_data_provenance() -> None:
    assert ATTACK["source"] == "https://github.com/mitre-attack/attack-stix-data"
    assert re.fullmatch(r"[0-9a-f]{40}", ATTACK["source_commit"])
    assert ATTACK["attack_version"] == "20.1"
    assert len(ATTACK["techniques"]) > 600


@pytest.mark.parametrize(
    ("technique", "tactic"),
    [("T1003.006", "CredentialAccess"), ("T1558.003", "CredentialAccess"), ("T1098.001", "Persistence"),
     ("T1098.003", "PrivilegeEscalation"), ("T1110.003", "CredentialAccess"), ("T1078.004", "InitialAccess"),
     ("T1685.002", "DefenseEvasion")],
)
def test_mvp_techniques_are_current(technique: str, tactic: str) -> None:
    entry = ATTACK["techniques"][technique]
    assert not entry["revoked"] and not entry["deprecated"]
    assert tactic in entry["tactics"]


def test_attack_attribution_is_embedded_and_documented() -> None:
    assert ATTACK["copyright"].startswith("Copyright") and "The MITRE Corporation" in ATTACK["copyright"]
    assert "THIRD_PARTY_NOTICES.md" in ATTACK["license"]
    notices = (REPO_ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    assert f"version **{ATTACK['attack_version']}**" in notices
    assert ATTACK["source_commit"] in notices
    assert ATTACK["source_file"] in notices
    assert ATTACK["copyright"] in notices
    assert "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license" in notices
    assert "This work is reproduced and distributed with the permission of The MITRE Corporation." in notices


def test_revoked_technique_points_to_replacement() -> None:
    assert ATTACK["techniques"]["T1562.008"]["revoked"] is True
    assert ATTACK["techniques"]["T1562.008"]["revoked_by"] == "T1685.002"


def test_licensing_matrix_loads_and_is_consistent() -> None:
    ref = vc.load_reference_data()
    for table, entry in ref.tables.items():
        if entry["status"] != "documented":
            assert entry["gate"] in ref.gates, table
    assert ref.tables["SigninLogs"]["export_requires_any"] == ["entra_id_p1"]
    assert ref.tables["AuditLogs"]["status"] == "unresolved"


def test_every_licensing_gate_is_documented() -> None:
    gates = yaml.safe_load((REPO_ROOT / "tools" / "data" / "licensing-matrix.yml").read_text(encoding="utf-8"))["gates"]
    for gate in gates:
        assert gate in LICENSING_DOC, f"{gate} missing from docs/cost-and-licensing.md"


def test_invalid_licensing_matrix_is_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "matrix.yml"
    bad.write_text(
        "licences: [none]\ngates: {}\ntables:\n  AuditLogs: {status: unresolved, export_requires_any: [none]}\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="requires a gate"):
        vc.load_reference_data(licensing_path=bad)
