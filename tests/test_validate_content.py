"""Tests for tools/validate_content.py.

Strategy: tests/fixtures/valid is a consistent corpus that must produce zero findings. Each
negative test copies that corpus, applies ONE mutation and asserts that the expected finding is
reported for that file. Cases tagged P1-P10 reproduce the defects found in the Phase 0 review.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Callable

import pytest
import validate_content as vc
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
VALID = REPO_ROOT / "tests" / "fixtures" / "valid"

Mutation = Callable[[dict[str, Any]], None]

AD_DET = "detections/DET-AD-001.yml"
ENTRA_DET = "detections/DET-ENTRA-001.yml"
AD_SCN = "scenarios/SCN-AD-001.yml"
ENTRA_SCN = "scenarios/SCN-ENTRA-001.yml"


def _corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    shutil.copytree(VALID, root)
    return root


def _run(root: Path) -> list:
    return vc.validate(
        vc.discover(root / "detections"), vc.discover(root / "scenarios"),
        content_roots=(root / "detections", root / "scenarios"),
    )


def _mutate(root: Path, relative: str, mutation: Mutation) -> Path:
    path = root / relative
    data = vc.load_yaml(path)
    mutation(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def _messages_for(findings: list, path: Path) -> list[str]:
    return [f.message for f in findings if f.path.resolve() == path.resolve()]


def _set(path: list, value: Any) -> Mutation:
    def apply(data: dict[str, Any]) -> None:
        node = data
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return apply


def _delete(path: list) -> Mutation:
    def apply(data: dict[str, Any]) -> None:
        node = data
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]

    return apply


def _chain(*mutations: Mutation) -> Mutation:
    def apply(data: dict[str, Any]) -> None:
        for mutation in mutations:
            mutation(data)

    return apply


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #
def test_schemas_are_valid_draft_2020_12() -> None:
    assert set(vc.load_validators(vc.SCHEMA_DIR)) == {"detection", "scenario"}


def test_valid_fixture_corpus_has_no_findings(tmp_path: Path) -> None:
    findings = _run(_corpus(tmp_path))
    assert findings == [], "\n".join(f.render(tmp_path) for f in findings)


def test_empty_content_directories_are_valid(tmp_path: Path) -> None:
    (tmp_path / "detections").mkdir()
    (tmp_path / "scenarios").mkdir()
    assert _run(tmp_path) == []


def test_repository_content_is_valid() -> None:
    """The real detections/ and scenarios/ directories (empty in Phase 0) must validate."""
    findings = vc.validate(vc.discover(REPO_ROOT / "detections"), vc.discover(REPO_ROOT / "scenarios"))
    assert findings == [], "\n".join(f.render(REPO_ROOT) for f in findings)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("PT5M", 300), ("PT1H", 3600), ("P1D", 86400), ("P1DT12H", 129600), ("PT1H30M", 5400),
     ("P", None), ("PT", None), ("5M", None), ("P1W", None)],
)
def test_parse_duration(value: str, expected: int | None) -> None:
    parsed = vc.parse_duration(value)
    assert (parsed.total_seconds() if parsed else None) == expected


def test_unquoted_dates_are_accepted(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    path = root / AD_DET
    path.write_text(path.read_text(encoding="utf-8").replace('"2026-11-11"', "2026-11-11"), encoding="utf-8")
    assert _run(root) == []


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    path = root / AD_DET
    path.write_text(path.read_text(encoding="utf-8") + "severity: High\n", encoding="utf-8")
    assert any("duplicate key" in m for m in _messages_for(_run(root), path))


# --------------------------------------------------------------------------- #
# One mutation -> one expected finding
# --------------------------------------------------------------------------- #
NEGATIVE_CASES = [
    # Detection structure
    pytest.param(AD_DET, _set(["id"], "DET-XX-001"), "does not match", id="det-bad-id-pattern"),
    pytest.param(AD_DET, _delete(["mitre"]), "'mitre' is a required property", id="det-missing-mitre"),
    pytest.param(AD_DET, _set(["mitre", "tactics"], ["Hacking"]), "is not one of", id="det-unknown-tactic"),
    pytest.param(AD_DET, _set(["mitre", "techniques", 0, "id"], "T155"), "does not match", id="det-bad-technique-id"),
    pytest.param(AD_DET, _set(["owner"], "someone"), "Additional properties are not allowed", id="det-unknown-property"),
    pytest.param(AD_DET, _set(["severity"], "Critical"), "is not one of", id="det-bad-severity"),
    pytest.param(AD_DET, _set(["rule", "sentinel_rule_id"], "not-a-guid"), "does not match", id="det-bad-rule-guid"),
    pytest.param(AD_DET, _set(["modified"], "2026-01-01"), "earlier than", id="det-modified-before-created"),
    pytest.param(AD_DET, _set(["created"], "2026-13-40"), "is not a 'date'", id="det-invalid-date"),
    pytest.param(AD_DET, _set(["tuning", "false_positives"], []), "non-empty", id="det-empty-false-positives"),
    pytest.param(AD_DET, _set(["references"], ["http://example.com"]), "does not match", id="det-non-https-reference"),
    # Detection rule timing
    pytest.param(AD_DET, _set(["rule", "query_frequency"], "PT1M"), "between PT5M and P14D", id="det-frequency-too-low"),
    pytest.param(AD_DET, _set(["rule", "query_period"], "P15D"), "between PT5M and P14D", id="det-period-too-high"),
    pytest.param(
        AD_DET, _chain(_set(["rule", "query_frequency"], "PT1H"), _set(["rule", "query_period"], "PT30M")),
        "shorter than", id="det-period-shorter-than-frequency",
    ),
    pytest.param(AD_DET, _set(["rule", "query_frequency"], "5 minutes"), "does not match", id="det-non-iso-duration"),
    pytest.param(AD_DET, _delete(["rule", "trigger"]), "'trigger' is a required property", id="det-scheduled-without-trigger"),
    pytest.param(ENTRA_DET, _set(["rule", "query_frequency"], "PT5M"), "should not be valid under", id="det-nrt-with-frequency"),
    pytest.param(AD_DET, _set(["rule", "query"], "SecurityEvent\n| where " + "x" * 10_100), "Sentinel limit", id="det-query-too-long"),
    pytest.param(AD_DET, _set(["validation", "timeout"], "PT0S"), "validation.timeout must be between", id="P4-timeout-zero"),
    pytest.param(AD_DET, _set(["validation", "timeout"], "P2D"), "validation.timeout must be between", id="det-timeout-too-long"),
    pytest.param(
        AD_DET, _set(["rule", "suppression"], {"enabled": True, "duration": "P30D"}),
        "rule.suppression.duration must be between", id="P4-suppression-too-long",
    ),
    pytest.param(
        AD_DET, _set(["rule", "incident", "grouping", "lookback"], "P8D"),
        "grouping.lookback must be between", id="P4-grouping-lookback-too-long",
    ),
    # Status / maturity (P10)
    pytest.param(AD_DET, _set(["status"], "stable"), "is not one of", id="P10-maturity-cannot-be-declared"),
    pytest.param(AD_DET, _set(["status"], "testing"), "is not one of", id="P10-testing-cannot-be-declared"),
    pytest.param(
        AD_DET, _chain(_set(["status"], "ready"), _set(["validation", "scenarios"], [])),
        "requires at least one", id="det-ready-without-scenarios",
    ),
    # Correlation (P6)
    pytest.param(
        AD_DET, _set(["validation", "correlation"], {"strategy": "time_window_only"}),
        "'justification' is a required property", id="P6-time-window-only-without-justification",
    ),
    pytest.param(
        AD_DET, _set(["validation", "correlation"], {"strategy": "run_marker", "marker_columns": ["ServiceName"]}),
        "impossible", id="det-run-marker-but-scenario-has-none",
    ),
    pytest.param(
        AD_DET, _set(["validation", "correlation"], {"strategy": "run_marker"}),
        "'marker_columns' is a required property", id="det-run-marker-without-columns",
    ),
    # Incident expectations (separate from alert validation)
    pytest.param(
        ENTRA_DET, _set(["validation", "incident"], {"expected": True}),
        "rule.incident.create is not true", id="det-incident-expected-without-creation",
    ),
    # Licensing (P7)
    pytest.param(
        AD_DET, _set(["data_sources"], [{"table": "SigninLogs", "collection": "entra_diagnostic_settings"}]),
        "licence mismatch: table SigninLogs", id="P7-signin-logs-without-p1",
    ),
    pytest.param(
        AD_DET, _set(["prerequisites", "licensing"], ["none", "entra_id_p2"]),
        "cannot be combined", id="det-licensing-none-plus",
    ),
    pytest.param(
        ENTRA_DET, _delete(["prerequisites", "licensing_gates"]),
        "licensing gate LIC-001 must be listed", id="det-unresolved-table-without-gate",
    ),
    pytest.param(
        AD_DET, _set(["prerequisites", "licensing_gates"], ["LIC-001"]),
        "gate not required", id="det-unused-gate",
    ),
    pytest.param(
        ENTRA_DET, _set(["prerequisites", "licensing_gates"], ["LIC-001", "LIC-999"]),
        "unknown gate", id="det-unknown-gate",
    ),
    pytest.param(
        AD_DET, _set(["data_sources"], [{"table": "MadeUpTable", "collection": "ama_windows_event_log"}]),
        "not in the licensing matrix", id="det-table-not-in-matrix",
    ),
    # MITRE (P8)
    pytest.param(AD_DET, _set(["mitre", "tactics"], ["Impact"]), "none of them is in mitre.tactics", id="P8-technique-tactic-mismatch"),
    pytest.param(
        AD_DET, _set(["mitre", "tactics"], ["CredentialAccess", "Impact"]),
        "MITRE tactic Impact is not a tactic of any declared technique", id="P8-extra-tactic",
    ),
    pytest.param(
        AD_DET, _set(["mitre", "techniques"], [{"id": "T9999", "name": "Nonexistent"}]),
        "does not exist in ATT&CK", id="det-unknown-technique",
    ),
    pytest.param(
        AD_DET, _set(["mitre", "techniques"], [{"id": "T1562.008", "name": "Impair Defenses: Disable or Modify Cloud Logs"}]),
        "is revoked in ATT&CK 20.1; use T1685.002", id="det-revoked-technique",
    ),
    pytest.param(
        AD_DET, _set(["mitre", "techniques", 0, "name"], "Kerberoast attack"),
        "name mismatch", id="det-technique-name-mismatch",
    ),
    # References
    pytest.param(AD_DET, _set(["validation", "scenarios"], ["SCN-AD-999"]), "unknown scenario", id="det-unknown-scenario-ref"),
    pytest.param(
        AD_DET, _set(["validation", "scenarios"], ["SCN-AD-001", "SCN-ENTRA-001"]),
        "does not list this detection", id="det-non-bidirectional-reference",
    ),
    pytest.param(
        AD_SCN, _set(["expected_detections"], [{"detection_id": "DET-ENTRA-001", "expected_outcome": "alert"}]),
        "no ATT&CK technique in common", id="scn-technique-overlap",
    ),
    # Scenario structure and safety
    pytest.param(AD_SCN, _set(["id"], "SCN-AD-1"), "does not match", id="scn-bad-id-pattern"),
    pytest.param(AD_SCN, _set(["status"], "active"), "is not one of", id="scn-maturity-cannot-be-declared"),
    pytest.param(AD_SCN, _set(["safety", "destructive"], True), "True was expected", id="scn-destructive-without-approval"),
    pytest.param(AD_SCN, _set(["safety", "impact"], "high"), "True was expected", id="scn-high-impact-without-approval"),
    pytest.param(AD_SCN, _set(["safety", "reversible"], False), "True was expected", id="scn-irreversible-without-approval"),
    pytest.param(AD_SCN, _set(["safety", "allowed_environments"], ["production"]), "'lab' was expected", id="scn-non-lab-environment"),
    pytest.param(AD_SCN, _set(["cleanup"], {"required": False}), "'justification' is a required property", id="scn-no-cleanup-without-justification"),
    pytest.param(AD_SCN, _delete(["cleanup", "executor"]), "'executor' is a required property", id="scn-cleanup-without-executor"),
    pytest.param(AD_SCN, _delete(["cleanup", "sweep"]), "'sweep' is a required property", id="scn-cleanup-without-sweep"),
    pytest.param(ENTRA_SCN, _set(["run_marker", "template"], "HDV-static-value"), "does not match", id="scn-marker-without-run-id"),
    pytest.param(ENTRA_SCN, _set(["run_marker", "template"], "X-{run_id}"), "does not match", id="scn-marker-without-prefix"),
    pytest.param(ENTRA_SCN, _delete(["run_marker", "template"]), "'template' is a required property", id="scn-marker-without-template"),
    pytest.param(
        AD_SCN, _set(["executor", "script"], "scenarios/scripts/../../etc/evil.ps1"),
        "path traversal", id="scn-script-path-traversal",
    ),
    pytest.param(
        AD_SCN, _set(["executor", "arguments"], ["-Name", "x; whoami"]),
        "shell metacharacter", id="scn-shell-metacharacter",
    ),
    pytest.param(
        AD_SCN, _set(["executor"], {"type": "invoke_atomic", "timeout": "PT5M", "elevation_required": False, "atomic": {"technique": "T1558.003"}}),
        "is not valid under any of the given schemas", id="scn-atomic-without-guid-and-commit",
    ),
    pytest.param(
        AD_SCN,
        _set(["expected_detections"], [{"detection_id": "DET-AD-001", "expected_outcome": "alert"}, {"detection_id": "DET-AD-777", "expected_outcome": "alert"}]),
        "unknown detection", id="scn-unknown-detection-ref",
    ),
    pytest.param(
        AD_SCN,
        _set(["expected_detections"], [{"detection_id": "DET-AD-001", "expected_outcome": "alert"} for _ in range(2)]),
        "more than once", id="scn-duplicate-expected-detection",
    ),
    pytest.param(
        AD_SCN, _set(["mitre", "techniques"], [{"id": "T1110.003", "name": "Brute Force: Password Spraying"}]),
        "rate_limit", id="scn-brute-force-without-rate-limit",
    ),
    pytest.param(AD_SCN, _set(["target", "component"], "DC02"), "is not one of", id="scn-unknown-component"),
    pytest.param(AD_SCN, _set(["target", "execution_host"], "LAPTOP"), "is not valid under any of the given schemas", id="scn-unknown-execution-host"),
    pytest.param(AD_SCN, _set(["inputs"], {"SPN-Account": {"description": "bad name", "type": "string"}}), "does not match", id="scn-bad-input-name"),
    # Secrets (P3)
    pytest.param(
        AD_SCN, _set(["inputs", "spn_account", "sensitive"], True),
        None, id="scn-sensitive-without-default-is-fine",
    ),
    pytest.param(
        AD_SCN, _chain(_set(["inputs", "spn_account", "sensitive"], True), _set(["inputs", "spn_account", "default"], "Summer2026!")),
        "should not be valid under", id="P3-sensitive-input-with-default",
    ),
    # Placeholders (P5)
    pytest.param(
        AD_SCN, _set(["executor", "arguments"], ["-ServiceAccount", "{spn_account}", "-Target", "{undeclared_input}"]),
        "undeclared placeholder '{undeclared_input}'", id="P5-undeclared-placeholder",
    ),
    pytest.param(
        AD_SCN, _set(["executor", "arguments"], ["-ServiceAccount", "{spn_account}", "-Marker", "{run_marker}"]),
        "run_marker.placement is none", id="scn-run-marker-placeholder-without-marker",
    ),
    pytest.param(
        AD_SCN, _set(["inputs", "unused_input"], {"description": "never referenced", "type": "string"}),
        "never used", id="scn-unused-input",
    ),
    pytest.param(
        AD_SCN, _set(["inputs", "run_id"], {"description": "spoofed run id", "type": "string"}),
        "should not be valid under", id="scn-reserved-input-name",
    ),
]


@pytest.mark.parametrize(("relative", "mutation", "expected"), NEGATIVE_CASES)
def test_negative_cases(tmp_path: Path, relative: str, mutation: Mutation, expected: str | None) -> None:
    root = _corpus(tmp_path)
    path = _mutate(root, relative, mutation)
    messages = _messages_for(_run(root), path)
    if expected is None:
        assert messages == []
    else:
        assert any(expected in m for m in messages), f"expected '{expected}' in findings for {relative}, got: {messages}"


# --------------------------------------------------------------------------- #
# Corpus-level cases
# --------------------------------------------------------------------------- #
def test_P1_file_name_must_match_id_exactly(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    wrong = root / "detections" / "DET-AD-0010.yml"
    (root / AD_DET).rename(wrong)
    assert any("file name must be" in m for m in _messages_for(_run(root), wrong))


@pytest.mark.parametrize("name", ["DET-AD-001.yml", "DET-AD-001-kerberoasting.yml", "DET-AD-001-rc4-tgs.yml"])
def test_P1_accepted_file_names(tmp_path: Path, name: str) -> None:
    root = _corpus(tmp_path)
    target = root / "detections" / name
    if target.name != "DET-AD-001.yml":
        (root / AD_DET).rename(target)
    assert not any("file name" in m for m in _messages_for(_run(root), target))


@pytest.mark.parametrize("name", ["kerberoasting.yml", "DET-AD-001_old.yml", "DET-AD-001-Kerberoasting.yml", "DET-AD-0011.yml"])
def test_P1_rejected_file_names(tmp_path: Path, name: str) -> None:
    root = _corpus(tmp_path)
    target = root / "detections" / name
    (root / AD_DET).rename(target)
    assert any("file name must be" in m for m in _messages_for(_run(root), target))


def test_P2_bidirectional_scenario_to_detection(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    _mutate(root, AD_DET, _set(["validation", "scenarios"], []))
    messages = _messages_for(_run(root), root / AD_SCN)
    assert any("does not list this scenario" in m for m in messages), messages


def test_duplicate_detection_id(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    copy = root / "detections" / "DET-AD-001-copy.yml"
    shutil.copy(root / AD_DET, copy)
    _mutate(root, "detections/DET-AD-001-copy.yml", _set(["rule", "sentinel_rule_id"], "036982b6-aee6-4d1f-ada7-7358876dfb99"))
    assert any("duplicate id 'DET-AD-001'" in f.message for f in _run(root))


def test_duplicate_sentinel_rule_id(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    rule_id = vc.load_yaml(root / AD_DET)["rule"]["sentinel_rule_id"]
    path = _mutate(root, ENTRA_DET, _set(["rule", "sentinel_rule_id"], rule_id))
    assert any("duplicate rule.sentinel_rule_id" in m for m in _messages_for(_run(root), path))


# --------------------------------------------------------------------------- #
# Output (P9)
# --------------------------------------------------------------------------- #
def test_P9_annotation_escaping() -> None:
    finding = vc.Finding(REPO_ROOT / "detections" / "a,b:c.yml", "line one\nline two 100% sure\r")
    line = vc.format_finding(finding, github_actions=True)
    assert "\n" not in line and "\r" not in line
    assert line == "::error file=detections/a%2Cb%3Ac.yml::line one%0Aline two 100%25 sure%0D"


def test_P9_yaml_errors_are_single_line(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    (root / AD_DET).write_text("id: [unclosed\n", encoding="utf-8")
    messages = _messages_for(_run(root), root / AD_DET)
    assert messages and all("\n" not in m for m in messages)


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _corpus(tmp_path)
    args = ["--detections", str(root / "detections"), "--scenarios", str(root / "scenarios")]
    ok = vc.main(args)
    _mutate(root, AD_DET, _set(["severity"], "Critical"))
    bad = vc.main(args)
    missing = vc.main([*args, "--attack-data", str(tmp_path / "missing.json")])
    assert (ok, bad, missing) == (0, 1, 2)
    assert "finding(s)" in capsys.readouterr().out
