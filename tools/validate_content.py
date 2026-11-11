#!/usr/bin/env python3
"""Validate detection and scenario content against the project schemas and reference data.

Layers of checks:

1. Input hardening - size limit, UTF-8, no symbolic links, no YAML anchors/aliases,
                     no custom tags, no duplicate keys, bounded nesting depth.
2. Structural      - JSON Schema (Draft 2020-12) in ``schemas/``.
3. Semantic        - exact file naming, ISO 8601 duration ranges, query length, date
                     ordering, placeholders vs declared inputs, safety invariants.
4. Reference data  - licensing matrix (tools/data/licensing-matrix.yml) and pinned
                     MITRE ATT&CK data (tools/data/attack-enterprise.json).
5. Corpus          - unique IDs, bidirectional detection <-> scenario references,
                     correlation feasibility, shared ATT&CK techniques.

This tool performs NO network calls and does NOT check KQL syntax or that tables/columns
exist in a workspace. KQL parsing is planned for Phase 3 (see docs/roadmap.md).

Exit codes: 0 = all content valid, 1 = findings reported, 2 = usage/setup error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Iterable

import yaml
from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schemas"
DATA_DIR = Path(__file__).resolve().parent / "data"
ATTACK_DATA = DATA_DIR / "attack-enterprise.json"
LICENSING_MATRIX = DATA_DIR / "licensing-matrix.yml"

# Input hardening limits.
MAX_FILE_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 32

# Sentinel limits. Frequency/period/query length per Sentinel scheduled-rule documentation;
# suppression and grouping ranges reflect the analytics-rule UI options (verify in Phase 3).
MIN_FREQUENCY, MAX_FREQUENCY = timedelta(minutes=5), timedelta(days=14)
MIN_PERIOD, MAX_PERIOD = timedelta(minutes=5), timedelta(days=14)
MIN_SUPPRESSION, MAX_SUPPRESSION = timedelta(minutes=5), timedelta(hours=24)
MIN_GROUPING_LOOKBACK, MAX_GROUPING_LOOKBACK = timedelta(minutes=5), timedelta(days=7)
MIN_TIMEOUT, MAX_TIMEOUT = timedelta(minutes=5), timedelta(days=1)
MAX_QUERY_CHARS = 10_000

RESERVED_PLACEHOLDERS = {"run_id", "run_marker"}
PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
PLACEHOLDER_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
SHELL_METACHARACTERS = re.compile(r"[;&|`$<>\r\n]")
BRUTE_FORCE_TECHNIQUE = re.compile(r"^T1110(\.\d{3})?$")
DURATION_RE = re.compile(
    r"^P(?=\d|T\d)(?:(?P<days>\d+)D)?(?:T(?=\d)(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?$"
)
LICENCE_STATUSES = {"documented", "inferred", "unresolved"}


@dataclass(frozen=True)
class Finding:
    path: Path
    message: str

    def render(self, root: Path) -> str:
        return f"{_display_path(self.path, root)}: {self.message}"


@dataclass
class Document:
    kind: str  # "detection" | "scenario"
    path: Path
    data: dict[str, Any]


@dataclass(frozen=True)
class ReferenceData:
    attack_version: str
    techniques: dict[str, dict[str, Any]]
    licences: frozenset[str]
    implies: dict[str, frozenset[str]]
    tables: dict[str, dict[str, Any]]
    gates: dict[str, dict[str, Any]]


class ContentError(Exception):
    """Raised when a file must be rejected before structural validation."""


# --------------------------------------------------------------------------- #
# Hardened YAML loading
# --------------------------------------------------------------------------- #
class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that keeps dates as strings and rejects duplicate keys.

    PyYAML converts unquoted ``2026-11-11`` into ``datetime.date`` (which would fail
    ``type: string``) and silently keeps the last of duplicated keys.
    """


_StrictLoader.yaml_implicit_resolvers = {
    key: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def _construct_mapping_no_duplicates(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, f"found duplicate key {key!r}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_duplicates)


def _depth(value: Any, limit: int) -> int:
    """Iterative depth computation (no recursion, so hostile input cannot overflow the stack)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, level = stack.pop()
        deepest = max(deepest, level)
        if deepest > limit:
            return deepest
        if isinstance(node, dict):
            stack.extend((v, level + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, level + 1) for v in node)
    return deepest


def load_yaml(path: Path, root: Path | None = None) -> Any:
    """Load one content file defensively. Raises ContentError with a single-line reason.

    ``root`` is the content directory; symbolic links are rejected for the file itself and
    for every directory between the file and ``root``.
    """
    if path.is_symlink() or (root is not None and _symlink_below(path, root)):
        raise ContentError("symbolic links are not allowed in content directories")
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ContentError(f"file is {size} bytes; limit is {MAX_FILE_BYTES}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContentError(f"file is not valid UTF-8 ({exc.reason} at byte {exc.start})") from None
    _prescan_nesting(text, MAX_NESTING_DEPTH)
    try:
        for event in yaml.parse(text, Loader=_StrictLoader):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise ContentError("YAML anchors and aliases are not allowed")
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        raise ContentError("YAML parse error: " + " ".join(str(exc).split())) from None
    except RecursionError:
        raise ContentError(f"YAML nesting too deep (limit {MAX_NESTING_DEPTH})") from None
    if _depth(data, MAX_NESTING_DEPTH) > MAX_NESTING_DEPTH:
        raise ContentError(f"YAML nesting too deep (limit {MAX_NESTING_DEPTH})")
    return data


def _prescan_nesting(text: str, limit: int) -> None:
    """Cheap linear guard run BEFORE the YAML parser.

    PyYAML's scanner degrades super-linearly on deeply nested flow collections, so depth must
    be bounded before parsing. Tracks [ { ] } outside quoted scalars and comments, plus block
    indentation. Approximate by design: it can only reject, never accept, content.
    """
    depth = 0
    quote: str | None = None
    previous = "\n"
    in_comment = False
    for char in text:
        if in_comment:
            if char == "\n":
                in_comment = False
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'" and previous in " \t\n[{,:":
            quote = char
        elif char == "#" and previous in " \t\n":
            in_comment = True
        elif char in "[{":
            depth += 1
            if depth > limit:
                raise ContentError(f"YAML nesting too deep (limit {limit})")
        elif char in "]}":
            depth = max(0, depth - 1)
        previous = char
    for line in text.splitlines():
        stripped = line.lstrip(" ")
        if stripped and not stripped.startswith("#") and (len(line) - len(stripped)) > 4 * limit:
            raise ContentError(f"YAML nesting too deep (limit {limit})")


def _symlink_below(path: Path, root: Path) -> bool:
    """True if any directory between ``root`` (exclusive) and ``path`` is a symbolic link."""
    root_abs = root.absolute()
    current = path.absolute().parent
    while current != root_abs and root_abs in current.parents:
        if current.is_symlink():
            return True
        current = current.parent
    return False


def _root_for(path: Path, roots: Iterable[Path]) -> Path | None:
    absolute = path.absolute()
    for root in roots:
        if root.absolute() == absolute.parent or root.absolute() in absolute.parents:
            return root
    return None


# --------------------------------------------------------------------------- #
# Reference data
# --------------------------------------------------------------------------- #
def load_reference_data(attack_path: Path = ATTACK_DATA, licensing_path: Path = LICENSING_MATRIX) -> ReferenceData:
    with attack_path.open("r", encoding="utf-8") as handle:
        attack = json.load(handle)
    with licensing_path.open("r", encoding="utf-8") as handle:
        matrix = yaml.load(handle, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass

    licences = frozenset(matrix["licences"])
    gates = dict(matrix.get("gates") or {})
    tables = dict(matrix["tables"])
    problems = []
    for name, entry in tables.items():
        if entry.get("status") not in LICENCE_STATUSES:
            problems.append(f"table {name}: invalid status {entry.get('status')!r}")
        if not set(entry.get("export_requires_any") or []) <= licences or not entry.get("export_requires_any"):
            problems.append(f"table {name}: export_requires_any must be a non-empty subset of licences")
        if entry.get("status") != "documented" and entry.get("gate") not in gates:
            problems.append(f"table {name}: status {entry.get('status')} requires a gate defined under 'gates'")
    for gate_id in gates:
        if not re.fullmatch(r"LIC-\d{3}", gate_id):
            problems.append(f"gate {gate_id}: invalid id")
    if problems:
        raise ValueError("invalid licensing matrix: " + "; ".join(problems))

    implies = {k: frozenset(v) for k, v in (matrix.get("implies") or {}).items()}
    return ReferenceData(
        attack_version=str(attack["attack_version"]),
        techniques=attack["techniques"],
        licences=licences,
        implies=implies,
        tables=tables,
        gates=gates,
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_duration(value: str) -> timedelta | None:
    match = DURATION_RE.match(value or "")
    if not match:
        return None
    parts = {k: int(v) if v else 0 for k, v in match.groupdict().items()}
    return timedelta(**parts)


def load_validators(schema_dir: Path) -> dict[str, Draft202012Validator]:
    validators = {}
    for kind in ("detection", "scenario"):
        schema_path = schema_dir / f"{kind}.schema.json"
        with schema_path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
        Draft202012Validator.check_schema(schema)
        validators[kind] = Draft202012Validator(schema, format_checker=FormatChecker())
    return validators


def discover(directory: Path | None) -> list[Path]:
    if directory is None or not directory.is_dir():
        return []
    files = [p for p in directory.rglob("*") if p.suffix in {".yml", ".yaml"} and (p.is_file() or p.is_symlink())]
    # scenarios/scripts holds executor scripts, not content files.
    return sorted(p for p in files if "scripts" not in p.relative_to(directory).parts)


def _json_path(error_path: Iterable[Any]) -> str:
    parts = [f"[{p}]" if isinstance(p, int) else f".{p}" for p in error_path]
    return "$" + "".join(parts)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.absolute().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _check_range(path: Path, label: str, value: str | None, low: timedelta, high: timedelta, text: str) -> list[Finding]:
    if value is None:
        return []
    parsed = parse_duration(value)
    if parsed is not None and not (low <= parsed <= high):
        return [Finding(path, f"{label} must be between {text}")]
    return []


def _technique_ids(data: dict[str, Any]) -> list[str]:
    return [t.get("id", "") for t in (data.get("mitre") or {}).get("techniques", []) if isinstance(t, dict)]


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #
def check_structure(
    doc_path: Path, kind: str, validators: dict[str, Draft202012Validator], root: Path | None = None
) -> tuple[Document | None, list[Finding]]:
    try:
        data = load_yaml(doc_path, root)
    except ContentError as exc:
        return None, [Finding(doc_path, str(exc))]
    except OSError as exc:
        return None, [Finding(doc_path, f"cannot read file: {exc.strerror}")]
    if not isinstance(data, dict):
        return None, [Finding(doc_path, "top-level YAML value must be a mapping")]

    errors = sorted(validators[kind].iter_errors(data), key=lambda e: list(e.absolute_path))
    findings = [Finding(doc_path, f"schema: {_json_path(e.absolute_path)}: {e.message}") for e in errors]
    return Document(kind, doc_path, data), findings


def check_common(doc: Document) -> list[Finding]:
    findings: list[Finding] = []
    data = doc.data
    doc_id = data.get("id")
    if isinstance(doc_id, str) and not re.fullmatch(re.escape(doc_id) + r"(-[a-z0-9]+)*", doc.path.stem):
        findings.append(
            Finding(doc.path, f"file name must be '{doc_id}.yml' or '{doc_id}-<lowercase-slug>.yml' (got '{doc.path.name}')")
        )
    created, modified = data.get("created"), data.get("modified")
    try:
        if created and modified and date.fromisoformat(modified) < date.fromisoformat(created):
            findings.append(Finding(doc.path, "'modified' is earlier than 'created'"))
    except (TypeError, ValueError):
        pass  # format errors are already reported by the schema
    return findings


def check_mitre(doc: Document, ref: ReferenceData, declared_tactics: list[str] | None) -> list[Finding]:
    findings: list[Finding] = []
    technique_tactics: set[str] = set()
    for technique in (doc.data.get("mitre") or {}).get("techniques", []) or []:
        if not isinstance(technique, dict) or not isinstance(technique.get("id"), str):
            continue
        tid, name = technique["id"], technique.get("name")
        entry = ref.techniques.get(tid)
        if entry is None:
            findings.append(Finding(doc.path, f"MITRE technique {tid} does not exist in ATT&CK {ref.attack_version}"))
            continue
        if entry.get("revoked") or entry.get("deprecated"):
            state = "revoked" if entry.get("revoked") else "deprecated"
            hint = f"; use {entry['revoked_by']}" if entry.get("revoked_by") else ""
            findings.append(Finding(doc.path, f"MITRE technique {tid} is {state} in ATT&CK {ref.attack_version}{hint}"))
        accepted = {entry["name"], entry.get("display_name")}
        if name not in accepted:
            expected = entry.get("display_name") or entry["name"]
            findings.append(Finding(doc.path, f"MITRE technique {tid} name mismatch: expected '{expected}'"))
        own = set(entry.get("tactics", []))
        technique_tactics |= own
        if declared_tactics is not None and own and not own & set(declared_tactics):
            findings.append(
                Finding(doc.path, f"MITRE technique {tid} belongs to {sorted(own)}; none of them is in mitre.tactics")
            )
    if declared_tactics is not None and technique_tactics:
        for tactic in declared_tactics:
            if tactic not in technique_tactics:
                findings.append(
                    Finding(doc.path, f"MITRE tactic {tactic} is not a tactic of any declared technique (ATT&CK {ref.attack_version})")
                )
    return findings


def check_detection(doc: Document, ref: ReferenceData) -> list[Finding]:
    findings: list[Finding] = []
    path, data = doc.path, doc.data
    rule = data.get("rule") or {}
    query = rule.get("query") or ""

    if len(query) > MAX_QUERY_CHARS:
        findings.append(Finding(path, f"rule.query is {len(query)} characters; Sentinel limit is {MAX_QUERY_CHARS}"))

    if rule.get("kind") == "scheduled":
        findings += _check_range(path, "rule.query_frequency", rule.get("query_frequency"), MIN_FREQUENCY, MAX_FREQUENCY, "PT5M and P14D")
        findings += _check_range(path, "rule.query_period", rule.get("query_period"), MIN_PERIOD, MAX_PERIOD, "PT5M and P14D")
        freq, period = parse_duration(rule.get("query_frequency", "")), parse_duration(rule.get("query_period", ""))
        if freq is not None and period is not None and period < freq:
            findings.append(
                Finding(path, "rule.query_period is shorter than rule.query_frequency (events between runs would never be evaluated)")
            )
    suppression = rule.get("suppression") or {}
    findings += _check_range(path, "rule.suppression.duration", suppression.get("duration"), MIN_SUPPRESSION, MAX_SUPPRESSION, "PT5M and PT24H")
    grouping = (rule.get("incident") or {}).get("grouping") or {}
    findings += _check_range(path, "rule.incident.grouping.lookback", grouping.get("lookback"), MIN_GROUPING_LOOKBACK, MAX_GROUPING_LOOKBACK, "PT5M and P7D")

    validation = data.get("validation") or {}
    findings += _check_range(path, "validation.timeout", validation.get("timeout"), MIN_TIMEOUT, MAX_TIMEOUT, "PT5M and P1D")
    incident_expectation = validation.get("incident") or {}
    findings += _check_range(path, "validation.incident.timeout", incident_expectation.get("timeout"), MIN_TIMEOUT, MAX_TIMEOUT, "PT5M and P1D")
    if incident_expectation.get("expected") is True and (rule.get("incident") or {}).get("create") is not True:
        findings.append(Finding(path, "validation.incident.expected is true but rule.incident.create is not true"))

    if data.get("status") == "ready" and not validation.get("scenarios"):
        findings.append(Finding(path, "status 'ready' requires at least one entry in validation.scenarios"))

    findings += check_licensing(doc, ref)
    findings += check_mitre(doc, ref, (data.get("mitre") or {}).get("tactics") or [])
    return findings


def _satisfies(declared: set[str], required_any: list[str], ref: ReferenceData) -> bool:
    effective = set(declared)
    for licence in declared:
        effective |= ref.implies.get(licence, frozenset())
    return any(req in effective for req in required_any)


def check_licensing(doc: Document, ref: ReferenceData) -> list[Finding]:
    findings: list[Finding] = []
    prerequisites = doc.data.get("prerequisites") or {}
    declared = set(prerequisites.get("licensing") or [])
    declared_gates = set(prerequisites.get("licensing_gates") or [])
    if "none" in declared and len(declared) > 1:
        findings.append(Finding(doc.path, "prerequisites.licensing: 'none' cannot be combined with other licences"))

    needed_gates: set[str] = set()
    for source in doc.data.get("data_sources") or []:
        table = source.get("table") if isinstance(source, dict) else None
        if not isinstance(table, str):
            continue
        entry = ref.tables.get(table)
        if entry is None:
            findings.append(Finding(doc.path, f"table {table} is not in the licensing matrix (tools/data/licensing-matrix.yml); add it with a source"))
            continue
        if declared and not _satisfies(declared, entry["export_requires_any"], ref):
            findings.append(
                Finding(doc.path, f"licence mismatch: table {table} requires one of {entry['export_requires_any']} for export; declared {sorted(declared)}")
            )
        if entry["status"] != "documented":
            needed_gates.add(entry["gate"])

    for gate in sorted(needed_gates - declared_gates):
        findings.append(Finding(doc.path, f"licensing gate {gate} must be listed in prerequisites.licensing_gates ({ref.gates[gate]['question']})"))
    for gate in sorted(declared_gates - needed_gates):
        reason = "unknown gate" if gate not in ref.gates else "gate not required by any data source"
        findings.append(Finding(doc.path, f"prerequisites.licensing_gates lists {gate}: {reason}"))
    return findings


def _executors(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    cleanup = data.get("cleanup") or {}
    found = [("executor", data.get("executor")), ("cleanup.executor", cleanup.get("executor")),
             ("cleanup.sweep.executor", (cleanup.get("sweep") or {}).get("executor"))]
    return [(label, ex) for label, ex in found if isinstance(ex, dict)]


def check_scenario(doc: Document, ref: ReferenceData) -> list[Finding]:
    findings: list[Finding] = []
    path, data = doc.path, doc.data

    techniques = _technique_ids(data)
    safety = data.get("safety") or {}
    if any(BRUTE_FORCE_TECHNIQUE.match(t) for t in techniques) and "rate_limit" not in safety:
        findings.append(Finding(path, "brute-force scenarios (T1110.*) must declare safety.rate_limit"))

    outcomes = [d.get("detection_id") for d in data.get("expected_detections", []) if isinstance(d, dict)]
    duplicates = {d for d in outcomes if outcomes.count(d) > 1}
    if duplicates:
        findings.append(Finding(path, f"expected_detections lists the same detection more than once: {sorted(duplicates)}"))

    declared_inputs = set((data.get("inputs") or {}).keys())
    marker_placement = (data.get("run_marker") or {}).get("placement")
    used: set[str] = set()
    for label, executor in _executors(data):
        script = executor.get("script")
        if isinstance(script, str) and (
            ".." in Path(script).parts or script.startswith(("/", "\\")) or "\\" in script or ":" in script
        ):
            findings.append(Finding(path, f"{label}.script: path traversal or absolute path is not allowed ('{script}')"))
        for argument in executor.get("arguments") or []:
            if not isinstance(argument, str):
                continue
            if SHELL_METACHARACTERS.search(argument):
                findings.append(Finding(path, f"{label}.arguments: shell metacharacter or newline is not allowed"))
            for name in PLACEHOLDER.findall(argument):
                used.add(name)
                if not PLACEHOLDER_NAME.match(name):
                    findings.append(Finding(path, f"{label}.arguments: malformed placeholder '{{{name}}}'"))
                elif name not in declared_inputs | RESERVED_PLACEHOLDERS:
                    findings.append(Finding(path, f"{label}.arguments: undeclared placeholder '{{{name}}}' (declare it under inputs)"))
                elif name == "run_marker" and marker_placement == "none":
                    findings.append(Finding(path, f"{label}.arguments: '{{run_marker}}' used but run_marker.placement is none"))
    for name in sorted(declared_inputs - used):
        findings.append(Finding(path, f"inputs.{name} is declared but never used in any executor arguments"))

    for telemetry in data.get("expected_telemetry") or []:
        table = telemetry.get("table") if isinstance(telemetry, dict) else None
        if isinstance(table, str) and table not in ref.tables:
            findings.append(Finding(path, f"expected_telemetry table {table} is not in the licensing matrix"))

    findings += check_mitre(doc, ref, None)
    return findings


def _parents(techniques: Iterable[str]) -> set[str]:
    return {t.split(".")[0] for t in techniques}


def check_corpus(detections: list[Document], scenarios: list[Document]) -> list[Finding]:
    findings: list[Finding] = []

    for docs in (detections, scenarios):
        seen: dict[str, Path] = {}
        for doc in docs:
            doc_id = doc.data.get("id")
            if not isinstance(doc_id, str):
                continue
            if doc_id in seen:
                findings.append(Finding(doc.path, f"duplicate id '{doc_id}' (also defined in {seen[doc_id].name})"))
            else:
                seen[doc_id] = doc.path

    rule_ids: dict[str, Path] = {}
    for doc in detections:
        rule_id = (doc.data.get("rule") or {}).get("sentinel_rule_id")
        if isinstance(rule_id, str):
            if rule_id in rule_ids:
                findings.append(Finding(doc.path, f"duplicate rule.sentinel_rule_id (also used in {rule_ids[rule_id].name})"))
            else:
                rule_ids[rule_id] = doc.path

    detection_by_id = {d.data.get("id"): d for d in detections}
    scenario_by_id = {s.data.get("id"): s for s in scenarios}

    for doc in detections:
        validation = doc.data.get("validation") or {}
        strategy = (validation.get("correlation") or {}).get("strategy")
        for scenario_id in validation.get("scenarios", []) or []:
            scenario = scenario_by_id.get(scenario_id)
            if scenario is None:
                findings.append(Finding(doc.path, f"validation.scenarios references unknown scenario '{scenario_id}'"))
                continue
            expected = {d.get("detection_id") for d in scenario.data.get("expected_detections", []) if isinstance(d, dict)}
            if doc.data.get("id") not in expected:
                findings.append(
                    Finding(doc.path, f"scenario '{scenario_id}' does not list this detection in expected_detections (references must be bidirectional)")
                )
            placement = (scenario.data.get("run_marker") or {}).get("placement")
            if strategy == "run_marker" and placement == "none":
                findings.append(
                    Finding(doc.path, f"correlation strategy run_marker is impossible: scenario '{scenario_id}' has run_marker.placement none")
                )

    for doc in scenarios:
        for expected in doc.data.get("expected_detections", []) or []:
            if not isinstance(expected, dict):
                continue
            detection_id = expected.get("detection_id")
            detection = detection_by_id.get(detection_id)
            if detection is None:
                findings.append(Finding(doc.path, f"expected_detections references unknown detection '{detection_id}'"))
                continue
            listed = (detection.data.get("validation") or {}).get("scenarios") or []
            if doc.data.get("id") not in listed:
                findings.append(
                    Finding(doc.path, f"detection '{detection_id}' does not list this scenario in validation.scenarios (references must be bidirectional)")
                )
            if expected.get("expected_outcome") == "alert" and not (
                _parents(_technique_ids(doc.data)) & _parents(_technique_ids(detection.data))
            ):
                findings.append(
                    Finding(doc.path, f"no ATT&CK technique in common with expected detection '{detection_id}'")
                )
    return findings


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
def validate(
    detection_files: list[Path],
    scenario_files: list[Path],
    schema_dir: Path = SCHEMA_DIR,
    reference: ReferenceData | None = None,
    content_roots: Iterable[Path] = (),
) -> list[Finding]:
    validators = load_validators(schema_dir)
    ref = reference or load_reference_data()
    roots = list(content_roots)
    findings: list[Finding] = []
    detections: list[Document] = []
    scenarios: list[Document] = []

    for kind, files, bucket, semantic in (
        ("detection", detection_files, detections, check_detection),
        ("scenario", scenario_files, scenarios, check_scenario),
    ):
        for path in files:
            doc, structural = check_structure(path, kind, validators, _root_for(path, roots))
            findings.extend(structural)
            if doc is None:
                continue
            bucket.append(doc)
            findings.extend(check_common(doc))
            findings.extend(semantic(doc, ref))

    findings.extend(check_corpus(detections, scenarios))
    return findings


def escape_annotation_data(value: str) -> str:
    """Escape a GitHub Actions workflow-command message."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_annotation_property(value: str) -> str:
    """Escape a GitHub Actions workflow-command property value (e.g. file=)."""
    return escape_annotation_data(value).replace(":", "%3A").replace(",", "%2C")


def format_finding(finding: Finding, github_actions: bool) -> str:
    if github_actions:
        rel = _display_path(finding.path, REPO_ROOT)
        return f"::error file={escape_annotation_property(rel)}::{escape_annotation_data(finding.message)}"
    return "ERROR " + finding.render(REPO_ROOT).replace("\r", " ").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--detections", type=Path, default=REPO_ROOT / "detections", help="detections directory")
    parser.add_argument("--scenarios", type=Path, default=REPO_ROOT / "scenarios", help="scenarios directory")
    parser.add_argument("--schemas", type=Path, default=SCHEMA_DIR, help="schema directory")
    parser.add_argument("--attack-data", type=Path, default=ATTACK_DATA, help="pinned ATT&CK data (JSON)")
    parser.add_argument("--licensing-matrix", type=Path, default=LICENSING_MATRIX, help="licensing matrix (YAML)")
    args = parser.parse_args(argv)

    try:
        reference = load_reference_data(args.attack_data, args.licensing_matrix)
        detection_files = discover(args.detections)
        scenario_files = discover(args.scenarios)
        findings = validate(detection_files, scenario_files, args.schemas, reference, (args.detections, args.scenarios))
    except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
        print(f"setup error: {exc}", file=sys.stderr)
        return 2

    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for finding in findings:
        print(format_finding(finding, in_actions))

    print(
        f"Validated {len(detection_files)} detection(s) and {len(scenario_files)} scenario(s) "
        f"against ATT&CK {reference.attack_version}: {len(findings)} finding(s)."
    )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
