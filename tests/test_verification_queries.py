"""Static checks for KQL verification queries (queries/verification/**/*.kql).

The queries cannot be executed in CI (no workspace). These checks keep them honest:
headers present, tables known to the licensing matrix, licensing gates consistent with it,
watchlists declared, no hard-coded placeholders, and an explicit execution status.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import validate_content as vc

REPO_ROOT = Path(__file__).resolve().parent.parent
QUERIES = sorted((REPO_ROOT / "queries" / "verification").rglob("*.kql"))
REQUIRED = ("id", "title", "module", "tables", "licensing_gates", "watchlists", "status", "expected")
REF = vc.load_reference_data()


def header(path: Path) -> tuple[dict[str, str], str]:
    fields: dict[str, str] = {}
    body: list[str] = []
    in_header = True
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^// (\w+): (.+)$", line) if in_header else None
        if match:
            fields[match.group(1)] = match.group(2).strip()
        else:
            in_header = False
            body.append(line)
    return fields, "\n".join(body)


def split(value: str) -> set[str]:
    return set() if value == "none" else {item.strip() for item in value.split(",")}


def test_queries_exist() -> None:
    assert len(QUERIES) >= 6


def test_query_ids_unique_and_match_file_names() -> None:
    ids = [header(p)[0].get("id") for p in QUERIES]
    assert len(ids) == len(set(ids))
    for path, query_id in zip(QUERIES, ids):
        assert re.fullmatch(r"[A-Z]{3}-V\d{2}", query_id or ""), path.name
        assert path.name.startswith(f"{query_id}-"), path.name


@pytest.mark.parametrize("path", QUERIES, ids=lambda p: p.name)
def test_query_header_and_consistency(path: Path) -> None:
    fields, body = header(path)
    assert set(REQUIRED) <= set(fields), f"missing header fields: {set(REQUIRED) - set(fields)}"
    assert re.fullmatch(r"not executed|executed \d{4}-\d{2}-\d{2}", fields["status"])

    tables = split(fields["tables"])
    assert tables, "at least one table"
    needed_gates: set[str] = set()
    for table in tables:
        assert table in REF.tables, f"{table} is not in tools/data/licensing-matrix.yml"
        assert re.search(rf"(^|\n){re.escape(table)}\b", body), f"{table} declared but not queried"
        entry = REF.tables[table]
        if entry["status"] != "documented":
            needed_gates.add(entry["gate"])
    assert split(fields["licensing_gates"]) == needed_gates, f"licensing_gates must be {sorted(needed_gates) or 'none'}"

    used_watchlists = set(re.findall(r'_GetWatchlist\("([A-Za-z0-9_]+)"\)', body))
    assert split(fields["watchlists"]) == used_watchlists

    assert "<REPLACE" not in body and "<REQUIRED" not in body
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body), "no hard-coded IP addresses"
    assert not re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", body), "no hard-coded GUIDs"
