"""CI security policy, enforced as tests (docs/architecture.md section 6)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
SHA_PIN = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")


def _load(path: Path) -> dict:
    # PyYAML (YAML 1.1) parses the key "on" as boolean True.
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["on"] = data.pop(True, data.get("on"))
    return data


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_default_permissions_are_read_only(workflow: Path) -> None:
    assert _load(workflow)["permissions"] == {"contents": "read"}


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_dangerous_triggers(workflow: Path) -> None:
    triggers = _load(workflow)["on"]
    assert "pull_request_target" not in triggers
    assert "workflow_run" not in triggers


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_oidc_only_at_job_level_with_protected_environment(workflow: Path) -> None:
    data = _load(workflow)
    assert "id-token" not in data["permissions"]
    for name, job in data["jobs"].items():
        if (job.get("permissions") or {}).get("id-token") == "write":
            assert job.get("environment"), f"job {name} requests an OIDC token without a protected environment"
            assert "pull_request" not in data["on"], f"job {name}: OIDC jobs must not run on pull_request"


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_actions_pinned_by_sha_and_credentials_not_persisted(workflow: Path) -> None:
    for job in _load(workflow)["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses:
                assert SHA_PIN.match(uses), f"action not pinned to a commit SHA: {uses}"
                if uses.startswith("actions/checkout@"):
                    assert step.get("with", {}).get("persist-credentials") is False


def test_ci_uses_python_312_and_hash_locked_install() -> None:
    text = (REPO_ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    assert 'python-version: "3.12"' in text
    assert "--require-hashes -r requirements-dev.txt" in text


def test_no_duplicate_runs_for_feature_branches() -> None:
    triggers = _load(REPO_ROOT / ".github" / "workflows" / "validate.yml")["on"]
    assert triggers["push"]["branches"] == ["main"]


def test_secret_scanning_job_exists() -> None:
    jobs = _load(REPO_ROOT / ".github" / "workflows" / "validate.yml")["jobs"]
    assert any("gitleaks" in str(step.get("run", "")) for job in jobs.values() for step in job["steps"])


def test_requirements_are_hash_locked() -> None:
    lines = (REPO_ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
    pins = [line for line in lines if re.match(r"^[A-Za-z0-9_.-]+==", line)]
    assert pins and all(line.rstrip().endswith("\\") for line in pins), "every pin must be followed by --hash lines"
    assert sum("--hash=sha256:" in line for line in lines) >= len(pins)
