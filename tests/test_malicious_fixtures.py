"""The validator must reject hostile input safely: specific finding, no crash, bounded time."""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest
import validate_content as vc

REPO_ROOT = Path(__file__).resolve().parent.parent
VALID = REPO_ROOT / "tests" / "fixtures" / "valid"
MALICIOUS = REPO_ROOT / "tests" / "fixtures" / "malicious"
TIME_LIMIT_SECONDS = 5.0


def _corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    shutil.copytree(VALID, root)
    return root


def _run(root: Path) -> list:
    return vc.validate(
        vc.discover(root / "detections"), vc.discover(root / "scenarios"),
        content_roots=(root / "detections", root / "scenarios"),
    )


def _expected(path: Path) -> str:
    first = path.read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("# expect-error: "), f"{path.name} must start with '# expect-error: '"
    return first.removeprefix("# expect-error: ").strip()


MALICIOUS_FILES = sorted(p for p in MALICIOUS.rglob("*.yml"))


def test_malicious_fixture_set_is_not_empty() -> None:
    assert len(MALICIOUS_FILES) >= 10


@pytest.mark.parametrize("fixture", MALICIOUS_FILES, ids=lambda p: p.stem)
def test_malicious_fixture_is_rejected(tmp_path: Path, fixture: Path) -> None:
    root = _corpus(tmp_path)
    target = root / fixture.parent.name / fixture.name
    shutil.copy(fixture, target)
    started = time.monotonic()
    findings = _run(root)
    elapsed = time.monotonic() - started
    messages = [f.message for f in findings if f.path.resolve() == target.resolve()]
    assert any(_expected(fixture) in m for m in messages), messages
    assert elapsed < TIME_LIMIT_SECONDS, f"validation took {elapsed:.1f}s"


def test_oversized_file_is_rejected(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    target = root / "detections" / "DET-AD-950.yml"
    target.write_text("description: '" + "A" * (vc.MAX_FILE_BYTES + 10) + "'\n", encoding="utf-8")
    assert any("limit is" in f.message for f in _run(root) if f.path == target)


def test_invalid_utf8_is_rejected(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    target = root / "detections" / "DET-AD-951.yml"
    target.write_bytes(b"id: DET-AD-951\ntitle: \xff\xfe broken\n")
    assert any("not valid UTF-8" in f.message for f in _run(root) if f.path == target)


@pytest.mark.parametrize("depth", [vc.MAX_NESTING_DEPTH + 5, 20_000])
def test_excessive_nesting_is_rejected(tmp_path: Path, depth: int) -> None:
    root = _corpus(tmp_path)
    target = root / "detections" / "DET-AD-952.yml"
    target.write_text("id: " + "[" * depth + "]" * depth + "\n", encoding="utf-8")
    started = time.monotonic()
    messages = [f.message for f in _run(root) if f.path == target]
    assert any("nesting too deep" in m for m in messages), messages
    assert time.monotonic() - started < TIME_LIMIT_SECONDS


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlinked_file_is_rejected(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    outside = tmp_path / "outside.yml"
    outside.write_text("id: DET-AD-953\n", encoding="utf-8")
    link = root / "detections" / "DET-AD-953.yml"
    link.symlink_to(outside)
    assert any("symbolic links are not allowed" in f.message for f in _run(root) if f.path == link)


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlinked_directory_is_rejected(tmp_path: Path) -> None:
    root = _corpus(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "DET-AD-954.yml").write_text("id: DET-AD-954\n", encoding="utf-8")
    (root / "detections" / "linked").symlink_to(outside, target_is_directory=True)
    files = vc.discover(root / "detections")
    findings = vc.validate(files, [], content_roots=(root / "detections",))
    linked = [f for f in findings if "linked" in f.path.parts]
    # Either discovery does not follow the link, or the file is rejected as a symlink.
    assert all("symbolic links are not allowed" in f.message for f in linked if "DET-AD-954" in f.path.name) or not any(
        "linked" in p.parts for p in files
    )
