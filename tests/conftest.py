"""Shared test setup: import paths for tools/validate_content.py and the validator/hdv package."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT / "validator") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "validator"))

if "validate_content" not in sys.modules:
    _spec = importlib.util.spec_from_file_location("validate_content", REPO_ROOT / "tools" / "validate_content.py")
    _module = importlib.util.module_from_spec(_spec)
    sys.modules["validate_content"] = _module
    _spec.loader.exec_module(_module)
