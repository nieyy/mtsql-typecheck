"""Shared fixture for the CLI tests (Phase 5).

The PARTIAL/termination helpers live in ``test_cli.py`` itself because the
test trees intentionally have no shared package (see the bundle-test
conftest for the same technique at the bundle layer).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture
def outroot(tmp_path: Path) -> Path:
    """A real (symlink-free) root for CLI output directories.

    ``tmp_path`` is resolved explicitly because the bundle writer rejects
    symlink path components by design, and on macOS ``/var`` is a symlink.
    """
    root = Path(os.path.realpath(tmp_path)) / "outroot"
    root.mkdir()
    return root
