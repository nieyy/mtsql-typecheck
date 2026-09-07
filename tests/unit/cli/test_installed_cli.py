"""Installed-CLI packaging tests (design 6.3.3/7 Phase 5, test ID B04).

Builds a wheel from this repository, installs it into a throwaway virtual
environment created *outside* the repository, and verifies the installed
``mt-typecheck`` entry point: help, an offline generate/validate smoke run,
the import path coming from the installed package (not the workspace ``src``
tree), non-overwrite of an existing output directory, and the absence of
network-client imports in the installed runtime sources.

The build deliberately avoids the network: the ``build`` package is used only
when already importable (with ``--no-isolation``); otherwise the local
``pip wheel --no-deps --no-build-isolation`` fallback builds the wheel from
the already-installed setuptools/wheel.  The wheel has no runtime dependencies
(stdlib only), so the isolated installation works with ``--no-index
--no-deps``.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

# Network/DB client modules the runtime must never import (design 6.5: the
# CLI accepts no DSN, connects to nothing, performs no network call).
_BANNED_MODULES = (
    "socket",
    "ssl",
    "urllib",
    "http",
    "ftplib",
    "telnetlib",
    "smtplib",
    "poplib",
    "imaplib",
    "nntplib",
    "asyncio",
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "pymysql",
    "mysql",
    "MySQLdb",
)


def _banned_import_pattern() -> re.Pattern[str]:
    alternation = "|".join(re.escape(name) for name in _BANNED_MODULES)
    return re.compile(rf"^\s*(?:import|from)\s+({alternation})\b")


@pytest.fixture(scope="module")
def installed_cli(tmp_path_factory) -> dict:
    """Build a wheel and install it into an isolated venv outside the repo.

    The wheel is built locally and offline (no downloads).  An in-tree
    ``build/`` directory may appear as a side effect of setuptools' in-place
    PEP 517 build; it is removed afterwards, but only when it did not exist
    before this fixture ran.
    """
    scratch = tmp_path_factory.mktemp("b04-installed-cli")
    dist_dir = scratch / "dist"
    dist_dir.mkdir()
    in_tree_build_dir = REPO_ROOT / "build"
    in_tree_build_dir_preexisting = in_tree_build_dir.exists()

    if importlib.util.find_spec("build") is not None:
        build_cmd = [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            str(dist_dir),
            str(REPO_ROOT),
        ]
    else:
        build_cmd = [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(REPO_ROOT),
            "--no-deps",
            "--no-build-isolation",
            "-w",
            str(dist_dir),
        ]
    built = subprocess.run(build_cmd, capture_output=True, text=True, timeout=600)
    assert built.returncode == 0, built.stderr[-4000:]
    wheels = list(dist_dir.glob("mtsql_typecheck-*.whl"))
    assert len(wheels) == 1, f"expected exactly one wheel, got {wheels}"

    venv_dir = scratch / "venv"
    created = subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert created.returncode == 0, created.stderr[-4000:]
    venv_python = venv_dir / "bin" / "python"
    assert venv_python.is_file()
    installed = subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheels[0]),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert installed.returncode == 0, installed.stderr[-4000:]

    def _cleanup_in_tree_build_dir() -> None:
        if not in_tree_build_dir_preexisting and in_tree_build_dir.is_dir():
            shutil.rmtree(in_tree_build_dir, ignore_errors=True)

    try:
        return {
            "venv": venv_dir,
            "venv_python": venv_python,
            "cli": venv_dir / "bin" / "mt-typecheck",
            "wheel": wheels[0],
        }
    finally:
        _cleanup_in_tree_build_dir()


def _run(command: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=300, **kwargs)


def test_help_lists_offline_commands(installed_cli) -> None:
    result = _run([str(installed_cli["cli"]), "--help"])
    assert result.returncode == 0, result.stderr
    assert "generate" in result.stdout
    assert "validate" in result.stdout


def test_generate_and_validate_smoke(installed_cli, tmp_path: Path) -> None:
    out = tmp_path / "smoke-bundle"
    generated = _run(
        [
            str(installed_cli["cli"]),
            "generate",
            "--profile",
            "mysql80-exact-v1",
            "--seed",
            "42",
            "--cases",
            "2",
            "--output",
            str(out),
        ]
    )
    assert generated.returncode == 0, generated.stderr
    assert "status: COMPLETE" in generated.stdout
    manifest = json.loads((out / "generation-manifest.json").read_text("utf-8"))
    assert manifest["status"] == "COMPLETE"
    assert manifest["statistics"]["emitted_occurrences"] == 2

    validated = _run([str(installed_cli["cli"]), "validate", "--input", str(out)])
    assert validated.returncode == 0, validated.stderr
    assert "validation OK (offline)" in validated.stdout


def test_import_path_comes_from_installed_package(installed_cli) -> None:
    probe = (
        "import mtsql_typecheck, mtsql_typecheck.cli.main as m; "
        "print(mtsql_typecheck.__file__); print(m.__file__)"
    )
    result = _run([str(installed_cli["venv_python"]), "-c", probe])
    assert result.returncode == 0, result.stderr
    lines = result.stdout.strip().splitlines()
    assert len(lines) == 2
    site_packages = str(installed_cli["venv"] / "lib")
    workspace_src = str(REPO_ROOT / "src")
    for line in lines:
        assert line.startswith(site_packages), (
            f"import path {line!r} is not inside the installed venv"
        )
        assert workspace_src not in line, (
            f"import path {line!r} resolves into the workspace source tree"
        )
        assert line.endswith(".py")


def test_existing_output_directory_is_not_overwritten(installed_cli, tmp_path) -> None:
    out = tmp_path / "keep"
    first = _run(
        [
            str(installed_cli["cli"]),
            "generate",
            "--profile",
            "mysql80-exact-v1",
            "--seed",
            "3",
            "--cases",
            "1",
            "--output",
            str(out),
        ]
    )
    assert first.returncode == 0, first.stderr
    manifest_before = (out / "generation-manifest.json").read_bytes()
    second = _run(
        [
            str(installed_cli["cli"]),
            "generate",
            "--profile",
            "mysql80-exact-v1",
            "--seed",
            "4",
            "--cases",
            "1",
            "--output",
            str(out),
        ]
    )
    assert second.returncode == 2
    assert (out / "generation-manifest.json").read_bytes() == manifest_before


def test_installed_runtime_has_no_network_client_imports(installed_cli) -> None:
    pattern = _banned_import_pattern()
    package_dir = installed_cli["venv"] / "lib"
    found = list(package_dir.glob("python*/site-packages/mtsql_typecheck/**/*.py"))
    assert found, "installed mtsql_typecheck sources not found in the venv"
    offenders: list[str] = []
    for source in found:
        # D3: the MySQL driver shim (mtsql_typecheck/adapters/) legitimately
        # imports PyMySQL at module scope behind the opt-in ``mysql`` extra.
        # Its no-network/no-driver behavior is enforced by subprocess hygiene
        # tests in tests/unit/adapters; the static scan covers the rest.
        if "/mtsql_typecheck/adapters/" in source.as_posix():
            continue
        for number, line in enumerate(
            source.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if pattern.match(line):
                offenders.append(f"{source}:{number}: {line.strip()}")
    assert not offenders, "network/DB client imports found:\n" + "\n".join(offenders)
