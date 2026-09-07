"""Offline end-to-end tests for the D4 delivery CLI (Phase 5a).

Closed loops over REAL file sinks only — no database, no network, no driver
import: D1 generation → report package → move → evidence-verify of the moved
package → export, plus tamper detection, repeat-run stability, cancellation,
I/O failure and budget-expiry exit mapping.

This file is intentionally NOT marked ``integration``: it must be collected
by the default offline CI run (same convention as tests/integration/
test_d2_offline.py).  Fixture builders are imported from the unit suites
(test_selection / the reduction fakes) because they are the reviewed,
offline-only construction path for evidence trees.

Cancellation, ENOSPC-style I/O failure and budget expiry are driven through
the module's injection seams (the cancel flag, the Snapshotter constructor
and the monotonic clock) so the tests are deterministic; real SIGINT
delivery is absorbed by the same handler installed in cli/main.py and its
KeyboardInterrupt fallback is covered by the CLI suite.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.cli import delivery as cd
from mtsql_typecheck.cli.main import main
from mtsql_typecheck.evidence.snapshot import SnapshotIoError

_TEST_DIR = Path(__file__).resolve().parent
_DELIVERY_TEST_DIR = _TEST_DIR.parent / "unit" / "delivery"
_REDUCTION_TEST_DIR = _TEST_DIR.parent / "unit" / "reduction"
for _path in (_DELIVERY_TEST_DIR, _REDUCTION_TEST_DIR):
    if str(_path) not in sys.path:
        sys.path.append(str(_path))

import test_selection as ts  # noqa: E402


def _tree_hashes(root: Path) -> dict[str, str]:
    """sha256 of every regular file under ``root``, keyed by relpath."""
    import hashlib

    hashes: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            rel = path.relative_to(root).as_posix()
            hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _verify(root: Path, out: Path, *extra: str) -> int:
    return main(["evidence-verify", "--input", str(root), "--output", str(out), *extra])


def _manifest(out: Path) -> dict:
    return json.loads((out / "evidence-manifest.json").read_text("utf-8"))


@pytest.fixture
def outroot(tmp_path: Path) -> Path:
    # Same real-path root the unit CLI suite uses (snapshot placement and
    # the bundle writer reject symlink components; macOS /var is a symlink).
    root = tmp_path.resolve() / "outroot"
    root.mkdir()
    return root


# --------------------------------------------------------------------------
# Closed loop (design 6.4.1 + acceptance E12 shape)
# --------------------------------------------------------------------------


def test_closed_loop_report_move_verify_export(outroot: Path, tmp_path: Path) -> None:
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    before = _tree_hashes(gen_root)

    # 1. report over the real generation bundle.
    report_pkg = outroot / "report-pkg"
    assert main(["report", "--input", str(gen_root), "--output", str(report_pkg)]) == 0
    report_manifest = _manifest(report_pkg)
    assert report_manifest["kind"] == "report"

    # 2. Move the package somewhere else entirely: identity is
    # content-derived, so the moved package must keep its delivery_id.
    moved = tmp_path.resolve() / "moved-elsewhere" / "report-pkg"
    moved.parent.mkdir()
    report_pkg.rename(moved)
    moved_hashes = _tree_hashes(moved)

    # 3. evidence-verify the moved package.
    verify_pkg = outroot / "verify-pkg"
    assert _verify(moved, verify_pkg) == 0
    verify_manifest = _manifest(verify_pkg)
    assert verify_manifest["delivery_id"] == report_manifest["delivery_id"]
    assert verify_manifest["kind"] == "verification"

    # 4. The verification run never modified the input tree.
    assert _tree_hashes(moved) == moved_hashes
    assert _tree_hashes(gen_root) == before

    # 5. Export SQL-debug material for a real generated case out of the
    # moved package (the derivation re-derives the inner native source).
    case_id = ts._generation_case_ids(gen_root)[0]
    sql_pkg = outroot / "sql-pkg"
    assert (
        main(
            [
                "export",
                "--input",
                str(moved),
                "--case-id",
                case_id,
                "--select",
                "original",
                "--format",
                "sql",
                "--output",
                str(sql_pkg),
            ]
        )
        == 0
    )
    readme = (sql_pkg / "README.md").read_text("utf-8")
    assert "candidate/unverified" in readme
    assert "not accepted by mt-typecheck run --input" in readme

    # 6. Regression export without a review is refused (REVIEW_REQUIRED → 3)
    # and writes nothing.
    regression_pkg = outroot / "regression-pkg"
    assert (
        main(
            [
                "export",
                "--input",
                str(moved),
                "--case-id",
                case_id,
                "--select",
                "original",
                "--format",
                "regression",
                "--output",
                str(regression_pkg),
            ]
        )
        == 3
    )
    assert not regression_pkg.exists()


def test_tampered_package_is_refused_and_input_untouched(
    outroot: Path, tmp_path: Path
) -> None:
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    report_pkg = outroot / "report-pkg"
    assert main(["report", "--input", str(gen_root), "--output", str(report_pkg)]) == 0
    moved = tmp_path.resolve() / "moved" / "report-pkg"
    moved.parent.mkdir()
    report_pkg.rename(moved)

    # Deliberate corruption: rewrite one sealed file.
    (moved / "report.md").write_text("tampered by the test\n", encoding="utf-8")
    tampered_hashes = _tree_hashes(moved)

    out = outroot / "verify-pkg"
    assert _verify(moved, out) == 2
    assert not out.exists()  # a refused run leaves no output skeleton
    # The refusing run modified nothing further in the input tree.
    assert _tree_hashes(moved) == tampered_hashes


def test_repeated_verification_is_stable_120_times(
    outroot: Path, tmp_path: Path
) -> None:
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    report_pkg = outroot / "report-pkg"
    assert main(["report", "--input", str(gen_root), "--output", str(report_pkg)]) == 0
    moved = tmp_path.resolve() / "moved" / "report-pkg"
    moved.parent.mkdir()
    report_pkg.rename(moved)

    delivery_ids = set()
    for index in range(120):
        out = outroot / f"verify-{index:03d}"
        assert _verify(moved, out) == 0, index
        delivery_ids.add(_manifest(out)["delivery_id"])
        assert _manifest(out)["completion"] == "COMPLETE"
    # Every sequential derivation reproduces the same pinned identity.
    assert len(delivery_ids) == 1


# --------------------------------------------------------------------------
# Cancellation, I/O failure, budget expiry
# --------------------------------------------------------------------------


def test_cancel_flag_publishes_no_manifest(
    outroot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _AlwaysCancelled:
        def flag(self) -> bool:
            return True

        def handler(self, signum, frame) -> None:  # pragma: no cover
            pass

    monkeypatch.setattr(cd, "_CancelState", _AlwaysCancelled)
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    out = outroot / "pkg"
    assert _verify(gen_root, out) == 130
    assert out.exists()  # unsealed directory kept for inspection
    assert not (out / "evidence-manifest.json").exists()


def test_output_io_failure_maps_to_exit_1(
    outroot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _FailingSnapshotter:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def capture(self, plan) -> None:
            raise SnapshotIoError("simulated ENOSPC while creating the snapshot")

    monkeypatch.setattr(cd, "Snapshotter", _FailingSnapshotter)
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    out = outroot / "pkg"
    assert _verify(gen_root, out) == 1
    assert not out.exists()


def test_budget_expiry_maps_to_exit_3(
    outroot: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def _expiring_clock() -> float:
        calls["n"] += 1
        return 0.0 if calls["n"] <= 2 else 1.0e9

    monkeypatch.setattr(cd, "_monotonic", _expiring_clock)
    gen_root = tmp_path.resolve() / "gen"
    ts._write_generation_bundle(gen_root)
    out = outroot / "pkg"
    assert _verify(gen_root, out) == 3
    # Nothing sealed as COMPLETE: a budget-expired audit stays partial.
    if (out / "evidence-manifest.json").exists():
        assert _manifest(out)["completion"] == "PARTIAL"
