"""Bounded read-side entry of generation/bundle.py::validate_output_dir
(design 6.5, Phase 2).

The default call (``limits=None, control=None``) must keep the historical
behavior and results byte-for-byte; with caps, validation stops at the first
exceeded cap with the bundle's own ``BundleBudgetError`` instead of
producing a partial verdict, and a control is honoured at every loop
boundary.  No existing check is weakened: the same tampered bundles still
produce the same problems when no cap fires.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.execution import Control, ControlCancelled, default_control
from mtsql_typecheck.generation.bundle import (
    MANIFEST_NAME,
    BundleBudgetError,
    BundleReadLimits,
    ProblemKind,
    ValidationReport,
    validate_output_dir,
    write_bundle,
)

from conftest import generate_result, small_profile

SEED = 42


def write_small_bundle(outroot: Path, count: int = 8):
    result = generate_result(small_profile(), SEED, count)
    outcome = write_bundle(result, outroot / "bundle")
    return outcome


def test_defaults_are_unchanged(outroot) -> None:
    outcome = write_small_bundle(outroot)
    baseline = validate_output_dir(outcome.output_dir)
    assert baseline.ok
    assert baseline == validate_output_dir(outcome.output_dir, limits=BundleReadLimits())
    assert baseline == validate_output_dir(
        outcome.output_dir, limits=BundleReadLimits(max_files=10_000)
    )
    assert baseline == validate_output_dir(
        outcome.output_dir,
        limits=BundleReadLimits(
            max_files=10_000,
            max_file_bytes=8 * 1024 * 1024,
            max_total_bytes=256 * 1024 * 1024,
        ),
    )
    assert baseline == validate_output_dir(
        outcome.output_dir, control=default_control(60.0)
    )


def test_valid_limits_still_catch_tampering(outroot) -> None:
    """Caps add early-stop, they do not weaken any existing check."""
    outcome = write_small_bundle(outroot)
    manifest_path = outcome.output_dir / MANIFEST_NAME
    document_limit = manifest_path.stat().st_size
    report = validate_output_dir(
        outcome.output_dir,
        limits=BundleReadLimits(
            max_files=10_000,
            max_file_bytes=document_limit * 16,
            max_total_bytes=64 * 1024 * 1024,
        ),
    )
    assert report == validate_output_dir(outcome.output_dir)
    assert report.ok


def test_max_files_cap_stops_validation_early(outroot) -> None:
    outcome = write_small_bundle(outroot)
    with pytest.raises(BundleBudgetError) as excinfo:
        validate_output_dir(outcome.output_dir, limits=BundleReadLimits(max_files=2))
    assert "max_files=2" in str(excinfo.value)
    # A cap of zero fires before anything is read.
    with pytest.raises(BundleBudgetError) as excinfo:
        validate_output_dir(outcome.output_dir, limits=BundleReadLimits(max_files=0))
    assert "max_files=0" in str(excinfo.value)


def test_max_file_bytes_cap_fires_naming_the_cap(outroot) -> None:
    outcome = write_small_bundle(outroot)
    manifest_size = (outcome.output_dir / MANIFEST_NAME).stat().st_size
    with pytest.raises(BundleBudgetError) as excinfo:
        validate_output_dir(
            outcome.output_dir,
            limits=BundleReadLimits(max_file_bytes=manifest_size - 1),
        )
    assert f"max_file_bytes={manifest_size - 1}" in str(excinfo.value)


def test_max_total_bytes_cap_fires_naming_the_cap(outroot) -> None:
    outcome = write_small_bundle(outroot)
    manifest_size = (outcome.output_dir / MANIFEST_NAME).stat().st_size
    with pytest.raises(BundleBudgetError) as excinfo:
        validate_output_dir(
            outcome.output_dir,
            limits=BundleReadLimits(max_total_bytes=manifest_size - 1),
        )
    assert f"max_total_bytes={manifest_size - 1}" in str(excinfo.value)


def test_invalid_limit_values_are_rejected() -> None:
    with pytest.raises(BundleBudgetError):
        BundleReadLimits(max_files=-1)
    with pytest.raises(BundleBudgetError):
        BundleReadLimits(max_file_bytes=True)
    with pytest.raises(BundleBudgetError):
        BundleReadLimits(max_total_bytes="100")


def test_cancelled_control_raises_control_cancelled(outroot) -> None:
    outcome = write_small_bundle(outroot)
    control = Control(time.monotonic, None, lambda: True)
    with pytest.raises(ControlCancelled):
        validate_output_dir(outcome.output_dir, control=control)


def test_expired_deadline_raises_bundle_budget_error(outroot) -> None:
    outcome = write_small_bundle(outroot)
    control = Control(time.monotonic, 0.0, lambda: False)
    with pytest.raises(BundleBudgetError) as excinfo:
        validate_output_dir(outcome.output_dir, control=control)
    assert "deadline" in str(excinfo.value)


def test_limits_type_is_checked(outroot) -> None:
    outcome = write_small_bundle(outroot)
    with pytest.raises(BundleBudgetError):
        validate_output_dir(outcome.output_dir, limits={"max_files": 3})
