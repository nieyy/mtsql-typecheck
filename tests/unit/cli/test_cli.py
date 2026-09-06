"""Unit tests for the offline CLI (design 6.3.3, 6.5; B01/B03 at the CLI seam).

Expectations are hand-written from the design's exit-code table; nothing is
asserted against the CLI's own output fed back as an expectation.  All output
directories live under a real (symlink-free) root because the bundle layer
refuses symlink path components by design.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mtsql_typecheck.cli.main import main
from mtsql_typecheck.contracts.case import (
    CaseBundle,
    GenerationManifest,
    GenerationStatus,
    OrdinalOutcome,
    OrdinalReceipt,
    Profile,
    RuleSelector,
    IndexVariant,
    TemplateId,
)
from mtsql_typecheck.generation.bundle import (
    CASES_DIRNAME,
    MANIFEST_NAME,
    PROFILE_NAME,
    CASE_DOC_NAME,
    STATIC_CHECK_NAME,
    PREVIEW_A_NAME,
    PREVIEW_B_NAME,
)
from mtsql_typecheck.generation.generator import (
    GENERATOR_IDENTITY,
    CaseOccurrence,
    GenerationRejection,
    GenerationResult,
    generate_case,
    profile_hash,
)

# --------------------------------------------------------------------------
# Helpers (duplicated from the bundle-test conftest on purpose: the test
# trees are separate roots without a shared package)
# --------------------------------------------------------------------------


def two_combo_profile() -> Profile:
    """Small deterministic profile: integer-decimal x Q1 x none."""
    return Profile(
        rules=(RuleSelector("mysql80.integer-decimal", 1),),
        templates=(TemplateId.Q1,),
        index_variants=(IndexVariant.NONE,),
        row_count=8,
        predicate_atoms=1,
        attempts_per_ordinal=8,
        max_payload_bytes=1024 * 1024,
        max_bundle_bytes=256 * 1024 * 1024,
    )


def partial_generation_result(
    profile: Profile,
    seed: int,
    count: int,
    reject_ordinals: frozenset[int],
) -> GenerationResult:
    """A real GenerationResult with the listed ordinals finally rejected."""

    def hook(ordinal: int, retry_index: int, payload):
        return None if ordinal in reject_ordinals else payload

    profile_hash_hex = profile_hash(profile)
    bundles: list[CaseBundle] = []
    occurrences: dict[str, int] = {}
    receipts: list[OrdinalReceipt] = []
    rejections: list[GenerationRejection] = []
    attempted_candidates = 0
    emitted_occurrences = 0
    rejected_ordinals = 0
    for ordinal in range(count):
        produced = generate_case(
            profile, profile_hash_hex, seed, ordinal, attempt_hook=hook
        )
        if isinstance(produced, CaseBundle):
            receipts.append(
                OrdinalReceipt(
                    ordinal=ordinal,
                    outcome=OrdinalOutcome.EMITTED,
                    case_id=produced.case_id,
                    retry_count=0,
                )
            )
            attempted_candidates += 1
            emitted_occurrences += 1
            occurrences[produced.case_id] = occurrences.get(produced.case_id, 0) + 1
            if occurrences[produced.case_id] == 1:
                bundles.append(produced)
        else:
            receipts.append(produced)
            attempted_candidates += produced.retry_count
            rejected_ordinals += 1
            rejections.append(
                GenerationRejection(
                    ordinal=ordinal,
                    retry_index=max(produced.retry_count - 1, 0),
                    reason=produced.reason or "attempts exhausted",
                )
            )
    status = (
        GenerationStatus.PARTIAL if rejected_ordinals else GenerationStatus.COMPLETE
    )
    manifest = GenerationManifest(
        profile_hash=profile_hash_hex,
        seed=seed,
        requested_ordinals=count,
        attempted_candidates=attempted_candidates,
        emitted_occurrences=emitted_occurrences,
        unique_cases=len(bundles),
        rejected_ordinals=rejected_ordinals,
        interrupted_ordinals=0,
        not_attempted=count - len(receipts),
        status=status,
        generator=GENERATOR_IDENTITY,
        receipts=tuple(receipts),
        case_files=(),
        reason=None,
    )
    return GenerationResult(
        profile=profile,
        profile_hash=profile_hash_hex,
        seed=seed,
        bundles=tuple(bundles),
        occurrences=tuple(
            CaseOccurrence(case_id, seen) for case_id, seen in occurrences.items()
        ),
        receipts=tuple(receipts),
        records=(),
        rejections=tuple(rejections),
        manifest=manifest,
    )


# --------------------------------------------------------------------------
# Normal path (B01)
# --------------------------------------------------------------------------


def test_generate_complete_then_validate_roundtrip(outroot: Path, capsys) -> None:
    out = outroot / "bundle"
    code = main(
        [
            "generate",
            "--profile",
            "mysql80-exact-v1",
            "--seed",
            "42",
            "--cases",
            "3",
            "--output",
            str(out),
        ]
    )
    assert code == 0
    assert (out / MANIFEST_NAME).is_file()
    assert (out / PROFILE_NAME).is_file()
    case_dirs = sorted((out / CASES_DIRNAME).iterdir())
    assert len(case_dirs) == 3
    for case_dir in case_dirs:
        assert {
            CASE_DOC_NAME,
            STATIC_CHECK_NAME,
            PREVIEW_A_NAME,
            PREVIEW_B_NAME,
        } <= {entry.name for entry in case_dir.iterdir()}

    summary = capsys.readouterr().out
    assert "status: COMPLETE\n" in summary
    assert "requested_ordinals: 3" in summary
    assert "emitted_occurrences: 3" in summary
    assert "unique_cases: 3" in summary
    assert "rejected_ordinals: 0" in summary
    assert "no database connection, execution or comparison" in summary

    code = main(["validate", "--input", str(out)])
    assert code == 0
    report = capsys.readouterr().out
    assert "manifest_status: COMPLETE" in report
    assert "validation OK (offline)" in report
    assert "does NOT mean a database MATCH" in report


def test_generate_is_deterministic_for_same_seed(outroot: Path) -> None:
    first = outroot / "first"
    second = outroot / "second"
    argv = ["--profile", "mysql80-exact-v1", "--seed", "7", "--cases", "3"]
    assert main(["generate", *argv, "--output", str(first)]) == 0
    assert main(["generate", *argv, "--output", str(second)]) == 0
    assert (first / PROFILE_NAME).read_bytes() == (second / PROFILE_NAME).read_bytes()
    assert sorted(p.name for p in (first / CASES_DIRNAME).iterdir()) == sorted(
        p.name for p in (second / CASES_DIRNAME).iterdir()
    )


# --------------------------------------------------------------------------
# PARTIAL: legal request that did not finish (exit 3)
# --------------------------------------------------------------------------


def test_generate_partial_exit_3(outroot: Path, monkeypatch, capsys) -> None:
    profile = two_combo_profile()

    def patched_generate_cases(profile_arg, seed, count, should_cancel=None):
        return partial_generation_result(profile_arg, seed, count, frozenset({1}))

    monkeypatch.setattr(
        "mtsql_typecheck.generation.bundle.generate_cases", patched_generate_cases
    )
    out = outroot / "bundle"
    code = main(
        [
            "generate",
            "--profile-file",
            str(_write_profile_file(outroot, profile)),
            "--seed",
            "5",
            "--cases",
            "3",
            "--output",
            str(out),
        ]
    )
    assert code == 3
    summary = capsys.readouterr().out
    assert "status: PARTIAL\n" in summary
    assert "rejected_ordinals: 1" in summary
    assert (out / MANIFEST_NAME).is_file()

    # validate agrees: content valid, request unfinished -> 3, with a
    # status line (and no fake success wording).
    capsys.readouterr()
    code = main(["validate", "--input", str(out)])
    assert code == 3
    report = capsys.readouterr().out
    assert "manifest_status: PARTIAL" in report
    assert "bundle is not COMPLETE" in report
    assert "validation OK" not in report


def _write_profile_file(outroot: Path, profile) -> Path:
    path = outroot / f"profile-{len(list(outroot.iterdir()))}.json"
    path.write_text(json.dumps(profile.to_obj()), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Illegal input (exit 2)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv_builder",
    [
        lambda out: ["--cases", "0", "--seed", "1", "--output", str(out)],
        lambda out: ["--cases", "10001", "--seed", "1", "--output", str(out)],
        lambda out: ["--cases", "abc", "--seed", "1", "--output", str(out)],
        lambda out: ["--cases", "1", "--seed", "-1", "--output", str(out)],
        lambda out: ["--cases", "1", "--seed", "18446744073709551616",
                     "--output", str(out)],
        lambda out: ["--cases", "1", "--seed", "notanumber", "--output", str(out)],
        lambda out: ["--cases", "1", "--seed", "1", "--output", str(out),
                     "--profile", "unknown-profile"],
        lambda out: ["--cases", "1", "--seed", "1", "--output", str(out),
                     "--profile", "mysql80-exact-v1", "--profile-file", "x.json"],
        lambda out: ["--cases", "1", "--seed", "1", "--output", str(out),
                     "--profile-file", str(out / "does-not-exist.json")],
    ],
)
def test_generate_illegal_input_exit_2(outroot: Path, argv_builder) -> None:
    out = outroot / "never-created"
    code = main(["generate", *argv_builder(out)])
    assert code == 2
    assert not out.exists()


def test_generate_existing_output_dir_exit_2(outroot: Path) -> None:
    out = outroot / "bundle"
    assert main(["generate", "--profile", "mysql80-exact-v1", "--seed", "1",
                 "--cases", "2", "--output", str(out)]) == 0
    manifest_before = (out / MANIFEST_NAME).read_bytes()
    code = main(["generate", "--profile", "mysql80-exact-v1", "--seed", "2",
                 "--cases", "2", "--output", str(out)])
    assert code == 2
    assert (out / MANIFEST_NAME).read_bytes() == manifest_before


def test_generate_symlink_component_exit_2(outroot: Path) -> None:
    real = outroot / "real"
    real.mkdir()
    link = outroot / "link"
    link.symlink_to(real)
    out = link / "bundle"
    code = main(["generate", "--profile", "mysql80-exact-v1", "--seed", "1",
                 "--cases", "1", "--output", str(out)])
    assert code == 2
    assert not (real / "bundle").exists()


def test_validate_missing_directory_exit_2(outroot: Path) -> None:
    assert main(["validate", "--input", str(outroot / "absent")]) == 2


def test_no_subcommand_exit_2_and_help_exit_0(capsys) -> None:
    assert main([]) == 2
    capsys.readouterr()
    assert main(["--help"]) == 0
    help_text = capsys.readouterr().out
    assert "generate" in help_text and "validate" in help_text


# --------------------------------------------------------------------------
# --profile-file (restricted JSON profile, design 6.3.3)
# --------------------------------------------------------------------------


def test_profile_file_backfills_documented_defaults(outroot: Path) -> None:
    path = outroot / "profile.json"
    # Only selectors given: all documented default budgets are backfilled.
    path.write_text(
        json.dumps(
            {
                "rules": [{"rule_id": "mysql80.signed-widen", "rule_version": 1}],
                "templates": ["Q1"],
                "index_variants": ["none"],
            }
        ),
        encoding="utf-8",
    )
    out = outroot / "bundle"
    code = main(["generate", "--profile-file", str(path), "--seed", "11",
                 "--cases", "2", "--output", str(out)])
    assert code == 0
    stored = json.loads((out / PROFILE_NAME).read_text(encoding="utf-8"))
    assert stored["row_count"] == 32
    assert stored["max_payload_bytes"] == 1024 * 1024
    assert stored["templates"] == ["Q1"]
    assert stored["rules"] == [
        {"rule_id": "mysql80.signed-widen", "rule_version": 1}
    ]


def test_profile_file_unsorted_selectors_are_sorted(outroot: Path) -> None:
    path = outroot / "profile.json"
    path.write_text(
        json.dumps(
            {
                "rules": [
                    {"rule_id": "mysql80.signed-widen", "rule_version": 1},
                    {"rule_id": "mysql80.decimal-widen", "rule_version": 1},
                ],
                "templates": ["Q2", "Q1"],
                "index_variants": ["none", "ix_v"],
            }
        ),
        encoding="utf-8",
    )
    out = outroot / "bundle"
    code = main(["generate", "--profile-file", str(path), "--seed", "3",
                 "--cases", "2", "--output", str(out)])
    assert code == 0
    stored = json.loads((out / PROFILE_NAME).read_text(encoding="utf-8"))
    assert stored["templates"] == ["Q1", "Q2"]
    assert stored["index_variants"] == ["ix_v", "none"]
    assert [rule["rule_id"] for rule in stored["rules"]] == [
        "mysql80.decimal-widen",
        "mysql80.signed-widen",
    ]


_BAD_DOCUMENT_INDEX = iter(range(1000))


@pytest.mark.parametrize(
    "document",
    [
        # Unknown field.
        {"bogus_field": 1},
        # Unknown rule id.
        {"rules": [{"rule_id": "mysql80.nope", "rule_version": 1}]},
        # Unknown rule version.
        {"rules": [{"rule_id": "mysql80.signed-widen", "rule_version": 2}]},
        # Duplicate selector.
        {
            "rules": [
                {"rule_id": "mysql80.signed-widen", "rule_version": 1},
                {"rule_id": "mysql80.signed-widen", "rule_version": 1},
            ]
        },
        # Over-cap budget.
        {"max_payload_bytes": 2 * 1024 * 1024},
        {"max_bundle_bytes": 300 * 1024 * 1024},
        {"row_count": 1025},
        {"predicate_atoms": 3},
        {"attempts_per_ordinal": 9},
        # Unknown schema version.
        {"profile_schema_version": 2},
        # Empty selection: rules present but no template overlap.
        {
            "rules": [{"rule_id": "mysql80.signed-widen", "rule_version": 1}],
            "templates": [],
        },
    ],
)
def test_profile_file_rejections_exit_2(outroot: Path, document) -> None:
    path = outroot / f"bad-{next(_BAD_DOCUMENT_INDEX)}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    out = outroot / "bundle"
    code = main(["generate", "--profile-file", str(path), "--seed", "1",
                 "--cases", "1", "--output", str(out)])
    assert code == 2, document
    assert not out.exists()


def test_profile_file_non_json_exit_2(outroot: Path) -> None:
    path = outroot / "profile.json"
    path.write_text('{"row_count": 32, "row_count": 33}', encoding="utf-8")
    out = outroot / "bundle"
    code = main(["generate", "--profile-file", str(path), "--seed", "1",
                 "--cases", "1", "--output", str(out)])
    assert code == 2
    assert not out.exists()


def test_profile_file_cannot_carry_seed_or_cases(outroot: Path) -> None:
    """seed/cases are request parameters: an unknown profile field carrying
    them is rejected, and the CLI values stay authoritative."""
    path = outroot / "profile.json"
    path.write_text(
        json.dumps({"seed": 1, "cases": 1}), encoding="utf-8"
    )
    out = outroot / "bundle"
    code = main(["generate", "--profile-file", str(path), "--seed", "9",
                 "--cases", "1", "--output", str(out)])
    assert code == 2
    assert not out.exists()


# --------------------------------------------------------------------------
# Cancellation (exit 130, B03 at the CLI seam)
# --------------------------------------------------------------------------


def test_sigint_flag_via_controlled_self_signal(outroot: Path, monkeypatch) -> None:
    """Deterministic cancellation injection: the patched write step delivers
    a real SIGINT to this process once, which the CLI handler must absorb
    into the cancel flag; the generation then stops as ABORTED -> exit 130."""
    import mtsql_typecheck.cli.main as _cli_module
    from mtsql_typecheck.generation.bundle import (
        generate_and_write as real_generate_and_write,
    )

    delivered = []

    def patched_generate_and_write(profile, seed, count, output_dir, *, should_cancel=None, budget=None):
        assert should_cancel is not None
        assert not should_cancel()
        delivered.append(os.kill(os.getpid(), signal.SIGINT))
        return real_generate_and_write(
            profile, seed, count, output_dir, should_cancel=should_cancel, budget=budget
        )

    monkeypatch.setattr(
        _cli_module, "generate_and_write", patched_generate_and_write
    )
    out = outroot / "bundle"
    code = main(["generate", "--profile", "mysql80-exact-v1", "--seed", "21",
                 "--cases", "3", "--output", str(out)])
    assert delivered
    assert code == 130
    manifest = json.loads((out / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["status"] == "ABORTED"
    assert "cancel" in (manifest.get("reason") or "")


def test_sigint_subprocess_exit_130_with_terminating_manifest(outroot: Path) -> None:
    """Real Ctrl-C path: SIGINT is delivered while the subprocess is generating
    (the built-in profile needs ~10s for the full 10000 ordinals; the signal
    is sent at ~1.5s, well past interpreter startup).  Too-early delivery is
    benign (the flag is simply set before generation starts) and too-late
    delivery still ends ABORTED, so the 130 assertion does not race."""
    out = outroot / "bundle"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mtsql_typecheck.cli.main",
            "generate",
            "--profile",
            "mysql80-exact-v1",
            "--seed",
            "42",
            "--cases",
            "10000",
            "--output",
            str(out),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        time.sleep(1.5)
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
        stdout, stderr = proc.communicate(timeout=300)
    finally:
        if proc.poll() is None:  # pragma: no cover - defensive
            proc.kill()
            proc.communicate()
    assert proc.returncode == 130, (proc.returncode, stdout, stderr)
    manifest_path = out / MANIFEST_NAME
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "ABORTED"
    assert "cancel" in (manifest.get("reason") or "")
    # Completed evidence is preserved: emitted + rejected + interrupted +
    # not_attempted conserved, no traceback shown to the user.
    statistics = manifest["statistics"]
    assert (
        statistics["emitted_occurrences"]
        + statistics["rejected_ordinals"]
        + statistics["interrupted_ordinals"]
        + statistics["not_attempted"]
        == statistics["requested_ordinals"]
    )
    assert "Traceback" not in stderr


# --------------------------------------------------------------------------
# I/O failure (exit 1)
# --------------------------------------------------------------------------


def test_unwritable_parent_exit_1(outroot: Path) -> None:
    if os.geteuid() == 0:  # pragma: no cover - permission test needs non-root
        pytest.skip("permission test cannot run as root")
    parent = outroot / "locked"
    parent.mkdir()
    out = parent / "bundle"
    parent.chmod(0o000)
    try:
        code = main(["generate", "--profile", "mysql80-exact-v1", "--seed", "1",
                     "--cases", "1", "--output", str(out)])
    finally:
        parent.chmod(0o755)
    assert code == 1
    assert not out.exists()
