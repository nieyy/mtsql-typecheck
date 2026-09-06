"""Shared helpers for the bundle tests (B01/B02/B03).

Expectations here are hand-written from the design constants; nothing is
computed by calling the validator under test and feeding its output back as
an expectation.  Case identities used in assertions are pinned by generating
once and freezing the resulting ids, never re-derived at assert time.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import (
    CaseBundle,
    GenerationManifest,
    GenerationStatus,
    OrdinalOutcome,
    OrdinalReceipt,
    Profile,
    RuleSelector,
    TemplateId,
    IndexVariant,
)
from mtsql_typecheck.contracts.codec import canonical_json
from mtsql_typecheck.generation.bundle import (
    MANIFEST_NAME,
    PROFILE_NAME,
    CASES_DIRNAME,
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


@pytest.fixture
def outroot(tmp_path: Path) -> Path:
    """A real (symlink-free) root directory for bundle output directories.

    ``tmp_path`` is already resolved by pytest on macOS, but tests make that
    explicit: the bundle writer rejects symlink path components by design.
    """
    root = Path(os.path.realpath(tmp_path)) / "outroot"
    root.mkdir()
    return root


def small_profile() -> Profile:
    """Two-combination profile: integer-decimal x Q1 x none.

    Q1 carries no predicate/arithmetic and the 8-row normal input is filled
    entirely from the fixed boundary dictionary, so payloads for the empty
    and all-NULL slots repeat across visits: ordinals 36 and 76 (and 35 and
    75) produce the same case_id, giving real multi-occurrence cases without
    any special generator support.
    """
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


def generate_result(
    profile: Profile,
    seed: int,
    count: int,
    reject_ordinals: frozenset[int] = frozenset(),
) -> GenerationResult:
    """Aggregate per-ordinal ``generate_case`` calls into a GenerationResult.

    Mirrors the accounting of ``generate_cases`` while injecting a
    construction-rejection hook for the listed ordinals, so PARTIAL results
    with (optionally zero) emitted cases can be produced without real
    constraint failures.
    """
    profile_hash_hex = profile_hash(profile)
    bundles: list[CaseBundle] = []
    occurrences: dict[str, int] = {}
    receipts: list[OrdinalReceipt] = []
    rejections: list[GenerationRejection] = []
    attempted_candidates = 0
    emitted_occurrences = 0
    rejected_ordinals = 0

    def hook(ordinal: int, retry_index: int, payload):
        return None if ordinal in reject_ordinals else payload

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

    if rejected_ordinals:
        status = GenerationStatus.PARTIAL
        reason = None
    else:
        status = GenerationStatus.COMPLETE
        reason = None
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
        reason=reason,
    )
    return GenerationResult(
        profile=profile,
        profile_hash=profile_hash_hex,
        seed=seed,
        bundles=tuple(bundles),
        occurrences=tuple(
            CaseOccurrence(case_id, count_) for case_id, count_ in occurrences.items()
        ),
        receipts=tuple(receipts),
        records=(),
        rejections=tuple(rejections),
        manifest=manifest,
    )


def rewrite_manifest(out_dir: Path, mutate) -> None:
    """Rewrite generation-manifest.json with a mutation applied to its dict.

    The file is re-encoded canonically (plus the trailing newline the writer
    uses), so the validator's canonical-form check is not what fires; only
    the semantic mutation is under test.
    """
    path = out_dir / MANIFEST_NAME
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_bytes(canonical_json(document) + b"\n")


def read_manifest_document(out_dir: Path) -> dict:
    document = json.loads((out_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def case_file_names() -> tuple[str, ...]:
    return (CASE_DOC_NAME, PREVIEW_A_NAME, PREVIEW_B_NAME, STATIC_CHECK_NAME)


__all__ = [
    "MANIFEST_NAME",
    "PROFILE_NAME",
    "CASES_DIRNAME",
    "CASE_DOC_NAME",
    "STATIC_CHECK_NAME",
    "PREVIEW_A_NAME",
    "PREVIEW_B_NAME",
    "outroot",
    "small_profile",
    "generate_result",
    "rewrite_manifest",
    "read_manifest_document",
    "case_file_names",
]
