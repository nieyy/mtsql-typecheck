"""Offline delivery CLI (D4 Phase 5a): ``evidence-verify``, ``report`` and
``export`` (design 6.2.3, 6.3, 6.4.1, 6.4.6).

All three commands run the same derivation pipeline over one native evidence
source (or an existing D4 delivery package, whose single
``raw/<source-id>/`` closure is re-derived — identity is content-derived, so
re-derivation reproduces the original ``source_id``/``delivery_id`` and
reviews bound to the package still bind) and then differ only in what they
seal:

- ``evidence-verify``: assessment + manifest (verification package);
- ``report``: assessment + reviews + report.json/md/html + manifest
  (report package);
- ``export``: one selected case as SQL-debug or regression material via
  ``delivery.export.export_case`` (the derivation snapshot lives in a
  private temporary workspace so it never overlaps ``--output``).

Exit codes (design 6.3 table; first match wins, see :func:`compute_exit_code`):

- ``130`` cancellation (SIGINT or the shared cancel flag).  A cancelled run
  never publishes a manifest; the unsealed output directory is left in
  place for inspection (design 6.4.1 step 6).
- ``1``   internal error / output I/O failure (ENOSPC, fsync failure,
  unclassifiable package file).  Never the input's fault.
- ``2``   illegal or unreadable input: unknown/conflicting native format,
  hint mismatch, empty input tree, corrupt root documents, corrupt or
  incomplete delivery package, illegal review documents, refused or
  ambiguous case selection, an existing or unwritable-placement output
  directory, input exceeding the stated byte limits.
- ``3``   incomplete verification: source changed mid-read, PARTIAL
  structure, applicable checks not recomputed, applicable provenance left
  UNVERIFIED, execution safety UNKNOWN/UNSAFE, review conflict, exhausted
  time budget, render budget exceeded.  Pure generation sources never
  drop to 3 merely for lacking execution records (their semantic and
  provenance dimensions are not applicable).
- ``4``   verification/report completed AND at least one recomputable
  mismatch-candidate finding is present (see
  :func:`_candidate_attempt_keys` for the exact predicate).
- ``0``   otherwise (verification completed with no candidate finding;
  a successful export always exits 0 even with retained risks).

Every retained reason is printed on stdout even when a higher-precedence
code wins.  Refusal paths (exit 2, cancellation) never leave a sealed
package behind; export refusals in particular happen before any write
(delivery/export.py gate order).

This module performs no database and no network I/O; everything it imports
is offline (cli/main.py keeps only the online/driver imports deferred).
"""

from __future__ import annotations

import argparse
import os
import signal
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, NamedTuple, Optional, Sequence

from ..contracts.case import ContractError
from ..contracts.codec import (
    canonical_json,
    decode_generation_manifest,
    parse_strict_json,
)
from ..contracts.delivery import (
    CollectionStatus,
    DeliveryCompletion,
    DeliveryKind,
    EvidenceAssessment,
    EvidenceManifest,
    ExportFormat,
    Limits,
    MAX_TIME_BUDGET_SECONDS,
    NativeKind,
    SemanticStatus,
    SourceDescriptor,
    StructuralStatus,
    SyntheticKind,
    compute_delivery_id,
    decode_finding_review,
)
from ..contracts.execution import Control, ControlCancelled
from ..contracts.oracle import ComparisonStatus, decode_comparison
from ..contracts.runner import load_runner_manifest
from ..delivery.export import ExportRefused, export_case
from ..delivery.selection import CaseSelector, SelectionError, select_case
from ..evidence.assessment import SourceAssessment, assess_snapshot
from ..evidence.manifest import (
    DeliveryError,
    Problem,
    collect_delivery_files,
    validate_delivery_dir,
    write_evidence_manifest,
)
from ..evidence.native import (
    RootDetectionError,
    SourcePlan,
    detect_native_kind,
    enumerate_source,
)
from ..evidence.reader import (
    BudgetExhaustedError,
    EvidenceReadError,
    SourceChangedError,
    SourceReader,
)
from ..evidence.snapshot import SnapshotIoError, Snapshotter
from ..reporting.build import build_report
from ..reporting.coverage import compute_execution_counts, compute_generation_counts
from ..reporting.findings import (
    DuplicateOccurrenceError,
    aggregate_findings,
    collect_occurrences,
)
from ..reporting.html import render_html
from ..reporting.markdown import render_markdown
from ..reporting.model import (
    AttemptSummary,
    ExecutionCounts,
    GenerationCounts,
    LimitExceeded,
    UnsafeLinkError,
)
from ..reporting.review import ReviewValidationError, apply_reviews
from .main import (
    EXIT_CANCELLED,
    EXIT_INCOMPLETE,
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    _CancelState,
    _error_line,
    _install_sigint_handler,
)

EXIT_CANDIDATE = 4

DELIVERY_COMMANDS: tuple[str, ...] = ("evidence-verify", "report", "export")

# D4 CLI writer identity, in step with the project version (pyproject 0.1.0).
# It is stamped into manifests and reports and is deliberately not read from
# installed-package metadata (the project ships from a source tree).
WRITER_VERSION = "0.1.0"

_CANDIDATE_NOTE = (
    "note: a mismatch-candidate is a candidate finding, not a confirmed "
    "database bug (D0 core invariants)"
)
_OFFLINE_NOTE = (
    "note: derived offline from the recorded evidence only; nothing here "
    "proves the database itself correct"
)
_CASE_DETAIL_LIMITATION = (
    "case detail rows are not derived by this CLI version; occurrence rows "
    "carry the binding facts"
)


# --------------------------------------------------------------------------
# Exit-code mapping (design 6.3)
# --------------------------------------------------------------------------


class ExitReason(NamedTuple):
    """One retained reason: the exit class it induces plus a stable short
    reason string.  All reasons are printed even when a higher-precedence
    class wins the first-match table."""

    code: int
    reason: str


# Precedence of the design 6.3 table: cancellation, internal failure,
# illegal input, incomplete verification, candidate finding.
_EXIT_PRECEDENCE: tuple[int, ...] = (
    EXIT_CANCELLED,
    EXIT_INTERNAL_ERROR,
    EXIT_USAGE,
    EXIT_INCOMPLETE,
    EXIT_CANDIDATE,
)


def compute_exit_code(reasons: Sequence[ExitReason]) -> int:
    """Map retained exit reasons to ONE process exit code (design 6.3).

    First match wins over :data:`_EXIT_PRECEDENCE`; the caller prints every
    reason regardless of which one wins.  With no reasons the verification
    completed cleanly: exit 0.
    """
    for code in _EXIT_PRECEDENCE:
        for reason in reasons:
            if reason.code == code:
                return code
    return EXIT_OK


# The single testable classification of ``delivery.export.ExportRefused``
# codes (design 6.3 export row): missing/unsatisfied gates keep the finding
# reproducible and map to 3; illegal/conflicting states map to 2; a failed
# post-write self-validation is a tool fault and maps to 1.  Unknown codes
# (a code added to export.py without updating this table) fall back to 2 —
# refuse loudly rather than pass silently.
EXPORT_REFUSAL_EXIT: dict[str, int] = {
    # --- missing / unsatisfied gate (缺失类 → 3) ---
    "REVIEW_REQUIRED": EXIT_INCOMPLETE,
    "RECOMPUTE_NOT_AVAILABLE": EXIT_INCOMPLETE,
    "STRUCTURAL_NOT_COMPLETE": EXIT_INCOMPLETE,
    "REVIEW_NOT_CONFIRMED": EXIT_INCOMPLETE,
    "SYNTHETIC_UNKNOWN": EXIT_INCOMPLETE,
    "RENDER_NOT_AVAILABLE": EXIT_INCOMPLETE,
    # --- illegal / conflicting state (非法/冲突类 → 2) ---
    "REVIEW_INVALID": EXIT_USAGE,
    "REVIEW_CONFLICT": EXIT_USAGE,
    "REVIEW_HISTORICAL": EXIT_USAGE,
    "IDENTITY_BROKEN": EXIT_USAGE,
    "STRUCTURAL_CORRUPT": EXIT_USAGE,
    "SEMANTIC_CONFLICT": EXIT_USAGE,
    "PROVENANCE_CONFLICT": EXIT_USAGE,
    "EXECUTION_UNSAFE": EXIT_USAGE,
    "CASE_CORRUPT": EXIT_USAGE,
    "UNSAFE_SQL_PACKAGE": EXIT_USAGE,
    "RELATION_SPEC_OVERSIZE": EXIT_USAGE,
    "OUTPUT_NOT_WRITABLE": EXIT_USAGE,
    "UNSUPPORTED_NATIVE_KIND": EXIT_USAGE,
    # --- tool fault after writing started → 1 ---
    "SELF_VALIDATION_FAILED": EXIT_INTERNAL_ERROR,
}


# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------


def _mib_argument(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if not 1 <= value <= 1024:
        raise argparse.ArgumentTypeError("value must be between 1 and 1024 MiB")
    return value


def _time_budget_argument(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if not 1 <= value <= MAX_TIME_BUDGET_SECONDS:
        raise argparse.ArgumentTypeError(
            "--time-budget-seconds must be a whole number between 1 and "
            f"{MAX_TIME_BUDGET_SECONDS}"
        )
    return value


def _format_argument(text: str) -> ExportFormat:
    try:
        return ExportFormat(text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"unknown export format {text!r}; expected sql or regression"
        ) from None


def register_delivery_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register the three D4 delivery subcommands on the offline parser."""
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--input", required=True, metavar="SOURCE-DIRECTORY")
    shared.add_argument("--output", required=True, metavar="NEW-DIRECTORY")
    shared.add_argument(
        "--input-kind",
        choices=("generation", "run", "trace", "attempt", "delivery"),
        default=None,
        help="expected native format of --input (default: auto-detect)",
    )
    shared.add_argument(
        "--time-budget-seconds",
        type=_time_budget_argument,
        default=None,
        metavar="N",
        help="audit time budget in whole seconds (default: Limits default)",
    )
    shared.add_argument(
        "--max-input-mib",
        type=_mib_argument,
        default=None,
        metavar="N",
        help="total input read budget in MiB (default: Limits default)",
    )
    shared.add_argument(
        "--max-output-mib",
        type=_mib_argument,
        default=None,
        metavar="N",
        help="total output write budget in MiB (default: Limits default)",
    )

    verify = subparsers.add_parser(
        "evidence-verify",
        parents=[shared],
        help="re-audit one evidence source and seal a verification package",
    )
    verify.set_defaults(delivery_command="evidence-verify")

    report = subparsers.add_parser(
        "report",
        parents=[shared],
        help="build a human-readable evidence report package",
    )
    report.add_argument(
        "--review",
        action="append",
        default=None,
        metavar="FILE",
        help="finding-review JSON document; repeatable",
    )
    report.set_defaults(delivery_command="report")

    export = subparsers.add_parser(
        "export",
        parents=[shared],
        help="export one selected case as SQL-debug or regression material",
    )
    export.add_argument("--case-id", required=True, metavar="CASE-ID")
    export.add_argument("--select", required=True, choices=("original", "best"))
    export.add_argument("--occurrence-id", default=None, metavar="ID")
    export.add_argument("--format", required=True, type=_format_argument)
    export.add_argument(
        "--review",
        action="append",
        default=None,
        metavar="FILE",
        help="finding-review JSON document; repeatable",
    )
    export.set_defaults(delivery_command="export")


def dispatch_delivery(args: argparse.Namespace) -> int:
    """Dispatch one delivery subcommand; returns the process exit code."""
    handler = _DELIVERY_HANDLERS[args.delivery_command]
    cancel = _CancelState()
    previous = _install_sigint_handler(cancel)
    try:
        return handler(args, cancel)
    except KeyboardInterrupt:
        # The installed handler absorbs the first SIGINT; a second delivered
        # SIGINT (or a non-installable context) lands here and maps to 130.
        _error_line("cancelled by user (SIGINT)")
        return EXIT_CANCELLED
    except Exception as exc:  # internal fault: exit 1, never a false pass
        _error_line(f"internal error: {exc!r}")
        return EXIT_INTERNAL_ERROR
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


# --------------------------------------------------------------------------
# Error mapping for the derivation pipeline
# --------------------------------------------------------------------------


class _CommandFailure(Exception):
    """A refusal or environment failure already mapped to an exit code.

    ``message`` is user-facing and printed to stderr by the command wrapper.
    Raised for usage refusals (exit 2) and source-changed refusals (exit 3)
    detected inside the pipeline; every other error family is mapped by
    :func:`_pipeline_errors`.
    """

    def __init__(self, exit_code: int, message: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.message = message


@contextmanager
def _pipeline_errors() -> Iterator[None]:
    """Map pipeline error families onto exit codes (design 6.3).

    Order matters: ``ControlCancelled``/``BudgetExhaustedError`` are
    ``ContractError`` subclasses, and ``SnapshotIoError``/
    ``SourceChangedError`` are ``EvidenceReadError`` subclasses, so the
    specific families must be caught before their bases.
    """
    try:
        yield
    except _CommandFailure as exc:
        _error_line(exc.message)
        raise _ExitWithCode(exc.exit_code) from None
    except ControlCancelled:
        _error_line("cancelled by user (SIGINT); the unsealed output directory was left in place")
        raise _ExitWithCode(EXIT_CANCELLED) from None
    except BudgetExhaustedError as exc:
        _error_line(f"time budget exhausted: {exc}")
        raise _ExitWithCode(EXIT_INCOMPLETE) from None
    except SourceChangedError as exc:
        _error_line(f"the source changed while it was being read: {exc}")
        raise _ExitWithCode(EXIT_INCOMPLETE) from None
    except SnapshotIoError as exc:
        _error_line(f"output I/O failure: {exc}")
        raise _ExitWithCode(EXIT_INTERNAL_ERROR) from None
    except DeliveryError as exc:
        # Delivery-package integrity errors surface as validation problems
        # (exit 2) before anything is written; one here is a tool fault.
        _error_line(f"internal delivery error: {exc}")
        raise _ExitWithCode(EXIT_INTERNAL_ERROR) from None
    except EvidenceReadError as exc:
        # RootInvalidError, RootDetectionError, SnapshotSetupError,
        # MissingEntryError, ReadLimitExceededError: the input does not
        # satisfy the stated limits or is not a readable evidence root.
        _error_line(exc)
        raise _ExitWithCode(EXIT_USAGE) from None
    except ContractError as exc:
        # Corrupt native root documents found during enumeration.
        _error_line(exc)
        raise _ExitWithCode(EXIT_USAGE) from None
    except OSError as exc:
        _error_line(f"output I/O failure: {exc}")
        raise _ExitWithCode(EXIT_INTERNAL_ERROR) from None


class _ExitWithCode(Exception):
    """Internal control-flow signal carrying a final exit code."""

    def __init__(self, exit_code: int) -> None:
        super().__init__(exit_code)
        self.exit_code = exit_code


def _finish(command: Callable[[], int]) -> int:
    """Run a command body under :func:`_pipeline_errors` and turn
    :class:`_ExitWithCode` into its exit code.  The mapping context manager
    must live INSIDE this catcher: it converts a mapped exception into
    ``_ExitWithCode`` while unwinding, and that replacement surfaces here."""
    try:
        with _pipeline_errors():
            return command()
    except _ExitWithCode as exc:
        return exc.exit_code


# --------------------------------------------------------------------------
# Shared derivation pipeline
# --------------------------------------------------------------------------


def _monotonic() -> float:
    """``time.monotonic`` behind a module-level seam so tests can simulate
    budget expiry deterministically."""
    return time.monotonic()


def _limits_from_args(args: argparse.Namespace) -> Limits:
    """Build read/write limits from the CLI flags.

    Flags are never unlimited: with no flag the :class:`Limits` defaults
    apply.  ``--max-input-mib``/``--max-output-mib`` cap the totals and
    lower the single-file caps when the total is smaller than the default
    single-file cap (so one file can never exceed the stated total).
    """
    overrides: dict[str, float] = {}
    if args.max_input_mib is not None:
        total = args.max_input_mib * 1024 * 1024
        overrides["max_total_source_bytes"] = total
        if total < Limits().max_single_source_file_bytes:
            overrides["max_single_source_file_bytes"] = total
    if args.max_output_mib is not None:
        total = args.max_output_mib * 1024 * 1024
        overrides["max_output_total_bytes"] = total
        if total < Limits().max_output_single_file_bytes:
            overrides["max_output_single_file_bytes"] = total
    if args.time_budget_seconds is not None:
        overrides["time_budget_seconds"] = float(args.time_budget_seconds)
    return Limits(**overrides)


@dataclass(frozen=True)
class DerivedSource:
    """One derived source assessment plus everything the sealing steps need.

    ``workspace`` is the snapshot output root (the caller's ``--output`` for
    verify/report, a private temporary directory for export); it holds
    ``raw/<source_id>/`` plus, once sealed, the package documents.
    """

    assessment: SourceAssessment
    plan: SourcePlan
    snapshot: object  # evidence.snapshot.SnapshotResult
    workspace: Path
    limits: Limits
    control: Control
    descriptor: SourceDescriptor
    delivery_id: str
    synthetic: SyntheticKind
    occurrences: tuple  # tuple[FindingOccurrence, ...]
    comparisons: dict  # attempt key -> decoded Comparison | None
    runner_manifest: object  # RunnerManifest | None


def _load_review_files(paths: Optional[Sequence[str]]) -> list:
    """Strictly decode every ``--review`` document (contracts codec).

    Runs before any output directory is touched so an illegal review is a
    pure usage refusal (exit 2) with no output skeleton left behind.
    """
    reviews = []
    for path_text in paths or ():
        try:
            data = Path(path_text).read_bytes()
        except OSError as exc:
            raise _CommandFailure(
                EXIT_USAGE, f"cannot read review file {path_text!r}: {exc}"
            ) from None
        try:
            reviews.append(decode_finding_review(parse_strict_json(data), what=path_text))
        except ContractError as exc:
            raise _CommandFailure(
                EXIT_USAGE, f"illegal review document {path_text!r}: {exc}"
            ) from None
    return reviews


def _resolve_input_root(
    root: Path, kind_hint: Optional[str], limits: Limits
) -> tuple[Path, NativeKind]:
    """Resolve ``--input`` to the native root to derive.

    A delivery package is validated FIRST (:func:`validate_delivery_dir`);
    any problem — corrupt manifest, hash mismatch, missing file, extra file
    — is a refusal (exit 2).  The single ``raw/<source-id>/`` closure is
    then re-derived as a native source.
    """
    try:
        kind = detect_native_kind(root, kind_hint=kind_hint)
    except RootDetectionError as exc:
        raise _CommandFailure(
            EXIT_USAGE, f"cannot identify the input format: {exc}"
        ) from None
    if kind is not NativeKind.DELIVERY:
        return root, kind

    validation = validate_delivery_dir(root, limits)
    if not validation.ok:
        details = "; ".join(
            f"{problem.code}: {problem.path or '<root>'}"
            for problem in validation.problems[:8]
        )
        raise _CommandFailure(
            EXIT_USAGE,
            "the delivery package failed integrity validation: " + details,
        )
    raw_root = root / "raw"
    try:
        entries = sorted(os.scandir(raw_root), key=lambda entry: entry.name)
    except OSError as exc:
        raise _CommandFailure(
            EXIT_USAGE, f"cannot list the package raw closure: {exc}"
        ) from None
    source_dirs = [entry for entry in entries if entry.is_dir(follow_symlinks=False)]
    if len(source_dirs) != 1:
        raise _CommandFailure(
            EXIT_USAGE,
            "a delivery package must contain exactly one raw/<source-id> "
            f"directory; found {len(source_dirs)}",
        )
    inner = Path(source_dirs[0].path)
    try:
        inner_kind = detect_native_kind(inner)
    except RootDetectionError as exc:
        raise _CommandFailure(
            EXIT_USAGE, f"cannot identify the packaged source format: {exc}"
        ) from None
    if inner_kind in (NativeKind.DELIVERY, NativeKind.UNKNOWN):
        raise _CommandFailure(
            EXIT_USAGE,
            "the raw closure of a delivery package must hold native "
            f"evidence, not another package (detected {inner_kind.value})",
        )
    return inner, inner_kind


def _synthetic_of(assessment: SourceAssessment) -> SyntheticKind:
    """Aggregate the per-attempt synthetic classification conservatively.

    Every attempt row carries the synthetic flag of its own recorded
    request (assessment layer); a single distinct non-UNKNOWN value wins,
    mixed or absent values keep UNKNOWN (design 6.2.2: an undetermined
    classification must never be upgraded).
    """
    concrete = {
        row.synthetic
        for row in assessment.attempts
        if row.synthetic is not SyntheticKind.UNKNOWN
    }
    if len(concrete) == 1:
        return next(iter(concrete))
    return SyntheticKind.UNKNOWN


def _descriptor_for(snapshot, plan: SourcePlan, synthetic: SyntheticKind) -> SourceDescriptor:
    collection = CollectionStatus.COLLECTED
    if snapshot.source_changed:
        collection = CollectionStatus.SOURCE_CHANGED
    elif snapshot.missing_paths:
        collection = CollectionStatus.PARTIALLY_READ
    return SourceDescriptor(
        source_id=snapshot.source_id,
        native_kind=plan.kind,
        root_document=plan.root_document,
        snapshot_digest=snapshot.snapshot_digest,
        synthetic=synthetic,
        collection_status=collection,
        native_versions=plan.native_versions,
        observed_writer_version=plan.observed_writer_version,
        source_commit=plan.source_commit,
        producer=plan.producer,
        missing_files=snapshot.missing_paths,
    )


def _open_snapshot_reader(snapshot, workspace: Path, limits: Limits, deadline: float):
    """A fresh bounded reader over the snapshot copy at
    ``<workspace>/raw/<source-id>/`` (the same bytes that were hashed)."""
    return SourceReader(
        workspace / "raw" / snapshot.source_id,
        limits=limits,
        clock=_monotonic,
        deadline=deadline,
    )


def _load_attempt_comparisons(
    snapshot, assessment: SourceAssessment, workspace: Path, limits: Limits, deadline: float
) -> dict:
    """Strictly decode each assessed attempt's recorded comparison document
    from the SNAPSHOT copy — the same bytes the semantic audit hashed.

    Returns ``{attempt_key: Comparison | None}`` keyed by ``attempt_id``
    (``""`` for the single pseudo-attempt of attempt/trace sources).  A
    missing or undecodable document maps to ``None``; statuses are never
    fabricated from row data alone.
    """
    keys = [row.attempt_id or "" for row in assessment.attempts]
    if not keys:
        return {}
    try:
        with _open_snapshot_reader(snapshot, workspace, limits, deadline) as reader:
            result: dict = {}
            for key in keys:
                relpath = (
                    "comparison.json" if key == "" else f"attempts/{key}/comparison.json"
                )
                try:
                    data = reader.read_bytes(
                        relpath, max_bytes=limits.max_json_document_bytes
                    )
                    result[key] = decode_comparison(parse_strict_json(data))
                except (EvidenceReadError, ContractError):
                    result[key] = None
            return result
    except (EvidenceReadError, OSError):
        # The snapshot copy itself became unreadable: no statuses at all.
        return {key: None for key in keys}


def _load_runner_manifest(snapshot, workspace: Path, limits: Limits, deadline: float):
    if snapshot.kind is not NativeKind.RUN:
        return None
    try:
        with _open_snapshot_reader(snapshot, workspace, limits, deadline) as reader:
            data = reader.read_bytes(
                "runner-manifest.json", max_bytes=limits.max_json_document_bytes
            )
            return load_runner_manifest(parse_strict_json(data))
    except (EvidenceReadError, OSError, ContractError):
        # Structural corruption is already reported by the structural
        # dimension; the counts section is then simply omitted.
        return None


def _load_generation_manifest(
    snapshot, workspace: Path, limits: Limits, deadline: float
):
    if snapshot.kind is not NativeKind.GENERATION:
        return None
    try:
        with _open_snapshot_reader(snapshot, workspace, limits, deadline) as reader:
            data = reader.read_bytes(
                "generation-manifest.json", max_bytes=limits.max_json_document_bytes
            )
            return decode_generation_manifest(parse_strict_json(data))
    except (EvidenceReadError, OSError, ContractError):
        return None


# Map a recorded comparison status onto the reporting-layer attempt status
# (design 6.4.4 execution row; ATTEMPT_STATUSES vocabulary).
_ATTEMPT_STATUS_MAP = {
    ComparisonStatus.MISMATCH_CANDIDATE: "MATCH_CANDIDATE",
    ComparisonStatus.MATCH: "COMPLETED",
    ComparisonStatus.NOT_APPLICABLE: "NOT_APPLICABLE",
    ComparisonStatus.INCONCLUSIVE: "UNDECIDABLE",
}


def _execution_counts(
    snapshot, runner_manifest, comparisons: dict, assessment: SourceAssessment
) -> Optional[ExecutionCounts]:
    """Execution-layer counts for run sources.

    Only attempts whose recorded comparison could be decoded from the
    snapshot copy are summarised; attempts without a readable document are
    omitted (never fabricated).  ``both_selects`` stays ``None`` — the
    native comparison document does not record it and D4 does not guess.
    """
    if snapshot.kind is not NativeKind.RUN or runner_manifest is None:
        return None
    summaries = []
    for row in assessment.attempts:
        if row.attempt_id is None:
            continue
        comparison = comparisons.get(row.attempt_id)
        if comparison is None:
            continue
        status = _ATTEMPT_STATUS_MAP.get(comparison.status)
        if status is None:
            continue
        summaries.append(
            AttemptSummary(attempt_id=row.attempt_id, both_selects=None, status=status)
        )
    return compute_execution_counts(runner_manifest, summaries)


def _candidate_attempt_keys(
    assessment: SourceAssessment, plan: SourcePlan, comparisons: dict
) -> tuple[str, ...]:
    """The precise exit-4 candidate predicate (design 6.3 row 4).

    An attempt row counts as a *recomputable candidate* exactly when:

    (a) its semantic recompute is RECOMPUTED — the offline oracle actually
        reproduced the recorded comparison hash — AND
    (b) the recorded outcome is a mismatch candidate.  For run/attempt
        sources (b) is read from the snapshot copy's comparison document
        (``ComparisonStatus.MISMATCH_CANDIDATE``); a missing or undecodable
        document is NOT a candidate (conservative).  For full-trace sources
        the D2 engine only records comparisons inside a mismatch-candidate
        reduction or replay chain (legacy traces are NOT_RECOMPUTED), so
        RECOMPUTED alone satisfies (b) there — a documented interpretation.

    Rows whose semantic dimension status is CONFLICT never count: the
    record contradicts its own documents, so nothing about it is
    recomputable.  The return value is the sorted tuple of contributing
    attempt keys (``""`` for single-pseudo-attempt sources), empty when
    there is none.
    """
    if assessment.semantic.status is SemanticStatus.CONFLICT:
        return ()
    trace = plan.kind is NativeKind.TRACE
    keys = []
    for row in assessment.attempts:
        if row.recompute is not SemanticStatus.RECOMPUTED:
            continue
        key = row.attempt_id or ""
        if trace:
            keys.append(key)
            continue
        comparison = comparisons.get(key)
        if comparison is not None and comparison.status is (
            ComparisonStatus.MISMATCH_CANDIDATE
        ):
            keys.append(key)
    return tuple(sorted(keys))


def _derive_source(
    input_text: str,
    workspace: Path,
    args: argparse.Namespace,
    cancel: _CancelState,
) -> DerivedSource:
    """Run detect → enumerate → snapshot → assess for one source.

    Refusals raise :class:`_CommandFailure` or are mapped by
    :func:`_pipeline_errors`; callers must wrap the call accordingly.
    """
    limits = _limits_from_args(args)
    start = _monotonic()
    deadline = start + limits.time_budget_seconds
    control = Control(_monotonic, deadline, cancel.flag)

    root, kind = _resolve_input_root(
        Path(input_text), getattr(args, "input_kind", None), limits
    )
    with SourceReader(root, limits=limits, clock=_monotonic, deadline=deadline) as reader:
        plan = enumerate_source(reader, kind, limits)
        if not plan.files:
            raise _CommandFailure(
                EXIT_USAGE,
                "the input root holds no readable evidence files; nothing "
                "to verify (zero comparable cases is not a pass)",
            )
        snapshotter = Snapshotter(
            reader, workspace, limits, clock=_monotonic, deadline=deadline
        )
        snapshot = snapshotter.capture(plan)
        if snapshot.source_changed:
            # Nothing was written; sealing would misrepresent a moving
            # source as verified evidence (design 6.4.1 item 4).
            raise _CommandFailure(
                EXIT_INCOMPLETE,
                "the source changed while it was being read; freeze the "
                "input (copy it) and re-run against the frozen copy",
            )
        assessment = assess_snapshot(
            snapshot, reader, plan, limits, control, snapshot_root=workspace
        )

    synthetic = _synthetic_of(assessment)
    descriptor = _descriptor_for(snapshot, plan, synthetic)
    delivery_id = compute_delivery_id((descriptor,))
    try:
        occurrences = collect_occurrences(assessment.attempts, assessment.source_id)
    except DuplicateOccurrenceError as exc:
        raise _CommandFailure(
            EXIT_USAGE, f"ambiguous finding identity in the source: {exc}"
        ) from None
    comparisons = _load_attempt_comparisons(
        snapshot, assessment, workspace, limits, deadline
    )
    runner_manifest = _load_runner_manifest(snapshot, workspace, limits, deadline)
    return DerivedSource(
        assessment=assessment,
        plan=plan,
        snapshot=snapshot,
        workspace=workspace,
        limits=limits,
        control=control,
        descriptor=descriptor,
        delivery_id=delivery_id,
        synthetic=synthetic,
        occurrences=occurrences,
        comparisons=comparisons,
        runner_manifest=runner_manifest,
    )


# --------------------------------------------------------------------------
# Assessment reasons and summaries
# --------------------------------------------------------------------------


def _assessment_reasons(assessment: SourceAssessment) -> list[ExitReason]:
    """Translate the four dimensions into retained exit reasons.

    Applicability is respected exactly as the assessment layer states it:
    a dimension that does not apply to this native kind (e.g. semantics or
    provenance for a pure generation source) induces no reason at all.
    """
    reasons: list[ExitReason] = []
    structural = assessment.structural
    if structural.status in (StructuralStatus.CORRUPT, StructuralStatus.UNSUPPORTED):
        reasons.append(
            ExitReason(EXIT_USAGE, f"structural_{structural.status.value.lower()}")
        )
    elif structural.status is StructuralStatus.PARTIAL:
        reasons.append(ExitReason(EXIT_INCOMPLETE, "structural_partial"))

    semantic = assessment.semantic
    if semantic.status is SemanticStatus.CONFLICT:
        reasons.append(ExitReason(EXIT_USAGE, "semantic_conflict"))
    elif semantic.applicable and semantic.status is SemanticStatus.NOT_RECOMPUTED:
        reasons.append(ExitReason(EXIT_INCOMPLETE, "semantic_not_recomputed"))

    provenance = assessment.provenance
    if provenance.status.value == "CONFLICT":
        reasons.append(ExitReason(EXIT_USAGE, "provenance_conflict"))
    elif provenance.applicable and provenance.status.value == "UNVERIFIED":
        reasons.append(ExitReason(EXIT_INCOMPLETE, "provenance_unverified"))

    safety = assessment.execution_safety
    if safety.status.value == "UNSAFE":
        reasons.append(ExitReason(EXIT_INCOMPLETE, "execution_safety_unsafe"))
    elif safety.applicable and safety.status.value == "UNKNOWN":
        reasons.append(ExitReason(EXIT_INCOMPLETE, "execution_safety_unknown"))

    for dimension in (structural, semantic, provenance, safety):
        if "budget_exhausted" in dimension.reason_codes:
            reasons.append(ExitReason(EXIT_INCOMPLETE, "budget_exhausted"))
            break
    return reasons


def _budget_exhausted(derived: DerivedSource, reasons: Sequence[ExitReason]) -> bool:
    """The run hit the time budget: the control clock passed the deadline or
    the assessment recorded a skipped object for budget reasons."""
    return derived.control.expired() or any(
        reason.reason == "budget_exhausted" for reason in reasons
    )


def _retain_budget_reason(reasons: list[ExitReason]) -> None:
    """A budget-exhausted run is never a clean success (exit 3), even when
    no individual assessment object recorded the skip."""
    if not any(reason.reason == "budget_exhausted" for reason in reasons):
        reasons.append(ExitReason(EXIT_INCOMPLETE, "budget_exhausted"))


def _print_summary(
    command: str,
    derived: DerivedSource,
    reasons: Sequence[ExitReason],
    *,
    output_path: Path,
    completion: Optional[DeliveryCompletion] = None,
    candidate_keys: Sequence[str] = (),
) -> None:
    """Human stdout summary: identity, the four dimension statuses,
    completion, delivery id, retained reasons, output path.  English only."""
    assessment = derived.assessment
    lines = [
        f"command: {command}",
        f"source_id: {assessment.source_id}",
        f"native_kind: {assessment.native_kind.value}",
        f"structural: {assessment.structural.status.value}",
        f"semantic: {assessment.semantic.status.value}",
        f"provenance: {assessment.provenance.status.value}",
        f"execution_safety: {assessment.execution_safety.status.value}",
    ]
    if completion is not None:
        lines.append(f"completion: {completion.value}")
    lines.append(f"delivery_id: {derived.delivery_id}")
    lines.append(f"synthetic: {derived.synthetic.value}")
    if derived.snapshot.orphan_files:
        lines.append(f"orphan_files: {len(derived.snapshot.orphan_files)}")
    if candidate_keys:
        lines.append(f"candidate_attempts: {len(candidate_keys)}")
    unique_reasons = sorted({reason.reason for reason in reasons})
    lines.append("reasons: " + (", ".join(unique_reasons) if unique_reasons else "none"))
    lines.append(f"output: {output_path}")
    lines.append(_OFFLINE_NOTE)
    if candidate_keys:
        lines.append(_CANDIDATE_NOTE)
    print("\n".join(lines))


def _write_document(path: Path, obj: object) -> None:
    path.write_bytes(canonical_json(obj) + b"\n")


def _evidence_assessment_document(assessment: SourceAssessment) -> EvidenceAssessment:
    """The sanctioned ``assessment.json`` payload.

    ``SourceAssessment`` (the assessment-layer aggregate) has no serializer
    of its own; :class:`EvidenceAssessment` is the contracts-layer document
    with the sanctioned ``to_obj`` and carries exactly the four dimension
    records the file must hold (the attempt rows/selection proof stay in
    the report document, not in assessment.json).
    """
    return EvidenceAssessment(
        structural=assessment.structural,
        semantic=assessment.semantic,
        provenance=assessment.provenance,
        execution_safety=assessment.execution_safety,
    )


# --------------------------------------------------------------------------
# evidence-verify
# --------------------------------------------------------------------------


def _run_evidence_verify(args: argparse.Namespace, cancel: _CancelState) -> int:
    output = Path(args.output)

    def _body() -> int:
        derived = _derive_source(args.input, output, args, cancel)
        assessment = derived.assessment
        reasons = _assessment_reasons(assessment)
        candidate_keys = _candidate_attempt_keys(
            assessment, derived.plan, derived.comparisons
        )
        if candidate_keys:
            reasons.append(ExitReason(EXIT_CANDIDATE, "recomputable_candidate_present"))
        budget = _budget_exhausted(derived, reasons)
        completion = DeliveryCompletion.PARTIAL if budget else DeliveryCompletion.COMPLETE
        if budget:
            _retain_budget_reason(reasons)
        if cancel.flag():
            # Design 6.3/6.4.1: a cancelled delivery must not publish a
            # COMPLETE manifest; the unsealed directory stays for inspection.
            _print_summary(
                "evidence-verify",
                derived,
                reasons,
                output_path=output,
                candidate_keys=candidate_keys,
            )
            _error_line("cancelled by user (SIGINT); the evidence manifest was not sealed")
            return EXIT_CANCELLED
        try:
            _write_document(output / "assessment.json", _evidence_assessment_document(assessment).to_obj())
            files = collect_delivery_files(output, derived.limits)
            manifest = EvidenceManifest(
                delivery_id=derived.delivery_id,
                kind=DeliveryKind.VERIFICATION,
                writer_version=WRITER_VERSION,
                sources=(derived.descriptor,),
                files=files,
                completion=completion,
                producer=derived.plan.producer,
            )
            write_evidence_manifest(output, manifest)
        except (DeliveryError, OSError) as exc:
            _error_line(f"output I/O failure: {exc}")
            return EXIT_INTERNAL_ERROR
        _print_summary(
            "evidence-verify",
            derived,
            reasons,
            output_path=output,
            completion=completion,
            candidate_keys=candidate_keys,
        )
        return compute_exit_code(reasons)

    return _finish(_body)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def _dedupe_reviews(reviews: Sequence) -> list:
    """Keep one document per review_id (first wins); duplicates are legal
    input but only one copy is written into ``reviews/``."""
    seen: set[str] = set()
    ordered = []
    for review in reviews:
        if review.review_id in seen:
            continue
        seen.add(review.review_id)
        ordered.append(review)
    return ordered


def _run_report(args: argparse.Namespace, cancel: _CancelState) -> int:
    output = Path(args.output)

    def _body() -> int:
        try:
            reviews = _load_review_files(args.review)
        except _CommandFailure as exc:
            _error_line(exc.message)
            return exc.exit_code
        derived = _derive_source(args.input, output, args, cancel)
        assessment = derived.assessment
        limits = derived.limits
        reasons = _assessment_reasons(assessment)
        candidate_keys = _candidate_attempt_keys(
            assessment, derived.plan, derived.comparisons
        )
        if candidate_keys:
            reasons.append(ExitReason(EXIT_CANDIDATE, "recomputable_candidate_present"))
        budget = _budget_exhausted(derived, reasons)
        completion = DeliveryCompletion.PARTIAL if budget else DeliveryCompletion.COMPLETE
        if budget:
            _retain_budget_reason(reasons)

        occurrence_ids = {occurrence.occurrence_id for occurrence in derived.occurrences}
        try:
            reviewset = apply_reviews(
                # Reviews bind the CURRENT evidence digest (the derived
                # delivery_id) and the occurrences this source actually
                # carries, in explicit mode: a review for other evidence
                # stays historical and is displayed, never applied (6.4.5).
                reviews,
                evidence_digest=derived.delivery_id,
                occurrence_ids=occurrence_ids,
                mode="explicit",
            )
        except ReviewValidationError as exc:
            _error_line(f"illegal review input: {exc}")
            return EXIT_USAGE
        if reviewset.has_conflict:
            # Mutually exclusive opinions are preserved side by side in the
            # report; the original observation stays untouched (6.4.5).
            reasons.append(ExitReason(EXIT_INCOMPLETE, "review_conflict"))

        if cancel.flag():
            _print_summary(
                "report",
                derived,
                reasons,
                output_path=output,
                candidate_keys=candidate_keys,
            )
            _error_line("cancelled by user (SIGINT); the evidence manifest was not sealed")
            return EXIT_CANCELLED

        try:
            _write_document(
                output / "assessment.json",
                _evidence_assessment_document(assessment).to_obj(),
            )
            # Copies of every provided review go next to the evidence so the
            # package is self-contained (dedup by review_id).  With no
            # reviews the directory is not created at all.
            for review in _dedupe_reviews(reviews):
                reviews_dir = output / "reviews"
                reviews_dir.mkdir(exist_ok=True)
                _write_document(reviews_dir / f"{review.review_id}.json", review.to_obj())

            generation_manifest = _load_generation_manifest(
                derived.snapshot, output, limits, derived.control.deadline
            )
            generation_counts: Optional[GenerationCounts] = (
                compute_generation_counts(generation_manifest)
                if generation_manifest is not None
                else None
            )
            execution_counts = _execution_counts(
                derived.snapshot, derived.runner_manifest, derived.comparisons, assessment
            )

            # The inventory lists the pre-report evidence (assessment, raw
            # closure, review copies): report files cannot hash themselves;
            # they are sealed through the manifest instead.
            pre_files = collect_delivery_files(output, limits)
            orphan_problems = tuple(
                Problem(
                    code="orphan_file",
                    path=orphan,
                    detail="present in the source tree outside the declared "
                    "closure; recorded, never copied or interpreted",
                )
                for orphan in derived.snapshot.orphan_files
            )
            document = build_report(
                assessment=assessment,
                tool_name="mt-typecheck",
                writer_version=WRITER_VERSION,
                delivery_id=derived.delivery_id,
                synthetic=derived.synthetic,
                findings=aggregate_findings(
                    derived.occurrences,
                    reviews=reviews,
                    evidence_digest=derived.delivery_id,
                ),
                reviews=reviewset,
                occurrences=derived.occurrences,
                producer=derived.plan.producer,
                source_commit=derived.plan.source_commit,
                known_limitations=(_CASE_DETAIL_LIMITATION,),
                generation_counts=generation_counts,
                execution_counts=execution_counts,
                files=pre_files,
                problems=orphan_problems,
                reproduction_notes=(
                    "export reproduction: mt-typecheck export --input <this "
                    "package> --case-id <case-id> --select original --format "
                    "sql --output NEW-DIRECTORY",
                ),
            )
            _write_document(output / "report.json", document.to_obj())
            (output / "report.md").write_text(
                render_markdown(document, max_bytes=limits.max_markdown_bytes),
                encoding="utf-8",
            )
            (output / "report.html").write_text(
                render_html(document, max_bytes=limits.max_html_bytes),
                encoding="utf-8",
            )
            files = collect_delivery_files(output, limits)
            manifest = EvidenceManifest(
                delivery_id=derived.delivery_id,
                kind=DeliveryKind.REPORT,
                writer_version=WRITER_VERSION,
                sources=(derived.descriptor,),
                files=files,
                completion=completion,
                producer=derived.plan.producer,
            )
            write_evidence_manifest(output, manifest)
        except LimitExceeded as exc:
            # The report cannot be sealed within the render budget; the
            # unsealed directory stays (no manifest) and the outcome stays
            # partial, never a successful match.
            _error_line(f"report render budget exceeded: {exc}")
            return compute_exit_code(
                reasons + [ExitReason(EXIT_INCOMPLETE, "render_budget_exceeded")]
            )
        except (DeliveryError, OSError) as exc:
            _error_line(f"output I/O failure: {exc}")
            return EXIT_INTERNAL_ERROR
        except UnsafeLinkError as exc:
            _error_line(f"internal report link error: {exc}")
            return EXIT_INTERNAL_ERROR

        findings = document.findings
        _print_summary(
            "report",
            derived,
            reasons,
            output_path=output,
            completion=completion,
            candidate_keys=candidate_keys,
        )
        print(
            "findings: "
            f"real_candidates={findings.real_candidates} "
            f"synthetic_candidates={findings.synthetic_candidates} "
            f"unknown_synthetic_candidates={findings.unknown_synthetic_candidates} "
            f"conflicts={findings.conflicts} "
            f"unique_case_ids={findings.unique_case_ids}"
        )
        print(_CANDIDATE_NOTE)
        return compute_exit_code(reasons)

    return _finish(_body)


# --------------------------------------------------------------------------
# export
# --------------------------------------------------------------------------


def _bind_review_for_export(reviews, reviewset, selected):
    """Pick the review bound to the exported occurrence (design 6.4.6).

    The export gates require the review to bind the SELECTED occurrence and
    the CURRENT delivery digest.  ``apply_reviews`` already enforced the
    digest; here the occurrence binding is resolved: the first accepted
    review (sorted by review_id) naming ``selected.occurrence_id`` wins.
    When no accepted review names it but accepted reviews exist, the first
    accepted review is still handed over so the gate reports the precise
    binding failure (REVIEW_HISTORICAL → exit 2) instead of a bare
    REVIEW_REQUIRED (exit 3); with no accepted reviews the hand-over is
    ``None`` (REVIEW_REQUIRED).  SQL-debug exports ignore the review.
    """
    if selected.occurrence_id is None:
        return None
    for review in reviewset.accepted:
        if selected.occurrence_id in review.occurrence_ids:
            return review
    if reviewset.accepted:
        return reviewset.accepted[0]
    return None


def _run_export(args: argparse.Namespace, cancel: _CancelState) -> int:
    def _body() -> int:
        try:
            reviews = _load_review_files(args.review)
        except _CommandFailure as exc:
            _error_line(exc.message)
            return exc.exit_code

        # Export writes its own package layout into --output; the derivation
        # snapshot therefore lives in a private workspace that never overlaps
        # the output directory (and is removed afterwards).  realpath: macOS
        # temporary roots are often symlinks, and placement checks compare
        # real paths.
        try:
            with tempfile.TemporaryDirectory(prefix="mt-typecheck-export-") as tmp:
                workspace = Path(os.path.realpath(tmp)) / "derive"
                derived = _derive_source(args.input, workspace, args, cancel)

                selector = CaseSelector(
                    case_id=args.case_id,
                    select=args.select,
                    occurrence_id=args.occurrence_id,
                )
                try:
                    selected = select_case(
                        derived.assessment,
                        selector,
                        plan=derived.plan,
                        reader=object(),  # parity parameter; selection opens its own reader
                        snapshot_root=workspace,
                        limits=derived.limits,
                        control=derived.control,
                    )
                except SelectionError as exc:
                    # Design 6.3 row 2: ambiguous or otherwise refused case
                    # selection is illegal input; nothing was written anywhere.
                    raise _CommandFailure(
                        EXIT_USAGE, f"case selection refused: {exc}"
                    ) from None

                try:
                    reviewset = apply_reviews(
                        reviews,
                        evidence_digest=derived.delivery_id,
                        occurrence_ids={
                            occurrence.occurrence_id
                            for occurrence in derived.occurrences
                        },
                        mode="explicit",
                    )
                except ReviewValidationError as exc:
                    _error_line(f"illegal review input: {exc}")
                    return EXIT_USAGE
                chosen = _bind_review_for_export(reviews, reviewset, selected)

                try:
                    outcome = export_case(
                        selected,
                        output_root=Path(args.output),
                        limits=derived.limits,
                        export_format=args.format,
                        review=chosen,
                        reviewset=reviewset,
                        assessment=derived.assessment,
                        delivery_id=derived.delivery_id,
                        producer=derived.plan.producer,
                        plan=derived.plan,
                    )
                except ExportRefused as exc:
                    exit_code = EXPORT_REFUSAL_EXIT.get(exc.code, EXIT_USAGE)
                    raise _CommandFailure(
                        exit_code, f"export refused [{exc.code}]: {exc.message}"
                    ) from None
                except (DeliveryError, OSError) as exc:
                    _error_line(f"output I/O failure: {exc}")
                    return EXIT_INTERNAL_ERROR
        except _CommandFailure as exc:
            _error_line(exc.message)
            return exc.exit_code
        except OSError as exc:
            # The private derivation workspace itself could not be created.
            _error_line(f"output I/O failure: {exc}")
            return EXIT_INTERNAL_ERROR

        _print_summary("export", derived, [], output_path=outcome.output_root)
        print(
            f"export_id: {outcome.export_id}\n"
            f"format: {outcome.format.value}\n"
            f"regression_eligible: "
            f"{str(outcome.refusal is None and outcome.regression_eligible).lower()}"
        )
        if outcome.refusal is None and outcome.format is ExportFormat.SQL:
            print(
                "note: SQL-debug material is candidate/unverified reference "
                "material; it is never accepted by mt-typecheck run --input"
            )
        # Design 6.3: a successful export exits 0 even with retained risks.
        return EXIT_OK

    return _finish(_body)


# --------------------------------------------------------------------------
# Dispatch table (after the handlers are defined)
# --------------------------------------------------------------------------

_DELIVERY_HANDLERS = {
    "evidence-verify": _run_evidence_verify,
    "report": _run_report,
    "export": _run_export,
}
