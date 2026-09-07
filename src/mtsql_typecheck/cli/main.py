"""Offline CLI for D1 Phase 5: ``generate`` and ``validate`` (design 6.3.3).

This module is a thin, safety-focused wrapper around the pure generator and
the bundle layer:

    mt-typecheck generate --profile mysql80-exact-v1 --seed 42 --cases 100 \
        --output /path/to/new-directory
    mt-typecheck validate --input /path/to/new-directory

Safety invariants (design 6.5):

- No DSN parameter exists, no database connection is made, and no network
  call is performed.  The tool is offline; importing this module performs no
  I/O.
- The output directory must be a new directory; existing targets and symlink
  path components are refused (never followed).  Nothing inside an output
  directory is ever deleted or overwritten.
- ``--profile-file`` accepts only a restricted JSON profile document: it may
  filter already-reviewed rule/template/index combinations and adjust budgets
  within the hard caps, but cannot inject code, SQL or new rules.  Unknown
  fields, unknown or disabled rule versions, duplicate selectors and over-cap
  budgets are rejected.

Exit codes (design 6.3.3):

===  =========================================================
 0   generate: all requested ordinals emitted, manifest COMPLETE.
     validate: manifest COMPLETE and every check passed.  This is an
     *offline* success only; it never means a database MATCH.
 2   Illegal input (usage errors, unknown/disabled rule or version,
     existing output directory, symlink components) or, for validate,
     corrupt/illegal evidence (corruption outranks incompleteness).
 3   generate: legal request did not finish (retry/budget exhaustion,
     zero cases).  validate: saved content valid but manifest
     PARTIAL/ABORTED/legacy RUNNING.
 1   Tool internal error or non-content I/O failure.
130  The process was cancelled by the user (SIGINT).
===  =========================================================

Cancellation: for ``generate`` a SIGINT handler raises an internal cancel
flag that is forwarded as ``should_cancel`` to the bundle layer; generation
stops at the next ordinal boundary and the completed cases plus the
terminating manifest are persisted (status ABORTED), then the process exits
130 without a traceback.  For ``validate`` SIGINT keeps its default
disposition (raising ``KeyboardInterrupt``); it is caught and mapped to 130.
"""

from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import Optional

from mtsql_typecheck.contracts.case import ContractError, GenerationStatus
from mtsql_typecheck.contracts.codec import decode_profile, parse_strict_json
from mtsql_typecheck.generation.bundle import (
    BundleBudgetError,
    OutputDirExistsError,
    UnsafePathError,
    WriteOutcome,
    exit_code_for,
    generate_and_write,
    validate_output_dir,
)
from mtsql_typecheck.generation.generator import (
    GenerationResult,
    ProfileError,
    default_profile,
    validate_profile,
)

__all__ = ["main"]

PROGRAM = "mt-typecheck"
BUILTIN_PROFILE_NAMES = ("mysql80-exact-v1",)

EXIT_OK = 0
EXIT_INTERNAL_ERROR = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_CANCELLED = 130

UINT64_MAX = 2**64 - 1
MIN_CASES = 1
MAX_CASES = 10000

OFFLINE_NOTE = (
    "note: offline generation only; no database connection, execution or "
    "comparison was performed."
)


class UsageError(Exception):
    """A command-line input error; mapped to exit code 2."""


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """argparse parser that raises instead of calling ``sys.exit``.

    This keeps ``main()`` programmatically callable: usage errors become
    :class:`UsageError` (exit 2) instead of a process exit; ``--help`` still
    raises ``SystemExit(0)``, which :func:`main` converts to ``0``.
    """

    def error(self, message: str):  # type: ignore[override]
        raise UsageError(message)


def _uint64(text: str) -> int:
    try:
        value = int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"seed must be an integer, got {text!r}")
    if value < 0 or value > UINT64_MAX:
        raise argparse.ArgumentTypeError(
            f"seed must be a uint64 in [0, {UINT64_MAX}], got {value}"
        )
    return value


def _case_count(text: str) -> int:
    try:
        value = int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"cases must be an integer, got {text!r}")
    if value < MIN_CASES or value > MAX_CASES:
        raise argparse.ArgumentTypeError(
            f"cases must be in [{MIN_CASES}, {MAX_CASES}], got {value}"
        )
    return value


def _build_parser() -> _Parser:
    parser = _Parser(prog=PROGRAM, description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate", help="generate a case bundle into a new offline directory"
    )
    generate.add_argument("--profile", help="built-in profile name")
    generate.add_argument("--profile-file", help="restricted JSON profile file")
    generate.add_argument("--seed", required=True, type=_uint64, metavar="UINT64")
    generate.add_argument(
        "--cases", required=True, type=_case_count, metavar="1..10000"
    )
    generate.add_argument("--output", required=True, metavar="NEW-DIRECTORY")

    validate = subparsers.add_parser(
        "validate", help="offline-validate a written case bundle"
    )
    validate.add_argument("--input", required=True, metavar="BUNDLE-DIRECTORY")

    # Online subcommands (D3 Phase 5).  The import is deferred so the offline
    # parser construction keeps working without the online modules loaded,
    # and the online modules stay driver-free (no PyMySQL import).
    from .online import ONLINE_COMMANDS, register_online_commands

    register_online_commands(subparsers)
    parser._online_commands = frozenset(ONLINE_COMMANDS)  # type: ignore[attr-defined]

    # Delivery subcommands (D4 Phase 5).  The import is deferred like the
    # online one so offline parser construction stays self-contained.
    from .delivery import DELIVERY_COMMANDS, register_delivery_commands

    register_delivery_commands(subparsers)
    parser._delivery_commands = frozenset(DELIVERY_COMMANDS)  # type: ignore[attr-defined]
    return parser


# --------------------------------------------------------------------------
# Profile resolution (design 6.3.3)
# --------------------------------------------------------------------------


def _resolve_profile(profile_name: Optional[str], profile_file: Optional[str]):
    """Resolve --profile / --profile-file / built-in default to a Profile.

    The two options are mutually exclusive; only when neither is given is the
    built-in ``mysql80-exact-v1`` profile used.  All failures are input
    errors (exit 2).
    """
    if profile_name is not None and profile_file is not None:
        raise UsageError(
            "--profile and --profile-file are mutually exclusive; give exactly one"
        )
    if profile_name is not None:
        if profile_name not in BUILTIN_PROFILE_NAMES:
            raise UsageError(
                f"unknown profile {profile_name!r}; built-in profiles: "
                + ", ".join(BUILTIN_PROFILE_NAMES)
            )
        return default_profile()
    if profile_file is not None:
        return _load_profile_file(profile_file)
    return default_profile()


def _documented_profile_defaults() -> dict[str, object]:
    """The documented profile default values (design 6.3.3 schema 1)."""
    return default_profile().to_obj()


def _load_profile_file(path_text: str):
    """Strictly load a restricted profile JSON file.

    The loader backfills the documented profile defaults for missing fields
    and sorts the selector lists (design 6.3.3: "loader 先补齐有文档的
    profile 默认值并排序 selector"), then hands the completed document to
    the strict contract loader.  Unknown fields, illegal values, unknown or
    disabled rule versions, duplicate selectors and over-cap budgets are
    rejected by the completed document path; seed/cases never appear in a
    profile and are never taken from a profile file.
    """
    path = Path(path_text)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read profile file {str(path)!r}: {exc}")
    try:
        document = parse_strict_json(data)
    except ContractError as exc:
        raise UsageError(f"profile file {str(path)!r} is not strict JSON: {exc}")
    if not isinstance(document, dict):
        raise UsageError(f"profile file {str(path)!r} must contain a JSON object")

    completed: dict[str, object] = dict(_documented_profile_defaults())
    completed.update(document)  # unknown keys survive and are rejected below
    _sort_profile_selectors(completed)

    try:
        profile = decode_profile(completed, "profile file")
    except ContractError as exc:
        raise UsageError(f"profile file {str(path)!r} rejected: {exc}")
    try:
        # Unknown/disabled rule versions raise RuleRegistryError (a
        # ContractError), empty combination sets raise ProfileError; both are
        # input errors (design 6.3.3 exit-2 row), never tool errors.
        validate_profile(profile)
    except ContractError as exc:
        raise UsageError(f"profile file {str(path)!r} rejected: {exc}")
    return profile


def _sort_profile_selectors(document: dict[str, object]) -> None:
    """Sort the selector lists in place when they are well-formed lists.

    Sorting only reorders; duplicates, illegal values and non-list shapes are
    left for the strict loader to reject.
    """
    rules = document.get("rules")
    if isinstance(rules, list):
        document["rules"] = sorted(
            rules,
            key=lambda item: (
                item.get("rule_id", "") if isinstance(item, dict) else "",
                item.get("rule_version", 0)
                if isinstance(item, dict) and isinstance(item.get("rule_version"), int)
                else 0,
            ),
        )
    for field in ("templates", "index_variants"):
        values = document.get(field)
        if isinstance(values, list):
            document[field] = sorted(values, key=str)


# --------------------------------------------------------------------------
# Cancellation
# --------------------------------------------------------------------------


class _CancelState:
    """SIGINT flag shared with the generator's ``should_cancel`` callback.

    The signal handler only sets a boolean; the generator consults it at
    ordinal boundaries.  A second Ctrl-C is also absorbed (the handler does
    not raise), so the completed evidence is preserved instead of being cut
    short by an exception (design 6.5).
    """

    __slots__ = ("requested",)

    def __init__(self) -> None:
        self.requested = False

    def flag(self) -> bool:
        return self.requested

    def handler(self, signum, frame) -> None:  # noqa: ANN001 (signal API)
        self.requested = True


def _install_sigint_handler(cancel: _CancelState) -> Optional[object]:
    try:
        return signal.signal(signal.SIGINT, cancel.handler)
    except (ValueError, OSError):
        # Not the main thread (programmatic use) or no signal support: run
        # uncancellable; KeyboardInterrupt from a delivered SIGINT is caught
        # in main() and still maps to 130.
        return None


# --------------------------------------------------------------------------
# generate
# --------------------------------------------------------------------------


def _error_line(message: object) -> None:
    print(f"{PROGRAM}: error: {message}", file=sys.stderr)


def _print_generate_summary(result: GenerationResult, outcome: WriteOutcome) -> None:
    manifest = outcome.manifest
    lines = [
        f"status: {outcome.final_status.value}",
        f"output: {outcome.output_dir}",
        f"manifest_written: {'yes' if outcome.manifest_written else 'no'}",
        f"requested_ordinals: {manifest.requested_ordinals}",
        f"emitted_occurrences: {manifest.emitted_occurrences}",
        f"unique_cases: {manifest.unique_cases}",
        f"rejected_ordinals: {manifest.rejected_ordinals}",
        f"interrupted_ordinals: {manifest.interrupted_ordinals}",
        f"not_attempted: {manifest.not_attempted}",
        OFFLINE_NOTE,
    ]
    print("\n".join(lines))


def _cmd_generate(args: argparse.Namespace, cancel: _CancelState) -> int:
    try:
        profile = _resolve_profile(args.profile, args.profile_file)
    except UsageError as exc:
        _error_line(exc)
        return EXIT_USAGE

    try:
        result, outcome = generate_and_write(
            profile,
            args.seed,
            args.cases,
            Path(args.output),
            should_cancel=cancel.flag,
        )
    except (OutputDirExistsError, UnsafePathError, BundleBudgetError, ProfileError) as exc:
        # Input-level refusals (design 6.3.3 exit-2 row), including
        # unknown/disabled rules and over-cap profile budgets.
        _error_line(exc)
        return EXIT_USAGE
    except ContractError as exc:
        _error_line(f"internal error: {exc}")
        return EXIT_INTERNAL_ERROR
    except OSError as exc:
        _error_line(f"i/o failure: {exc}")
        return EXIT_INTERNAL_ERROR

    _print_generate_summary(result, outcome)
    if cancel.requested:
        # The process was cancelled by the user; completed evidence was
        # preserved and the terminating manifest was written.
        return EXIT_CANCELLED
    if outcome.io_error is not None:
        _error_line(f"i/o failure while writing the bundle: {outcome.io_error}")
        return EXIT_INTERNAL_ERROR
    if outcome.final_status is GenerationStatus.COMPLETE:
        return EXIT_OK
    return EXIT_INCOMPLETE


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


def _print_validate_report(report) -> None:  # noqa: ANN001 (ValidationReport)
    print(f"input: {report.output_dir}")
    status = (
        report.manifest_status.value
        if report.manifest_status is not None
        else "unknown"
    )
    print(f"manifest_status: {status}")
    print(f"cases_validated: {report.cases_validated}")
    print(f"counts_conserved: {report.counts_conserved}")
    for problem in report.problems:
        path = problem.path if problem.path is not None else "-"
        print(
            f"problem[{problem.severity}] {problem.kind.value} {path}: {problem.detail}"
        )
    if report.ok:
        print(
            "validation OK (offline): manifest COMPLETE, counts conserved, all "
            "files, hashes, rules and derived content verified."
        )
        print(
            "note: exit 0 means offline bundle consistency only; it does NOT "
            "mean a database MATCH or any database execution."
        )
    else:
        if not report.problems and report.manifest_status is not None:
            print(
                f"warning: bundle is not COMPLETE: manifest status is {status}; "
                "the saved content is valid but the generation request did not "
                "finish (this is not reported as a full pass)."
            )
        print(
            "note: validate is offline; it never executes SQL and never "
            "produces a database MATCH."
        )


def _cmd_validate(args: argparse.Namespace) -> int:
    # SIGINT keeps its default disposition here: it raises
    # KeyboardInterrupt, which main() maps to 130.
    report = validate_output_dir(Path(args.input))
    _print_validate_report(report)
    return exit_code_for(report)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    """Programmatic entry point; returns the process exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        _error_line(exc)
        return EXIT_USAGE
    except SystemExit as exc:  # --help
        return int(exc.code) if exc.code else 0

    cancel = _CancelState()
    try:
        if getattr(parser, "_online_commands", None) and args.command in parser._online_commands:  # type: ignore[attr-defined]
            # Deferred import (see _build_parser); dispatch_online maps the
            # online error families to the shared exit codes.
            from .online import dispatch_online

            return dispatch_online(args)
        if getattr(parser, "_delivery_commands", None) and args.command in parser._delivery_commands:  # type: ignore[attr-defined]
            # Deferred import (see _build_parser); dispatch_delivery maps
            # the delivery error families to the shared exit codes.
            from .delivery import dispatch_delivery

            return dispatch_delivery(args)
        if args.command == "generate":
            previous = _install_sigint_handler(cancel)
            try:
                return _cmd_generate(args, cancel)
            finally:
                if previous is not None:
                    signal.signal(signal.SIGINT, previous)
        return _cmd_validate(args)
    except KeyboardInterrupt:
        _error_line("cancelled by user (SIGINT)")
        return EXIT_CANCELLED


if __name__ == "__main__":
    sys.exit(main())
