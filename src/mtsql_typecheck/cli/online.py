"""Online CLI (D3 Phase 5): ``preflight`` / ``run`` / ``replay`` / ``reduce``
/ ``cleanup`` (design 6.3.1/6.3.3/6.4).

The commands wrap :mod:`mtsql_typecheck.runner.controller` and
:mod:`mtsql_typecheck.runner.evidence`; registration happens through
``cli.main`` (offline behaviour is untouched).  The subprocess worker path
lives in :mod:`mtsql_typecheck.runner.handlers`.

Import discipline: importing this module performs no I/O and imports
neither PyMySQL nor the adapters package; the certified driver is imported
only inside the probe/cleanup connection builders, so ``--help`` and parser
construction work on a bare install (design I01: online commands *refuse*
without the certified driver instead of falling back).

Exit codes (design 6.3.3; see ``runner.controller.exit_code_for``):
2 illegal input before test execution (bad target file, existing output,
  missing password variable, corrupt input evidence); 1 tool/persistence/
  unsafe-termination failure; 130 user cancel; 3 partial/inconclusive/
  environment-unsatisfied/unstable replay/budget-stopped reduction;
  0 complete with no candidate; 4 complete with a candidate (run),
  reproduced (replay) or a valid reduced counterexample (reduce).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable, Optional

from ..contracts.case import ContractError
from ..contracts.execution import default_control
from ..contracts.oracle import (
    ReductionPolicy,
    ReplayPolicy,
    dump_reduction_result,
    dump_replay_result,
)
from ..contracts.runner import (
    TARGET_CONFIG_MAX_BYTES,
    OwnershipEventKind,
    ProbeOutcome,
    RunnerCommand,
    RunnerManifest,
    RunnerStatus,
    load_ownership_journal,
    load_target_config,
)
from ..runner.cleanup import AttemptCleaner
from ..runner.controller import (
    RunController,
    RunOptions,
    CaseInputError,
    DispatcherError,
    WorkerDispatcher,
    dispatcher_env_for,
    dispatcher_env_passthrough,
    load_attempt_documents,
    reduce_candidate_documents,
    reduce_exit_code,
    replay_candidate_documents,
    replay_exit_code,
)
from ..runner.evidence import (
    EVIDENCE_BUDGET_DEFAULT,
    EVIDENCE_BUDGET_HARD_CAP,
    EvidencePathError,
    EvidenceWriter,
    write_exclusive_document,
)
from ..runner.naming import new_run_token
from ..runner.ownership import OWNERSHIP_JOURNAL_FILE_NAME, OwnershipJournal
from ..runner.preflight import PreflightError, run_preflight
from .main import (
    EXIT_CANCELLED,
    EXIT_INCOMPLETE,
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_USAGE,
    PROGRAM,
    UsageError,
    _CancelState,
    _error_line,
    _install_sigint_handler,
)

__all__ = ["ONLINE_COMMANDS", "register_online_commands", "dispatch_online"]

ONLINE_COMMANDS = ("preflight", "run", "replay", "reduce", "cleanup")

_EVIDENCE_BUDGET_DEFAULT_MIB = EVIDENCE_BUDGET_DEFAULT // (1024 * 1024)
_EVIDENCE_BUDGET_MAX_MIB = EVIDENCE_BUDGET_HARD_CAP // (1024 * 1024)
_PREFLIGHT_BUDGET_S = 30.0


def _evidence_budget_mib(text: str) -> int:
    try:
        value = int(text, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"evidence budget must be an integer, got {text!r}")
    if not 1 <= value <= _EVIDENCE_BUDGET_MAX_MIB:
        raise argparse.ArgumentTypeError(
            f"--evidence-budget-mib must be in [1, {_EVIDENCE_BUDGET_MAX_MIB}], got {value}"
        )
    return value


def register_online_commands(subparsers: argparse._SubParsersAction) -> None:  # noqa: SLF001
    """Register the online subcommands on the shared parser (exit-2 rows)."""
    preflight = subparsers.add_parser(
        "preflight", help="probe the target environment read-only into a new directory"
    )
    preflight.add_argument("--target", required=True, metavar="TARGET-FILE")
    preflight.add_argument("--output", required=True, metavar="NEW-DIRECTORY")

    run = subparsers.add_parser(
        "run", help="execute a case bundle against the target (online run)"
    )
    run.add_argument("--input", required=True, metavar="BUNDLE-DIRECTORY")
    run.add_argument("--target", required=True, metavar="TARGET-FILE")
    run.add_argument("--output", required=True, metavar="NEW-DIRECTORY")
    run.add_argument("--cases", type=int, default=None, metavar="N",
                     help="dispatch at most N cases from the bundle")
    run.add_argument("--evidence-budget-mib", type=_evidence_budget_mib,
                     default=_EVIDENCE_BUDGET_DEFAULT_MIB)

    replay = subparsers.add_parser(
        "replay", help="replay one recorded mismatch candidate three times"
    )
    replay.add_argument("--attempt", required=True, metavar="ATTEMPT-DIRECTORY")
    replay.add_argument("--output", required=True, metavar="NEW-DIRECTORY")
    replay.add_argument("--target", default=None, metavar="TARGET-FILE",
                        help="without it the candidate is never re-executed (NOT_REPLAYED)")
    replay.add_argument("--evidence-budget-mib", type=_evidence_budget_mib,
                        default=_EVIDENCE_BUDGET_DEFAULT_MIB)

    reduce = subparsers.add_parser(
        "reduce", help="reduce one recorded mismatch candidate"
    )
    reduce.add_argument("--attempt", required=True, metavar="ATTEMPT-DIRECTORY")
    reduce.add_argument("--output", required=True, metavar="NEW-DIRECTORY")
    reduce.add_argument("--target", default=None, metavar="TARGET-FILE",
                        help="without it no proposal is executed (FAILED/NO_EXECUTOR)")
    reduce.add_argument("--evidence-budget-mib", type=_evidence_budget_mib,
                        default=_EVIDENCE_BUDGET_DEFAULT_MIB)

    cleanup = subparsers.add_parser(
        "cleanup", help="inventory (and optionally drop) leftover attempt objects"
    )
    cleanup.add_argument("--input", required=True, metavar="RUN-OUTPUT-DIRECTORY")
    cleanup.add_argument("--apply", action="store_true",
                         help="drop the inventoried leftover objects (requires a wired cleaner)")
    cleanup.add_argument("--target", default=None, metavar="TARGET-FILE",
                         help="with --apply: bind the real cleanup executor to this target "
                              "(without it --apply is NOT_RUN)")


def dispatch_online(args: argparse.Namespace) -> int:
    """Route one online command; shared error mapping lives here."""
    try:
        if args.command == "preflight":
            return _cmd_preflight(args)
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "replay":
            return _cmd_replay(args)
        if args.command == "reduce":
            return _cmd_reduce(args)
        if args.command == "cleanup":
            return _cmd_cleanup(args)
    except KeyboardInterrupt:
        _error_line("cancelled by user (SIGINT)")
        return EXIT_CANCELLED
    except UsageError as exc:
        _error_line(exc)
        return EXIT_USAGE
    except CaseInputError as exc:
        _error_line(exc)
        return EXIT_USAGE
    except ContractError as exc:
        _error_line(f"internal error: {exc}")
        return EXIT_INTERNAL_ERROR
    except OSError as exc:
        _error_line(f"i/o failure: {exc}")
        return EXIT_INTERNAL_ERROR
    raise AssertionError(f"unknown online command {args.command!r}")


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------


def load_target_file(path_text: str):
    """Strictly load a target configuration file (exit-2 on any refusal)."""
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read target file {str(path)!r}: {exc}")
    if len(raw) > TARGET_CONFIG_MAX_BYTES:
        raise UsageError(
            f"target file {str(path)!r} exceeds {TARGET_CONFIG_MAX_BYTES} bytes"
        )
    try:
        return load_target_config(raw)
    except ContractError as exc:
        raise UsageError(f"target file {str(path)!r} rejected: {exc}")


def _open_output_or_usage(output_text: str) -> EvidenceWriter:
    try:
        return EvidenceWriter(Path(output_text))
    except EvidencePathError as exc:
        raise UsageError(exc)


def build_probe_source(config):
    """Build the read-only probe source (deferred adapter import; refuses
    without the certified driver -- design I01)."""
    from ..runner.config import ConfigError, connection_params_from_target

    try:
        params = connection_params_from_target(config)
    except ConfigError as exc:
        raise UsageError(str(exc))
    try:
        from ..adapters.mysql80 import MySQL80Adapter
    except ImportError as exc:
        raise UsageError(
            f"the certified MySQL driver is not installed ({exc}); online "
            "commands refuse to run without it"
        )
    return MySQL80Adapter(params, charset="utf8mb4")


def _print_run_summary(outcome) -> None:
    manifest = outcome.manifest
    print(f"command: run")
    if outcome.message:
        print(f"message: {outcome.message}")
    if manifest is None:
        print("manifest: not written")
        return
    print(f"status: {manifest.status.value}")
    if manifest.stop_reason is not None:
        print(f"stop_reason: {manifest.stop_reason}")
    print(f"requested: {manifest.requested}")
    print(f"completed: {manifest.completed}")
    print(f"match: {manifest.match}")
    print(f"candidate: {manifest.candidate}")
    print(f"inconclusive: {manifest.inconclusive}")
    print(f"not_applicable: {manifest.not_applicable}")
    print(f"output: {manifest.ref('runner_manifest')}")


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------


def _cmd_preflight(args: argparse.Namespace, *, probe_factory: Optional[Callable[[], object]] = None) -> int:
    config = load_target_file(args.target)
    writer = _open_output_or_usage(args.output)
    run_id = f"preflight-{new_run_token()}"
    if probe_factory is None:
        probe_factory = lambda: build_probe_source(config)  # noqa: E731
    try:
        probe_source = probe_factory()
        manifest = run_preflight(config, probe_source, default_control(_PREFLIGHT_BUDGET_S))
    except (PreflightError, ContractError, OSError) as exc:
        _error_line(f"preflight failed: {exc}")
        _write_preflight_manifest(writer, run_id, None, "PREFLIGHT_FAILED")
        return EXIT_INTERNAL_ERROR
    writer.write_environment(manifest)
    failed = any(probe.outcome is ProbeOutcome.FAIL for probe in manifest.probes)
    status = RunnerStatus.PARTIAL if failed else RunnerStatus.COMPLETE
    _write_preflight_manifest(
        writer, run_id, manifest, "ENVIRONMENT_UNSATISFIED" if failed else None
    )
    for probe in manifest.probes:
        print(f"probe[{probe.outcome.value}] {probe.probe_id}: {probe.detail}")
    if failed:
        print("preflight: environment is not satisfied (exit 3); no case was executed")
        return EXIT_INCOMPLETE
    print("preflight: all probes passed (this is not a MATCH and executed no case)")
    return EXIT_OK


def _write_preflight_manifest(writer, run_id, manifest, stop_reason) -> None:
    from ..contracts.runner import RUNNER_EVIDENCE_PROFILE

    refs = [("runner_manifest", "runner-manifest.json")]
    if manifest is not None:
        refs.insert(0, ("environment", "environment.json"))
    try:
        record = RunnerManifest(
            command=RunnerCommand.PREFLIGHT,
            run_id=run_id,
            status=RunnerStatus.ABORTED if manifest is None else (
                RunnerStatus.PARTIAL if stop_reason else RunnerStatus.COMPLETE
            ),
            stop_reason=stop_reason,
            requested=0,
            completed=0,
            comparable=0,
            match=0,
            candidate=0,
            inconclusive=0,
            not_applicable=0,
            leftover_objects=0,
            leftover_sessions=0,
            synthetic=False,
            evidence_profile=RUNNER_EVIDENCE_PROFILE,
            tool_version="0.1.0",
            contract_versions=(
                ("case", "1"),
                ("execution", "1"),
                ("oracle", "o1"),
                ("runner", "1"),
            ),
            refs=tuple(refs),
            sanitized_config_hash=(
                manifest.sanitized_config_hash if manifest is not None else "0" * 64
            ),
        )
        writer.write_manifest(record)
    except (ContractError, OSError):
        pass


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


def _cmd_run(args: argparse.Namespace, *, controller_factory: Optional[Callable[[], RunController]] = None) -> int:
    config = load_target_file(args.target)
    if args.cases is not None and args.cases < 1:
        raise UsageError("--cases must be >= 1")
    cancel = _CancelState()
    _install_sigint_handler(cancel)
    if controller_factory is not None:
        controller = controller_factory()
    else:
        controller = RunController(
            config=config,
            bundle_dir=Path(args.input),
            output=Path(args.output),
            options=RunOptions(
                evidence_budget_bytes=args.evidence_budget_mib * 1024 * 1024,
                cases_limit=args.cases,
                cancelled=cancel.flag,
            ),
        )
    outcome = controller.run()
    _print_run_summary(outcome)
    if outcome.cancelled:
        _error_line("cancelled by user (SIGINT); partial evidence was sealed")
    return outcome.exit_code()


# --------------------------------------------------------------------------
# replay / reduce
# --------------------------------------------------------------------------


def _cmd_replay(args: argparse.Namespace, *, executor_factory: Optional[Callable[[], object]] = None) -> int:
    budget = args.evidence_budget_mib * 1024 * 1024
    # Validate the attempt documents BEFORE opening the output root: a usage
    # refusal (exit 2) must not leave an output skeleton behind.
    load_attempt_documents(Path(args.attempt))
    sink = _open_trace_sink(Path(args.output), budget)
    executor = _executor_for(args, executor_factory)
    policy = ReplayPolicy()
    try:
        result = replay_candidate_documents(
            Path(args.attempt),
            executor=executor,
            trace_sink=sink,
            policy=policy,
            control=default_control(policy.total_budget_ms / 1000),
        )
    finally:
        if executor is not None:
            executor.close()
        sink.close()
    write_exclusive_document(
        sink.root / "replay-result.json", dump_replay_result(result)
    )
    print(f"replay outcome: {result.outcome.value}")
    if result.stop_reason is not None:
        print(f"stop_reason: {result.stop_reason.value}")
    print(
        f"attempts: {result.completed}/{result.requested} completed, "
        f"{result.matching_signature} reproduced the baseline signature"
    )
    return replay_exit_code(result)


def _cmd_reduce(args: argparse.Namespace, *, executor_factory: Optional[Callable[[], object]] = None) -> int:
    budget = args.evidence_budget_mib * 1024 * 1024
    # Validate the attempt documents BEFORE opening the output root: a usage
    # refusal (exit 2) must not leave an output skeleton behind.
    load_attempt_documents(Path(args.attempt))
    sink = _open_trace_sink(Path(args.output), budget)
    executor = _executor_for(args, executor_factory)
    policy = ReductionPolicy()
    try:
        result = reduce_candidate_documents(
            Path(args.attempt),
            executor=executor,
            trace_sink=sink,
            policy=policy,
            control=default_control(policy.total_budget_ms / 1000),
        )
    finally:
        if executor is not None:
            executor.close()
        sink.close()
    write_exclusive_document(
        sink.root / "reduce-result.json", dump_reduction_result(result)
    )
    print(f"reduce outcome: {result.outcome.value}")
    if result.stop_reason is not None:
        print(f"stop_reason: {result.stop_reason.value}")
    print(
        f"proposals: {result.proposals} proposed, {result.accepted} accepted; "
        f"best case: {result.best_case_id}"
    )
    return reduce_exit_code(result)


def _open_trace_sink(output: Path, budget: int):
    from ..reduction.trace import JsonlTraceSink, TracePathError

    try:
        return JsonlTraceSink(output, budget)
    except TracePathError as exc:
        # An existing/unsafe output root is an input refusal (exit 2);
        # budget/write failures stay ContractError and map to 1.
        raise UsageError(exc)


def _executor_for(args: argparse.Namespace, executor_factory):
    """Executor wiring for replay/reduce (design 6.3.1).

    Without ``--target`` no executor is built: the D2 layer then reports
    NOT_REPLAYED / NO_EXECUTOR and the command exits 3 instead of claiming a
    reproduction.  With ``--target`` the executor is a worker dispatcher; a
    caller-supplied factory (tests) wins over the default.
    """
    if executor_factory is not None:
        return executor_factory()
    if getattr(args, "target", None) is None:
        return None
    config = load_target_file(args.target)
    return WorkerDispatcher.spawn(
        env=dispatcher_env_for(config),
        env_passthrough=dispatcher_env_passthrough(config),
    )


# --------------------------------------------------------------------------
# cleanup
# --------------------------------------------------------------------------


def _cmd_cleanup(args: argparse.Namespace, *, cleaner_factory: Optional[Callable[[], AttemptCleaner]] = None) -> int:
    journal_path = Path(args.input) / OWNERSHIP_JOURNAL_FILE_NAME
    try:
        raw = journal_path.read_bytes()
    except OSError as exc:
        raise UsageError(f"cannot read ownership journal {str(journal_path)!r}: {exc}")
    try:
        events = load_ownership_journal(raw)
    except ContractError as exc:
        raise UsageError(f"ownership journal {str(journal_path)!r} is corrupt: {exc}")
    if not events:
        print("cleanup: journal is empty; nothing to inventory")
        return EXIT_OK

    run_id = events[0].run_id
    created: dict[str, object] = {}
    dropped: set[str] = set()
    attempt_tokens: dict[str, str] = {}
    run_token: Optional[str] = None
    for event in events:
        if event.event_kind is OwnershipEventKind.RUN_LOCK_ACQUIRED and event.token:
            run_token = event.token
        if event.event_kind is OwnershipEventKind.ATTEMPT_ALLOCATED:
            if event.attempt_id and event.token:
                attempt_tokens[event.attempt_id] = event.token
        if event.event_kind is OwnershipEventKind.OBJECT_CREATED and event.object_name:
            created[event.object_name] = event
        if event.event_kind is OwnershipEventKind.OBJECT_DROPPED and event.object_name:
            dropped.add(event.object_name)
    pending = {name: event for name, event in created.items() if name not in dropped}
    for name in sorted(created):
        state = "DROPPED" if name in dropped else "LEFTOVER"
        print(f"object[{state}] {name}")
    if not args.apply:
        print(
            f"cleanup inventory: {len(created)} created, {len(dropped)} dropped, "
            f"{len(pending)} leftover (display only; rerun with --apply to drop)"
        )
        return EXIT_INCOMPLETE if pending else EXIT_OK

    if cleaner_factory is None:
        target = getattr(args, "target", None)
        if target is None:
            print(
                "cleanup: --apply needs a wired cleanup executor (a live "
                "adapter connection implementing CleanupExecutor); pass "
                "--target to bind the real adapter (NOT_RUN without it); the "
                "inventory above is unchanged"
            )
            return EXIT_INCOMPLETE
        config = load_target_file(target)
        try:
            adapter = build_probe_source(config)
            adapter.connect_and_probe()
            journal = OwnershipJournal(
                Path(args.input) / OWNERSHIP_JOURNAL_FILE_NAME, run_id=run_id
            )
        except (ContractError, OSError) as exc:
            _error_line(f"cleanup: cannot bind the cleanup executor: {exc}")
            return EXIT_INTERNAL_ERROR
        # The adapter implements the CleanupExecutor surface (whitelisted,
        # naming-validated cleanup DDL + INFORMATION_SCHEMA presence probe);
        # every action is journaled by continuing the run's verified chain.
        cleaner = AttemptCleaner(adapter, journal)
    else:
        adapter = None
        journal = None
        cleaner = cleaner_factory()
    try:
        failures = 0
        attempts = sorted({event.attempt_id for event in pending.values() if event.attempt_id})
        for attempt_id in attempts:
            attempt_token = attempt_tokens.get(attempt_id)
            if run_token is None or attempt_token is None:
                failures += 1
                continue
            outcome = cleaner.clean(
                run_id=run_id,
                attempt_id=attempt_id,
                run_token=run_token,
                attempt_token=attempt_token,
            )
            if not outcome.completed:
                failures += 1
    finally:
        if journal is not None:
            journal.close()
        if adapter is not None:
            adapter.close()
    if failures:
        print(f"cleanup: {failures} attempt(s) could not be cleaned (exit 1)")
        return EXIT_INTERNAL_ERROR
    print("cleanup: all inventoried attempt objects were dropped and confirmed")
    return EXIT_OK
