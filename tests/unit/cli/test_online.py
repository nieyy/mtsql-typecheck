"""Unit tests for the online CLI subcommands (cli/online.py).

All execution paths use fakes: preflight runs against a fake probe source,
``run`` against a stub controller or the real controller over scripted
in-process execution ports (``tests/unit/runner/controller_fakes``), and the
fresh-import check runs a subprocess with PyMySQL blocked.  No MySQL, no
network.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import pytest

# The test trees intentionally have no shared package: pull the runner fakes
# in by path (same technique as the bundle tests).
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))

from controller_fakes import (  # noqa: E402
    FakeProbeSource,
    make_bundle,
    make_signed_payloads,
    make_target_config,
)
from mtsql_typecheck.cli.main import main  # noqa: E402
from mtsql_typecheck.cli import online  # noqa: E402
from mtsql_typecheck.contracts.runner import (  # noqa: E402
    OwnershipEventKind,
    RunnerCommand,
    RunnerStatus,
)
from mtsql_typecheck.runner.controller import (  # noqa: E402
    RunController,
    RunOptions,
    RunOutcome,
)
from mtsql_typecheck.runner.naming import new_attempt_token, new_run_token  # noqa: E402
from mtsql_typecheck.runner.ownership import OwnershipJournal  # noqa: E402
from mtsql_typecheck.runner.preflight import run_preflight  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"


def write_target(tmp_path: Path, name: str = "target.json") -> Path:
    from mtsql_typecheck.contracts.runner import dump_target_config

    path = tmp_path / name
    path.write_bytes(dump_target_config(make_target_config()))
    return path


# --------------------------------------------------------------------------
# Parser registration / --help without the mysql extra
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["preflight", "--target", "t.json", "--output", "o"],
        ["run", "--input", "b", "--target", "t.json", "--output", "o"],
        ["replay", "--attempt", "a", "--output", "o"],
        ["reduce", "--attempt", "a", "--output", "o"],
        ["cleanup", "--input", "d"],
    ],
)
def test_online_subcommands_are_registered(argv: list[str]) -> None:
    # Parsing alone must not touch the filesystem or the network; the invalid
    # paths must fail *after* parsing with the documented exit code (2), not
    # with a usage error about unknown commands.
    code = main(argv)
    assert code == 2


def test_help_works_for_offline_and_online_commands(capsys) -> None:
    assert main(["--help"]) == 0
    assert main(["run", "--help"]) == 0
    assert main(["replay", "--help"]) == 0
    assert main(["cleanup", "--help"]) == 0
    assert main(["generate", "--help"]) == 0  # offline parser unchanged
    captured = capsys.readouterr()
    assert "run" in captured.out


def test_fresh_import_without_pymysql(tmp_path: Path) -> None:
    """``--help``/imports work without the mysql extra (design I01)."""
    script = tmp_path / "fresh_import.py"
    script.write_text(
        "\n".join(
            [
                "import importlib.abc, sys",
                "class BlockPyMySQL(importlib.abc.MetaPathFinder):",
                "    def find_spec(self, fullname, path=None, target=None):",
                "        if fullname == 'pymysql' or fullname.startswith('pymysql.'):",
                "            raise ImportError('pymysql blocked for the fresh-import test')",
                "        return None",
                "sys.meta_path.insert(0, BlockPyMySQL())",
                "import mtsql_typecheck.cli.main",
                "import mtsql_typecheck.cli.online",
                "import mtsql_typecheck.runner.controller",
                "import mtsql_typecheck.runner.evidence",
                "import mtsql_typecheck.runner.handlers",
                "code = mtsql_typecheck.cli.main.main(['run', '--help'])",
                "assert code == 0, code",
                "print('FRESH-IMPORT-OK')",
            ]
        )
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC_DIR)
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "FRESH-IMPORT-OK" in result.stdout


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------


def test_preflight_bad_target_is_exit_2(tmp_path: Path) -> None:
    missing = tmp_path / "nope.json"
    assert main(["preflight", "--target", str(missing), "--output", str(tmp_path / "o")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"host": 1}')
    assert main(["preflight", "--target", str(bad), "--output", str(tmp_path / "o2")]) == 2
    # Neither run created an output directory.
    assert not (tmp_path / "o").exists()
    assert not (tmp_path / "o2").exists()


def test_preflight_existing_output_is_exit_2(tmp_path: Path) -> None:
    target = write_target(tmp_path)
    output = tmp_path / "out"
    output.mkdir()
    assert main(["preflight", "--target", str(target), "--output", str(output)]) == 2


def test_preflight_missing_password_env_is_exit_2(tmp_path: Path) -> None:
    from mtsql_typecheck.contracts.runner import dump_target_config

    config = make_target_config(password_env="MTTC_DEFINITELY_MISSING_PW")
    target = tmp_path / "target.json"
    target.write_bytes(dump_target_config(config))
    env_was_set = os.environ.pop("MTTC_DEFINITELY_MISSING_PW", None) is not None
    try:
        code = main(["preflight", "--target", str(target), "--output", str(tmp_path / "o")])
    finally:
        if env_was_set:
            os.environ["MTTC_DEFINITELY_MISSING_PW"] = "x"
    assert code == 2


def test_preflight_with_fake_probe_passes(tmp_path: Path, outroot: Path) -> None:
    target = write_target(tmp_path)
    output = outroot / "preflight-ok"
    args = argparse.Namespace(target=str(target), output=str(output))
    code = online._cmd_preflight(args, probe_factory=FakeProbeSource)
    assert code == 0
    assert (output / "environment.json").is_file()
    assert (output / "runner-manifest.json").is_file()


def test_preflight_with_failing_fact_is_exit_3(tmp_path: Path, outroot: Path) -> None:
    target = write_target(tmp_path)
    output = outroot / "preflight-bad"
    args = argparse.Namespace(target=str(target), output=str(output))

    class FailingProbe(FakeProbeSource):
        def fetch_environment_facts(self):
            facts = dict(super().fetch_environment_facts())
            facts["version"] = "5.7.40-log"
            return facts

    code = online._cmd_preflight(args, probe_factory=FailingProbe)
    assert code == 3
    manifest_text = (output / "runner-manifest.json").read_text()
    assert "ENVIRONMENT_UNSATISFIED" in manifest_text
    assert (output / "environment.json").is_file()


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------


class StubController:
    def __init__(self, outcome: RunOutcome) -> None:
        self._outcome = outcome
        self.run_calls = 0

    def run(self) -> RunOutcome:
        self.run_calls += 1
        return self._outcome


def _run_namespace(tmp_path: Path, **overrides) -> argparse.Namespace:
    values = {
        "input": str(tmp_path / "bundle"),
        "target": str(write_target(tmp_path)),
        "output": str(tmp_path / "out"),
        "cases": None,
        "evidence_budget_mib": 1,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _complete_manifest(candidate: int):
    from mtsql_typecheck.contracts.runner import RUNNER_EVIDENCE_PROFILE, RunnerManifest

    return RunnerManifest(
        command=RunnerCommand.RUN,
        run_id="run-x",
        status=RunnerStatus.COMPLETE,
        requested=1,
        completed=1,
        comparable=1,
        match=1 - candidate,
        candidate=candidate,
        inconclusive=0,
        not_applicable=0,
        leftover_objects=0,
        leftover_sessions=0,
        synthetic=False,
        evidence_profile=RUNNER_EVIDENCE_PROFILE,
        tool_version="0.1.0",
        contract_versions=(("case", "1"), ("execution", "1"), ("oracle", "o1"), ("runner", "1")),
        refs=(("runner_manifest", "runner-manifest.json"),),
        sanitized_config_hash="a" * 64,
    )


def test_run_maps_candidate_run_to_exit_4(tmp_path: Path, capsys) -> None:
    controller = StubController(RunOutcome(manifest=_complete_manifest(candidate=1)))
    code = online._cmd_run(_run_namespace(tmp_path), controller_factory=lambda: controller)
    assert code == 4
    assert controller.run_calls == 1
    assert "candidate: 1" in capsys.readouterr().out


def test_run_maps_zero_candidate_run_to_exit_0(tmp_path: Path) -> None:
    controller = StubController(RunOutcome(manifest=_complete_manifest(candidate=0)))
    assert online._cmd_run(_run_namespace(tmp_path), controller_factory=lambda: controller) == 0


def test_run_cases_zero_is_exit_2(tmp_path: Path) -> None:
    args = _run_namespace(tmp_path, cases=0)
    code = main(["run", "--input", args.input, "--target", args.target,
                 "--output", args.output, "--cases", "0"])
    assert code == 2


def test_run_bad_target_is_exit_2(tmp_path: Path) -> None:
    code = main(["run", "--input", str(tmp_path / "bundle"),
                 "--target", str(tmp_path / "missing.json"),
                 "--output", str(tmp_path / "out")])
    assert code == 2


def test_run_real_worker_path_fails_closed_before_execution(tmp_path: Path) -> None:
    """Without a wired production port factory the run refuses before any SQL.

    The preflight worker has no probe factory wired in Phase 5 (NOT_RUN), so
    the controller surfaces PREFLIGHT_FAILED and exits 1 -- it must never
    report success or dispatch a case.
    """
    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)
    code = main(
        [
            "run",
            "--input",
            str(bundle),
            "--target",
            str(write_target(tmp_path)),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert code == 1
    manifest_text = (tmp_path / "out" / "runner-manifest.json").read_text()
    assert "PREFLIGHT_FAILED" in manifest_text
    assert not any((tmp_path / "out" / "attempts").iterdir())


# --------------------------------------------------------------------------
# replay / reduce
# --------------------------------------------------------------------------


def _candidate_attempt_dir(tmp_path: Path) -> Path:
    """Produce a real run output and return its mismatch-candidate attempt."""
    from controller_fakes import AttemptFakes, InlineDispatcher
    from mtsql_typecheck.contracts.codec import case_id_of

    payloads = make_signed_payloads()
    bundle = make_bundle(tmp_path / "bundle", payloads)

    def factory(request):
        b_result = None
        if case_id_of(request.payload) == case_id_of(payloads[1]):
            from execution_fakes import int_value

            b_result = ((int_value(999),),)
        return InlineDispatcher(AttemptFakes(request.payload, b_result=b_result).build())

    controller = RunController(
        config=make_target_config(),
        bundle_dir=bundle,
        output=tmp_path / "out",
        options=RunOptions(),
        dispatcher_factory=factory,
        preflight_fn=lambda config, control: run_preflight(config, FakeProbeSource(), control),
    )
    outcome = controller.run()
    assert outcome.exit_code() == 4
    attempts = sorted((tmp_path / "out" / "attempts").iterdir())
    assert len(attempts) == 2
    from mtsql_typecheck.contracts.oracle import ComparisonStatus, load_comparison

    for attempt_dir in attempts:
        comparison = load_comparison((attempt_dir / "comparison.json").read_bytes())
        if comparison.status is ComparisonStatus.MISMATCH_CANDIDATE:
            return attempt_dir
    raise AssertionError("no mismatch-candidate attempt was recorded")


def test_replay_missing_attempt_is_exit_2(tmp_path: Path) -> None:
    assert main(["replay", "--attempt", str(tmp_path / "nope"), "--output", str(tmp_path / "o")]) == 2
    # A usage refusal must not leave an output skeleton behind (regression:
    # replay/reduce used to create the trace root before validating the
    # attempt documents).
    assert not (tmp_path / "o").exists()


def test_reduce_missing_attempt_is_exit_2_without_output(tmp_path: Path) -> None:
    assert main(["reduce", "--attempt", str(tmp_path / "nope"), "--output", str(tmp_path / "o")]) == 2
    assert not (tmp_path / "o").exists()


def test_replay_without_target_is_not_replayed_exit_3(tmp_path: Path) -> None:
    attempt = _candidate_attempt_dir(tmp_path)
    output = tmp_path / "replay-out"
    code = main(["replay", "--attempt", str(attempt), "--output", str(output)])
    assert code == 3
    result_text = (output / "replay-result.json").read_text()
    assert "NOT_REPLAYED" in result_text


def test_reduce_without_target_exits_1_failed(tmp_path: Path) -> None:
    attempt = _candidate_attempt_dir(tmp_path)
    output = tmp_path / "reduce-out"
    code = main(["reduce", "--attempt", str(attempt), "--output", str(output)])
    # Without an executor no proposal can be executed: the D2 engine reports
    # FAILED/NO_EXECUTOR, which maps to exit 1 (never a silent success).
    assert code == 1
    result_text = (output / "reduce-result.json").read_text()
    assert "FAILED" in result_text


# --------------------------------------------------------------------------
# cleanup
# --------------------------------------------------------------------------


def test_cleanup_missing_journal_is_exit_2(tmp_path: Path) -> None:
    assert main(["cleanup", "--input", str(tmp_path / "nope")]) == 2


def _journal_with_leftover(path: Path) -> None:
    run_token = "0123456789abcdef"
    attempt_token = "fedcba9876543210"
    journal = OwnershipJournal(path / "ownership.jsonl", run_id=f"run-{run_token}")
    try:
        journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED, token=run_token)
        journal.append(
            OwnershipEventKind.ATTEMPT_ALLOCATED,
            attempt_id=f"at-000001-{attempt_token}",
            token=attempt_token,
        )
        journal.append(
            OwnershipEventKind.OBJECT_CREATED,
            attempt_id=f"at-000001-{attempt_token}",
            object_name=f"tc_{run_token}_{attempt_token}_a",
        )
        journal.append(OwnershipEventKind.RUN_SEALED)
    finally:
        journal.close()


def test_cleanup_inventory_reports_leftover_as_exit_3(tmp_path: Path, capsys) -> None:
    root = tmp_path / "runout"
    root.mkdir()
    _journal_with_leftover(root)
    code = main(["cleanup", "--input", str(root)])
    assert code == 3
    captured = capsys.readouterr()
    assert "LEFTOVER" in captured.out


def test_cleanup_inventory_without_leftover_is_exit_0(tmp_path: Path) -> None:
    root = tmp_path / "runout"
    root.mkdir()
    journal = OwnershipJournal(root / "ownership.jsonl", run_id="run-test0000000001")
    try:
        journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED, token="0123456789abcdef")
        journal.append(OwnershipEventKind.RUN_SEALED)
    finally:
        journal.close()
    assert main(["cleanup", "--input", str(root)]) == 0


def test_cleanup_apply_is_not_wired_in_phase_5(tmp_path: Path, capsys) -> None:
    root = tmp_path / "runout"
    root.mkdir()
    _journal_with_leftover(root)
    code = main(["cleanup", "--input", str(root), "--apply"])
    assert code == 3
    captured = capsys.readouterr()
    assert "NOT_RUN" in captured.out
