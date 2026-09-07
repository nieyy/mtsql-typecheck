"""Unit tests for the exclusive snapshot capture (design 6.4.1, 6.5).

Expected digests are computed independently from the frozen contract identity
function over plain ``hashlib`` file hashes -- never from the capture code
under test.  Fakes only: no database, no network.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Tuple

import pytest

from mtsql_typecheck.contracts.delivery import (
    Limits,
    NativeKind,
    compute_snapshot_digest,
    compute_source_id,
)
from mtsql_typecheck.evidence.reader import (
    BudgetExhaustedError,
    EntryStat,
    SourceChangedError,
    SourceReader,
)
from mtsql_typecheck.evidence.snapshot import (
    SnapshotFileRecord,
    SnapshotIoError,
    SnapshotResult,
    SnapshotSetupError,
    Snapshotter,
)

TREE = {
    "request.json": b'{"schema": 1}\n',
    "environment/nested/env.json": b'{"os": "linux"}\n',
    "cases/π-case/case.json": "unicode π😀 contents\n".encode("utf-8"),
    "cases/π-case/empty.json": b"",
    "cases/plain/attempts.jsonl": b"\n  leading blank \n\t tabbed \n",
}


@dataclass(frozen=True)
class PlannedFile:
    relpath: str
    max_bytes: int


@dataclass(frozen=True)
class Plan:
    kind: NativeKind
    root_document: str
    files: Tuple[PlannedFile, ...]
    orphan_files: Tuple[str, ...] = ()


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def default_plan(tree: dict[str, bytes], extra_missing: Tuple[str, ...] = ()) -> Plan:
    files = tuple(
        PlannedFile(relpath=rel, max_bytes=1024 * 1024) for rel in sorted(tree)
    ) + tuple(PlannedFile(relpath=rel, max_bytes=1024 * 1024) for rel in extra_missing)
    files = tuple(sorted(files, key=lambda f: f.relpath))
    return Plan(
        kind=NativeKind.ATTEMPT,
        root_document="request.json",
        files=files,
        orphan_files=(),
    )


def expected_digest(
    tree: dict[str, bytes], missing: Tuple[str, ...] = ()
) -> str:
    return compute_snapshot_digest(
        "attempt",
        "request.json",
        [(rel, len(data), hashlib.sha256(data).hexdigest()) for rel, data in sorted(tree.items())],
        sorted(missing),
    )


class RecordingReader:
    """Test double delegating to a real SourceReader with mutation hooks:

    - ``read_hooks[relpath]``: called instead of the real read.
    - ``stat_overrides[relpath]``: (min_call_count, size, mtime) applied from
      the Nth stat call onward (call 1 = pass 1, call 2 = pass 2 pre-read,
      call 3 = final sweep).
    """

    def __init__(self, inner: SourceReader) -> None:
        self._inner = inner
        self.read_hooks: dict[str, Callable[[], bytes]] = {}
        self.stat_overrides: dict[str, Tuple[int, int, int]] = {}
        self._stat_calls: dict[str, int] = {}

    def stat(self, relpath: str) -> EntryStat:
        st = self._inner.stat(relpath)
        rule = self.stat_overrides.get(relpath)
        if rule is not None:
            count = self._stat_calls.get(relpath, 0) + 1
            self._stat_calls[relpath] = count
            if count >= rule[0]:
                return EntryStat(
                    relpath=st.relpath, kind=st.kind, size_bytes=rule[1], mtime_ns=rule[2]
                )
        return st

    def read_bytes(self, relpath: str, *, max_bytes: int) -> bytes:
        hook = self.read_hooks.get(relpath)
        if hook is not None:
            return hook()
        return self._inner.read_bytes(relpath, max_bytes=max_bytes)

    def read_jsonl(self, relpath: str, **kwargs):
        return self._inner.read_jsonl(relpath, **kwargs)


def raw_dir(output_root: Path, result: SnapshotResult) -> Path:
    return output_root / "raw" / result.source_id


# ---------------------------------------------------------------------------
# Normal capture
# ---------------------------------------------------------------------------


def test_capture_preserves_bytes_exactly(tmp_path: Path) -> None:
    source = tmp_path / "src"
    output = tmp_path / "out"
    write_tree(source, TREE)
    with SourceReader(source, limits=Limits()) as reader:
        result = Snapshotter(reader, output, Limits()).capture(default_plan(TREE))

    assert result.source_changed is False
    assert result.missing_paths == ()
    assert result.orphan_files == ()
    assert result.kind is NativeKind.ATTEMPT
    assert result.bytes_written == sum(len(d) for d in TREE.values())
    assert [f.relpath for f in result.files] == sorted(TREE)
    assert result.source_id == compute_source_id(result.snapshot_digest)
    assert result.snapshot_digest == expected_digest(TREE)

    raw = raw_dir(output, result)
    for rel, data in TREE.items():
        copied = raw / rel
        assert copied.is_file(), rel
        assert copied.read_bytes() == data, rel
    # nothing outside raw/<source-id>/ was written
    assert sorted(p.name for p in output.iterdir()) == ["raw"]
    assert sorted(p.name for p in (output / "raw").iterdir()) == [result.source_id]
    # original tree untouched
    for rel, data in TREE.items():
        assert (source / rel).read_bytes() == data


def test_snapshot_file_record_validation() -> None:
    with pytest.raises(ValueError):
        SnapshotFileRecord(relpath="../escape", size_bytes=1, sha256="0" * 64)
    with pytest.raises(ValueError):
        SnapshotFileRecord(relpath="ok.txt", size_bytes=1, sha256="nothex")
    with pytest.raises(ValueError):
        SnapshotFileRecord(relpath="ok.txt", size_bytes=-1, sha256="0" * 64)


def test_result_source_id_binding_is_enforced() -> None:
    with pytest.raises(ValueError):
        SnapshotResult(
            kind=NativeKind.ATTEMPT,
            source_id="s-" + "0" * 64,
            snapshot_digest="1" * 64,
            files=(),
            missing_paths=(),
            orphan_files=(),
            bytes_written=0,
            source_changed=False,
        )


# ---------------------------------------------------------------------------
# Identity: content-based, independent of location and mtimes
# ---------------------------------------------------------------------------


def test_moving_the_tree_preserves_source_id_and_digest(tmp_path: Path) -> None:
    source_a = tmp_path / "a"
    source_b = tmp_path / "b-moved-elsewhere"
    write_tree(source_a, TREE)
    shutil.copytree(source_a, source_b, symlinks=False)
    out_a = tmp_path / "out-a"
    out_b = tmp_path / "out-b"
    with SourceReader(source_a, limits=Limits()) as reader_a, SourceReader(
        source_b, limits=Limits()
    ) as reader_b:
        result_a = Snapshotter(reader_a, out_a, Limits()).capture(default_plan(TREE))
        result_b = Snapshotter(reader_b, out_b, Limits()).capture(default_plan(TREE))
    assert result_a.source_id == result_b.source_id
    assert result_a.snapshot_digest == result_b.snapshot_digest


def test_single_byte_change_changes_the_digest(tmp_path: Path) -> None:
    source = tmp_path / "src"
    changed = dict(TREE)
    changed["cases/plain/attempts.jsonl"] = b"\n  leading blank \n\t tabbed \t\n"
    assert changed["cases/plain/attempts.jsonl"] != TREE["cases/plain/attempts.jsonl"]
    write_tree(source, changed)
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        result = Snapshotter(reader, out, Limits()).capture(default_plan(changed))
    assert result.snapshot_digest == expected_digest(changed)
    assert result.snapshot_digest != expected_digest(TREE)


# ---------------------------------------------------------------------------
# Missing closure members and orphans
# ---------------------------------------------------------------------------


def test_missing_closure_member_is_recorded_and_changes_the_digest(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        snapshotter = Snapshotter(reader, out, Limits())
        result = snapshotter.capture(default_plan(TREE, extra_missing=("cases/ghost.json",)))
    assert result.missing_paths == ("cases/ghost.json",)
    assert result.source_changed is False
    assert result.snapshot_digest == expected_digest(TREE, ("cases/ghost.json",))
    assert result.snapshot_digest != expected_digest(TREE)
    assert not (raw_dir(out, result) / "cases" / "ghost.json").exists()


def test_orphan_files_are_never_copied(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    write_tree(source, {"stray-orphan.txt": b"not in the closure"})
    out = tmp_path / "out"
    plan = Plan(
        kind=NativeKind.ATTEMPT,
        root_document="request.json",
        files=tuple(sorted(
            (PlannedFile(rel, 1024 * 1024) for rel in TREE), key=lambda f: f.relpath
        )),
        orphan_files=("stray-orphan.txt",),
    )
    with SourceReader(source, limits=Limits()) as reader:
        result = Snapshotter(reader, out, Limits()).capture(plan)
    assert result.orphan_files == ("stray-orphan.txt",)
    raw = raw_dir(out, result)
    assert not (raw / "stray-orphan.txt").exists()
    assert result.snapshot_digest == expected_digest(TREE)


# ---------------------------------------------------------------------------
# Output placement refusals (design 6.4.1 item 1)
# ---------------------------------------------------------------------------


def test_existing_output_root_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    output = tmp_path / "out"
    output.mkdir()
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, output, Limits())


def test_output_inside_input_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, source / "sub" / "out", Limits())
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, source / "out", Limits())


def test_output_equal_to_input_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, source, Limits())


def test_input_inside_output_by_spelling_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import mtsql_typecheck.evidence.snapshot as snapshot_module

    source = tmp_path / "src"
    write_tree(source, TREE)
    output = tmp_path / "out"
    real_abspath = os.path.abspath

    def fake_abspath(value):
        text = os.fspath(value)
        if text == str(source):
            # pretend the input root was reached through a spelling that sits
            # inside the (not yet existing) output root
            return str(output / "inside" / "src")
        return real_abspath(text)

    monkeypatch.setattr(snapshot_module.os.path, "abspath", fake_abspath)
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, output, Limits())


def test_capture_refuses_output_that_appeared_after_setup(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    output = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        snapshotter = Snapshotter(reader, output, Limits())
        output.mkdir()
        with pytest.raises(SnapshotSetupError):
            snapshotter.capture(default_plan(TREE))


# ---------------------------------------------------------------------------
# Budget (design 6.5)
# ---------------------------------------------------------------------------


def test_output_budget_exhaustion_stops_publishing(tmp_path: Path) -> None:
    source = tmp_path / "src"
    files = {"a.json": b"a" * 50, "b.json": b"b" * 60, "c.json": b"c" * 10}
    write_tree(source, files)
    limits = Limits(
        max_output_single_file_bytes=64,
        max_output_total_bytes=100,
        min_diagnostic_reserve_bytes=1,
    )
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        snapshotter = Snapshotter(reader, out, limits)
        with pytest.raises(BudgetExhaustedError):
            snapshotter.capture(default_plan(files))
    # raw budget is 100 - 1 = 99 bytes: a.json (50) fits, b.json (60) exceeds
    raw = out / "raw"
    source_dirs = list(raw.iterdir())
    assert len(source_dirs) == 1
    copied = source_dirs[0]
    assert (copied / "a.json").read_bytes() == files["a.json"]
    assert not (copied / "b.json").exists()
    assert not (copied / "c.json").exists()
    # originals untouched
    for rel, data in files.items():
        assert (source / rel).read_bytes() == data


def test_reserve_is_counted_inside_the_output_budget(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, {"only.json": b"x" * 41})
    limits = Limits(
        max_output_single_file_bytes=41,
        max_output_total_bytes=50,
        min_diagnostic_reserve_bytes=10,
    )
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(BudgetExhaustedError):
            Snapshotter(reader, out, limits).capture(default_plan({"only.json": b"x" * 41}))


# ---------------------------------------------------------------------------
# fsync failure injection
# ---------------------------------------------------------------------------


def test_fsync_failure_does_not_corrupt_originals_or_seal(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    plan = default_plan(TREE)

    def failing_fsync(fd: int) -> None:
        raise OSError("injected fsync failure")

    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotIoError):
            Snapshotter(reader, out, Limits(), fsync=failing_fsync).capture(plan)
    # originals untouched, byte for byte
    for rel, data in TREE.items():
        assert (source / rel).read_bytes() == data
    # nothing was published as a sealed snapshot: no result, and the output
    # (if anything was created at all) holds no complete manifest structure.
    # The caller decides what to do with the leftover directory.
    if out.exists():
        for copied in out.rglob("*"):
            if copied.is_file():
                rel = copied.relative_to(out / "raw" / list((out / "raw").iterdir())[0].name)
                assert TREE.get(str(rel)) is None or copied.read_bytes() == TREE[str(rel)]


# ---------------------------------------------------------------------------
# Source change handling (design 6.4.1 item 4)
# ---------------------------------------------------------------------------


def test_source_change_during_pass_one_writes_nothing(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as inner:
        wrapper = RecordingReader(inner)
        ordered = sorted(TREE)
        first_rel, second_rel = ordered[0], ordered[1]

        reads = {"n": 0}

        def hook() -> bytes:
            reads["n"] += 1
            if reads["n"] == 1:  # pass-1 read of the first file succeeds
                return TREE[first_rel]
            raise SourceChangedError("source drifted away mid-capture")

        # the hook serves both files' reads; the pass-1 read of the second
        # file is overall read #2 and aborts pass 1
        wrapper.read_hooks[first_rel] = hook
        wrapper.read_hooks[second_rel] = hook
        snapshotter = Snapshotter(inner, out, Limits())
        snapshotter._reader = wrapper
        result = snapshotter.capture(default_plan(TREE))
    assert result.source_changed is True
    assert result.bytes_written == 0
    assert [f.relpath for f in result.files] == [first_rel]
    assert result.snapshot_digest == compute_snapshot_digest(
        "attempt",
        "request.json",
        [(first_rel, len(TREE[first_rel]), hashlib.sha256(TREE[first_rel]).hexdigest())],
        (),
    )
    assert not out.exists()


def test_source_change_during_pass_two_stops_publishing(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    ordered = sorted(TREE)
    target = ordered[2]  # some middle file

    reads = {"n": 0}

    def hook() -> bytes:
        reads["n"] += 1
        if reads["n"] == 1:  # pass 1
            return TREE[target]
        return b"TAMPERED-CONTENT"  # pass 2 returns different bytes

    with SourceReader(source, limits=Limits()) as inner:
        wrapper = RecordingReader(inner)
        wrapper.read_hooks[target] = hook
        snapshotter = Snapshotter(inner, out, Limits())
        snapshotter._reader = wrapper
        result = snapshotter.capture(default_plan(TREE))

    assert result.source_changed is True
    # result keeps the full safely-read diagnostic closure with verified
    # pass-1 hashes, digest computed over exactly those records
    assert [f.relpath for f in result.files] == ordered
    assert result.snapshot_digest == expected_digest(TREE)
    assert result.source_id == compute_source_id(result.snapshot_digest)
    # but only the verified prefix actually reached raw/
    raw = raw_dir(out, result)
    for rel in ordered[: ordered.index(target)]:
        assert (raw / rel).read_bytes() == TREE[rel]
    assert not (raw / target).exists()


def test_final_restat_change_marks_result_unsealed(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    target = sorted(TREE)[1]
    with SourceReader(source, limits=Limits()) as inner:
        wrapper = RecordingReader(inner)
        # call 3 = final sweep: report a bumped mtime for the target file
        wrapper.stat_overrides[target] = (3, len(TREE[target]), 1)
        snapshotter = Snapshotter(inner, out, Limits())
        snapshotter._reader = wrapper
        result = snapshotter.capture(default_plan(TREE))

    assert result.source_changed is True
    assert result.bytes_written == sum(len(d) for d in TREE.values())
    # the whole closure was captured and verified before the sweep noticed
    raw = raw_dir(out, result)
    for rel, data in TREE.items():
        assert (raw / rel).read_bytes() == data
    assert result.snapshot_digest == expected_digest(TREE)


def test_file_deleted_before_pass_two_marks_change(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    victim = sorted(TREE)[0]
    with SourceReader(source, limits=Limits()) as reader:
        snapshotter = Snapshotter(reader, out, Limits())
        original_read = SourceReader.read_bytes

        def deleting_read(self, relpath, *, max_bytes):
            data = original_read(self, relpath, max_bytes=max_bytes)
            (source / victim).unlink()
            SourceReader.read_bytes = original_read
            return data

        SourceReader.read_bytes = deleting_read
        try:
            result = snapshotter.capture(default_plan(TREE))
        finally:
            SourceReader.read_bytes = original_read
    assert result.source_changed is True
    assert not (raw_dir(out, result) / victim).exists()


# ---------------------------------------------------------------------------
# Deadline and plan validation
# ---------------------------------------------------------------------------


def test_expired_deadline_aborts_capture(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(BudgetExhaustedError):
            Snapshotter(
                reader, out, Limits(), clock=lambda: 99.0, deadline=1.0
            ).capture(default_plan(TREE))
    assert not out.exists()


def test_duplicate_plan_paths_are_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    plan = Plan(
        kind=NativeKind.ATTEMPT,
        root_document="request.json",
        files=(
            PlannedFile("request.json", 1024),
            PlannedFile("request.json", 1024),
        ),
    )
    with SourceReader(source, limits=Limits()) as reader:
        with pytest.raises(SnapshotSetupError):
            Snapshotter(reader, out, Limits()).capture(plan)
    assert not out.exists()


def test_invalid_plan_shapes_are_refused(tmp_path: Path) -> None:
    source = tmp_path / "src"
    write_tree(source, TREE)
    out = tmp_path / "out"
    with SourceReader(source, limits=Limits()) as reader:
        snapshotter = Snapshotter(reader, out, Limits())
        with pytest.raises(SnapshotSetupError):
            snapshotter.capture(
                Plan(kind="not-a-kind", root_document="request.json", files=())
            )
        with pytest.raises(SnapshotSetupError):
            snapshotter.capture(
                Plan(kind=NativeKind.ATTEMPT, root_document="request.json",
                     files=(PlannedFile("request.json", -1),))
            )
    assert not out.exists()
