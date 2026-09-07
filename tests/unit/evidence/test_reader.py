"""Unit tests for the safe bounded source reader (design 6.4.1, 6.5).

Fakes and real temporary files only: no database, no network.  Over-limit
rejections are proven to stop BEFORE over-reading via injected opener/read
counting hooks (design Phase 1 verification: 用文件打开计数证明超限前停止).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.delivery import Limits
from mtsql_typecheck.evidence.reader import (
    BudgetExhaustedError,
    EntryStat,
    EvidenceReadError,
    MissingEntryError,
    ReadLimitExceededError,
    RootInvalidError,
    SourceChangedError,
    SourceReader,
    UnsafePathError,
)

TREE = {
    "request.json": b'{"schema": 1}\n',
    "cases/one/case.json": 'نص unicode π😀\n'.encode("utf-8"),
    "cases/one/empty.json": b"",
    "cases/one/whitespace.json": b"\n  spaced  \t\n\n",
    "deep/a/b/c/d.txt": b"x",
}


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


class CountingOpener:
    """Injectable opener recording every open call."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, path, flags, dir_fd=None):
        self.calls += 1
        return os.open(path, flags, dir_fd=dir_fd)


class CountingRead:
    """Injectable read seam recording how many bytes the kernel delivered."""

    def __init__(self) -> None:
        self.total_bytes = 0
        self.calls = 0

    def __call__(self, fd: int, size: int) -> bytes:
        data = os.read(fd, size)
        self.total_bytes += len(data)
        self.calls += 1
        return data


class FakeClock:
    """Monotonic fake advancing a fixed step on every call."""

    def __init__(self, start: float = 0.0, step: float = 1.0) -> None:
        self.now = start
        self.step = step

    def __call__(self) -> float:
        self.now += self.step
        return self.now


def make_reader(root: Path, **kwargs) -> SourceReader:
    kwargs.setdefault("limits", Limits())
    return SourceReader(root, **kwargs)


# ---------------------------------------------------------------------------
# Normal reads preserve bytes exactly
# ---------------------------------------------------------------------------


def test_read_bytes_preserves_tree_byte_for_byte(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        for rel, data in TREE.items():
            max_bytes = max(len(data), 1)
            assert reader.read_bytes(rel, max_bytes=max_bytes) == data, rel


def test_read_empty_file_with_zero_budget(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        assert reader.read_bytes("cases/one/empty.json", max_bytes=0) == b""


def test_stat_kinds_and_exists(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        st = reader.stat("request.json")
        assert isinstance(st, EntryStat)
        assert (st.kind, st.size_bytes) == ("file", len(TREE["request.json"]))
        assert st.mtime_ns > 0
        assert reader.stat("cases").kind == "dir"
        assert reader.stat("").kind == "dir"
        assert reader.exists("request.json") is True
        assert reader.exists("cases") is True
        assert reader.exists("no/such/entry") is False


def test_list_dir_is_sorted(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        assert reader.list_dir("") == ["cases", "deep", "request.json"]
        assert reader.list_dir("cases/one") == [
            "case.json",
            "empty.json",
            "whitespace.json",
        ]


def test_missing_entry_raises(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        with pytest.raises(MissingEntryError):
            reader.stat("cases/ghost.json")
        with pytest.raises(MissingEntryError):
            reader.read_bytes("cases/ghost.json", max_bytes=10)
        with pytest.raises(MissingEntryError):
            reader.list_dir("cases/ghost")


# ---------------------------------------------------------------------------
# JSONL reading
# ---------------------------------------------------------------------------


def test_jsonl_lines_and_line_numbers(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.jsonl": b'{"n":1}\n{"n":2}\n\n{"n":3}'})
    with make_reader(tmp_path) as reader:
        lines = reader.read_jsonl("a.jsonl", max_line_bytes=100, max_total_bytes=1000)
    assert lines == [(1, b'{"n":1}'), (2, b'{"n":2}'), (3, b""), (4, b'{"n":3}')]


def test_jsonl_empty_file(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.jsonl": b""})
    with make_reader(tmp_path) as reader:
        assert reader.read_jsonl("a.jsonl", max_line_bytes=10, max_total_bytes=10) == []


# ---------------------------------------------------------------------------
# walk
# ---------------------------------------------------------------------------


def test_walk_is_deterministic_and_covers_the_tree(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        entries = list(reader.walk("", max_entries=100))
    assert entries == [
        ("cases", "dir"),
        ("cases/one", "dir"),
        ("cases/one/case.json", "file"),
        ("cases/one/empty.json", "file"),
        ("cases/one/whitespace.json", "file"),
        ("deep", "dir"),
        ("deep/a", "dir"),
        ("deep/a/b", "dir"),
        ("deep/a/b/c", "dir"),
        ("deep/a/b/c/d.txt", "file"),
        ("request.json", "file"),
    ]


def test_walk_yields_prefix_first(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        entries = list(reader.walk("cases/one", max_entries=100))
    assert entries[0] == ("cases/one", "dir")
    assert ("cases/one/case.json", "file") in entries
    assert all(e[0].startswith("cases/one") for e in entries)


def test_walk_max_entries_exceeded(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        with pytest.raises(ReadLimitExceededError):
            list(reader.walk("", max_entries=3))


def test_walk_rechecks_root_identity(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    reader = make_reader(tmp_path)
    with reader:
        reader._root_identity = (12345, 67890)
        with pytest.raises(SourceChangedError):
            list(reader.walk("", max_entries=100))


# ---------------------------------------------------------------------------
# Unsafe paths (design 6.4.1 item 1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relpath",
    [
        "/etc/passwd",
        "//server/share",
        "a/../b",
        "../escape",
        "./here",
        "a/./b",
        "a//b",
        "trailing/",
        "a\\b",
        "a\x00b",
        "C:\\\\windows",
    ],
)
def test_unsafe_paths_are_refused(tmp_path: Path, relpath: str) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        with pytest.raises(UnsafePathError):
            reader.stat(relpath)
        with pytest.raises(UnsafePathError):
            reader.read_bytes(relpath, max_bytes=10)
        with pytest.raises(UnsafePathError):
            reader.list_dir(relpath)


def test_over_long_path_is_refused(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    long_name = "n" * 200
    relpath = "/".join([long_name] * 6)  # 6*200 + 5 separators > 1024 bytes
    assert len(relpath.encode("utf-8")) > Limits().max_path_bytes
    with make_reader(tmp_path) as reader:
        with pytest.raises(UnsafePathError):
            reader.stat(relpath)


def test_depth_limit_is_enforced(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a/b/c/d/e/f/g.txt": b"x"})
    limits = Limits(max_dir_depth=3)
    with SourceReader(tmp_path, limits=limits) as reader:
        with pytest.raises(UnsafePathError):
            reader.stat("a/b/c/d/e/f/g.txt")
        with pytest.raises(UnsafePathError):
            list(reader.walk("", max_entries=100))
        # within the limit it works
        assert reader.stat("a/b/c").kind == "dir"


def test_depth_17_tree_refused_with_default_limits(tmp_path: Path) -> None:
    deep = Path(tmp_path)
    for name in [f"d{i}" for i in range(17)]:
        deep = deep / name
    deep.mkdir(parents=True)
    (deep / "leaf.txt").write_bytes(b"x")
    with make_reader(tmp_path) as reader:
        relpath = "/".join([f"d{i}" for i in range(17)] + ["leaf.txt"])
        with pytest.raises(UnsafePathError):
            reader.read_bytes(relpath, max_bytes=10)
        with pytest.raises(UnsafePathError):
            list(reader.walk("", max_entries=1000))


# ---------------------------------------------------------------------------
# Symlinks and non-regular files
# ---------------------------------------------------------------------------


def test_symlink_root_is_refused(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    link = tmp_path.parent / (tmp_path.name + "-link")
    link.symlink_to(tmp_path)
    try:
        with pytest.raises(RootInvalidError):
            make_reader(link)
    finally:
        link.unlink()


def test_symlink_component_is_refused(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    os.symlink("one", tmp_path / "cases" / "link")
    with make_reader(tmp_path) as reader:
        with pytest.raises(UnsafePathError):
            reader.read_bytes("cases/link/case.json", max_bytes=100)
        with pytest.raises(UnsafePathError):
            reader.stat("cases/link/case.json")
        # walk reports the symlink without ever opening it
        entries = list(reader.walk("cases", max_entries=100))
        assert ("cases/link", "other") in entries


def test_symlink_final_component_is_refused(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    os.symlink("request.json", tmp_path / "alias.json")
    with make_reader(tmp_path) as reader:
        with pytest.raises(UnsafePathError):
            reader.read_bytes("alias.json", max_bytes=100)
        with pytest.raises(UnsafePathError):
            reader.stat("alias.json")
        with pytest.raises(UnsafePathError):
            reader.exists("alias.json")


def test_fifo_is_refused_as_document(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    os.mkfifo(tmp_path / "pipe")
    with make_reader(tmp_path) as reader:
        assert reader.stat("pipe").kind == "other"
        with pytest.raises(UnsafePathError):
            reader.read_bytes("pipe", max_bytes=100)


def test_read_directory_is_refused(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        with pytest.raises(UnsafePathError):
            reader.read_bytes("cases", max_bytes=100)


# ---------------------------------------------------------------------------
# Bounded reads: reject BEFORE over-reading (design 6.5, Phase 1 proof)
# ---------------------------------------------------------------------------


def test_over_limit_document_rejected_without_opening(tmp_path: Path) -> None:
    write_tree(tmp_path, {"big.json": b"x" * 1000})
    reader = make_reader(tmp_path)
    opener = CountingOpener()
    reader._opener = opener
    with reader:
        with pytest.raises(ReadLimitExceededError):
            reader.read_bytes("big.json", max_bytes=999)
        # Zero opens: the size precheck rejected the file before it was opened.
        assert opener.calls == 0


def test_over_limit_jsonl_total_rejected_without_opening(tmp_path: Path) -> None:
    write_tree(tmp_path, {"big.jsonl": b"x" * 1000})
    reader = make_reader(tmp_path)
    opener = CountingOpener()
    reader._opener = opener
    with reader:
        with pytest.raises(ReadLimitExceededError):
            reader.read_jsonl("big.jsonl", max_line_bytes=100, max_total_bytes=999)
        assert opener.calls == 0


def test_over_limit_jsonl_line_stops_before_reading_the_whole_file(
    tmp_path: Path,
) -> None:
    huge = b"y" * 400_000
    payload = b'{"n":1}\n' + huge + b"\n" + b'{"n":2}\n'
    write_tree(tmp_path, {"trace.jsonl": payload})
    reader = make_reader(tmp_path)
    opener = CountingOpener()
    counting_read = CountingRead()
    reader._opener = opener
    reader._read = counting_read
    with reader:
        with pytest.raises(ReadLimitExceededError) as excinfo:
            reader.read_jsonl("trace.jsonl", max_line_bytes=1000, max_total_bytes=10_000_000)
        # The opener ran exactly once (the single bounded file open).
        assert opener.calls == 1
        # Bytes actually delivered from the kernel stayed far below the file
        # size: the reader stopped as soon as the over-limit line was proven
        # over the cap instead of draining the rest of the file.
        assert counting_read.total_bytes < len(payload) - 100_000
        assert "line 2" in str(excinfo.value)


def test_over_limit_document_via_growth_is_bounded(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.bin": b"a" * 10})
    reader = make_reader(tmp_path)
    counting_read = CountingRead()
    reader._read = counting_read

    original_read = os.read

    def growing_read(fd: int, size: int) -> bytes:
        data = original_read(fd, size)
        if data:
            # grow the file while it is being read
            with open(tmp_path / "f.bin", "ab") as handle:
                handle.write(b"b" * 1000)
        return data

    reader._read = growing_read
    with reader:
        with pytest.raises(SourceChangedError):
            reader.read_bytes("f.bin", max_bytes=10_000)
        # even the growth path never delivered more than the cap
        assert counting_read.total_bytes <= 10_000 + 64 * 1024


# ---------------------------------------------------------------------------
# Change detection
# ---------------------------------------------------------------------------


def test_mtime_change_during_read_is_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": b"0123456789" * 100})
    target = tmp_path / "f.txt"
    reader = make_reader(tmp_path)
    original_read = os.read

    def mutating_read(fd: int, size: int) -> bytes:
        data = original_read(fd, size)
        if data:
            st = os.lstat(target)
            os.utime(target, ns=(st.st_atime_ns, st.st_mtime_ns + 1))
        return data

    reader._read = mutating_read
    with reader:
        with pytest.raises(SourceChangedError):
            reader.read_bytes("f.txt", max_bytes=10_000)


def test_replacement_between_lstat_and_open_is_detected(tmp_path: Path) -> None:
    write_tree(tmp_path, {"f.txt": b"original"})
    reader = make_reader(tmp_path)
    real_open = os.open
    state = {"swapped": False}

    def swapping_opener(path, flags, dir_fd=None):
        if not state["swapped"] and path == "f.txt":
            state["swapped"] = True
            (tmp_path / "f.txt").write_bytes(b"REPLACED")
        return real_open(path, flags, dir_fd=dir_fd)

    reader._opener = swapping_opener
    with reader:
        with pytest.raises(SourceChangedError):
            reader.read_bytes("f.txt", max_bytes=100)


# ---------------------------------------------------------------------------
# Deadline and lifecycle
# ---------------------------------------------------------------------------


def test_deadline_expires_during_walk(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    clock = FakeClock()
    with SourceReader(tmp_path, limits=Limits(), clock=clock, deadline=2.5) as reader:
        with pytest.raises(BudgetExhaustedError):
            list(reader.walk("", max_entries=100))


def test_deadline_expires_during_jsonl_read(tmp_path: Path) -> None:
    payload = b"".join(b'{"n":%d}\n' % i for i in range(5000))
    write_tree(tmp_path, {"big.jsonl": payload})
    clock = FakeClock()
    with SourceReader(tmp_path, limits=Limits(), clock=clock, deadline=1.5) as reader:
        with pytest.raises(BudgetExhaustedError):
            reader.read_jsonl("big.jsonl", max_line_bytes=100, max_total_bytes=1_000_000)


def test_deadline_expires_before_read(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    clock = FakeClock(start=10.0)
    with SourceReader(tmp_path, limits=Limits(), clock=clock, deadline=10.5) as reader:
        with pytest.raises(BudgetExhaustedError):
            reader.read_bytes("request.json", max_bytes=100)


def test_closed_reader_raises(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    reader = make_reader(tmp_path)
    reader.close()
    reader.close()  # idempotent
    with pytest.raises(EvidenceReadError):
        reader.stat("request.json")


def test_reader_context_manager_closes(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        assert reader.read_bytes("request.json", max_bytes=100)
        dirfd = reader._dirfd
    with pytest.raises(OSError):
        os.fstat(dirfd)


def test_invalid_root_kinds_are_refused(tmp_path: Path) -> None:
    plain = tmp_path / "plain.txt"
    plain.write_bytes(b"not a dir")
    with pytest.raises(RootInvalidError):
        make_reader(plain)
    with pytest.raises(RootInvalidError):
        make_reader(tmp_path / "does-not-exist")


def test_bad_argument_types_are_rejected(tmp_path: Path) -> None:
    write_tree(tmp_path, TREE)
    with make_reader(tmp_path) as reader:
        with pytest.raises(ValueError):
            reader.read_bytes("request.json", max_bytes=-1)
        with pytest.raises(ValueError):
            reader.read_jsonl("request.json", max_line_bytes=-1, max_total_bytes=10)
        with pytest.raises(ValueError):
            list(reader.walk("", max_entries=-1))
