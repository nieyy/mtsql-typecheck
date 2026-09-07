"""Ownership journal and quarantine latch tests (design 6.2.1/6.2.3/6.4.5).

Round trips go through the contracts helpers (``load_ownership_journal``);
tamper cases mutate the file bytes by hand.  The fsync hook is a recording
spy, never a real disk dependency.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import ContractError
from mtsql_typecheck.contracts.runner import (
    OWNERSHIP_GENESIS_HASH,
    OwnershipEventKind,
    load_ownership_journal,
)
from mtsql_typecheck.runner.ownership import (
    OwnershipJournal,
    OwnershipJournalCorruptError,
    OwnershipWriteError,
    QuarantineError,
    QuarantineLatch,
)

RUN_ID = "run-20260906"


def _append_three(journal: OwnershipJournal) -> None:
    journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
    journal.append(
        OwnershipEventKind.ATTEMPT_ALLOCATED,
        attempt_id="attempt-1",
        token="ab" * 8,
    )
    journal.append(
        OwnershipEventKind.OBJECT_ALLOCATED,
        attempt_id="attempt-1",
        object_name="tc_" + "ab" * 8 + "_" + "cd" * 8 + "_a",
    )


class TestOwnershipJournal:
    def test_append_verify_and_chain_shape(self, tmp_path: Path):
        journal = OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)
        _append_three(journal)
        loaded = journal.verify()
        assert len(loaded) == 3
        assert loaded[0].seq == 1
        assert loaded[0].prev_event_hash == OWNERSHIP_GENESIS_HASH
        assert loaded[1].prev_event_hash == loaded[0].content_hash
        assert loaded[2].prev_event_hash == loaded[1].content_hash
        assert all(event.run_id == RUN_ID for event in loaded)
        journal.close()

    def test_on_disk_round_trip_via_contracts_loader(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        with OwnershipJournal(path, run_id=RUN_ID) as journal:
            _append_three(journal)
        loaded = load_ownership_journal(path.read_bytes())
        assert [event.seq for event in loaded] == [1, 2, 3]
        assert loaded[1].event_kind is OwnershipEventKind.ATTEMPT_ALLOCATED
        assert loaded[1].attempt_id == "attempt-1"

    def test_reopen_continues_seq_from_loaded_genesis(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        with OwnershipJournal(path, run_id=RUN_ID) as first:
            _append_three(first)
        with OwnershipJournal(path, run_id=RUN_ID) as second:
            assert second.next_seq == 4
            event = second.append(OwnershipEventKind.RUN_SEALED)
            assert event.seq == 4
            assert event.prev_event_hash == load_ownership_journal(path.read_bytes())[-2].content_hash
        assert len(load_ownership_journal(path.read_bytes())) == 4

    def test_fsync_hook_is_called_per_append(self, tmp_path: Path):
        calls: list[str] = []

        def hook(fd: int, what: str) -> None:
            del fd
            calls.append(what)

        with OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID, fsync_hook=hook) as journal:
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        assert calls == ["ownership-journal"]

    def test_tampered_file_refuses_to_open(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        with OwnershipJournal(path, run_id=RUN_ID) as journal:
            _append_three(journal)
        raw = path.read_bytes()
        # Flip one content byte inside the first line (keeping it valid JSONL
        # shape but breaking the content hash).
        tampered = raw.replace(b'"seq":1', b'"seq":2', 1) if b'"seq":1' in raw else raw
        assert tampered != raw
        path.write_bytes(tampered)
        with pytest.raises(OwnershipJournalCorruptError):
            OwnershipJournal(path, run_id=RUN_ID)

    def test_tampered_tail_detected_by_verify_and_append_refused(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        journal = OwnershipJournal(path, run_id=RUN_ID)
        _append_three(journal)
        raw = path.read_bytes()
        # Append an unterminated extra event line whose content hash is wrong.
        path.write_bytes(raw + b'{"attempt_id":null,"connection_id":null,"content_hash":"0"}\n')
        with pytest.raises(OwnershipJournalCorruptError):
            journal.verify()
        assert journal.inconsistent
        with pytest.raises(OwnershipJournalCorruptError):
            journal.append(OwnershipEventKind.RUN_SEALED)
        journal.close()

    def test_diverged_prefix_refuses_appends(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        journal = OwnershipJournal(path, run_id=RUN_ID)
        journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        # A second writer appends behind our back (single-writer violation).
        other = OwnershipJournal(path, run_id=RUN_ID)
        other.append(OwnershipEventKind.RUN_SEALED)
        other.close()
        with pytest.raises(OwnershipJournalCorruptError):
            journal.verify()
        assert journal.inconsistent
        with pytest.raises(OwnershipJournalCorruptError):
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        journal.close()

    def test_foreign_run_id_is_refused(self, tmp_path: Path):
        path = tmp_path / "ownership.jsonl"
        with OwnershipJournal(path, run_id="other-run") as journal:
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        with pytest.raises(OwnershipJournalCorruptError):
            OwnershipJournal(path, run_id=RUN_ID)

    def test_write_failure_marks_journal_failed(self, tmp_path: Path):
        def failing_fsync(fd: int, what: str) -> None:
            raise OSError("disk gone")

        journal = OwnershipJournal(
            tmp_path / "ownership.jsonl", run_id=RUN_ID, fsync_hook=failing_fsync
        )
        with pytest.raises(OwnershipWriteError):
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        assert journal.failed
        with pytest.raises(OwnershipWriteError):
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)
        journal.close()

    def test_missing_parent_directory_is_refused(self, tmp_path: Path):
        with pytest.raises(ContractError):
            OwnershipJournal(tmp_path / "nope" / "ownership.jsonl", run_id=RUN_ID)

    def test_append_after_close_is_refused(self, tmp_path: Path):
        journal = OwnershipJournal(tmp_path / "ownership.jsonl", run_id=RUN_ID)
        journal.close()
        with pytest.raises(ContractError):
            journal.append(OwnershipEventKind.RUN_LOCK_ACQUIRED)


class TestQuarantineLatch:
    def test_initially_allows_dispatch(self):
        latch = QuarantineLatch()
        assert not latch.tripped
        assert latch.allow_dispatch()
        latch.require_dispatch_allowed()

    def test_trip_is_idempotent_and_terminal(self):
        latch = QuarantineLatch()
        latch.trip("termination unknown")
        assert latch.tripped
        assert latch.reason == "termination unknown"
        # Later trips cannot change the reason or un-trip the latch.
        latch.trip("different reason")
        assert latch.reason == "termination unknown"
        assert latch.tripped

    def test_tripped_latch_stops_dispatch_forever(self):
        latch = QuarantineLatch()
        latch.trip("cleanup failed")
        assert not latch.allow_dispatch()
        with pytest.raises(QuarantineError):
            latch.require_dispatch_allowed()

    def test_reason_must_be_bounded_text(self):
        latch = QuarantineLatch()
        with pytest.raises(ContractError):
            latch.trip("")
        with pytest.raises(ContractError):
            latch.trip("x" * 513)
        with pytest.raises(ContractError):
            latch.trip(None)  # type: ignore[arg-type]
        assert not latch.tripped
