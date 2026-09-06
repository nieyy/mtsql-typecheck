"""T01 persistence-matrix tests for reduction/trace.py (D2 Phase 5).

Every expectation here is hand-written: record hashes are recomputed in the
test with ``hashlib`` over content dicts the test constructs itself (never
by calling sink internals), and corrupt/partial trace files are built line
by line by the test-side ``Script`` helper instead of the sink under test.
The sink under test is ``JsonlTraceSink`` plus the read-side ``read_trace``;
the frozen contract models and codec primitives are shared test
infrastructure, not the code under test.
"""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.oracle import (
    EVIDENCE_APPEND_HARD_CAP,
    EVIDENCE_RESERVE_BYTES,
    ArtifactRef,
    TraceRecord,
)
from mtsql_typecheck.reduction.trace import (
    BEST_SOURCE_ACCEPTED,
    BEST_SOURCE_ORIGINAL,
    FILES_DIR_NAME,
    TRACE_FILE_NAME,
    JsonlTraceSink,
    TraceBudgetError,
    TraceOrderError,
    TracePathError,
    TraceWriteError,
    read_trace,
)

GENESIS = "0" * 64
CASE_ID = "a" * 64
HASH1 = "c" * 64
ATTEMPT_HASH = "b" * 64

ORIGINAL_DATA = json.dumps(
    {"kind": "case-payload", "label": "original"}, sort_keys=True, separators=(",", ":")
).encode("utf-8")
CHILD_DATA = json.dumps(
    {"kind": "case-payload", "label": "child"}, sort_keys=True, separators=(",", ":")
).encode("utf-8")
OTHER_DATA = json.dumps(
    {"kind": "case-payload", "label": "other", "v": [1, 2, 3]},
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")

START_COMPLEXITY = [10, 5, 4, 30, 100]
CHILD_COMPLEXITY = [5, 3, 2, 12, 50]


# --------------------------------------------------------------------------
# Test-side independent helpers
# --------------------------------------------------------------------------


def canonical(value: object) -> bytes:
    """The documented canonical JSON form, rebuilt by hand in the test."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def expected_hash(content: dict) -> str:
    """Independent record-hash recomputation over content minus ``hash``."""
    return hashlib.sha256(canonical(content)).hexdigest()


def ref_obj(ref: ArtifactRef) -> dict:
    return {
        "path": ref.path,
        "size_bytes": ref.size_bytes,
        "sha256": ref.sha256,
        "schema_version": ref.schema_version,
    }


def line_size(record: TraceRecord) -> int:
    return len(canonical(record.to_obj())) + 1


class Chain:
    """Test-side builder of properly chained TraceRecords."""

    def __init__(self) -> None:
        self.seq = 0
        self.prev = GENESIS
        self.log: list[tuple[int, str, str]] = []  # (seq, kind, hash)

    def _content(self, seq, kind, payload_ref, inline, prev) -> dict:
        return {
            "seq": seq,
            "kind": kind,
            "payload_ref": ref_obj(payload_ref) if payload_ref is not None else None,
            "inline": inline,
            "prev_hash": prev,
        }

    def record(self, kind, payload_ref=None, inline=None) -> TraceRecord:
        self.seq += 1
        content = self._content(self.seq, kind, payload_ref, inline, self.prev)
        digest = expected_hash(content)
        record = TraceRecord(
            seq=self.seq,
            kind=kind,
            payload_ref=payload_ref,
            inline=inline,
            prev_hash=self.prev,
            hash=digest,
        )
        self.prev = digest
        self.log.append((self.seq, kind, digest))
        return record

    def peek(self, kind, payload_ref=None, inline=None) -> TraceRecord:
        """Build the next record without advancing the chain."""
        content = self._content(self.seq + 1, kind, payload_ref, inline, self.prev)
        digest = expected_hash(content)
        return TraceRecord(
            seq=self.seq + 1,
            kind=kind,
            payload_ref=payload_ref,
            inline=inline,
            prev_hash=self.prev,
            hash=digest,
        )

    def comparison_hashes(self, count: int = 3) -> list[str]:
        return [h for _, kind, h in self.log if kind == "COMPARISON"][-count:]


class Script:
    """Hand-built raw trace files for partial/corrupt read-side scenarios."""

    def __init__(self) -> None:
        self.lines: list[bytes] = []
        self.files: dict[str, bytes] = {}
        self.seq = 0
        self.prev = GENESIS

    def payload(self, data: bytes) -> dict:
        sha = hashlib.sha256(data).hexdigest()
        path = f"{FILES_DIR_NAME}/{sha}.json"
        self.files[path] = data
        return {"path": path, "size_bytes": len(data), "sha256": sha, "schema_version": 1}

    def add(self, kind, payload_ref=None, inline=None, *, seq=None, prev=None) -> str:
        self.seq += 1
        content = {
            "seq": self.seq if seq is None else seq,
            "kind": kind,
            "payload_ref": payload_ref,
            "inline": inline,
            "prev_hash": self.prev if prev is None else prev,
        }
        digest = expected_hash(content)
        obj = dict(content)
        obj["hash"] = digest
        self.lines.append(canonical(obj) + b"\n")
        if seq is None and prev is None:
            self.prev = digest
        return digest

    def raw(self, data: bytes) -> None:
        self.lines.append(data)

    def write(self, root: Path) -> Path:
        root.mkdir(parents=True)
        (root / FILES_DIR_NAME).mkdir()
        (root / TRACE_FILE_NAME).write_bytes(b"".join(self.lines))
        for rel, data in self.files.items():
            (root / rel).write_bytes(data)
        return root

    def record_count(self) -> int:
        return len(self.lines)


def add_head(script: Script, complexity: list[int]) -> dict:
    original = script.payload(ORIGINAL_DATA)
    script.add("SNAPSHOT", payload_ref=original, inline={"case_id": CASE_ID})
    script.add(
        "START",
        inline={"complexity": complexity, "payload_ref": original, "case_id": CASE_ID},
    )
    return original


def add_group(script: Script, prefix: str, *, prep_fail: int = -1) -> list[str]:
    comparison_hashes: list[str] = []
    for attempt in range(3):
        script.add("REQUESTED", inline={"attempt_id": f"{prefix}{attempt}"})
        if attempt != prep_fail:
            script.add("EXPECTATION", inline={"request_hash": HASH1})
        script.add(
            "EVIDENCE",
            payload_ref=script.payload(canonical({"evidence": f"{prefix}{attempt}"})),
            inline={"attempt_id": f"{prefix}{attempt}"},
        )
        script.add("RESULT", inline={"attempt_id": f"{prefix}{attempt}"})
        comparison_hashes.append(
            script.add(
                "COMPARISON",
                payload_ref=script.payload(canonical({"c": f"{prefix}{attempt}"})),
                inline={"attempt_id": f"{prefix}{attempt}"},
            )
        )
    script.add("REPLAY", inline={})
    return comparison_hashes


class SpyHook:
    """Records fsync hook invocations; can fail on the n-th call of a kind."""

    def __init__(self, fail_on=None):
        self.events: list[str] = []
        self.fail_on = fail_on  # e.g. (3, "trace-file")

    def __call__(self, fd: int, what: str) -> None:
        self.events.append(what)
        if self.fail_on is not None and what == self.fail_on[1]:
            if self.events.count(what) >= self.fail_on[0]:
                raise OSError(28, "No space left on device")


# --------------------------------------------------------------------------
# Shared drivers
# --------------------------------------------------------------------------


def drive_run(sink: JsonlTraceSink, chain: Chain, *, finish: bool = True):
    """Drive one complete reduction-shaped run through the sink."""
    receipts = []
    published_bytes = 0
    original_ref = sink.publish_payload(ORIGINAL_DATA)
    published_bytes += len(ORIGINAL_DATA)
    receipts.append(
        sink.append(chain.record("SNAPSHOT", payload_ref=original_ref, inline={"case_id": CASE_ID}))
    )
    receipts.append(
        sink.append(
            chain.record(
                "START",
                inline={
                    "complexity": START_COMPLEXITY,
                    "payload_ref": ref_obj(original_ref),
                    "case_id": CASE_ID,
                },
            )
        )
    )
    for group in range(2):
        for attempt in range(3):
            label = f"g{group}a{attempt}"
            receipts.append(
                sink.append(chain.record("REQUESTED", inline={"attempt_id": label}))
            )
            prepare_failed = group == 0 and attempt == 1
            if not prepare_failed:
                receipts.append(
                    sink.append(chain.record("EXPECTATION", inline={"request_hash": HASH1}))
                )
            evidence = sink.publish_payload(
                canonical({"evidence": label, "rows": list(range(attempt + 1))})
            )
            published_bytes += evidence.size_bytes
            receipts.append(
                sink.append(chain.record("EVIDENCE", payload_ref=evidence, inline={"attempt_id": label}))
            )
            receipts.append(sink.append(chain.record("RESULT", inline={"attempt_id": label})))
            comparison = sink.publish_payload(canonical({"comparison": label}))
            published_bytes += comparison.size_bytes
            receipts.append(
                sink.append(
                    chain.record("COMPARISON", payload_ref=comparison, inline={"attempt_id": label})
                )
            )
        receipts.append(sink.append(chain.record("REPLAY", inline={"group": group})))
    child_ref = sink.publish_payload(CHILD_DATA)
    published_bytes += len(CHILD_DATA)
    receipts.append(
        sink.append(
            chain.record(
                "ACCEPTED",
                payload_ref=child_ref,
                inline={
                    "child_payload_ref": ref_obj(child_ref),
                    "parent_complexity": START_COMPLEXITY,
                    "child_complexity": CHILD_COMPLEXITY,
                    "comparison_hashes": chain.comparison_hashes(3),
                    "attempt_hashes": [ATTEMPT_HASH] * 3,
                },
            )
        )
    )
    if finish:
        receipts.append(sink.append(chain.record("FINISHED", inline={"outcome": "REDUCED"})))
    return receipts, child_ref, published_bytes


def expected_kinds() -> list[str]:
    kinds = ["SNAPSHOT", "START"]
    for group in range(2):
        for attempt in range(3):
            kinds.append("REQUESTED")
            if not (group == 0 and attempt == 1):
                kinds.append("EXPECTATION")
            kinds += ["EVIDENCE", "RESULT", "COMPARISON"]
        kinds.append("REPLAY")
    kinds += ["ACCEPTED", "FINISHED"]
    return kinds


def new_sink(tmp_path: Path, budget: int = 256 * 1024 * 1024, hook=None) -> JsonlTraceSink:
    return JsonlTraceSink(tmp_path / "out", budget, fsync_hook=hook)


# --------------------------------------------------------------------------
# Happy path: grammar, independent hash chain, receipts, audit
# --------------------------------------------------------------------------


def test_happy_path_full_grammar_chain_and_audit(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    receipts, child_ref, published_bytes = drive_run(sink, chain)
    sink.close()

    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    lines = raw.split(b"\n")[:-1]
    assert len(lines) == len(expected_kinds()) == len(receipts) == len(chain.log)

    # Exact mandatory order.
    parsed = [json.loads(line) for line in lines]
    assert [obj["kind"] for obj in parsed] == expected_kinds()

    # Independent chain recomputation: seq, prev_hash and hash are rebuilt by
    # the test over its own content dicts, never via the sink.
    prev = GENESIS
    for seq, obj in enumerate(parsed, start=1):
        assert obj["seq"] == seq
        assert obj["prev_hash"] == prev
        content = {k: obj[k] for k in ("seq", "kind", "payload_ref", "inline", "prev_hash")}
        assert obj["hash"] == expected_hash(content)
        prev = obj["hash"]

    # Receipts match the independently computed chain.
    for receipt, (seq, kind, digest) in zip(receipts, chain.log):
        assert (receipt.seq, receipt.kind, receipt.record_hash) == (seq, kind, digest)

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "COMPLETE"
    assert audit.records_verified == len(lines)
    assert audit.best_source == BEST_SOURCE_ACCEPTED
    assert audit.best_payload_ref is not None
    assert audit.best_payload_ref.path == child_ref.path
    assert audit.last_record_hash == chain.prev

    # Payloads live in dependency files; the trace carries references only.
    assert b'"rows"' not in raw
    child_file = tmp_path / "out" / child_ref.path
    assert child_file.read_bytes() == CHILD_DATA
    assert child_file.stat().st_size == child_ref.size_bytes

    # read_trace is read-only: the file is byte-identical afterwards.
    assert (tmp_path / "out" / TRACE_FILE_NAME).read_bytes() == raw


def test_receipts_and_byte_accounting(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    receipts, _, published_bytes = drive_run(sink, chain)
    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert sink.bytes_written == len(raw)
    # The budget settles both trace lines and published payload bytes.
    assert sink.remaining_bytes == 256 * 1024 * 1024 - len(raw) - published_bytes
    assert published_bytes > 0
    sink.close()


def test_fsync_hook_observed_before_receipt(tmp_path):
    hook = SpyHook()
    sink = new_sink(tmp_path, hook=hook)
    chain = Chain()
    original_ref = sink.publish_payload(ORIGINAL_DATA)
    assert "payload-file" in hook.events
    assert "dir" in hook.events
    before = list(hook.events)
    receipt = sink.append(
        chain.record("SNAPSHOT", payload_ref=original_ref, inline={"case_id": CASE_ID})
    )
    # The hook runs synchronously inside append, so the trace-file fsync for
    # this record happened before the receipt was returned.
    assert hook.events[len(before) :].count("trace-file") == 1
    assert receipt.seq == 1
    sink.append(
        chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID})
    )
    assert hook.events.count("trace-file") == 2
    sink.append(chain.record("FINISHED", inline=None))
    assert hook.events.count("trace-file") == 3
    sink.close()


# --------------------------------------------------------------------------
# Grammar guard
# --------------------------------------------------------------------------


def test_grammar_rejects_out_of_order_kinds(tmp_path):
    scenarios = {
        "start_first": ["START"],
        "snapshot_twice": ["SNAPSHOT", "SNAPSHOT"],
        "replay_without_attempt": ["SNAPSHOT", "START", "REPLAY"],
        "accepted_first": ["ACCEPTED"],
        "result_without_evidence": ["SNAPSHOT", "START", "REQUESTED", "RESULT"],
        "double_expectation": ["SNAPSHOT", "START", "REQUESTED", "EXPECTATION", "EXPECTATION"],
        "expectation_after_failure_branch": [
            "SNAPSHOT",
            "START",
            "REQUESTED",
            "EVIDENCE",
            "EXPECTATION",
        ],
        "finished_mid_attempt": ["SNAPSHOT", "START", "REQUESTED", "FINISHED"],
        "accepted_without_replay": [
            "SNAPSHOT",
            "START",
            "REQUESTED",
            "EXPECTATION",
            "EVIDENCE",
            "RESULT",
            "COMPARISON",
            "ACCEPTED",
        ],
        "fourth_attempt_in_group": ["SNAPSHOT", "START"]
        + ["REQUESTED", "EXPECTATION", "EVIDENCE", "RESULT", "COMPARISON"] * 3
        + ["REQUESTED"],
        "record_after_finished": ["SNAPSHOT", "START", "FINISHED", "REQUESTED"],
    }
    for name, kinds in scenarios.items():
        root = tmp_path / name
        sink = JsonlTraceSink(root, 256 * 1024 * 1024)
        chain = Chain()
        for kind in kinds[:-1]:
            sink.append(chain.record(kind, inline={"n": name}))
        size_before = sink.bytes_written
        with pytest.raises(TraceOrderError):
            sink.append(chain.record(kinds[-1], inline={"n": name}))
        assert sink.bytes_written == size_before, name
        sink.close()


def test_grammar_rejects_bad_seq_and_stale_prev_hash(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    size_before = sink.bytes_written

    duplicate = TraceRecord(
        seq=1,
        kind="START",
        inline=None,
        prev_hash=GENESIS,
        hash=expected_hash(
            {"seq": 1, "kind": "START", "payload_ref": None, "inline": None, "prev_hash": GENESIS}
        ),
    )
    with pytest.raises(TraceOrderError):
        sink.append(duplicate)

    stale = TraceRecord(
        seq=2,
        kind="START",
        inline=None,
        prev_hash=GENESIS,
        hash=expected_hash(
            {"seq": 2, "kind": "START", "payload_ref": None, "inline": None, "prev_hash": GENESIS}
        ),
    )
    with pytest.raises(TraceOrderError):
        sink.append(stale)
    assert sink.bytes_written == size_before
    sink.close()


# --------------------------------------------------------------------------
# T01 persistence matrix (design line 559)
# --------------------------------------------------------------------------


def test_t01_budget_refused_before_requested_no_execution(tmp_path):
    chain = Chain()
    snapshot = chain.record("SNAPSHOT", inline={"case_id": CASE_ID})
    start = chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID})
    budget = EVIDENCE_RESERVE_BYTES + line_size(snapshot) + line_size(start)
    sink = new_sink(tmp_path, budget=budget)
    sink.append(snapshot)
    sink.append(start)
    with pytest.raises(TraceBudgetError):
        sink.reserve(1)  # any dispatch is refused: no execution authorization
    assert sink.bytes_written == line_size(snapshot) + line_size(start)
    sink.close()

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 2
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert b'"REQUESTED"' not in raw


def test_t01_after_requested_before_prepare(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    sink.append(chain.record("REQUESTED", inline={"attempt_id": "g0a0"}))
    sink.close()  # crash before prepare

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 3
    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert b'"EXPECTATION"' not in raw and b'"EVIDENCE"' not in raw


def test_t01_after_expectation_before_execute(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    sink.append(chain.record("REQUESTED", inline={"attempt_id": "g0a0"}))
    sink.append(chain.record("EXPECTATION", inline={"request_hash": HASH1}))
    sink.close()  # crash before execute

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 4
    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert b'"EVIDENCE"' not in raw and b'"RESULT"' not in raw


def test_t01_published_dependency_without_result_does_not_upgrade(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    sink.append(chain.record("REQUESTED", inline={"attempt_id": "g0a0"}))
    evidence = sink.publish_payload(canonical({"evidence": "orphan"}))
    sink.append(chain.record("EVIDENCE", payload_ref=evidence, inline={"attempt_id": "g0a0"}))
    sink.close()  # crash before RESULT

    assert (tmp_path / "out" / evidence.path).exists()  # orphan file on disk
    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 4
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    assert audit.best_payload_ref is None  # only the original would qualify


def test_t01_complete_group_without_accepted_child_not_best(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    for attempt in range(3):
        label = f"g0a{attempt}"
        sink.append(chain.record("REQUESTED", inline={"attempt_id": label}))
        sink.append(chain.record("EXPECTATION", inline={"request_hash": HASH1}))
        evidence = sink.publish_payload(canonical({"evidence": label}))
        sink.append(chain.record("EVIDENCE", payload_ref=evidence, inline=None))
        sink.append(chain.record("RESULT", inline=None))
        comparison = sink.publish_payload(canonical({"comparison": label}))
        sink.append(chain.record("COMPARISON", payload_ref=comparison, inline=None))
    sink.append(chain.record("REPLAY", inline={"group": 0}))
    sink.close()  # crash before ACCEPTED

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.best_source == BEST_SOURCE_ORIGINAL  # child must NOT become best
    assert audit.best_payload_ref is None
    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert b'"ACCEPTED"' not in raw


def test_t01_accepted_without_finished_partial_but_best_recoverable(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    receipts, child_ref, _ = drive_run(sink, chain, finish=False)
    sink.close()  # crash before FINISHED
    assert len(receipts) == 34

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 34
    assert audit.best_source == BEST_SOURCE_ACCEPTED
    assert audit.best_payload_ref is not None
    assert audit.best_payload_ref.path == child_ref.path
    assert audit.last_record_hash == chain.prev


# --------------------------------------------------------------------------
# PARTIAL tails
# --------------------------------------------------------------------------


def test_partial_unterminated_final_record(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    drive_run(sink, chain, finish=False)
    sink.close()
    # A torn final write: FINISHED without its trailing newline.
    accepted_hash = chain.prev
    finished = chain.record("FINISHED", inline={"outcome": "REDUCED"})
    with open(tmp_path / "out" / TRACE_FILE_NAME, "ab") as fh:
        fh.write(canonical(finished.to_obj()))  # no b"\n"

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 34
    assert "unterminated" in audit.detail
    assert audit.last_record_hash == accepted_hash  # the ACCEPTED is still trusted
    assert audit.best_source == BEST_SOURCE_ACCEPTED


def test_partial_bad_json_tail(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    drive_run(sink, chain, finish=False)
    sink.close()
    with open(tmp_path / "out" / TRACE_FILE_NAME, "ab") as fh:
        fh.write(b'{"seq":35,"kind":"FINISHED",garbled')

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 34
    assert audit.best_source == BEST_SOURCE_ACCEPTED


# --------------------------------------------------------------------------
# CORRUPT traces
# --------------------------------------------------------------------------


def test_corrupt_bad_json_complete_line(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    sink.close()
    with open(tmp_path / "out" / TRACE_FILE_NAME, "ab") as fh:
        fh.write(b'{"broken":\n')  # terminated line, invalid JSON

    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "CORRUPT"
    assert audit.records_verified == 2
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    assert audit.last_record_hash == chain.prev


def test_corrupt_tampered_hash_stops_trust(tmp_path):
    script = Script()
    script.add("SNAPSHOT", inline={"case_id": CASE_ID})
    script.add("START", inline={"complexity": [9, 1, 1, 1, 1], "payload_ref": None, "case_id": CASE_ID})
    victim = script.lines[1]
    obj = json.loads(victim)
    flipped = "0" if obj["hash"][0] != "0" else "1"
    obj["hash"] = flipped + obj["hash"][1:]
    script.lines[1] = canonical(obj) + b"\n"
    # Valid records after the tampered point must NOT be searched past; a
    # would-be best ACCEPTED after corruption is never honored.
    add_group(script, "g0")
    child = script.payload(CHILD_DATA)
    script.add(
        "ACCEPTED",
        payload_ref=child,
        inline={
            "child_payload_ref": child,
            "parent_complexity": [9, 1, 1, 1, 1],
            "child_complexity": [4, 1, 1, 1, 1],
            "comparison_hashes": [script.prev] * 3,
            "attempt_hashes": [ATTEMPT_HASH] * 3,
        },
    )
    script.add("FINISHED", inline=None)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert audit.records_verified == 1
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    assert audit.best_payload_ref is None


def test_corrupt_duplicate_seq(tmp_path):
    script = Script()
    script.add("SNAPSHOT", inline={"case_id": CASE_ID})
    script.add("START", inline={"complexity": [9, 1, 1, 1, 1], "payload_ref": None, "case_id": CASE_ID})
    # A well-hashed record that repeats seq 2.
    script.add("REQUESTED", inline={"attempt_id": "x"}, seq=2)
    script.add("FINISHED", inline=None)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert "expected 3" in audit.detail
    assert audit.records_verified == 2


def test_corrupt_stale_prev_hash(tmp_path):
    script = Script()
    script.add("SNAPSHOT", inline={"case_id": CASE_ID})
    script.add("START", inline={"complexity": [9, 1, 1, 1, 1], "payload_ref": None, "case_id": CASE_ID})
    script.add("REQUESTED", inline={"attempt_id": "x"}, prev=GENESIS)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert "prev_hash" in audit.detail
    assert audit.records_verified == 2


def test_corrupt_missing_dependency_file(tmp_path):
    script = Script()
    add_head(script, [9, 1, 1, 1, 1])
    ghost = script.payload(OTHER_DATA)
    del script.files[ghost["path"]]  # referenced but never written
    script.add("EVIDENCE", payload_ref=ghost, inline=None)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert "missing" in audit.detail
    assert audit.records_verified == 2


def test_corrupt_dependency_content_mismatch(tmp_path):
    script = Script()
    add_head(script, [9, 1, 1, 1, 1])
    ref = script.payload(OTHER_DATA)
    script.files[ref["path"]] = b"tampered bytes"  # planted different content
    script.add("EVIDENCE", payload_ref=ref, inline=None)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert audit.records_verified == 2


def test_corrupt_dependency_outside_files_layout(tmp_path):
    script = Script()
    add_head(script, [9, 1, 1, 1, 1])
    rogue = {"path": "etc/passwd.json", "size_bytes": 1, "sha256": "d" * 64, "schema_version": 1}
    script.add("EVIDENCE", payload_ref=rogue, inline=None)
    root = script.write(tmp_path / "out")
    (root / "etc").mkdir()
    (root / "etc" / "passwd.json").write_bytes(b"x")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    assert "layout" in audit.detail


def _forged_prefix(complexity: list[int]) -> tuple[Script, list[str]]:
    script = Script()
    add_head(script, complexity)
    hashes = add_group(script, "g0")
    return script, hashes


@pytest.mark.parametrize(
    "mutation",
    ["non_decreasing", "equal_complexity", "stale_parent", "missing_child_file", "wrong_comparisons"],
)
def test_corrupt_forged_accepted(tmp_path, mutation):
    complexity = [9, 1, 1, 1, 1]
    script, comparisons = _forged_prefix(complexity)
    child = script.payload(CHILD_DATA)
    if mutation == "missing_child_file":
        del script.files[child["path"]]
    variants = {
        "non_decreasing": ([8, 1, 1, 1, 1], [8, 1, 1, 1, 1], comparisons),
        "equal_complexity": (complexity, complexity, comparisons),
        "stale_parent": ([7, 1, 1, 1, 1], [6, 1, 1, 1, 1], comparisons),
        "missing_child_file": (complexity, [4, 1, 1, 1, 1], comparisons),
        "wrong_comparisons": (complexity, [4, 1, 1, 1, 1], [ATTEMPT_HASH] * 3),
    }
    parent_c, child_c, comp_hashes = variants[mutation]
    script.add(
        "ACCEPTED",
        payload_ref=child,
        inline={
            "child_payload_ref": child,
            "parent_complexity": parent_c,
            "child_complexity": child_c,
            "comparison_hashes": comp_hashes,
            "attempt_hashes": [ATTEMPT_HASH] * 3,
        },
    )
    # A later valid-looking tail must never be searched past.
    better = script.payload(OTHER_DATA)
    script.add(
        "ACCEPTED",
        payload_ref=better,
        inline={
            "child_payload_ref": better,
            "parent_complexity": [4, 1, 1, 1, 1],
            "child_complexity": [1, 1, 1, 1, 1],
            "comparison_hashes": [script.prev] * 3,
            "attempt_hashes": [ATTEMPT_HASH] * 3,
        },
    )
    script.add("FINISHED", inline=None)
    root = script.write(tmp_path / "out")

    audit = read_trace(root)
    assert audit.trace_status == "CORRUPT"
    # Records before the forged ACCEPTED are still trusted.
    assert audit.records_verified == script.record_count() - 3
    assert audit.best_source == BEST_SOURCE_ORIGINAL
    assert audit.best_payload_ref is not None  # original snapshot still resolves
    assert audit.best_payload_ref.path.startswith(f"{FILES_DIR_NAME}/")


# --------------------------------------------------------------------------
# Path attacks
# --------------------------------------------------------------------------


def test_refuses_symlink_component_in_root(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(TracePathError):
        JsonlTraceSink(link / "out", 256 * 1024 * 1024)
    with pytest.raises(TracePathError):
        read_trace(link / "out")


def test_refuses_dotdot_component(tmp_path):
    with pytest.raises(TracePathError):
        JsonlTraceSink(tmp_path / "a" / ".." / "out", 256 * 1024 * 1024)
    with pytest.raises(TracePathError):
        read_trace(tmp_path / "a" / ".." / "out")


def test_second_writer_session_refused(tmp_path):
    root = tmp_path / "out"
    first = JsonlTraceSink(root, 256 * 1024 * 1024)
    with pytest.raises(TracePathError):
        JsonlTraceSink(root, 256 * 1024 * 1024)
    # An existing (empty) root directory itself is not a refusal reason.
    (tmp_path / "other").mkdir()
    JsonlTraceSink(tmp_path / "other", 256 * 1024 * 1024).close()
    first.close()


def test_payload_name_collision_same_content_accepted_different_refused(tmp_path):
    sink = new_sink(tmp_path)
    first = sink.publish_payload(ORIGINAL_DATA)
    again = sink.publish_payload(ORIGINAL_DATA)
    assert first == again
    target = tmp_path / "out" / first.path
    assert target.read_bytes() == ORIGINAL_DATA

    planted = tmp_path / "out" / f"{FILES_DIR_NAME}/{hashlib.sha256(OTHER_DATA).hexdigest()}.json"
    planted.write_bytes(b"evil bytes with a different length")
    with pytest.raises(TracePathError):
        sink.publish_payload(OTHER_DATA)
    # A path refusal is not an OS-level sink failure.
    assert sink.failed is False
    sink.close()


def test_concurrent_publish_race_same_content(tmp_path):
    sink = new_sink(tmp_path)

    def publish(_: int) -> ArtifactRef:
        return sink.publish_payload(ORIGINAL_DATA + b" " * 4096)

    with ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(publish, range(8)))
    assert all(ref == refs[0] for ref in refs)
    files = list((tmp_path / "out" / FILES_DIR_NAME).glob("*.json"))
    assert len(files) == 1
    sink.close()


# --------------------------------------------------------------------------
# Budget behaviour
# --------------------------------------------------------------------------


def test_tiny_budget_refuses_dispatch_before_any_write(tmp_path):
    sink = new_sink(tmp_path, budget=EVIDENCE_RESERVE_BYTES)
    chain = Chain()
    snapshot = chain.peek("SNAPSHOT", inline={"case_id": CASE_ID})
    with pytest.raises(TraceBudgetError):
        sink.reserve(line_size(snapshot))
    with pytest.raises(TraceBudgetError):
        sink.append(snapshot)
    assert (tmp_path / "out" / TRACE_FILE_NAME).stat().st_size == 0
    assert sink.failed is False  # budget refusal is not a sink failure
    sink.close()


def test_reserve_is_not_consumed_and_writes_settle(tmp_path):
    sink = new_sink(tmp_path, budget=1024 * 1024)
    chain = Chain()
    snapshot = chain.record("SNAPSHOT", inline={"case_id": CASE_ID})
    assert sink.remaining_bytes == 1024 * 1024
    sink.reserve(line_size(snapshot))
    assert sink.remaining_bytes == 1024 * 1024  # reserve checks, never consumes
    sink.append(snapshot)
    assert sink.remaining_bytes == 1024 * 1024 - line_size(snapshot)
    assert sink.bytes_written == line_size(snapshot)
    with pytest.raises(TraceBudgetError):
        sink.reserve(1024 * 1024)  # would break the termination reserve
    sink.close()


def test_reserve_floor_keeps_termination_record_writable(tmp_path):
    chain = Chain()
    snapshot = chain.record("SNAPSHOT", inline={"case_id": CASE_ID})
    start = chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID})
    requested = chain.peek(
        "REQUESTED",
        inline={"attempt_id": "g0a0", "padding": "p" * 256},
    )
    finished = chain.record("FINISHED", inline=None)
    budget = (
        EVIDENCE_RESERVE_BYTES
        + line_size(snapshot)
        + line_size(start)
        + line_size(requested)
        - 1
    )
    sink = new_sink(tmp_path, budget=budget)
    sink.append(snapshot)
    sink.append(start)
    with pytest.raises(TraceBudgetError):
        sink.append(requested)  # would eat into the termination reserve
    sink.append(finished)  # FINISHED is allowed to consume the reserve
    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "COMPLETE"
    assert audit.records_verified == 3
    assert sink.remaining_bytes == budget - line_size(snapshot) - line_size(start) - line_size(finished)
    sink.close()


def test_enospc_injection_stops_sink_and_keeps_prefix(tmp_path):
    hook = SpyHook(fail_on=(3, "trace-file"))
    sink = new_sink(tmp_path, hook=hook)
    chain = Chain()
    sink.append(chain.record("SNAPSHOT", inline={"case_id": CASE_ID}))
    sink.append(chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID}))
    requested = chain.record("REQUESTED", inline={"attempt_id": "g0a0"})
    with pytest.raises(TraceWriteError):
        sink.append(requested)
    assert sink.failed is True

    size_after_failure = (tmp_path / "out" / TRACE_FILE_NAME).stat().st_size
    with pytest.raises(TraceWriteError):
        sink.append(chain.record("FINISHED", inline=None))
    assert (tmp_path / "out" / TRACE_FILE_NAME).stat().st_size == size_after_failure
    sink.close()

    # The already-written prefix (including the written-but-unconfirmed
    # REQUESTED line) stays valid and nothing is truncated.
    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "PARTIAL"
    assert audit.records_verified == 3
    assert audit.best_source == BEST_SOURCE_ORIGINAL


def test_budget_bounds_are_validated(tmp_path):
    with pytest.raises(TraceBudgetError):
        new_sink(tmp_path / "b0", budget=0)
    with pytest.raises(TraceBudgetError):
        new_sink(tmp_path / "b1", budget=EVIDENCE_APPEND_HARD_CAP + 1)


# --------------------------------------------------------------------------
# Scale note (design line 557): payloads as files, records carry references
# --------------------------------------------------------------------------


def test_records_reference_payloads_instead_of_holding_rows(tmp_path):
    sink = new_sink(tmp_path)
    chain = Chain()
    big_rows = [{"k": i, "v": f"value-{i:05d}"} for i in range(4096)]
    big_payload = sink.publish_payload(canonical({"rows": big_rows}))
    sink.append(
        chain.record("SNAPSHOT", payload_ref=big_payload, inline={"case_id": CASE_ID})
    )
    sink.append(
        chain.record("START", inline={"complexity": START_COMPLEXITY, "payload_ref": None, "case_id": CASE_ID})
    )
    sink.append(chain.record("FINISHED", inline=None))
    sink.close()

    raw = (tmp_path / "out" / TRACE_FILE_NAME).read_bytes()
    assert len(big_rows) * 16 > len(raw)  # trace stays tiny next to the payload
    assert b"value-00042" not in raw  # rows are not in the trace
    ref_path = tmp_path / "out" / big_payload.path
    assert ref_path.stat().st_size == big_payload.size_bytes
    assert hashlib.sha256(ref_path.read_bytes()).hexdigest() == big_payload.sha256
    audit = read_trace(tmp_path / "out")
    assert audit.trace_status == "COMPLETE"
    assert audit.best_payload_ref == big_payload


# --------------------------------------------------------------------------
# Read-side absence semantics
# --------------------------------------------------------------------------


def test_read_trace_missing_root_and_empty_file(tmp_path):
    missing = read_trace(tmp_path / "does-not-exist")
    assert missing.trace_status == "COMPLETE"
    assert missing.records_verified == 0
    assert missing.best_source == BEST_SOURCE_ORIGINAL
    assert missing.best_payload_ref is None
    assert missing.last_record_hash is None

    root = tmp_path / "empty"
    root.mkdir()
    empty = read_trace(root)
    assert empty.trace_status == "COMPLETE"
    assert empty.records_verified == 0

    (root / TRACE_FILE_NAME).write_bytes(b"")
    assert read_trace(root).records_verified == 0


def test_read_trace_rejects_unsafe_root(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / TRACE_FILE_NAME).write_bytes(b"")
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(TracePathError):
        read_trace(link)
    with pytest.raises(TracePathError):
        read_trace(tmp_path / ".." / "real")
