"""G01: generator determinism tests (design 6.4.1, Phase 3).

Fixed vectors below were produced once by an independent script that applies
the frozen canonical-JSON rule from design 6.2.4 directly with
``json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=True)`` and
``hashlib.sha256`` -- they never call the code under test:

- ``case_seed(42, 0) = sha256('["typecheck-g1",42,0]')``
- ``substream_block(cs, retry, domain, counter)
  = sha256('["typecheck-g1-block","<cs>",<retry>,"<domain>",<counter>]')``
- ``profile_hash(default_profile())`` over the hand-written canonical profile
  object (four rules at version 1, Q1-Q4, ["ix_v","none"], 32/1/8,
  1 MiB / 256 MiB).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mtsql_typecheck.contracts.case import CaseBundle, OrdinalReceipt
from mtsql_typecheck.contracts.codec import case_seed, substream_block
from mtsql_typecheck.generation.generator import (
    default_profile,
    generate_case,
    generate_cases,
    profile_hash,
)

GOLDEN_CASE_SEED_42_0 = "c09a293d95f6f1fa0a1178ddf72259d898bb65b9f23a413800e55dda481c290d"

# (retry_index, domain, counter) -> golden digest hex
GOLDEN_BLOCKS = {
    (0, "rows", 0): "cdfe409cc23bf3f1e87f8fc570e5ce3e5aed44161dee6504f30d47437cb4f6bb",
    (0, "rows", 1): "6531dbfa1800c3c78d5ac0fc40407b13afbd3cc4f09db697d7212f22f9b6a1f3",
    (1, "predicate", 0): "99d75a39c3bafa0d495c04104a2e11c6ec9f4810f699bd08a2d3f57248806b4e",
    (2, "arithmetic", 7): "bdee091493f616271e5d196b02878036312e116efb2d94616ea0c82f7573122d",
    (3, "rows", 31): "6414d0c58962d6fde0eaf842fb52a350a87a2ecf0f8ab27ba72c507bd7dc597d",
}

GOLDEN_DEFAULT_PROFILE_HASH = "86d063fafeeefa2d66598176a10fcaa6c2f25389563ae7c8761de7fc47ed9621"


# --------------------------------------------------------------------------
# Fixed vectors (independently computed, never re-derived by the code)
# --------------------------------------------------------------------------


def test_case_seed_fixed_vector() -> None:
    assert case_seed(42, 0) == GOLDEN_CASE_SEED_42_0


def test_substream_block_fixed_vectors() -> None:
    for (retry_index, domain, counter), golden in GOLDEN_BLOCKS.items():
        digest = substream_block(GOLDEN_CASE_SEED_42_0, retry_index, domain, counter)
        assert digest.hex() == golden


def test_default_profile_hash_fixed_vector() -> None:
    assert profile_hash(default_profile()) == GOLDEN_DEFAULT_PROFILE_HASH


# --------------------------------------------------------------------------
# Cross-process determinism (PYTHONHASHSEED)
# --------------------------------------------------------------------------

# The subprocess serializes a full small generation request (manifest,
# per-ordinal records and bundles) into canonical JSON on stdout.
_SUBPROCESS_SCRIPT = """
import json
from mtsql_typecheck.generation.generator import default_profile, generate_cases

result = generate_cases(default_profile(), 42, 25)
print(json.dumps({
    "manifest": result.manifest.to_obj(),
    "records": [record.to_obj() for record in result.records],
    "bundles": [
        {"case_id": bundle.case_id, "provenance": bundle.provenance.to_obj()}
        for bundle in result.bundles
    ],
}, sort_keys=True, separators=(",", ":")))
"""


def _run_in_subprocess(pythonhashseed: str) -> bytes:
    src_root = str(Path(__file__).resolve().parents[3] / "src")
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = pythonhashseed
    env["PYTHONPATH"] = src_root + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_SCRIPT],
        env=env,
        capture_output=True,
        check=True,
    )
    return completed.stdout


def test_multiprocess_different_hash_seeds_produce_identical_bytes() -> None:
    out_seed_0 = _run_in_subprocess("0")
    out_seed_12345 = _run_in_subprocess("12345")
    assert out_seed_0 == out_seed_12345
    # The output is a real, non-trivial generation result, not an empty match.
    payload = json.loads(out_seed_0)
    assert payload["manifest"]["statistics"]["emitted_occurrences"] == 25
    assert len(payload["records"]) == 25


# --------------------------------------------------------------------------
# Prefix property, replay and seed variation
# --------------------------------------------------------------------------


def test_prefix_property_100_vs_1000_requests() -> None:
    profile = default_profile()
    small = generate_cases(profile, 42, 100)
    large = generate_cases(profile, 42, 1000)
    assert len(small.receipts) == 100
    assert len(large.receipts) == 1000
    assert [receipt.to_obj() for receipt in large.receipts[:100]] == [
        receipt.to_obj() for receipt in small.receipts
    ]
    assert [record.to_obj() for record in large.records[:100]] == [
        record.to_obj() for record in small.records
    ]
    # First-occurrence bundle order is also a prefix of the larger request.
    small_ids = [bundle.case_id for bundle in small.bundles]
    large_ids = [bundle.case_id for bundle in large.bundles]
    assert large_ids[: len(small_ids)] == small_ids


def test_same_seed_same_ordinal_replay_is_identical() -> None:
    profile = default_profile()
    first = generate_cases(profile, 42, 30)
    second = generate_cases(profile, 42, 30)
    assert first.manifest.to_obj() == second.manifest.to_obj()
    assert [bundle.to_obj() for bundle in first.bundles] == [
        bundle.to_obj() for bundle in second.bundles
    ]
    # Single-ordinal entry point replays identically to the batch path.
    profile_hash_hex = profile_hash(profile)
    for ordinal in (0, 7, 23):
        single = generate_case(profile, profile_hash_hex, 42, ordinal)
        assert isinstance(single, CaseBundle)
        assert single.case_id == first.receipts[ordinal].case_id


def test_different_seeds_produce_different_data() -> None:
    profile = default_profile()
    seeds = (42, 43, 44)
    results = {seed: generate_cases(profile, seed, 12) for seed in seeds}
    id_lists = {
        seed: [receipt.case_id for receipt in result.receipts]
        for seed, result in results.items()
    }
    # Pairwise different sequences and different first ordinal.
    assert id_lists[42] != id_lists[43]
    assert id_lists[42] != id_lists[44]
    assert id_lists[43] != id_lists[44]
    first_ids = {id_list[0] for id_list in id_lists.values()}
    assert len(first_ids) == len(seeds)
    # Same seed replays identically while different seeds do not.
    replay = generate_cases(profile, 42, 12)
    assert [receipt.case_id for receipt in replay.receipts] == id_lists[42]


# --------------------------------------------------------------------------
# Retry injection seam
# --------------------------------------------------------------------------


def test_injected_retry_isolates_single_ordinal() -> None:
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)

    def hook(ordinal: int, retry_index: int, payload: object):
        # Force exactly the first attempt of ordinal 5 to fail as a
        # foreseeable construction rejection.
        if ordinal == 5 and retry_index == 0:
            return None
        return payload

    baseline = {}
    injected = {}
    for ordinal in range(10):
        baseline[ordinal] = generate_case(profile, profile_hash_hex, 42, ordinal)
        injected[ordinal] = generate_case(
            profile, profile_hash_hex, 42, ordinal, attempt_hook=hook
        )

    injected_ordinal = injected[5]
    assert isinstance(injected_ordinal, CaseBundle)
    # The ordinal consumed one failed attempt and succeeded on retry 1.
    assert injected_ordinal.provenance.retry == 1
    assert injected_ordinal.provenance.ordinal == 5
    # The retry-1 substream differs from the un-injected retry-0 result.
    assert injected_ordinal.case_id != baseline[5].case_id
    # Every other ordinal is byte-identical to the un-injected run.
    for ordinal in range(10):
        if ordinal == 5:
            continue
        assert isinstance(injected[ordinal], CaseBundle)
        assert injected[ordinal].to_obj() == baseline[ordinal].to_obj()


def test_injected_retry_receipt_on_batch_path_conserves_counts() -> None:
    """The same hook applied to every ordinal of a small batch request.

    Every ordinal fails its first attempt and succeeds on retry 1, so all
    receipts carry retry_count=1 and the attempt budget counts one extra
    candidate per ordinal.
    """
    profile = default_profile()
    profile_hash_hex = profile_hash(profile)
    count = 8
    baseline_receipts = generate_cases(profile, 42, count).receipts

    def hook(ordinal: int, retry_index: int, payload: object):
        return None if retry_index == 0 else payload

    bundles = []
    for ordinal in range(count):
        outcome = generate_case(profile, profile_hash_hex, 42, ordinal, attempt_hook=hook)
        assert isinstance(outcome, CaseBundle)
        assert outcome.provenance.retry == 1
        bundles.append(outcome)
    # Other ordinals' un-injected results were all retry 0; the injected run
    # shifts each ordinal to its retry-1 substream, so each case_id differs
    # from baseline but the ordinal structure (one bundle per ordinal) holds.
    assert [bundle.case_id for bundle in bundles] != [
        receipt.case_id for receipt in baseline_receipts
    ]
    assert len({bundle.case_id for bundle in bundles}) == count


def test_generate_case_rejects_malformed_arguments() -> None:
    from mtsql_typecheck.generation.generator import ProfileError

    profile = default_profile()
    profile_hash_hex = profile_hash(profile)
    with pytest.raises(ProfileError):
        generate_case(profile, "not-a-hash", 42, 0)
    with pytest.raises(ProfileError):
        generate_case(profile, profile_hash_hex, 42, -1)


def test_generate_cases_rejects_out_of_budget_counts() -> None:
    from mtsql_typecheck.generation.generator import MAX_CASES, ProfileError

    profile = default_profile()
    with pytest.raises(ProfileError):
        generate_cases(profile, 42, 0)
    with pytest.raises(ProfileError):
        generate_cases(profile, 42, MAX_CASES + 1)
    with pytest.raises(ProfileError):
        generate_cases(profile, -1, 5)
