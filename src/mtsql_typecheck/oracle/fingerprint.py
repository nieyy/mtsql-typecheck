"""Exact signatures and coarse fingerprints for the D2 oracle.

Implements oracle-d2-contract section 5 (``oracle/fingerprint.py``):

- ``exact_signature`` binds the exact differing multiset (per-side key/count
  tables sorted by canonical row-key bytes) to the case identity, the rule
  definition and the declared result relation.  It excludes attempt ids, row
  order and timing, so the same differing multiset observed in any attempt
  order yields the same signature.
- ``fingerprint`` is a coarse grouping key only: it covers rule identity,
  type pair, template, index variant, relation, renderer identity, codec
  version, environment and session profile, and never case_id, concrete
  values or row counts.  A shared fingerprint is never proof of the same
  root cause (design 6.4.2).

``definition_hash`` is resolved from the reviewed rule registry
(``rules.registry.get_rule``) because ``CasePayload`` carries only a
``RuleRef``; the registry read re-verifies hash consistency and unknown
rules raise (``UnknownRuleError`` is a ``ContractError``).  Importing this
module performs no I/O.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from ..contracts.case import (
    CasePayload,
    ContractError,
    SemverIdentity,
)
from ..contracts.codec import canonical_json, case_id_of, sha256_hex
from ..contracts.execution import SessionProfile
from ..contracts.oracle import ORACLE_VERSION
from .exact import key_persistent

__all__ = [
    "relation_hash",
    "exact_signature",
    "fingerprint",
]

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_VERSION_CHARS = 128

# Frozen domain tags (contract 5); changing them is a design revision.
_EXACT_SIGNATURE_TAG = "exact_signature_v1"
_FINGERPRINT_TAG = "fingerprint_v1"
_COMPARISON_SEMANTICS_TAG = "ROW_MULTISET_DIFFERENCE"


def _fail(msg: str) -> None:
    raise ContractError(msg)


def _check_payload(payload: object) -> CasePayload:
    if not isinstance(payload, CasePayload):
        _fail(f"payload must be a CasePayload, got {type(payload).__name__}")
    return payload


def _check_oracle_version(oracle_version: object) -> str:
    if not isinstance(oracle_version, str):
        _fail(f"oracle_version must be a str, got {type(oracle_version).__name__}")
    if oracle_version != ORACLE_VERSION:
        _fail(
            f"unsupported oracle_version {oracle_version!r}, "
            f"expected {ORACLE_VERSION!r}"
        )
    return oracle_version


def _definition_hash(payload: CasePayload) -> str:
    """Definition hash of the reviewed rule the payload references."""
    from ..rules.registry import get_rule

    rule = get_rule(payload.rule.rule_id, payload.rule.rule_version)
    return rule.definition_hash


# --------------------------------------------------------------------------
# Relation hash and key-count tables (contract 5)
# --------------------------------------------------------------------------


def relation_hash(payload: CasePayload) -> str:
    """sha256 over the canonical JSON of the declared result relation."""
    _check_payload(payload)
    return sha256_hex(canonical_json(payload.relation.to_obj()))


def _decode_persistent_key(data: bytes, name: str) -> list:
    """Validate a ``row_key_bytes`` key (canonical JSON list of value keys)."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(f"{name} key is not valid canonical JSON bytes: {exc}")
    if not isinstance(parsed, list):
        _fail(f"{name} key must decode to a JSON array, got {type(parsed).__name__}")
    persistent: list = []
    for element in parsed:
        if not isinstance(element, list) or not element:
            _fail(f"{name} key element must be a non-empty JSON array: {element!r}")
        if element == ["null"]:
            persistent.append(["null"])
            continue
        if (
            len(element) == 3
            and element[0] == "number"
            and isinstance(element[1], str)
            and isinstance(element[2], int)
            and not isinstance(element[2], bool)
        ):
            persistent.append(["number", element[1], element[2]])
            continue
        _fail(f"{name} key element is not a persistent value key: {element!r}")
    if canonical_json(persistent) != data:
        _fail(f"{name} key is not in canonical form: {data!r}")
    return persistent


def _count_entries(counts: Mapping, name: str) -> list:
    """Normalize a row_key -> count mapping into a byte-sorted entry list.

    Accepted key forms (they are pairwise distinguishable and normalize to
    the same entry for the same single-column multiset):

    - a bare value key ``("number", text, scale)`` / ``("null",)`` -> the
      flat persistent form ``key_persistent(key)`` (the contract 5
      ``[key, count]`` entry shape);
    - a ``row_key`` tuple of value keys -> the persistent list of its
      columns, flattened to the single persistent value key when the row
      has exactly one column;
    - canonical ``row_key_bytes`` bytes (contract 4 counter keys) -> the
      decoded persistent list, flattened the same way for one column.

    Counts must be positive ints (a multiset never carries a zero or
    negative multiplicity).
    """
    if not isinstance(counts, Mapping):
        _fail(f"{name} must be a row_key -> count mapping, got {type(counts).__name__}")
    entries: list = []
    for key, count in counts.items():
        if isinstance(key, tuple):
            try:
                persistent = key_persistent(key)
            except ContractError:
                columns = [key_persistent(value_key) for value_key in key]
                persistent = columns[0] if len(columns) == 1 else columns
        elif isinstance(key, (bytes, bytearray)):
            decoded = _decode_persistent_key(bytes(key), name)
            persistent = decoded[0] if len(decoded) == 1 else decoded
        else:
            _fail(
                f"{name} keys must be value keys, row_key tuples or "
                f"row_key_bytes, got {type(key).__name__}"
            )
        if isinstance(count, bool) or not isinstance(count, int):
            _fail(f"{name} counts must be ints, got {type(count).__name__}")
        if count < 1:
            _fail(f"{name} counts must be >= 1, got {count}")
        entries.append((canonical_json(persistent), persistent, count))
    entries.sort(key=lambda entry: entry[0])
    return [[persistent, count] for _, persistent, count in entries]


# --------------------------------------------------------------------------
# Signatures (contract 5)
# --------------------------------------------------------------------------


def exact_signature(
    payload: CasePayload,
    oracle_version: str,
    a_key_counts: Mapping,
    b_key_counts: Mapping,
) -> str:
    """Exact identity of one observed mismatching multiset pair.

    Hash input (canonical JSON): ``["exact_signature_v1", case_id, rule_id,
    rule_version, definition_hash, relation_hash, oracle_version,
    [["A", sorted [persistent_key, count] list], ["B", ...]]]``.  Attempt
    ids, row order and timing are excluded, so any attempt that reproduces
    the same differing multiset for the same case yields the same signature.
    """
    checked = _check_payload(payload)
    version = _check_oracle_version(oracle_version)
    a_entries = _count_entries(a_key_counts, "a_key_counts")
    b_entries = _count_entries(b_key_counts, "b_key_counts")
    material = [
        _EXACT_SIGNATURE_TAG,
        case_id_of(checked),
        checked.rule.rule_id,
        checked.rule.rule_version,
        _definition_hash(checked),
        relation_hash(checked),
        version,
        [["A", a_entries], ["B", b_entries]],
    ]
    return sha256_hex(canonical_json(material))


def fingerprint(
    payload: CasePayload,
    oracle_version: str,
    renderer_version: SemverIdentity,
    codec_version: str,
    environment_hash: str,
    session_profile: SessionProfile,
) -> str:
    """Coarse grouping fingerprint; never proof of the same root cause.

    Hash input (canonical JSON): ``["fingerprint_v1", rule_id, rule_version,
    definition_hash, a_type, b_type, template_id, index_variant,
    relation_hash, oracle_version, [renderer.id, renderer.version],
    codec_version, environment_hash, session_profile, "ROW_MULTISET_DIFFERENCE"]``.
    case_id, concrete values and row counts are excluded.
    """
    checked = _check_payload(payload)
    version = _check_oracle_version(oracle_version)
    if not isinstance(renderer_version, SemverIdentity):
        _fail(
            f"renderer_version must be a SemverIdentity, got "
            f"{type(renderer_version).__name__}"
        )
    if not isinstance(codec_version, str) or not codec_version:
        _fail("codec_version must be a non-empty str")
    if len(codec_version) > _MAX_VERSION_CHARS:
        _fail(f"codec_version must be at most {_MAX_VERSION_CHARS} chars")
    if not isinstance(environment_hash, str) or not _HEX64_RE.match(environment_hash):
        _fail(f"environment_hash must be lowercase 64-hex sha256, got {environment_hash!r}")
    if not isinstance(session_profile, SessionProfile):
        _fail(
            f"session_profile must be a SessionProfile, got "
            f"{type(session_profile).__name__}"
        )
    material = [
        _FINGERPRINT_TAG,
        checked.rule.rule_id,
        checked.rule.rule_version,
        _definition_hash(checked),
        checked.a_type.to_obj(),
        checked.b_type.to_obj(),
        str(checked.query.template_id.value),
        str(checked.table.index_variant.value),
        relation_hash(checked),
        version,
        [renderer_version.id, renderer_version.version],
        codec_version,
        environment_hash,
        session_profile.to_obj(),
        _COMPARISON_SEMANTICS_TAG,
    ]
    return sha256_hex(canonical_json(material))
