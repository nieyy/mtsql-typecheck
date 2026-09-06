"""D2 reduction strategy: deterministic proposals and complexity (design 6.4.4).

Pure functions over a validated :class:`CasePayload`: no I/O, no randomness,
no clocks, no floats and no database access.  ``iter_proposals`` enumerates
the fixed proposal order the engine walks serially; ``complexity`` is the
metric the engine compares.  D2 proposes, D1 disposes: every proposal is a
frozen ``contracts.case`` transform model that must round-trip through
``generation.transforms.apply_transform`` (APPLIED / REJECTED / NO_CHANGE,
never an exception); whether a candidate actually reduces is decided by D1
revalidation and replay, never here.

Complexity metric
-----------------
``complexity`` returns the tuple ``(row_count, predicate_node_count,
non_null_value_count, magnitude_sum, canonical_payload_byte_length)``.  The
engine compares these tuples with strict Python tuple (lexicographic)
ordering and accepts a child only when its complexity is strictly less than
the current best's -- a same-or-worse candidate is rejected before any
execution.  The tuple is a search heuristic: it is never proof that a case
is semantically smaller, and no hash ordering ever substitutes for it
(design 6.4.4).

``predicate_node_count`` counts Compare/Between/IsNull/And/Or nodes (0 when
the predicate is absent).  ``non_null_value_count`` counts non-NULL shared
row values plus non-NULL logical literal slots (Compare right constant,
Between lower/upper endpoints, the Q4 arithmetic constant); the Q4 ``k`` is
counted exactly once even though the projection references the same node.
``magnitude_sum`` sums ``|coefficient|`` over exactly the same value set
(an integer value is its own coefficient; NULL contributes 0; decimal scale
is preserved; rids are excluded).  All arithmetic is exact Python integer
arithmetic -- the sum can grow large but must never lose precision, so no
float and no normalization is applied anywhere.

Candidate values (design 6.4.4) are drawn from ``NULL, 0, +unit, -unit``
and the toward-zero half of the current value, deduplicated, keeping the
slot's value kind and decimal scale.  The integer unit is 1; the decimal
unit is coefficient 1 at the slot's scale.  Halving is integer ``abs(x)//2``
restored to the sign of ``x`` (toward zero: -7 -> -3, 7 -> 3), never a
float division.  A NULL slot has no original scale, so the unit is taken at
the payload's shared decimal scale (``a_type.scale``, which equal-scale
rules require both sides to declare) when both sides are decimal, and at
integer kind otherwise.
"""

from __future__ import annotations

from typing import Iterator, Literal, Optional

from ..contracts.case import (
    And,
    Between,
    CasePayload,
    Compare,
    ContractError,
    DecimalType,
    DecimalValue,
    ExactValue,
    IntegerValue,
    NullValue,
    Or,
    PathNode,
    Predicate,
    QuerySpec,
    RemoveRows,
    ReplaceLiteral,
    ReplaceValue,
    Row,
    SimplifyPredicate,
    Transform,
)
from ..contracts.codec import canonical_json

__all__ = ["complexity", "iter_proposals"]


def _require_payload(payload: object) -> None:
    """B01-style entry validation: strategy inputs are CasePayloads only."""
    if not isinstance(payload, CasePayload):
        raise ContractError(
            f"reduction strategy needs a CasePayload, got {type(payload).__name__}"
        )


# --------------------------------------------------------------------------
# Literal slot traversal (shared by complexity and replace_literal)
# --------------------------------------------------------------------------


def _atom_literal_slots(
    prefix: tuple[PathNode, ...], atom: Predicate
) -> Iterator[tuple[tuple[PathNode, ...], ExactValue, bool]]:
    """Yield ``(path, current_value, null_allowed)`` for one predicate atom.

    ``null_allowed`` mirrors D1's structural rules: a Compare constant may be
    NULL, a BETWEEN endpoint must not (design 6.2.2, enforced by the frozen
    ``Between`` model).  An IsNull atom carries no addressable constant.
    """
    if isinstance(atom, Compare):
        yield prefix + (PathNode.RIGHT, PathNode.CONSTANT), atom.right.value, True
    elif isinstance(atom, Between):
        yield prefix + (PathNode.LOWER, PathNode.CONSTANT), atom.lower.value, False
        yield prefix + (PathNode.UPPER, PathNode.CONSTANT), atom.upper.value, False


def _iter_literal_slots(
    query: QuerySpec,
) -> Iterator[tuple[tuple[PathNode, ...], ExactValue, bool]]:
    """Enumerate every exact-value slot in IR preorder (design 6.4.4).

    Order: And/Or left child then right child, Between lower then upper,
    and finally the Q4 arithmetic constant (``predicate/arithmetic/constant``
    -- the only encoding of ``k`` in the frozen PathNode vocabulary).
    """
    predicate = query.predicate
    if predicate is not None:
        if isinstance(predicate, (And, Or)):
            for step in (PathNode.LEFT, PathNode.RIGHT):
                atom = predicate.left if step is PathNode.LEFT else predicate.right
                yield from _atom_literal_slots((PathNode.PREDICATE, step), atom)
        else:
            yield from _atom_literal_slots((PathNode.PREDICATE,), predicate)
    if query.arithmetic is not None:
        yield (
            (PathNode.PREDICATE, PathNode.ARITHMETIC, PathNode.CONSTANT),
            query.arithmetic.constant,
            False,
        )


# --------------------------------------------------------------------------
# complexity
# --------------------------------------------------------------------------


def _count_predicate_nodes(predicate: Optional[Predicate]) -> int:
    """Count Compare/Between/IsNull/And/Or nodes; 0 when the predicate is None."""
    if predicate is None:
        return 0
    if isinstance(predicate, (And, Or)):
        return 1 + _count_predicate_nodes(predicate.left) + _count_predicate_nodes(
            predicate.right
        )
    return 1


def _magnitude(value: ExactValue) -> int:
    """``|coefficient|`` of an exact value; NULL contributes 0."""
    if isinstance(value, IntegerValue):
        return abs(value.value)
    if isinstance(value, DecimalValue):
        return abs(value.coefficient)
    return 0


def complexity(payload: CasePayload) -> tuple[int, int, int, int, int]:
    """Reduction complexity of ``payload`` as a strictly-lexicographic tuple.

    Returns ``(row_count, predicate_node_count, non_null_value_count,
    magnitude_sum, canonical payload byte length)`` where the byte length is
    ``len(canonical_json(payload.to_obj()))`` (payload only: no preview, no
    provenance).  The engine compares two complexities with strict tuple
    ordering and requires a strictly smaller candidate; equal or larger is
    rejected before execution.  All components are exact integers.
    """
    _require_payload(payload)
    rows = payload.rows.rows
    node_count = _count_predicate_nodes(payload.query.predicate)
    value_count = 0
    magnitude_sum = 0
    for row in rows:
        if not isinstance(row.value, NullValue):
            value_count += 1
            magnitude_sum += _magnitude(row.value)
    for _path, value, _null_allowed in _iter_literal_slots(payload.query):
        # The Q4 k slot is yielded once from query.arithmetic; the projection
        # re-uses the same node and is never traversed separately.
        if not isinstance(value, NullValue):
            value_count += 1
            magnitude_sum += _magnitude(value)
    byte_length = len(canonical_json(payload.to_obj()))
    return (len(rows), node_count, value_count, magnitude_sum, byte_length)


# --------------------------------------------------------------------------
# Candidate value construction
# --------------------------------------------------------------------------


def _toward_zero_half(value: int) -> int:
    """``sign(x) * (abs(x) // 2)``; exact integer halving toward zero."""
    return abs(value) // 2 if value >= 0 else -(abs(value) // 2)


def _shared_value_scale(payload: CasePayload) -> Optional[int]:
    """Scale for a NULL slot's unit candidates.

    Decimal logical data requires both sides declared decimal (frozen
    ``CasePayload`` row-domain check), so ``a_type.scale`` is the shared
    scale a NULL slot's replacement must carry; integer-kind payloads use
    integer candidates.
    """
    if isinstance(payload.a_type, DecimalType) and isinstance(payload.b_type, DecimalType):
        return payload.a_type.scale
    return None


def _base_values(scale: Optional[int]) -> tuple[ExactValue, ExactValue, ExactValue]:
    """``(0, +unit, -unit)`` at integer kind or at the given decimal scale."""
    if scale is None:
        return (IntegerValue(0), IntegerValue(1), IntegerValue(-1))
    return (DecimalValue(0, scale), DecimalValue(1, scale), DecimalValue(-1, scale))


def _slot_scale(payload: CasePayload, current: ExactValue) -> Optional[int]:
    """Unit-candidate scale for one slot: its own scale, else the shared one."""
    if isinstance(current, DecimalValue):
        return current.scale
    if isinstance(current, NullValue):
        return _shared_value_scale(payload)
    return None  # integer slot: integer unit


def _halved(current: ExactValue) -> Optional[ExactValue]:
    """Toward-zero half of a non-NULL value at its own kind/scale; None for NULL."""
    if isinstance(current, IntegerValue):
        return IntegerValue(_toward_zero_half(current.value))
    if isinstance(current, DecimalValue):
        return DecimalValue(_toward_zero_half(current.coefficient), current.scale)
    return None


def _value_candidates(
    current: ExactValue,
    scale: Optional[int],
    null_position: Optional[Literal["first", "last"]],
) -> list[ExactValue]:
    """Deduplicated candidate values for one slot, in the fixed design order.

    ``null_position="first"`` is the shared-row order (NULL, 0, +unit,
    -unit, halve); ``"last"`` is the literal order (0, +unit, -unit, halve,
    NULL) used only where D1 allows a NULL literal.  ``None`` keeps NULL out
    entirely (BETWEEN endpoints, the Q4 constant).  A candidate equal to the
    current value or already emitted is dropped, so halving never duplicates
    0/unit and a value is never proposed to replace itself.
    """
    zero, unit, neg_unit = _base_values(scale)
    candidates: list[ExactValue] = []
    if null_position == "first":
        candidates.append(NullValue())
    candidates.extend((zero, unit, neg_unit))
    halved = _halved(current)
    if halved is not None:
        candidates.append(halved)
    if null_position == "last":
        candidates.append(NullValue())
    selected: list[ExactValue] = []
    for candidate in candidates:
        if candidate == current or candidate in selected:
            continue
        selected.append(candidate)
    return selected


# --------------------------------------------------------------------------
# Phase 1: remove_rows
# --------------------------------------------------------------------------


def _iter_remove_rows(payload: CasePayload) -> Iterator[RemoveRows]:
    """Row-deletion proposals in the fixed design order (design 6.4.4).

    Delete-all first; then for each granularity ``g`` = 2, 4, 8, ... up to
    ``n`` the remaining rows (by position, rid values preserved) are split
    into blocks ``i`` = 1..g over positions ``[floor(i*n/g),
    floor((i+1)*n/g))``: each block is proposed, then its complement.  Empty
    deletions are skipped and rid tuples already proposed are not repeated,
    so a g-block that is a single row suppresses the later single-row
    proposal for the same rid.  Finally every single row is proposed in rid
    order.  ``n == 0`` proposes nothing; for ``n == 1`` only delete-all
    remains (the single-row proposal is the same tuple and is deduplicated).
    """
    rows: tuple[Row, ...] = payload.rows.rows
    n = len(rows)
    if n == 0:
        return
    rids = [row.rid for row in rows]
    seen: set[tuple[int, ...]] = set()

    def emit(rids_tuple: tuple[int, ...]) -> Optional[RemoveRows]:
        if not rids_tuple or rids_tuple in seen:
            return None
        seen.add(rids_tuple)
        return RemoveRows(rids_tuple)

    delete_all = tuple(rids)
    seen.add(delete_all)
    yield RemoveRows(delete_all)
    g = 2
    while g <= n:
        for i in range(1, g + 1):
            start = i * n // g
            end = min((i + 1) * n // g, n)
            if start >= end:
                continue  # empty block: no empty deletion is proposed
            block = tuple(rids[start:end])
            complement = tuple(rid for index, rid in enumerate(rids) if not start <= index < end)
            for candidate in (block, complement):
                proposal = emit(candidate)
                if proposal is not None:
                    yield proposal
        g *= 2
    for rid in rids:
        proposal = emit((rid,))
        if proposal is not None:
            yield proposal


# --------------------------------------------------------------------------
# Public proposal enumeration
# --------------------------------------------------------------------------


def iter_proposals(payload: CasePayload) -> Iterator[Transform]:
    """Deterministic proposal iterator over ``payload`` (design 6.4.4).

    Fixed phase order, each phase fully drained before the next:

    1. ``remove_rows`` (delete-all, block deletions with complements down to
       single rows, rid values preserved);
    2. ``simplify_predicate`` (And/Or left child then right child);
    3. ``replace_value`` (shared row values, per rid ascending, candidates
       NULL, 0, +unit, -unit, toward-zero half, deduplicated);
    4. ``replace_literal`` (IR preorder: And/Or left then right, Between
       lower then upper, finally the Q4 arithmetic constant; candidates
       0, +unit, -unit, halve, then NULL only where D1 allows it).

    Every emitted object is a frozen ``contracts.case`` transform model and
    is safe to hand to ``generation.transforms.apply_transform``.  Draining
    the iterator twice yields equal sequences; the function is a pure
    generator over the payload and performs no I/O.
    """
    _require_payload(payload)
    yield from _iter_remove_rows(payload)
    query = payload.query
    if isinstance(query.predicate, (And, Or)):
        # The frozen IR allows exactly one compound level, so both children
        # are existing atoms and D1's SimplifyPredicate accepts these paths.
        yield SimplifyPredicate((PathNode.PREDICATE, PathNode.LEFT))
        yield SimplifyPredicate((PathNode.PREDICATE, PathNode.RIGHT))
    shared_scale = _shared_value_scale(payload)
    for row in payload.rows.rows:
        scale = _slot_scale(payload, row.value)
        for value in _value_candidates(row.value, scale, "first"):
            yield ReplaceValue(row.rid, value)
    for path, current, null_allowed in _iter_literal_slots(query):
        scale = _slot_scale(payload, current)
        null_position: Optional[Literal["first", "last"]] = "last" if null_allowed else None
        for value in _value_candidates(current, scale, null_position):
            yield ReplaceLiteral(path, value)
