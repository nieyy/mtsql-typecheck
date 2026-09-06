"""Revalidated transforms for D1 (design 6.4.3, 6.3.1 ``apply_transform``; T01).

``apply_transform`` is a pure function: D2 proposes a transform, D1 rebuilds
the child payload by copy construction, re-derives its case_id and re-runs the
full static validation.  No search policy, no I/O, no database operations and
no SQL-text parsing: transforms operate only on the structured IR and the
shared logical rows.

Closed path grammar (frozen PathNode vocabulary, design 6.2.4/6.4.3)
---------------------------------------------------------------------
The frozen contract constructors require every path to start with the
``predicate`` root step and to hold at least two steps
(``path[0] is PathNode.PREDICATE``, ``len(path) >= 2``).  On top of that
frozen constraint this module fixes the following closed grammar:

- ``simplify_predicate``: ``("predicate", LEFT|RIGHT)`` selects the surviving
  child atom of the AND/OR node that holds it; the compound parent is replaced
  by that existing atom, e.g. ``(A AND B) -> A`` via ``("predicate", "left")``
  and ``(A OR B) -> B`` via ``("predicate", "right")``.  The frozen IR allows
  exactly one compound level (And/Or join two atoms), so longer paths cannot
  locate any compound node and are rejected as out of range.
- ``replace_literal`` addresses an exact-value slot and always ends with the
  ``constant`` step:
  - bare Compare predicate:  ``("predicate", "right", "constant")``
  - bare Between predicate:  ``("predicate", "lower"|"upper", "constant")``
  - atom inside And/Or:      ``("predicate", LEFT|RIGHT,
                               "right"|"lower"|"upper", "constant")``
  - Q4 arithmetic constant:  ``("predicate", "arithmetic", "constant")``

  The Q4 ``k`` path carries the leading ``predicate`` step because the frozen
  contract mandates it for every path; the ``arithmetic`` step then selects
  ``QuerySpec.arithmetic``.  This is the only encoding of the arithmetic
  constant expressible in the frozen PathNode vocabulary.

Semantic decisions
------------------
- ``NO_CHANGE``: the rebuilt child payload hashes back to the parent case_id;
  the result carries no child and is not a reduction success.
- Rejections carry the reason code of the first VIOLATED condition of the
  child's full ``validate_case`` re-run, or of a structural pre-check (missing
  rid, invalid path, wrong literal kind); a rejected result never carries an
  executable child.
- Runtime facts are never inherited: ``apply_transform`` accepts no facts and
  the child's check is a fresh static check whose runtime conditions are
  PENDING/missing_fact only (design 6.4.3: any child invalidates old runs).
- Coverage category labels (design 6.4.1 slots, e.g. the empty-table slot 18)
  have no field in ``CasePayload`` or ``TransformResult``: they are generation
  manifest bookkeeping (design 6.6) that never enters case_id.  The child
  payload carries the post-transform row set itself, so downstream consumers
  derive an empty/all-NULL situation from the payload content; no label field
  is invented here.
- Cross-rule transforms are impossible by construction: the four transform
  models carry no rule/type/template fields, so no transform can change the
  rule binding, the A/B column types or the query template; every child is
  revalidated against the parent's rule reference.
- The child bundle carries a zero provenance marker: ``apply_transform`` has
  no generation context, provenance never enters case_id, and D2 owns the
  attempt/ordinal provenance when sealing a child into a run.
"""

from __future__ import annotations

import dataclasses
from typing import Iterable, Optional

from ..contracts.case import (
    And,
    Arithmetic,
    Between,
    CaseBundle,
    CasePayload,
    CheckStatus,
    Compare,
    ContractError,
    ExactLiteral,
    IntegerValue,
    IsNull,
    NullValue,
    Or,
    PathNode,
    Predicate,
    Projection,
    Provenance,
    QuerySpec,
    ReasonCode,
    RemoveRows,
    ReplaceLiteral,
    ReplaceValue,
    Row,
    Rows,
    SimplifyPredicate,
    StaticCheckStatus,
    TemplateId,
    Transform,
    TransformResult,
    TransformStatus,
)
from ..contracts.codec import case_id_of
from ..rules.exact_numeric import check_common_value_domain
from ..rules.registry import UnknownRuleError, get_rule
from .render import render_preview
from .validation import validate_case

__all__ = ["apply_transform", "list_rejected"]

# Provenance marker for child bundles: apply_transform runs outside any
# generation ordinal, and provenance never participates in case_id (6.2.4).
_CHILD_PROVENANCE = Provenance(seed=0, ordinal=0, profile_hash="0" * 64, retry=0)


class _Rejection(Exception):
    """Internal control flow: a semantically rejected transform."""

    def __init__(self, reason: ReasonCode) -> None:
        super().__init__(str(reason.value))
        self.reason = reason


# --------------------------------------------------------------------------
# Shared-rows transforms
# --------------------------------------------------------------------------


def _apply_remove_rows(payload: CasePayload, transform: RemoveRows) -> Rows:
    """Delete the named rids from the shared rows; rids are never renumbered.

    Deleting down to the empty table is allowed (design 6.4.3); the remaining
    rows keep their original rids and canonical rid order.
    """
    requested = set(transform.rids)
    existing = {row.rid for row in payload.rows.rows}
    missing = sorted(requested - existing)
    if missing:
        # Every rid must exist in the parent; there is no partial deletion.
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    kept = tuple(row for row in payload.rows.rows if row.rid not in requested)
    return Rows(kept, max_rows=payload.rows.max_rows)


def _precheck_shared_value(payload: CasePayload, value: object) -> None:
    """Rule-aware literal-kind/domain pre-check for a new shared value.

    ``check_common_value_domain`` is the same judgment the full revalidation
    applies to loaded rows; running it first turns wrong-kind values (a
    decimal on an integer-only rule, a wrong-scale decimal, a value outside
    the narrower side's domain) into a stable rejection instead of a
    construction error.  An unknown rule reference is left to the child's
    full revalidation, which reports ``unknown_version``.
    """
    try:
        rule = get_rule(payload.rule.rule_id, payload.rule.rule_version)
    except UnknownRuleError:
        return
    result = check_common_value_domain(rule, payload.a_type, payload.b_type, value)
    if result.status is CheckStatus.VIOLATED:
        assert result.reason is not None
        raise _Rejection(result.reason)


def _apply_replace_value(payload: CasePayload, transform: ReplaceValue) -> Rows:
    """Replace one row's shared logical value on both sides at once.

    The payload holds a single logical row sequence, so there is no per-side
    row store and no single-sided edit is expressible: the replacement value
    is the one value both A and B will carry.
    """
    target: Optional[Row] = None
    for row in payload.rows.rows:
        if row.rid == transform.rid:
            target = row
            break
    if target is None:
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    _precheck_shared_value(payload, transform.value)
    replaced = tuple(
        Row(row.rid, transform.value) if row.rid == transform.rid else row
        for row in payload.rows.rows
    )
    return Rows(replaced, max_rows=payload.rows.max_rows)


# --------------------------------------------------------------------------
# Predicate / arithmetic transforms
# --------------------------------------------------------------------------


def _apply_simplify(query: QuerySpec, path: tuple[PathNode, ...]) -> Predicate:
    """Replace the AND/OR node holding the addressed child by that child.

    The last path step selects the surviving atom; the compound node holding
    it must exist.  With the frozen IR (one compound level over two atoms)
    this is exactly ``("predicate", LEFT|RIGHT)``; anything else is an
    invalid or out-of-range path.
    """
    if query.predicate is None:
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    steps = path[1:]
    if not steps:
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    node: Predicate = query.predicate
    for step in steps[:-1]:
        if isinstance(node, (And, Or)) and step in (PathNode.LEFT, PathNode.RIGHT):
            node = node.left if step is PathNode.LEFT else node.right
        else:
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    last = steps[-1]
    if not isinstance(node, (And, Or)) or last not in (PathNode.LEFT, PathNode.RIGHT):
        # The path points at a non-AND-OR node or uses a step a compound
        # predicate does not have (lower/upper/constant/arithmetic).
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    return node.left if last is PathNode.LEFT else node.right


def _replace_constant(
    node: Predicate, steps: tuple[PathNode, ...], value: object
) -> Predicate:
    """Rebuild the predicate with the addressed exact-value slot replaced."""
    if not steps:
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    step = steps[0]
    rest = steps[1:]
    if isinstance(node, (And, Or)):
        compound = And if isinstance(node, And) else Or
        if step is PathNode.LEFT:
            return compound(_replace_constant(node.left, rest, value), node.right)
        if step is PathNode.RIGHT:
            return compound(node.left, _replace_constant(node.right, rest, value))
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    if isinstance(node, Compare):
        if step is PathNode.RIGHT and rest == (PathNode.CONSTANT,):
            # NULL is legal at the constant position of a plain comparison.
            return Compare(node.op, ExactLiteral(value))  # type: ignore[arg-type]
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    if isinstance(node, Between):
        if rest != (PathNode.CONSTANT,):
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
        if isinstance(value, NullValue):
            # BETWEEN endpoints must not be NULL (design 6.2.2); the frozen
            # Between model would raise, this becomes a stable rejection.
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
        if step is PathNode.LOWER:
            return Between(ExactLiteral(value), node.upper)  # type: ignore[arg-type]
        if step is PathNode.UPPER:
            return Between(node.lower, ExactLiteral(value))  # type: ignore[arg-type]
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    # IsNull carries no constant slot; nothing else is addressable.
    raise _Rejection(ReasonCode.INVALID_STRUCTURE)


def _apply_replace_literal(
    query: QuerySpec, transform: ReplaceLiteral
) -> tuple[Optional[Predicate], Optional[Arithmetic]]:
    """Locate the addressed constant slot and rebuild predicate/arithmetic.

    Returns ``(new_predicate, new_arithmetic)``; unchanged parts are passed
    through by identity.
    """
    path = transform.path
    if path[1] is PathNode.ARITHMETIC:
        # Q4 k: ("predicate", "arithmetic", "constant").
        if len(path) != 3 or path[2] is not PathNode.CONSTANT:
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
        if query.arithmetic is None:
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
        if not isinstance(transform.value, IntegerValue):
            # The Q4 constant k is an integer by IR contract; a decimal or
            # NULL replacement is a stable rejection, not a construction error.
            raise _Rejection(ReasonCode.INVALID_STRUCTURE)
        arithmetic = Arithmetic(query.arithmetic.op, transform.value)
        return query.predicate, arithmetic
    if query.predicate is None:
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    new_predicate = _replace_constant(query.predicate, path[1:], transform.value)
    return new_predicate, query.arithmetic


# --------------------------------------------------------------------------
# Child construction
# --------------------------------------------------------------------------


def _rebuild_query(
    query: QuerySpec,
    predicate: Optional[Predicate],
    arithmetic: Optional[Arithmetic],
) -> QuerySpec:
    """Rebuild the QuerySpec, re-binding the Q4 projection to the arithmetic."""
    projections = query.projections
    if query.template_id is TemplateId.Q4 and arithmetic is not query.arithmetic:
        # Q4's single projection must reuse the (new) arithmetic node.
        projections = (Projection("c0", arithmetic),)  # type: ignore[list-item]
    return QuerySpec(query.template_id, predicate, arithmetic, projections)


def _build_child(payload: CasePayload, transform: Transform) -> CasePayload:
    """Copy-construct the child payload; the parent object is never touched."""
    query = payload.query
    predicate = query.predicate
    arithmetic = query.arithmetic
    rows = payload.rows
    if isinstance(transform, RemoveRows):
        rows = _apply_remove_rows(payload, transform)
    elif isinstance(transform, ReplaceValue):
        rows = _apply_replace_value(payload, transform)
    elif isinstance(transform, SimplifyPredicate):
        predicate = _apply_simplify(query, transform.path)
    elif isinstance(transform, ReplaceLiteral):
        predicate, arithmetic = _apply_replace_literal(query, transform)
    else:  # defensive: the closed transform union is exhausted above
        raise ContractError(f"unsupported transform {type(transform).__name__}")
    if query.template_id is TemplateId.Q2 and predicate is None:
        # Defensive template guard: Q2 must keep a predicate.  With the frozen
        # IR a simplification always yields an existing atom, so no public
        # transform can express removing the only predicate; this guard keeps
        # the invariant explicit should the IR ever grow.
        raise _Rejection(ReasonCode.INVALID_STRUCTURE)
    child_query = _rebuild_query(query, predicate, arithmetic)
    return dataclasses.replace(payload, rows=rows, query=child_query)


# --------------------------------------------------------------------------
# Public entry points
# --------------------------------------------------------------------------


def apply_transform(payload: CasePayload, transform: Transform) -> TransformResult:
    """Apply one D2-proposed transform to a validated parent payload.

    Pure function: rebuilds the child payload by copy construction, derives
    the child case_id from its content and re-runs the full static validation.
    Outcomes (design 6.4.3):

    - ``APPLIED``: the child is statically valid; the result carries the child
      bundle (fresh preview SQL, zero provenance marker) and the child's own
      static check.  Runtime facts of the parent are never inherited.
    - ``NO_CHANGE``: the rebuilt payload hashes to the parent case_id; no
      child is produced and this is not a reduction success.
    - ``REJECTED``: the transform is structurally inapplicable or the child
      fails full revalidation; the reason code of the first VIOLATED condition
      is reported and no executable child exists.

    The parent payload is assumed validated (design Phase 4 entry condition);
    its own defects surface through the child's revalidation as rejections.
    Malformed call inputs (a non-payload or non-transform object) raise
    ``ContractError`` instead of producing a result.
    """
    if not isinstance(payload, CasePayload):
        raise ContractError("apply_transform needs a CasePayload")
    if not isinstance(
        transform, (RemoveRows, ReplaceValue, SimplifyPredicate, ReplaceLiteral)
    ):
        raise ContractError("apply_transform needs a closed Transform node")
    parent_case_id = case_id_of(payload)
    try:
        child_payload = _build_child(payload, transform)
    except _Rejection as rejection:
        return TransformResult(
            parent_case_id=parent_case_id,
            transform=transform,
            status=TransformStatus.REJECTED,
            rejection_reason=rejection.reason,
        )
    except ContractError:
        # A transformed payload the frozen models cannot represent (defensive
        # backstop behind the explicit pre-checks above).
        return TransformResult(
            parent_case_id=parent_case_id,
            transform=transform,
            status=TransformStatus.REJECTED,
            rejection_reason=ReasonCode.INVALID_STRUCTURE,
        )
    child_case_id = case_id_of(child_payload)
    if child_case_id == parent_case_id:
        return TransformResult(
            parent_case_id=parent_case_id,
            transform=transform,
            status=TransformStatus.NO_CHANGE,
        )
    check = validate_case(child_payload)
    if check.status is not StaticCheckStatus.VALID_STATIC:
        first_violated = next(
            condition
            for condition in check.conditions
            if condition.status is CheckStatus.VIOLATED
        )
        assert first_violated.reason is not None  # contract invariant
        return TransformResult(
            parent_case_id=parent_case_id,
            transform=transform,
            status=TransformStatus.REJECTED,
            rejection_reason=first_violated.reason,
        )
    preview_a, preview_b = render_preview(child_payload)
    child = CaseBundle(
        payload=child_payload,
        provenance=_CHILD_PROVENANCE,
        preview_a_sql=preview_a,
        preview_b_sql=preview_b,
        static_check=check,
    )
    return TransformResult(
        parent_case_id=parent_case_id,
        transform=transform,
        status=TransformStatus.APPLIED,
        child=child,
        static_check=check,
    )


def list_rejected(results: Iterable[TransformResult]) -> tuple[TransformResult, ...]:
    """Filter a sequence of results to its REJECTED entries, order preserved."""
    return tuple(result for result in results if result.status is TransformStatus.REJECTED)
