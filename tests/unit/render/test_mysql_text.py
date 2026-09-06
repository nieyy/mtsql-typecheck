"""S01: MySQL text-protocol renderer tests (design 6.2.2, 6.3.2, 6.4.2).

All expected SQL texts are hand-written here; none are produced by the
renderer under test.  SHA-256 expectations used in ``test_statement_hash_*``
were computed once with an independent command (``shasum -a 256``) and are
hard-coded below; they are never computed by calling the renderer's own hash
helper against itself.
"""

from __future__ import annotations

import hashlib

import pytest

from mtsql_typecheck.contracts.case import (
    And,
    Arithmetic,
    ArithmeticOp,
    CasePayload,
    ColumnSpec,
    Compare,
    CompareOp,
    ContractError,
    DecimalType,
    DecimalValue,
    EnvironmentRequirements,
    ExactLiteral,
    IndexVariant,
    IntegerValue,
    IsNull,
    NameMap,
    NullValue,
    Or,
    Projection,
    QuerySpec,
    RelationMode,
    ResultColumnSpec,
    ResultRelationSpec,
    Row,
    Rows,
    RuleRef,
    SemverIdentity,
    SignedIntegerType,
    SignedIntName,
    TableSpec,
    TemplateId,
    TypeFamily,
    NullPolicy,
    ValueEquivalence,
    Between,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.generation.render import (
    MAX_INSERT_BATCH_ROWS,
    PREVIEW_NAME_MAP,
    RenderError,
    RenderPhase,
    RenderedStatement,
    render_pair,
    render_preview,
)

NAME_MAP = NameMap(database_a="db_a", database_b="db_b", table_a="t_a", table_b="t_b")

# Independent sha256 expectations (shasum -a 256 over the exact UTF-8 text).
HASH_PREVIEW_SELECT = (
    "aa3536900ad31700501dc05dea11daf65a4b2c47885f59502be13ec9e52a32cf"
)
HASH_PREVIEW_DDL_BIGINT = (
    "cf5fe093f01c8b2648574d03b219658d7e5df146faafa15d392dd55904a6a2d4"
)
HASH_PREVIEW_INSERT = (
    "dcf00d46eb623b99d035de6354c9dd5976b49a49b6b1054451823f4f26d03de5"
)
HASH_DDL_T_A_INT_IX_V = (
    "0b62efac46d0e71552d1cb7f736c35b7df413fd74ab4bd16cc73b41dd0723d07"
)

EXPECTED_DDL_T_A_INT_IX_V = (
    "CREATE TABLE `t_a` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` INT NULL, "
    "KEY `ix_v` (`v`))\n"
    "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
)


# --------------------------------------------------------------------------
# Payload construction helpers (contract models assembled by hand)
# --------------------------------------------------------------------------


def _family(type_spec) -> TypeFamily:
    return TypeFamily(type_spec.kind)


def _relation(query: QuerySpec, a_type, b_type) -> ResultRelationSpec:
    templates: dict[TemplateId, list[tuple[str, TypeFamily, TypeFamily, NullPolicy]]] = {
        TemplateId.Q1: [("c0", _family(a_type), _family(b_type), NullPolicy.PRESERVE)],
        TemplateId.Q2: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID)
        ],
        TemplateId.Q4: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.PRESERVE)
        ],
        TemplateId.Q3: [
            ("c0", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c1", TypeFamily.SIGNED_INTEGER, TypeFamily.SIGNED_INTEGER, NullPolicy.FORBID),
            ("c2", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c3", _family(a_type), _family(b_type), NullPolicy.PRESERVE),
            ("c4", TypeFamily.DECIMAL, TypeFamily.DECIMAL, NullPolicy.PRESERVE),
        ],
    }
    columns = tuple(
        ResultColumnSpec(alias, a_family, b_family, ValueEquivalence.EXACT_NUMERIC, null_policy)
        for alias, a_family, b_family, null_policy in templates[query.template_id]
    )
    return ResultRelationSpec(RelationMode.MULTISET_EXACT, columns)


def make_payload(
    *,
    a_type,
    b_type,
    rows: Rows,
    query: QuerySpec,
    index_variant: IndexVariant = IndexVariant.NONE,
    rule_id: str = "mysql80.integer-decimal",
    renderer: SemverIdentity = SemverIdentity("r1", "1"),
) -> CasePayload:
    table = TableSpec(
        logical_id="t0",
        columns=(
            ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
            ColumnSpec("v", a_type, True),
        ),
        primary_key=("rid",),
        index_variant=index_variant,
    )
    return CasePayload(
        rule=RuleRef(rule_id, 1),
        a_type=a_type,
        b_type=b_type,
        table=table,
        rows=rows,
        query=query,
        relation=_relation(query, a_type, b_type),
        environment=EnvironmentRequirements(
            database="mysql80",
            engine="innodb",
            scope="same-instance",
            sql_mode_tokens=REQUIRED_SQL_MODE_TOKENS,
            character_set="utf8mb4",
            collation="utf8mb4_bin",
            time_zone="+00:00",
        ),
        generator=SemverIdentity("g1", "1"),
        renderer=renderer,
    )


def integer_rows(*values: int) -> Rows:
    return Rows(tuple(Row(index + 1, IntegerValue(value)) for index, value in enumerate(values)))


def decimal_rows(*values: DecimalValue) -> Rows:
    return Rows(tuple(Row(index + 1, value) for index, value in enumerate(values)))


BIGINT = SignedIntegerType(SignedIntName.BIGINT)
INT = SignedIntegerType(SignedIntName.INT)


# --------------------------------------------------------------------------
# Golden: design 6.4.2 manual example, character for character
# --------------------------------------------------------------------------


GOLDEN_ROWS = Rows(
    (
        Row(1, NullValue()),
        Row(2, IntegerValue(0)),
        Row(3, IntegerValue(9007199254740993)),
        Row(4, IntegerValue(9007199254740993)),
    )
)

GOLDEN_PAYLOAD = make_payload(
    a_type=BIGINT,
    b_type=DecimalType(20, 0),
    rows=GOLDEN_ROWS,
    query=QuerySpec(TemplateId.Q1),
    rule_id="mysql80.integer-decimal",
)

EXPECTED_PREVIEW_A = (
    "CREATE TABLE `preview_a` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` BIGINT NULL)\n"
    "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n"
    "INSERT INTO `preview_a` VALUES "
    "(1,NULL),(2,0),(3,9007199254740993),(4,9007199254740993);\n"
    "SELECT `v` AS `c0` FROM `preview_a`;"
)

EXPECTED_PREVIEW_B = (
    "CREATE TABLE `preview_b` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` DECIMAL(20,0) NULL)\n"
    "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n"
    "INSERT INTO `preview_b` VALUES "
    "(1,NULL),(2,0),(3,9007199254740993),(4,9007199254740993);\n"
    "SELECT `v` AS `c0` FROM `preview_b`;"
)


class TestGoldenDesignExample:
    def test_preview_a_matches_design_example(self):
        preview_a, _ = render_preview(GOLDEN_PAYLOAD)
        assert preview_a == EXPECTED_PREVIEW_A

    def test_preview_b_matches_design_example(self):
        _, preview_b = render_preview(GOLDEN_PAYLOAD)
        assert preview_b == EXPECTED_PREVIEW_B

    def test_actual_pair_statement_texts(self):
        pair = render_pair(GOLDEN_PAYLOAD, NAME_MAP)
        assert [statement.phase for statement in pair.a] == [
            RenderPhase.DDL,
            RenderPhase.INSERT,
            RenderPhase.SELECT,
        ]
        assert pair.a[0].text == (
            "CREATE TABLE `t_a` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` BIGINT NULL)\n"
            "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
        )
        assert pair.a[1].text == (
            "INSERT INTO `t_a` VALUES "
            "(1,NULL),(2,0),(3,9007199254740993),(4,9007199254740993);"
        )
        assert pair.a[2].text == "SELECT `v` AS `c0` FROM `t_a`;"
        assert pair.b[0].text == (
            "CREATE TABLE `t_b` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` DECIMAL(20,0) NULL)\n"
            "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
        )
        assert pair.b[1].text == (
            "INSERT INTO `t_b` VALUES "
            "(1,NULL),(2,0),(3,9007199254740993),(4,9007199254740993);"
        )
        assert pair.b[2].text == "SELECT `v` AS `c0` FROM `t_b`;"

    def test_preview_statement_hashes_match_independent_shasum(self):
        # The three hash expectations were computed with `shasum -a 256` over
        # the hand-written statement texts in EXPECTED_PREVIEW_A, never via
        # the renderer's own helper.
        pair = render_pair(GOLDEN_PAYLOAD, PREVIEW_NAME_MAP)
        assert "\n".join(s.text for s in pair.a) == EXPECTED_PREVIEW_A
        assert [s.phase for s in pair.a] == [
            RenderPhase.DDL,
            RenderPhase.INSERT,
            RenderPhase.SELECT,
        ]
        assert pair.a[0].sql_hash == HASH_PREVIEW_DDL_BIGINT
        assert pair.a[1].sql_hash == HASH_PREVIEW_INSERT
        assert pair.a[2].sql_hash == HASH_PREVIEW_SELECT

    def test_preview_statements_match_pair_statements(self):
        preview_a, preview_b = render_preview(GOLDEN_PAYLOAD)
        pair = render_pair(GOLDEN_PAYLOAD, PREVIEW_NAME_MAP)
        assert preview_a == "\n".join(s.text for s in pair.a)
        assert preview_b == "\n".join(s.text for s in pair.b)

    def test_statements_are_text_protocol_without_parameters(self):
        pair = render_pair(GOLDEN_PAYLOAD, NAME_MAP)
        for statement in (*pair.a, *pair.b):
            assert isinstance(statement, RenderedStatement)
            assert statement.protocol == "text"
            assert statement.parameters == ()
            assert statement.sql_hash == hashlib.sha256(
                statement.text.encode("utf-8")
            ).hexdigest()

    def test_no_drop_statements_are_rendered(self):
        pair = render_pair(GOLDEN_PAYLOAD, NAME_MAP)
        for statement in (*pair.a, *pair.b):
            assert "DROP" not in statement.text.upper()
            assert "CAST" not in statement.text.upper()


# --------------------------------------------------------------------------
# INSERT batching
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("row_count", "expected_batch_sizes"),
    [
        (0, []),
        (1, [1]),
        (64, [64]),
        (65, [64, 1]),
        (1024, [64] * 16),
    ],
)
def test_insert_batching(row_count, expected_batch_sizes):
    rows = Rows(tuple(Row(index + 1, IntegerValue(0)) for index in range(row_count)))
    payload = make_payload(
        a_type=BIGINT, b_type=SignedIntegerType(SignedIntName.SMALLINT), rows=rows,
        query=QuerySpec(TemplateId.Q1), rule_id="mysql80.signed-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    for side in (pair.a, pair.b):
        inserts = [s for s in side if s.phase is RenderPhase.INSERT]
        assert len(inserts) == len(expected_batch_sizes)
        for statement, size in zip(inserts, expected_batch_sizes):
            assert statement.text.count(",(") == size - 1
            assert statement.text.startswith(f"INSERT INTO `{NAME_MAP.table_a if side is pair.a else NAME_MAP.table_b}` VALUES (")
        assert [s.phase for s in side] == (
            [RenderPhase.DDL, RenderPhase.SELECT]
            if row_count == 0
            else [RenderPhase.DDL] + [RenderPhase.INSERT] * len(expected_batch_sizes)
            + [RenderPhase.SELECT]
        )


def test_zero_rows_produce_no_insert_statement():
    payload = make_payload(
        a_type=BIGINT, b_type=DecimalType(20, 0), rows=Rows(()),
        query=QuerySpec(TemplateId.Q3),
        rule_id="mysql80.integer-decimal",
    )
    pair = render_pair(payload, NAME_MAP)
    assert [s.phase for s in pair.a] == [RenderPhase.DDL, RenderPhase.SELECT]
    assert all(s.phase is not RenderPhase.INSERT for s in pair.b)


def test_insert_rows_follow_payload_rid_order():
    rows = integer_rows(5, -7, 0, 9007199254740993)
    payload = make_payload(
        a_type=BIGINT, b_type=SignedIntegerType(SignedIntName.BIGINT), rows=rows,
        query=QuerySpec(TemplateId.Q1), rule_id="mysql80.signed-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[1].text == (
        "INSERT INTO `t_a` VALUES (1,5),(2,-7),(3,0),(4,9007199254740993);"
    )


def test_max_batch_constant_is_64():
    assert MAX_INSERT_BATCH_ROWS == 64


# --------------------------------------------------------------------------
# Exact numeric literals
# --------------------------------------------------------------------------


def test_integer_beyond_2_power_53_is_verbatim():
    rows = Rows(
        (
            Row(1, IntegerValue(9007199254740993)),
            Row(2, IntegerValue(-9007199254740993)),
            Row(3, IntegerValue(9223372036854775807)),
            Row(4, IntegerValue(-9223372036854775808)),
        )
    )
    payload = make_payload(
        a_type=BIGINT, b_type=SignedIntegerType(SignedIntName.BIGINT), rows=rows,
        query=QuerySpec(TemplateId.Q1), rule_id="mysql80.signed-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[1].text == (
        "INSERT INTO `t_a` VALUES "
        "(1,9007199254740993),(2,-9007199254740993),"
        "(3,9223372036854775807),(4,-9223372036854775808);"
    )


@pytest.mark.parametrize(
    ("coefficient", "scale", "expected_text"),
    [
        (0, 2, "0.00"),
        (0, 0, "0"),
        (5, 2, "0.05"),
        (-5, 2, "-0.05"),
        (12345, 2, "123.45"),
        (-12345, 2, "-123.45"),
        (5, 6, "0.000005"),
        (-5, 6, "-0.000005"),
        (1000000, 6, "1.000000"),
        (-1000000, 6, "-1.000000"),
        (123, 0, "123"),
        (-123, 0, "-123"),
        (1, 1, "0.1"),
        (-1, 1, "-0.1"),
        (105, 2, "1.05"),
    ],
)
def test_decimal_fixed_point_literal(coefficient, scale, expected_text):
    rows = decimal_rows(DecimalValue(coefficient, scale))
    payload = make_payload(
        a_type=DecimalType(9, scale if scale <= 9 else 9),
        b_type=DecimalType(18, scale if scale <= 9 else 9),
        rows=rows,
        query=QuerySpec(TemplateId.Q1),
        rule_id="mysql80.decimal-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[1].text == f"INSERT INTO `t_a` VALUES (1,{expected_text});"
    assert pair.b[1].text == f"INSERT INTO `t_b` VALUES (1,{expected_text});"


def test_no_scientific_notation_in_any_rendered_statement():
    rows = Rows(
        (
            Row(1, DecimalValue(5, 6)),
            Row(2, DecimalValue(-12345, 2)),
            Row(3, DecimalValue(9007199254740993, 0)),
        )
    )
    payload = make_payload(
        a_type=DecimalType(20, 6),
        b_type=DecimalType(30, 6),
        rows=rows,
        query=QuerySpec(TemplateId.Q1),
        rule_id="mysql80.decimal-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    for statement in (*pair.a, *pair.b):
        if statement.phase is not RenderPhase.INSERT:
            continue
        values = statement.text.split(" VALUES ", 1)[1].removesuffix(";")
        assert "e" not in values and "E" not in values


# --------------------------------------------------------------------------
# SELECT templates and predicates (golden text)
# --------------------------------------------------------------------------


def _q2_select(predicate) -> str:
    rows = integer_rows(0)
    payload = make_payload(
        a_type=BIGINT, b_type=SignedIntegerType(SignedIntName.SMALLINT), rows=rows,
        query=QuerySpec(TemplateId.Q2, predicate=predicate),
        rule_id="mysql80.signed-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    return pair.a[-1].text


@pytest.mark.parametrize(
    ("op", "expected_operator"),
    [
        (CompareOp.EQ, "="),
        (CompareOp.NE, "<>"),
        (CompareOp.LT, "<"),
        (CompareOp.LE, "<="),
        (CompareOp.GT, ">"),
        (CompareOp.GE, ">="),
    ],
)
def test_compare_operators(op, expected_operator):
    predicate = Compare(op, ExactLiteral(IntegerValue(5)))
    assert _q2_select(predicate) == f"SELECT `rid` AS `c0` FROM `t_a` WHERE `v` {expected_operator} 5;"


def test_null_safe_compare():
    predicate = Compare(CompareOp.NULL_SAFE_EQ, ExactLiteral(IntegerValue(0)))
    assert _q2_select(predicate) == "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` <=> 0;"


def test_compare_with_null_constant():
    predicate = Compare(CompareOp.EQ, ExactLiteral(NullValue()))
    assert _q2_select(predicate) == "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` = NULL;"


def test_null_safe_compare_with_null_constant():
    predicate = Compare(CompareOp.NULL_SAFE_EQ, ExactLiteral(NullValue()))
    assert _q2_select(predicate) == "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` <=> NULL;"


def test_between():
    predicate = Between(
        ExactLiteral(IntegerValue(-1)), ExactLiteral(IntegerValue(7))
    )
    assert _q2_select(predicate) == (
        "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` BETWEEN -1 AND 7;"
    )


def test_between_with_decimal_endpoints():
    def build():
        rows = decimal_rows(DecimalValue(0, 2))
        payload = make_payload(
            a_type=DecimalType(9, 2),
            b_type=DecimalType(18, 2),
            rows=rows,
            query=QuerySpec(
                TemplateId.Q2,
                predicate=Between(
                    ExactLiteral(DecimalValue(150, 2)), ExactLiteral(DecimalValue(300, 2))
                ),
            ),
            rule_id="mysql80.decimal-widen",
        )
        return render_pair(payload, NAME_MAP).a[-1].text

    assert build() == "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` BETWEEN 1.50 AND 3.00;"


def test_is_null_and_is_not_null():
    assert _q2_select(IsNull(False)) == "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` IS NULL;"
    assert _q2_select(IsNull(True)) == (
        "SELECT `rid` AS `c0` FROM `t_a` WHERE `v` IS NOT NULL;"
    )


def test_and_predicate_is_parenthesized_with_bare_atoms():
    predicate = _and_eq5_and_not_null()
    assert _q2_select(predicate) == (
        "SELECT `rid` AS `c0` FROM `t_a` WHERE (`v` = 5 AND `v` IS NOT NULL);"
    )


def _and_eq5_and_not_null():
    return And(Compare(CompareOp.EQ, ExactLiteral(IntegerValue(5))), IsNull(True))


def test_or_predicate_is_parenthesized_with_bare_atoms():
    predicate = Or(
        Compare(CompareOp.LE, ExactLiteral(IntegerValue(-1))),
        Compare(CompareOp.GE, ExactLiteral(IntegerValue(9))),
    )
    assert _q2_select(predicate) == (
        "SELECT `rid` AS `c0` FROM `t_a` WHERE (`v` <= -1 OR `v` >= 9);"
    )


def test_q3_select_without_where():
    payload = make_payload(
        a_type=BIGINT, b_type=DecimalType(20, 0), rows=integer_rows(0, 0),
        query=QuerySpec(TemplateId.Q3), rule_id="mysql80.integer-decimal",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[-1].text == (
        "SELECT COUNT(*) AS `c0`, COUNT(`v`) AS `c1`, MIN(`v`) AS `c2`, "
        "MAX(`v`) AS `c3`, SUM(`v`) AS `c4` FROM `t_a`;"
    )


def test_q3_select_with_where():
    payload = make_payload(
        a_type=BIGINT, b_type=DecimalType(20, 0), rows=integer_rows(3),
        query=QuerySpec(TemplateId.Q3, predicate=IsNull(True)),
        rule_id="mysql80.integer-decimal",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[-1].text == (
        "SELECT COUNT(*) AS `c0`, COUNT(`v`) AS `c1`, MIN(`v`) AS `c2`, "
        "MAX(`v`) AS `c3`, SUM(`v`) AS `c4` FROM `t_a` WHERE `v` IS NOT NULL;"
    )


def _q4_query(op: ArithmeticOp, constant: int, predicate=None) -> QuerySpec:
    arithmetic = Arithmetic(op, IntegerValue(constant))
    return QuerySpec(
        TemplateId.Q4,
        predicate=predicate,
        arithmetic=arithmetic,
        projections=(Projection("c0", arithmetic),),
    )


def test_q4_select_add():
    payload = make_payload(
        a_type=INT, b_type=BIGINT, rows=integer_rows(1),
        query=_q4_query(
            ArithmeticOp.ADD, 16, Compare(CompareOp.GT, ExactLiteral(IntegerValue(0)))
        ),
        rule_id="mysql80.signed-add-sub",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[-1].text == (
        "SELECT (`v` + 16) AS `c0` FROM `t_a` WHERE `v` > 0;"
    )


def test_q4_select_negative_constants():
    def select(op: ArithmeticOp, constant: int) -> str:
        payload = make_payload(
            a_type=INT, b_type=BIGINT, rows=integer_rows(1),
            query=_q4_query(op, constant),
            rule_id="mysql80.signed-add-sub",
        )
        return render_pair(payload, NAME_MAP).a[-1].text

    assert select(ArithmeticOp.ADD, -16) == "SELECT (`v` + -16) AS `c0` FROM `t_a`;"
    assert select(ArithmeticOp.SUBTRACT, 16) == "SELECT (`v` - 16) AS `c0` FROM `t_a`;"
    assert select(ArithmeticOp.SUBTRACT, -16) == "SELECT (`v` - -16) AS `c0` FROM `t_a`;"


# --------------------------------------------------------------------------
# DDL types and index variants
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("type_spec", "expected_sql_type"),
    [
        (SignedIntegerType(SignedIntName.TINYINT), "TINYINT"),
        (SignedIntegerType(SignedIntName.SMALLINT), "SMALLINT"),
        (SignedIntegerType(SignedIntName.MEDIUMINT), "MEDIUMINT"),
        (SignedIntegerType(SignedIntName.INT), "INT"),
        (SignedIntegerType(SignedIntName.BIGINT), "BIGINT"),
        (DecimalType(9, 2), "DECIMAL(9,2)"),
        (DecimalType(20, 0), "DECIMAL(20,0)"),
        (DecimalType(30, 6), "DECIMAL(30,6)"),
    ],
)
def test_ddl_type_names(type_spec, expected_sql_type):
    rows = integer_rows(0) if type_spec.kind == "signed_integer" else decimal_rows(
        DecimalValue(0, type_spec.scale)
    )
    payload = make_payload(
        a_type=type_spec,
        b_type=type_spec,
        rows=rows,
        query=QuerySpec(TemplateId.Q1),
        rule_id="mysql80.signed-widen"
        if type_spec.kind == "signed_integer"
        else "mysql80.decimal-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[0].text == (
        f"CREATE TABLE `t_a` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` {expected_sql_type} NULL)\n"
        "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
    )


def test_index_variant_none_has_no_secondary_key():
    pair = render_pair(GOLDEN_PAYLOAD, NAME_MAP)
    assert "KEY `" not in pair.a[0].text
    assert "KEY `" not in pair.b[0].text


def test_index_variant_ix_v_on_both_sides():
    rows = integer_rows(0)
    payload = make_payload(
        a_type=INT, b_type=BIGINT, rows=rows, query=QuerySpec(TemplateId.Q1),
        index_variant=IndexVariant.IX_V, rule_id="mysql80.signed-widen",
    )
    pair = render_pair(payload, NAME_MAP)
    assert pair.a[0].text == EXPECTED_DDL_T_A_INT_IX_V
    # Independent hash expectation (shasum -a 256), not derived from the renderer.
    assert pair.a[0].sql_hash == HASH_DDL_T_A_INT_IX_V
    assert pair.b[0].text == (
        "CREATE TABLE `t_b` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` BIGINT NULL, "
        "KEY `ix_v` (`v`))\n"
        "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;"
    )


# --------------------------------------------------------------------------
# NameMap handling and identifier injection rejection
# --------------------------------------------------------------------------


def test_different_name_maps_change_only_identifiers():
    other = NameMap(
        database_a="warehouse7", database_b="warehouse8", table_a="probe_left", table_b="probe_right"
    )
    pair = render_pair(GOLDEN_PAYLOAD, other)
    assert pair.a[2].text == "SELECT `v` AS `c0` FROM `probe_left`;"
    assert pair.b[2].text == "SELECT `v` AS `c0` FROM `probe_right`;"
    assert pair.a[0].text.startswith("CREATE TABLE `probe_left` (")
    assert pair.b[0].text.startswith("CREATE TABLE `probe_right` (")


@pytest.mark.parametrize(
    "bad_identifier",
    [
        "Table",
        "t-a",
        "t.a",
        "t`a",
        "a;DROP TABLE x",
        "a" * 49,
        "",
        "1abc",
        "_abc",
        "a b",
        "täble",
    ],
)
def test_invalid_identifiers_are_rejected(bad_identifier):
    with pytest.raises(ContractError):
        NameMap(database_a=bad_identifier, database_b="db_b", table_a="t_a", table_b="t_b")
    with pytest.raises(ContractError):
        NameMap(database_a="db_a", database_b="db_b", table_a=bad_identifier, table_b="t_b")
    with pytest.raises(ContractError):
        NameMap(database_a="db_a", database_b="db_b", table_a="t_a", table_b=bad_identifier)


def test_database_collision_rejected():
    with pytest.raises(ContractError):
        NameMap(database_a="same_db", database_b="same_db", table_a="t_a", table_b="t_b")


def test_table_collision_rejected_at_render_time():
    name_map = NameMap(database_a="db_a", database_b="db_b", table_a="same_t", table_b="same_t")
    with pytest.raises(RenderError) as excinfo:
        render_pair(GOLDEN_PAYLOAD, name_map)
    assert excinfo.value.reason.value == "invalid_structure"


def test_length_48_identifier_accepted():
    name_map = NameMap(
        database_a="d" * 48,
        database_b="e" * 48,
        table_a="t" * 48,
        table_b="u" * 48,
    )
    pair = render_pair(GOLDEN_PAYLOAD, name_map)
    assert pair.a[2].text == f"SELECT `v` AS `c0` FROM `{'t' * 48}`;"


def test_renderer_identity_mismatch_rejected():
    payload = make_payload(
        a_type=BIGINT,
        b_type=DecimalType(20, 0),
        rows=GOLDEN_ROWS,
        query=QuerySpec(TemplateId.Q1),
        renderer=SemverIdentity("r9", "9"),
    )
    with pytest.raises(RenderError) as excinfo:
        render_pair(payload, NAME_MAP)
    assert excinfo.value.reason.value == "unknown_version"


# --------------------------------------------------------------------------
# Preview vs actual consistency
# --------------------------------------------------------------------------


def test_preview_and_actual_have_identical_structure():
    preview_a, preview_b = render_preview(GOLDEN_PAYLOAD)
    pair = render_pair(GOLDEN_PAYLOAD, NAME_MAP)
    actual_a = "\n".join(s.text for s in pair.a)
    actual_b = "\n".join(s.text for s in pair.b)
    # Only the table identifiers differ between preview and actual rendering.
    assert actual_a.replace("`t_a`", "`preview_a`") == preview_a
    assert actual_b.replace("`t_b`", "`preview_b`") == preview_b


def test_preview_uses_fixed_preview_names():
    rows = Rows(tuple(Row(index + 1, IntegerValue(0)) for index in range(65)))
    payload = make_payload(
        a_type=INT, b_type=BIGINT, rows=rows, query=QuerySpec(TemplateId.Q1),
        rule_id="mysql80.signed-widen",
    )
    preview_a, preview_b = render_preview(payload)
    assert preview_a.count("INSERT INTO `preview_a` VALUES") == 2
    assert preview_b.count("INSERT INTO `preview_b` VALUES") == 2
    assert "`t0`" not in preview_a and "`t0`" not in preview_b
    assert preview_a.endswith("SELECT `v` AS `c0` FROM `preview_a`;")
    assert preview_b.endswith("SELECT `v` AS `c0` FROM `preview_b`;")
