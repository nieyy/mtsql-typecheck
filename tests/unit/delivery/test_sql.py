"""D4 delivery/sql.py tests (design 6.4.6, Phase 4).

The golden a.sql/b.sql texts are hand-authored here, character for character,
independently of the code under test.  Their SHA-256 expectations were
computed once with an external command (``shasum -a 256``) and are hard-coded;
they are never derived by calling the packager against itself.  The golden
case_id was likewise computed once (SHA-256 over the canonical payload JSON)
and pinned as a literal.
"""

from __future__ import annotations

import hashlib

import pytest

from mtsql_typecheck.contracts.case import (
    CasePayload,
    ColumnSpec,
    ContractError,
    DecimalType,
    EnvironmentRequirements,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullPolicy,
    NullValue,
    ObservedEnvironment,
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
    ValueEquivalence,
    REQUIRED_SQL_MODE_TOKENS,
)
from mtsql_typecheck.delivery.sql import (
    CANDIDATE_UNVERIFIED_MARKER,
    EnvironmentRequirementsDoc,
    ExportNameMap,
    NOT_RUN_INPUT_NOTE,
    OPTIMIZER_BASELINE_UNKNOWN,
    OPTIMIZER_BASELINE_UNKNOWN_NOTE,
    SessionPreconditions,
    SQL_VARIABLE_WHITELIST,
    assign_name_map,
    decode_environment_requirements_document,
    environment_requirements_document,
    environment_requirements_document_with_observed,
    render_session_sql,
    wrap_sql_package,
    _sql_literal,
)
from mtsql_typecheck.generation.render import render_pair

# Independent sha256 expectations over the exact UTF-8 golden file bytes
# (shasum -a 256), hand-pinned.
GOLDEN_A_SQL_SHA256 = "a44f6e47262cea4e849ffa91178b31cc4f06b0f9af564ede00ed66ef2bbe9fe3"
GOLDEN_B_SQL_SHA256 = "badbc192e315fef4bcef145184994ca52b9e4963c9619a91bb23b12b047e551e"

# Pinned once from the golden payload (SHA-256 over its canonical JSON).
GOLDEN_CASE_ID = "5402cf42a006062dd74958ff4fb83f21f9206938992982bdc70d930b9788687d"
GOLDEN_TOKEN = "goldentoken0"
GOLDEN_PREFIX = GOLDEN_CASE_ID[:8]


# --------------------------------------------------------------------------
# Hand-built golden payload (assembled directly from the contract models)
# --------------------------------------------------------------------------


def _golden_payload() -> CasePayload:
    a_type = SignedIntegerType(SignedIntName.BIGINT)
    b_type = DecimalType(20, 0)
    return CasePayload(
        rule=RuleRef("mysql80.integer-decimal", 1),
        a_type=a_type,
        b_type=b_type,
        table=TableSpec(
            logical_id="t0",
            columns=(
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", a_type, True),
            ),
            primary_key=("rid",),
            index_variant=IndexVariant.NONE,
        ),
        rows=Rows(
            (
                Row(1, NullValue()),
                Row(2, IntegerValue(0)),
                Row(3, IntegerValue(9007199254740993)),
                Row(4, IntegerValue(9007199254740993)),
            )
        ),
        query=QuerySpec(TemplateId.Q1),
        relation=ResultRelationSpec(
            RelationMode.MULTISET_EXACT,
            (
                ResultColumnSpec(
                    "c0",
                    TypeFamily.SIGNED_INTEGER,
                    TypeFamily.DECIMAL,
                    ValueEquivalence.EXACT_NUMERIC,
                    NullPolicy.PRESERVE,
                ),
            ),
        ),
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
        renderer=SemverIdentity("r1", "1"),
    )


def _golden_preconditions() -> SessionPreconditions:
    return SessionPreconditions(
        sql_mode_tokens=("NO_ENGINE_SUBSTITUTION", "ONLY_FULL_GROUP_BY", "STRICT_ALL_TABLES"),
        character_set="utf8mb4",
        collation="utf8mb4_bin",
        time_zone="+00:00",
        isolation_level="REPEATABLE READ",
        optimizer_baseline=None,
    )


def _golden_names() -> ExportNameMap:
    return assign_name_map(GOLDEN_CASE_ID, GOLDEN_TOKEN)


def _golden_pair():
    names = _golden_names()
    name_map = NameMap(
        database_a=names.database_a,
        database_b=names.database_b,
        table_a=names.table_a,
        table_b=names.table_b,
    )
    return render_pair(_golden_payload(), name_map)


def _golden_package():
    return wrap_sql_package(_golden_pair(), _golden_preconditions(), _golden_names())


# --------------------------------------------------------------------------
# Golden: full a.sql / b.sql files, character for character
# --------------------------------------------------------------------------

GOLDEN_SESSION_LINES = (
    "SET sql_mode = 'NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY,STRICT_ALL_TABLES';",
    "SET character_set_client = 'utf8mb4';",
    "SET character_set_results = 'utf8mb4';",
    "SET character_set_connection = 'utf8mb4';",
    "SET collation_connection = 'utf8mb4_bin';",
    "SET collation_database = 'utf8mb4_bin';",
    "SET collation_server = 'utf8mb4_bin';",
    "SET time_zone = '+00:00';",
    "SET transaction_isolation = 'REPEATABLE READ';",
)


def _golden_header() -> tuple[str, ...]:
    return (
        "# exported by mtsql-typecheck (D4 independent SQL delivery; design 6.4.6)",
        f"# case_id: {GOLDEN_CASE_ID}",
        f"# status: {CANDIDATE_UNVERIFIED_MARKER}; {NOT_RUN_INPUT_NOTE}",
    )


def _golden_side(table: str, v_type: str) -> str:
    header = "\n".join(_golden_header())
    session = "\n".join(GOLDEN_SESSION_LINES)
    d1 = (
        f"CREATE TABLE `{table}` (`rid` BIGINT NOT NULL PRIMARY KEY, `v` {v_type} NULL)\n"
        "  ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n"
        f"INSERT INTO `{table}` VALUES (1,NULL),(2,0),(3,9007199254740993),(4,9007199254740993);\n"
        f"SELECT `v` AS `c0` FROM `{table}`;"
    )
    database = "tc_" + table[2:]
    return (
        f"{header}\n{session}\nCREATE DATABASE `{database}`;\nUSE `{database}`;\n{d1}\n"
    )


class TestGoldenPackage:
    def test_golden_a_sql_byte_equality(self):
        package_a, _ = _golden_package()
        expected = _golden_side(f"t_a_{GOLDEN_TOKEN}_{GOLDEN_PREFIX}", "BIGINT")
        assert package_a == expected

    def test_golden_b_sql_byte_equality(self):
        _, package_b = _golden_package()
        expected = _golden_side(f"t_b_{GOLDEN_TOKEN}_{GOLDEN_PREFIX}", "DECIMAL(20,0)")
        assert package_b == expected

    def test_golden_file_hashes_pinned_independently(self):
        # The expected texts above were hashed once with shasum -a 256; the
        # packager output must match those independent digests too.
        package_a, package_b = _golden_package()
        assert hashlib.sha256(package_a.encode("utf-8")).hexdigest() == GOLDEN_A_SQL_SHA256
        assert hashlib.sha256(package_b.encode("utf-8")).hexdigest() == GOLDEN_B_SQL_SHA256

    def test_golden_set_block_alone(self):
        assert render_session_sql(_golden_preconditions()) == GOLDEN_SESSION_LINES

    def test_golden_case_id_header_is_pinned(self):
        package_a, _ = _golden_package()
        assert f"# case_id: {GOLDEN_CASE_ID}\n" in package_a


# --------------------------------------------------------------------------
# Statement order (design: independent golden check of the composition order)
# --------------------------------------------------------------------------


class TestStatementOrder:
    def _statement_kinds(self, package_sql: str) -> list[str]:
        kinds: list[str] = []
        for line in package_sql.splitlines():
            if line.startswith("#") or line.startswith("  "):
                continue
            if line.startswith("SET "):
                kinds.append("SET")
            elif line.startswith("CREATE DATABASE "):
                kinds.append("CREATE DATABASE")
            elif line.startswith("USE "):
                kinds.append("USE")
            elif line.startswith("CREATE TABLE "):
                kinds.append("CREATE TABLE")
            elif line.startswith("INSERT INTO "):
                kinds.append("INSERT")
            elif line.startswith("SELECT "):
                kinds.append("SELECT")
            else:
                kinds.append(f"UNEXPECTED:{line[:40]!r}")
        return kinds

    def test_order_matches_design(self):
        package_a, package_b = _golden_package()
        for package_sql, table in (
            (package_a, f"t_a_{GOLDEN_TOKEN}_{GOLDEN_PREFIX}"),
            (package_b, f"t_b_{GOLDEN_TOKEN}_{GOLDEN_PREFIX}"),
        ):
            assert self._statement_kinds(package_sql) == [
                "SET",
                "SET",
                "SET",
                "SET",
                "SET",
                "SET",
                "SET",
                "SET",
                "SET",
                "CREATE DATABASE",
                "USE",
                "CREATE TABLE",
                "INSERT",
                "SELECT",
            ]
            # The database created, the database used and the table touched agree.
            database = f"tc_{table[2:]}"
            assert f"CREATE DATABASE `{database}`;\nUSE `{database}`;\n" in package_sql
            assert package_sql.count(f"`{table}`") == 3
        # Every SQL statement line ends with exactly one semicolon; comment
        # lines and the CREATE TABLE first line (two-line DDL whose second
        # line carries the terminator) are the exceptions.
        for package_sql in (package_a, package_b):
            for line in package_sql.splitlines():
                if line.startswith("#") or line.startswith("CREATE TABLE "):
                    assert not line.endswith(";")
                elif line.startswith("  "):
                    assert line.endswith(";")
                else:
                    assert line.endswith(";")

    def test_d1_statements_are_verbatim(self):
        pair = _golden_pair()
        package_a, _ = _golden_package()
        for statement in pair.a:
            assert statement.text in package_a

    def test_file_ends_with_single_trailing_newline(self):
        package_a, package_b = _golden_package()
        for package_sql in (package_a, package_b):
            assert package_sql.endswith("\n")
            assert not package_sql.endswith("\n\n")


# --------------------------------------------------------------------------
# Injection resistance (design Phase 4: 恶意 session 值不能拼成第二条 SQL)
# --------------------------------------------------------------------------


class TestInjectionRejection:
    @pytest.mark.parametrize("hostile", [";", "'", "\\", "--", "\n", "\r", "\t", " "])
    @pytest.mark.parametrize(
        "field",
        ["character_set", "collation", "time_zone", "isolation_level", "optimizer_baseline"],
    )
    def test_hostile_values_rejected_at_validation(self, field, hostile):
        kwargs = {
            field: f"good{hostile}value"
            if field != "isolation_level"
            # "READ COMMITTED" itself contains a space; probe with a base
            # string that is never a whitelist member.
            else f"SERIALIZ{hostile}ABLE"
        }
        with pytest.raises(ContractError):
            SessionPreconditions(**kwargs)

    @pytest.mark.parametrize(
        "token",
        [
            "STRICT_ALL_TABLES;DROP TABLE t",
            "STRICT_ALL_TABLES'DROP",
            "STRICT_ALL_TABLES\\DROP",
            "STRICT_ALL_TABLES--DROP",
            "STRICT_ALL_TABLES\nDROP",
            "STRICT_ALL_TABLES DROP",
        ],
    )
    def test_hostile_sql_mode_token_rejected(self, token):
        with pytest.raises(ContractError):
            SessionPreconditions(sql_mode_tokens=(token,))

    def test_escaper_escapes_residual_quote_and_backslash(self):
        hostile = "x';DROP TABLE t;\\"
        literal = _sql_literal(hostile)
        # Exact hand-derived escaped form: backslash first, then the quote.
        assert literal == "'x\\';DROP TABLE t;\\\\'"
        # The literal opens and closes with quotes and no quote inside is bare.
        assert literal.startswith("'") and literal.endswith("'")
        inner = literal[1:-1]
        assert "\\'" in inner and "\\\\" in inner
        for index, char in enumerate(inner):
            if char == "'":
                assert index > 0 and inner[index - 1] == "\\"

    def test_escaper_keeps_hostile_value_inside_one_literal(self):
        literal = _sql_literal("SET x=1; DROP DATABASE y")
        assert literal == "'SET x=1; DROP DATABASE y'"
        # Even if it somehow reached a session statement, it is one quoted
        # value inside one SET statement, never a second statement.
        pre = SessionPreconditions(time_zone="+00:00")
        statements = render_session_sql(pre)
        assert len(statements) == 1 and statements[0] == "SET time_zone = '+00:00';"


# --------------------------------------------------------------------------
# No DROP / IF NOT EXISTS / force anywhere
# --------------------------------------------------------------------------


class TestBannedStatements:
    def test_no_banned_constructs_in_any_output(self):
        package_a, package_b = _golden_package()
        for package_sql in (package_a, package_b):
            lowered = package_sql.lower()
            assert "drop" not in lowered
            assert "if not exists" not in lowered
            assert "--force" not in lowered
            assert "if exists" not in lowered

    def test_create_database_has_no_if_not_exists(self):
        names = _golden_names()
        package_a, _ = _golden_package()
        assert f"CREATE DATABASE `{names.database_a}`;\n" in package_a


# --------------------------------------------------------------------------
# Name assignment: deterministic, token-sensitive, identity-stable
# --------------------------------------------------------------------------


class TestAssignNameMap:
    def test_reproducible_for_same_inputs(self):
        first = assign_name_map(GOLDEN_CASE_ID, GOLDEN_TOKEN)
        second = assign_name_map(GOLDEN_CASE_ID, GOLDEN_TOKEN)
        assert first == second

    def test_different_token_different_names(self):
        other = assign_name_map(GOLDEN_CASE_ID, "othertoken1")
        assert other.database_a != _golden_names().database_a
        assert other.database_b != _golden_names().database_b
        assert other.table_a != _golden_names().table_a
        assert other.table_b != _golden_names().table_b

    @pytest.mark.parametrize("token", ["GOLDENTOKEN0", "short", "with_underscore", "a" * 33, ""])
    def test_malformed_token_rejected(self, token):
        with pytest.raises(ContractError):
            assign_name_map(GOLDEN_CASE_ID, token)

    @pytest.mark.parametrize("case_id", ["", "xyz", GOLDEN_CASE_ID.upper(), GOLDEN_CASE_ID[:-1]])
    def test_malformed_case_id_rejected(self, case_id):
        with pytest.raises(ContractError):
            assign_name_map(case_id, GOLDEN_TOKEN)

    def test_names_are_legal_mysql_identifiers(self):
        names = assign_name_map(GOLDEN_CASE_ID, "a" * 32)
        for value in (names.database_a, names.database_b, names.table_a, names.table_b):
            assert 1 <= len(value) <= 64
            assert value[0].isalpha() and value == value.lower()
            assert all(char.isalnum() or char == "_" for char in value)

    def test_package_reproducible_and_token_only_changes_names(self):
        package_a1, package_b1 = _golden_package()
        package_a2, package_b2 = _golden_package()
        assert (package_a1, package_b1) == (package_a2, package_b2)

        other_pair = render_pair(
            _golden_payload(),
            NameMap(
                database_a=f"tc_a_othertoken1_{GOLDEN_PREFIX}",
                database_b=f"tc_b_othertoken1_{GOLDEN_PREFIX}",
                table_a=f"t_a_othertoken1_{GOLDEN_PREFIX}",
                table_b=f"t_b_othertoken1_{GOLDEN_PREFIX}",
            ),
        )
        package_a3, package_b3 = wrap_sql_package(
            other_pair, _golden_preconditions(), assign_name_map(GOLDEN_CASE_ID, "othertoken1")
        )
        # Same statement count; only the physical names differ.
        def statement_count(package_sql: str) -> int:
            return sum(
                1
                for line in package_sql.splitlines()
                if line.startswith(("SET ", "CREATE ", "USE ", "INSERT ", "SELECT "))
            )

        assert statement_count(package_a1) == statement_count(package_a3)
        assert statement_count(package_b1) == statement_count(package_b3)
        normalized_a1 = package_a1.replace(f"{GOLDEN_TOKEN}_{GOLDEN_PREFIX}", "NAMES")
        normalized_a3 = package_a3.replace(f"othertoken1_{GOLDEN_PREFIX}", "NAMES")
        assert normalized_a1 == normalized_a3

    def test_wrap_rejects_name_mismatch(self):
        pair = _golden_pair()
        wrong_names = assign_name_map(GOLDEN_CASE_ID, "othertoken1")
        with pytest.raises(ContractError):
            wrap_sql_package(pair, _golden_preconditions(), wrong_names)


# --------------------------------------------------------------------------
# SET rendering details: whitelist, optional fields, unknown fields never set
# --------------------------------------------------------------------------


class TestRenderSessionSql:
    def test_variable_names_are_within_the_fixed_whitelist(self):
        for statement in render_session_sql(_golden_preconditions()):
            variable = statement.split(" ", 2)[1]
            assert variable in SQL_VARIABLE_WHITELIST
        assert SQL_VARIABLE_WHITELIST == frozenset(
            {
                "sql_mode",
                "character_set_client",
                "character_set_results",
                "character_set_connection",
                "collation_connection",
                "collation_database",
                "collation_server",
                "time_zone",
                "transaction_isolation",
                "optimizer_switch",
            }
        )

    def test_empty_preconditions_render_nothing(self):
        assert render_session_sql(SessionPreconditions()) == ()

    def test_optimizer_switch_only_when_baseline_provided(self):
        without = render_session_sql(SessionPreconditions(time_zone="+00:00"))
        assert all("optimizer_switch" not in text for text in without)
        with_baseline = render_session_sql(
            SessionPreconditions(
                time_zone="+00:00", optimizer_baseline="index_merge=on,mrr=off"
            )
        )
        assert with_baseline[-1] == "SET optimizer_switch = 'index_merge=on,mrr=off';"

    def test_optional_fields_render_only_their_statements(self):
        statements = render_session_sql(SessionPreconditions(sql_mode_tokens=()))
        assert statements == ()
        only_charset = render_session_sql(SessionPreconditions(character_set="utf8mb4"))
        assert only_charset == (
            "SET character_set_client = 'utf8mb4';",
            "SET character_set_results = 'utf8mb4';",
            "SET character_set_connection = 'utf8mb4';",
        )

    def test_named_time_zone_accepted(self):
        statements = render_session_sql(SessionPreconditions(time_zone="Asia/Shanghai"))
        assert statements == ("SET time_zone = 'Asia/Shanghai';",)

    def test_isolation_whitelist(self):
        assert render_session_sql(
            SessionPreconditions(isolation_level="READ COMMITTED")
        ) == ("SET transaction_isolation = 'READ COMMITTED';",)
        for bad in ("READ-WRITTEN", "read committed", "SERIALIZABLE;DROP", ""):
            with pytest.raises(ContractError):
                SessionPreconditions(isolation_level=bad)

    def test_unknown_fields_note_never_rendered_into_sql(self):
        pre = SessionPreconditions(unknown_fields_note=("some server was patched",))
        assert render_session_sql(pre) == ()


# --------------------------------------------------------------------------
# Environment requirements document
# --------------------------------------------------------------------------


class TestEnvironmentRequirementsDocument:
    def test_generation_only_marks_baseline_unknown(self):
        doc = environment_requirements_document(_golden_payload())
        assert doc.optimizer_baseline == OPTIMIZER_BASELINE_UNKNOWN
        assert doc.database == "mysql80"
        assert doc.engine == "innodb"
        assert doc.scope == "same-instance"
        assert doc.sql_mode_tokens == REQUIRED_SQL_MODE_TOKENS
        assert doc.character_set == "utf8mb4"
        assert doc.collation == "utf8mb4_bin"
        assert doc.time_zone == "+00:00"
        # The README note exists for the builder and mentions the UNKNOWN state.
        assert OPTIMIZER_BASELINE_UNKNOWN in OPTIMIZER_BASELINE_UNKNOWN_NOTE

    def test_observed_environment_supplies_real_baseline(self):
        observed = ObservedEnvironment(
            instance_identity="inst-1",
            version="8.0.36",
            vendor="MySQL",
            build_id="b1",
            engine="InnoDB",
            sql_mode_tokens=("ONLY_FULL_GROUP_BY", "STRICT_TRANS_TABLES"),
            character_set="utf8mb4",
            collation="utf8mb4_bin",
            time_zone="+00:00",
            optimizer_switch="index_merge=on,mrr=off",
        )
        doc = environment_requirements_document_with_observed(
            _golden_payload().environment, observed
        )
        assert doc.optimizer_baseline == "index_merge=on,mrr=off"
        assert doc.character_set == "utf8mb4"

    def test_serialize_and_round_trip_decode(self):
        doc = environment_requirements_document(_golden_payload())
        decoded = decode_environment_requirements_document(doc.to_obj())
        assert decoded == doc
        observed = ObservedEnvironment(
            instance_identity="i",
            version="8.0.36",
            vendor="MySQL",
            build_id="b",
            engine="InnoDB",
            sql_mode_tokens=("STRICT_ALL_TABLES",),
            character_set="utf8mb4",
            collation="utf8mb4_bin",
            time_zone="+00:00",
            optimizer_switch="mrr=on",
        )
        doc2 = environment_requirements_document_with_observed(
            _golden_payload().environment, observed
        )
        assert decode_environment_requirements_document(doc2.to_obj()) == doc2

    def test_decode_rejects_unknown_or_missing_keys(self):
        doc = environment_requirements_document(_golden_payload())
        obj = dict(doc.to_obj())
        obj.pop("optimizer_baseline")
        with pytest.raises(ContractError):
            decode_environment_requirements_document(obj)
        obj2 = dict(doc.to_obj())
        obj2["extra"] = 1
        with pytest.raises(ContractError):
            decode_environment_requirements_document(obj2)

    def test_unsafe_values_refuse_export(self):
        for field, value in (
            ("character_set", "utf8mb4;DROP"),
            ("collation", "utf8mb4'bin"),
            ("time_zone", "+00:00;DROP"),
            ("optimizer_baseline", "index_merge=on;DROP"),
        ):
            kwargs = {
                "database": "mysql80",
                "engine": "innodb",
                "scope": "same-instance",
                "sql_mode_tokens": REQUIRED_SQL_MODE_TOKENS,
                "character_set": "utf8mb4",
                "collation": "utf8mb4_bin",
                "time_zone": "+00:00",
                "optimizer_baseline": OPTIMIZER_BASELINE_UNKNOWN,
            }
            kwargs[field] = value
            with pytest.raises(ContractError):
                EnvironmentRequirementsDoc(**kwargs)
