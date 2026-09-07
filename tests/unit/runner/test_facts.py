"""Unit tests for runner.facts (D3 Phase 4) -- pure helpers, no server.

Every expected value here is computed independently of the code under test:
the environment snapshot is compared against ``runner.preflight`` (the frozen
mapping source of truth) and against the hand-written builder in
``execution_fakes``; content hashes are recomputed with the D1 frozen
``generation.validation`` helpers; decoded rows and normalized table specs
are written out literally.  Nothing derives an expectation by calling the
function under test twice with the same arguments except where hash
stability across identical snapshots is itself the property under test.
"""

from __future__ import annotations

from typing import Mapping, Optional

import pytest

from execution_fakes import (
    BUILD_ID,
    DEFAULT_FACTS,
    SERVER_UUID,
    environment_from_facts,
    make_payload,
)

from mtsql_typecheck.contracts.case import (
    CheckStatus,
    ColumnSpec,
    ContractError,
    DecimalType,
    DecimalValue,
    ExpectedBinding,
    IndexVariant,
    IntegerValue,
    NameMap,
    NullValue,
    Row,
    SignedIntName,
    SignedIntegerType,
    TableSpec,
)
from mtsql_typecheck.contracts.codec import sha256_hex
from mtsql_typecheck.contracts.execution import default_control
from mtsql_typecheck.contracts.runner import (
    RUNNER_ADAPTER_ID,
    BuildIdSource,
    TlsConfig,
    TlsMode,
    TargetConfig,
)
from mtsql_typecheck.generation.validation import (
    environment_content_hash,
    name_map_content_hash,
)
from mtsql_typecheck.runner.facts import (
    FACTS_IDENTITY,
    FactCollectionError,
    attempt_fact_summary,
    content_hash_of_bytes,
    decode_readback_rows,
    normalize_side_schema,
    observed_environment_from_facts,
    rejected_requirement_id,
)
from mtsql_typecheck.runner.preflight import ProbeRuntimeIdentity, run_preflight


# --------------------------------------------------------------------------
# Shared builders
# --------------------------------------------------------------------------


def target_config() -> TargetConfig:
    return TargetConfig(
        adapter=RUNNER_ADAPTER_ID,
        host="mysql-test.example.internal",
        port=3306,
        unix_socket=None,
        user="typecheck",
        password_env="TYPECHECK_TEST_PASSWORD_ENV",
        expected_server_uuid=SERVER_UUID,
        build_id=BUILD_ID,
        database_prefix="tc_",
        dedicated_test_instance=True,
        tls=TlsConfig(TlsMode.DISABLED, None),
    )


IDENTITY = ProbeRuntimeIdentity(
    python_version="3.11.9",
    os_platform="Linux-6.1.0-x86_64",
    driver_name="pymysql",
    driver_version="1.1.2",
    adapter_version="mysql80-adapter-v1",
    mapping_version="mysql80-pymysql112-exact-v1",
)


class FakeProbeSource:
    """Minimal EnvironmentProbeSource: canned facts, no server."""

    def __init__(
        self,
        facts: Mapping[str, str],
        *,
        identity: ProbeRuntimeIdentity = IDENTITY,
        build_id: Optional[str] = None,
    ) -> None:
        self.facts = dict(facts)
        self._identity = identity
        self._build_id = build_id

    def fetch_environment_facts(self) -> Mapping[str, str]:
        return dict(self.facts)

    def runtime_identity(self) -> ProbeRuntimeIdentity:
        return self._identity

    def observed_build_id(self) -> Optional[str]:
        return self._build_id


def int_type() -> SignedIntegerType:
    return SignedIntegerType(SignedIntName.TINYINT)


def decimal_type() -> DecimalType:
    return DecimalType(9, 2)


def fact_summary_binding() -> ExpectedBinding:
    return ExpectedBinding(
        run_id="run-1",
        case_id="a" * 64,
        attempt_id="attempt-1",
        environment_hash="b" * 64,
        name_map_hash="c" * 64,
    )


def fact_summary_name_map() -> NameMap:
    return NameMap(
        database_a="tc_r1_attempt1_a",
        database_b="tc_r1_attempt1_b",
        table_a="case_a",
        table_b="case_b",
    )


# --------------------------------------------------------------------------
# observed_environment_from_facts
# --------------------------------------------------------------------------


class TestObservedEnvironmentFromFacts:
    def test_matches_the_frozen_preflight_mapping(self):
        manifest = run_preflight(
            target_config(), FakeProbeSource(DEFAULT_FACTS), default_control()
        )
        assert manifest.build_id_source is BuildIdSource.CONFIGURED
        assert (
            observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
            == manifest.observed_environment
        )

    def test_matches_the_independent_fakes_builder(self):
        assert observed_environment_from_facts(
            DEFAULT_FACTS, build_id=BUILD_ID
        ) == environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)

    def test_snapshot_fields_come_from_the_declared_facts(self):
        observed = observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        assert observed.instance_identity == str(SERVER_UUID).lower()
        assert observed.version == "8.0.39"
        assert observed.vendor == "mysql"
        assert observed.build_id == BUILD_ID
        assert observed.engine == "innodb"
        assert observed.sql_mode_tokens == (
            "NO_ENGINE_SUBSTITUTION",
            "ONLY_FULL_GROUP_BY",
            "STRICT_ALL_TABLES",
        )
        assert observed.character_set == "utf8mb4"
        assert observed.collation == "utf8mb4_bin"
        assert observed.time_zone == "+00:00"
        assert observed.optimizer_switch == "index_merge=on,mrr=off"

    def test_hash_is_stable_across_identical_snapshots(self):
        first = observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        second = observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        assert environment_content_hash(first) == environment_content_hash(second)

    def test_hash_changes_when_a_fact_changes(self):
        drifted = dict(DEFAULT_FACTS, optimizer_switch="index_merge=off,mrr=on")
        assert environment_content_hash(
            observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        ) != environment_content_hash(
            observed_environment_from_facts(drifted, build_id=BUILD_ID)
        )

    def test_missing_optional_facts_become_empty_strings(self):
        minimal = {
            "server_uuid": SERVER_UUID,
            "sql_mode": "STRICT_ALL_TABLES",
        }
        observed = observed_environment_from_facts(minimal, build_id=BUILD_ID)
        assert observed.version == ""
        assert observed.vendor == ""
        assert observed.engine == ""
        assert observed.character_set == ""
        assert observed.collation == ""
        assert observed.time_zone == ""
        assert observed.optimizer_switch == ""
        assert observed.sql_mode_tokens == ("STRICT_ALL_TABLES",)

    def test_sql_mode_token_order_is_normalized(self):
        reordered = dict(
            DEFAULT_FACTS,
            sql_mode="STRICT_ALL_TABLES,NO_ENGINE_SUBSTITUTION,ONLY_FULL_GROUP_BY",
        )
        assert observed_environment_from_facts(
            reordered, build_id=BUILD_ID
        ).sql_mode_tokens == observed_environment_from_facts(
            DEFAULT_FACTS, build_id=BUILD_ID
        ).sql_mode_tokens

    def test_fail_closed_on_unusable_server_uuid(self):
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts(
                dict(DEFAULT_FACTS, server_uuid="not-a-uuid"), build_id=BUILD_ID
            )
        missing = dict(DEFAULT_FACTS)
        del missing["server_uuid"]
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts(missing, build_id=BUILD_ID)

    def test_fail_closed_on_empty_sql_mode(self):
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts(
                dict(DEFAULT_FACTS, sql_mode=""), build_id=BUILD_ID
            )

    def test_fail_closed_on_non_string_fact_pairs(self):
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts(
                dict(DEFAULT_FACTS, version=8.039), build_id=BUILD_ID
            )
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts(
                {1: "x", **DEFAULT_FACTS}, build_id=BUILD_ID
            )

    def test_fail_closed_on_non_mapping_facts(self):
        with pytest.raises(FactCollectionError):
            observed_environment_from_facts([("server_uuid", SERVER_UUID)], build_id=BUILD_ID)


# --------------------------------------------------------------------------
# rejected_requirement_id
# --------------------------------------------------------------------------


class TestRejectedRequirementId:
    def setup_method(self):
        self.payload = make_payload(row_values=(IntegerValue(1),))

    def observed(self, **overrides) -> object:
        return observed_environment_from_facts(
            dict(DEFAULT_FACTS, **overrides), build_id=BUILD_ID
        )

    def test_clean_snapshot_proves_nothing(self):
        assert rejected_requirement_id(self.payload, self.observed()) is None

    def test_wrong_version_series_is_proven_by_the_snapshot(self):
        assert (
            rejected_requirement_id(self.payload, self.observed(version="5.7.44"))
            == "environment.version_series"
        )

    def test_mariadb_vendor_is_proven_by_the_snapshot(self):
        assert (
            rejected_requirement_id(
                self.payload,
                self.observed(version="10.11.6-MariaDB", version_comment="MariaDB"),
            )
            == "environment.version_series"
        )

    def test_missing_engine_is_proven_by_the_snapshot(self):
        facts = dict(DEFAULT_FACTS)
        del facts["innodb_version"]
        observed = observed_environment_from_facts(facts, build_id=BUILD_ID)
        assert rejected_requirement_id(self.payload, observed) == "environment.innodb"

    def test_empty_optimizer_switch_is_drift_not_proof(self):
        # An empty snapshot is PENDING (not evaluable), so no structured
        # rejection can be proven from it -- the caller records drift instead.
        facts = dict(DEFAULT_FACTS)
        del facts["optimizer_switch"]
        observed = observed_environment_from_facts(facts, build_id=BUILD_ID)
        assert rejected_requirement_id(self.payload, observed) is None

    def test_optimizer_switch_text_change_is_drift_not_proof(self):
        assert (
            rejected_requirement_id(
                self.payload, self.observed(optimizer_switch="index_merge=off,mrr=on")
            )
            is None
        )

    def test_non_payload_argument_is_refused(self):
        with pytest.raises(FactCollectionError):
            rejected_requirement_id("not a payload", self.observed())
        with pytest.raises(FactCollectionError):
            rejected_requirement_id(self.payload, "not an environment")


# --------------------------------------------------------------------------
# decode_readback_rows
# --------------------------------------------------------------------------


class TestDecodeReadbackRows:
    def test_integer_cells_decode_exactly(self):
        rows = decode_readback_rows(
            [
                (b"1", b"1"),
                (b"2", None),
                (b"3", b"-5"),
            ],
            declared_type=int_type(),
        )
        assert rows == (
            Row(1, IntegerValue(1)),
            Row(2, NullValue()),
            Row(3, IntegerValue(-5)),
        )

    def test_decimal_cells_keep_coefficient_and_server_scale(self):
        rows = decode_readback_rows(
            [
                (b"1", b"12.30"),
                (b"2", b"-0.01"),
                (b"3", b"5"),
                (b"4", None),
            ],
            declared_type=decimal_type(),
        )
        assert rows == (
            Row(1, DecimalValue(1230, 2)),
            Row(2, DecimalValue(-1, 2)),
            Row(3, DecimalValue(5, 0)),
            Row(4, NullValue()),
        )

    def test_trailing_zero_is_preserved_not_normalized(self):
        rows = decode_readback_rows([(b"1", b"1.50")], declared_type=decimal_type())
        assert rows == (Row(1, DecimalValue(150, 2)),)
        assert rows[0].value != DecimalValue(15, 1)

    def test_str_cells_are_accepted(self):
        rows = decode_readback_rows([("1", "7")], declared_type=int_type())
        assert rows == (Row(1, IntegerValue(7)),)

    def test_fail_closed_on_non_canonical_integer_text(self):
        for bad in ("01", "+1", "-0", "1.0", "1e5", ""):
            with pytest.raises(FactCollectionError):
                decode_readback_rows([(b"1", bad.encode())], declared_type=int_type())

    def test_fail_closed_on_non_decimal_text(self):
        # Leading zeros in the integer part are server-canonical ("0.01"),
        # so they are accepted; anything else outside fixed-point text is not.
        for bad in ("1.0e5", "+1.5", "", ".5", "1.", "1,5"):
            with pytest.raises(FactCollectionError):
                decode_readback_rows(
                    [(b"1", bad.encode())], declared_type=decimal_type()
                )

    def test_fail_closed_on_non_canonical_rid(self):
        for bad in ("01", "+1", "1.0", ""):
            with pytest.raises(FactCollectionError):
                decode_readback_rows(
                    [(bad.encode(), b"1")], declared_type=int_type()
                )
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(None, b"1")], declared_type=int_type())

    def test_rid_out_of_domain_raises_the_row_contract_error(self):
        # Canonical text ("-1", "0") that leaves the [1, 2^63-1] rid domain is
        # rejected by the Row contract, not silently coerced.
        for bad in ("-1", "0"):
            with pytest.raises(ContractError):
                decode_readback_rows(
                    [(bad.encode(), b"1")], declared_type=int_type()
                )

    def test_fail_closed_on_wrong_cell_count(self):
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(b"1", b"1", b"extra")], declared_type=int_type())
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(b"1",)], declared_type=int_type())

    def test_fail_closed_on_non_text_cells(self):
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(1, b"1")], declared_type=int_type())
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(b"1", 1.5)], declared_type=decimal_type())

    def test_fail_closed_on_invalid_utf8(self):
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(b"1", b"\xff\xfe")], declared_type=int_type())

    def test_fail_closed_on_unsupported_declared_type(self):
        with pytest.raises(FactCollectionError):
            decode_readback_rows([(b"1", b"1")], declared_type="not a type")


# --------------------------------------------------------------------------
# normalize_side_schema
# --------------------------------------------------------------------------


def base_tables_rows(table: bytes = b"case_a"):
    return ((table, b"BASE TABLE", b"InnoDB"),)


def base_columns_rows(v_type: bytes):
    return (
        (b"rid", b"bigint", b"NO", b"PRI", b"1"),
        (b"v", v_type, b"YES", b"", b"2"),
    )


class TestNormalizeSideSchema:
    def test_plain_variant_normalizes_to_the_declared_spec(self):
        spec = normalize_side_schema(
            tables_rows=base_tables_rows(),
            columns_rows=base_columns_rows(b"tinyint"),
            statistics_rows=(),
            declared_table="case_a",
            declared_type=int_type(),
            index_variant=IndexVariant.NONE,
        )
        assert spec == TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", int_type(), True),
            ),
            ("rid",),
            IndexVariant.NONE,
        )

    def test_indexed_decimal_variant_normalizes_to_the_declared_spec(self):
        spec = normalize_side_schema(
            tables_rows=base_tables_rows(b"case_b"),
            columns_rows=base_columns_rows(b"decimal(9,2)"),
            statistics_rows=((b"ix_v", b"1", b"v"),),
            declared_table="case_b",
            declared_type=decimal_type(),
            index_variant=IndexVariant.IX_V,
        )
        assert spec == TableSpec(
            "t0",
            (
                ColumnSpec("rid", SignedIntegerType(SignedIntName.BIGINT), False),
                ColumnSpec("v", decimal_type(), True),
            ),
            ("rid",),
            IndexVariant.IX_V,
        )

    def test_engine_and_table_type_matching_is_case_insensitive(self):
        spec = normalize_side_schema(
            tables_rows=((b"case_a", b"base table", b"INNODB"),),
            columns_rows=base_columns_rows(b"tinyint"),
            statistics_rows=(),
            declared_table="case_a",
            declared_type=int_type(),
            index_variant=IndexVariant.NONE,
        )
        assert spec.index_variant is IndexVariant.NONE

    def test_fail_closed_on_two_tables(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows() + ((b"other", b"BASE TABLE", b"InnoDB"),),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_wrong_table_name(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(b"case_b"),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_non_base_table(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=((b"case_a", b"VIEW", b"InnoDB"),),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_wrong_engine(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=((b"case_a", b"BASE TABLE", b"MyISAM"),),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_column_mismatch(self):
        # Declared TINYINT must read back as "tinyint" exactly; a drifted
        # column type is a schema mismatch, never a coerced fact.
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"smallint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_extra_or_missing_column(self):
        wide = base_columns_rows(b"tinyint") + ((b"w", b"int", b"YES", b"", b"3"),)
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=wide,
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"tinyint")[:1],
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_missing_primary_key_mark(self):
        rows = (
            (b"rid", b"bigint", b"NO", b"", b"1"),
            (b"v", b"tinyint", b"YES", b"", b"2"),
        )
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=rows,
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_unexpected_index_for_plain_variant(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=((b"ix_v", b"1", b"v"),),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )

    def test_fail_closed_on_missing_or_wrong_index_for_indexed_variant(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.IX_V,
            )
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=((b"ix_other", b"1", b"v"),),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.IX_V,
            )
        # A UNIQUE index is not the declared NON_UNIQUE secondary index.
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=base_tables_rows(),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=((b"ix_v", b"0", b"v"),),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.IX_V,
            )

    def test_fail_closed_on_null_probe_cells(self):
        with pytest.raises(FactCollectionError):
            normalize_side_schema(
                tables_rows=((b"case_a", None, b"InnoDB"),),
                columns_rows=base_columns_rows(b"tinyint"),
                statistics_rows=(),
                declared_table="case_a",
                declared_type=int_type(),
                index_variant=IndexVariant.NONE,
            )


# --------------------------------------------------------------------------
# attempt_fact_summary / content_hash_of_bytes / FACTS_IDENTITY
# --------------------------------------------------------------------------


class TestAttemptFactSummary:
    def test_summary_uses_the_frozen_hash_helpers(self):
        binding = fact_summary_binding()
        name_map = fact_summary_name_map()
        observed = observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        assert attempt_fact_summary(
            binding=binding, name_map=name_map, observed_environment=observed
        ) == {
            "run_id": "run-1",
            "case_id": "a" * 64,
            "attempt_id": "attempt-1",
            "environment_hash": "b" * 64,
            "observed_environment_hash": environment_content_hash(observed),
            "name_map_hash": name_map_content_hash(name_map),
        }

    def test_absent_observed_environment_is_visible_not_papered_over(self):
        summary = attempt_fact_summary(
            binding=fact_summary_binding(),
            name_map=fact_summary_name_map(),
            observed_environment=None,
        )
        assert summary["observed_environment_hash"] == ""
        assert summary["environment_hash"] == "b" * 64

    def test_fail_closed_on_wrong_argument_types(self):
        observed = observed_environment_from_facts(DEFAULT_FACTS, build_id=BUILD_ID)
        with pytest.raises(FactCollectionError):
            attempt_fact_summary(
                binding="not a binding",
                name_map=fact_summary_name_map(),
                observed_environment=observed,
            )
        with pytest.raises(FactCollectionError):
            attempt_fact_summary(
                binding=fact_summary_binding(),
                name_map="not a name map",
                observed_environment=observed,
            )


class TestModuleIdentity:
    def test_facts_identity_is_a_stable_non_empty_string(self):
        assert FACTS_IDENTITY == "runner-execution-facts-v1"

    def test_content_hash_of_bytes_is_sha256_hex(self):
        assert content_hash_of_bytes(b"payload bytes") == sha256_hex(b"payload bytes")

    def test_fact_collection_error_is_a_contract_error(self):
        assert issubclass(FactCollectionError, ContractError)


# CheckStatus is used only to document the vocabulary shared with validation;
# keep the import honest by asserting the frozen member this module relies on.
def test_check_status_vocabulary_is_frozen():
    assert {member.value for member in CheckStatus} >= {"SATISFIED", "VIOLATED", "PENDING"}
