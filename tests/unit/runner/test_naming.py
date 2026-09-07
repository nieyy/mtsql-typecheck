"""Naming tests (D3 design 6.2.3): token generation, tc_ name grammar, and
the exactly-48-char boundary.  Expectations are hand-built here; the
validator under test is never used to construct its own expected values.
"""

from __future__ import annotations

import pytest

from mtsql_typecheck.runner.naming import (
    ATTEMPT_TOKEN_HEX_CHARS,
    DATABASE_NAME_MAX_CHARS,
    RUN_TOKEN_HEX_CHARS,
    attempt_database_names,
    default_token_source,
    is_valid_database_name,
    marker_table_name,
    new_attempt_token,
    new_run_token,
    validate_database_name,
    validate_marker_table_name,
    validate_token,
    NamingError,
)


class TestTokens:
    def test_defaults_are_lowercase_hex_of_fixed_length(self):
        run = new_run_token()
        attempt = new_attempt_token()
        assert len(run) == RUN_TOKEN_HEX_CHARS == 16
        assert len(attempt) == ATTEMPT_TOKEN_HEX_CHARS == 16
        for token in (run, attempt):
            assert token == token.lower()
            assert all(c in "0123456789abcdef" for c in token)

    def test_injectable_source_is_used_and_validated(self):
        pinned = "ab" * 8
        assert new_run_token(lambda: pinned) == pinned
        assert new_attempt_token(lambda: pinned) == pinned

    def test_source_output_length_is_enforced(self):
        with pytest.raises(NamingError):
            new_run_token(lambda: "ab" * 7)  # too short
        with pytest.raises(NamingError):
            new_attempt_token(lambda: "ab" * 9)  # too long

    def test_two_draws_differ(self):
        assert default_token_source() != default_token_source()

    def test_validate_token_rejects_non_hex_and_bad_length(self):
        for bad in ("ABCDEFGH", "abcdefgh ", "0x12345", "", "zzzzzzzz", "0" * 7, "0" * 25):
            with pytest.raises(NamingError):
                validate_token(bad, "token")
        with pytest.raises(NamingError):
            validate_token(12345678, "token")


class TestAttemptDatabaseNames:
    def test_names_follow_the_frozen_pattern(self):
        a, b = attempt_database_names("ab" * 8, "cd" * 8)
        assert a == f"tc_{'ab' * 8}_{'cd' * 8}_a"
        assert b == f"tc_{'ab' * 8}_{'cd' * 8}_b"
        assert len(a) == 38

    def test_names_are_within_the_d1_limit(self):
        a, b = attempt_database_names("01" * 8, "23" * 8)
        assert len(a) <= DATABASE_NAME_MAX_CHARS == 48
        assert len(b) <= DATABASE_NAME_MAX_CHARS

    def test_repeated_calls_with_the_same_tokens_are_stable(self):
        first = attempt_database_names("11" * 8, "22" * 8)
        second = attempt_database_names("11" * 8, "22" * 8)
        assert first == second

    def test_bad_tokens_are_refused(self):
        with pytest.raises(NamingError):
            attempt_database_names("ZZ" * 8, "22" * 8)
        with pytest.raises(NamingError):
            attempt_database_names("11" * 8, "33" * 7)


class TestValidator:
    def test_generated_names_round_trip(self):
        a, b = attempt_database_names("aa" * 8, "bb" * 8)
        assert validate_database_name(a) == a
        assert validate_database_name(b) == b
        assert is_valid_database_name(a) and is_valid_database_name(b)

    def test_exactly_48_chars_is_accepted(self):
        # tc_ (3) + 21 + _ + 21 + _a (2) = 48
        run_token = "a" * 21
        attempt_token = "b" * 21
        name = f"tc_{run_token}_{attempt_token}_a"
        assert len(name) == 48
        assert validate_database_name(name) == name

    def test_over_48_chars_is_rejected(self):
        name = "tc_" + "a" * 22 + "_" + "b" * 22 + "_a"
        assert len(name) == 50
        with pytest.raises(NamingError):
            validate_database_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "not_tc_a1b2c3d4_12345678_a",
            "TC_aaaaaaaa_bbbbbbbb_a",  # wrong prefix case
            "tc_AAAAAAAA_bbbbbbbb_a",  # uppercase run token
            "tc_aaaaaaaa_bbbbbbbb_c",  # wrong side suffix
            "tc_aaaaaaaa_bbbbbbbb",  # missing suffix
            "tc_aaaaaaa_bbbbbbbb_a",  # run token too short (7)
            "tc_aaaaaaaaaaaaaaaaaaaaaaaa1_bbbbbbbb_a",  # run token too long (25)
            "tc_aaaaaaaa_bbbbbbbb_a ",  # trailing space
            "tc_aaaaaaaa_bbbbbbbb_a;DROP DATABASE x",  # injection-shaped
            "tc_aaaaaaaa_bbbbbbbb_a\x00",
        ],
    )
    def test_malformed_names_are_rejected(self, name):
        with pytest.raises(NamingError):
            validate_database_name(name)
        assert not is_valid_database_name(name)

    def test_run_token_binding_is_enforced(self):
        a, _ = attempt_database_names("aa" * 8, "bb" * 8)
        assert validate_database_name(a, run_token="aa" * 8) == a
        with pytest.raises(NamingError):
            validate_database_name(a, run_token="cc" * 8)


class TestMarkerTable:
    def test_marker_name_is_fixed_and_validated(self):
        assert marker_table_name() == "tc_ownership_marker"
        assert validate_marker_table_name("tc_ownership_marker") == "tc_ownership_marker"

    @pytest.mark.parametrize("name", ["case_a", "tc_marker", "OWNERSHIP", ""])
    def test_wrong_marker_names_are_rejected(self, name):
        with pytest.raises(NamingError):
            validate_marker_table_name(name)
