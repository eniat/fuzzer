"""
    Tests for SQL error-signature and blind-timing detection
"""
from fuzzer.fuzzers import detection


def test_sql_error_matches_known_signature():
    found, sig = detection.detectSQLError(
        "Warning: you have an error in your SQL syntax near line 1"
    )
    assert found
    assert sig


def test_sql_error_is_case_insensitive():
    found, _ = detection.detectSQLError("YOU HAVE AN ERROR IN YOUR SQL SYNTAX")
    assert found


def test_sql_error_ignores_clean_response():
    found, sig = detection.detectSQLError("<html>everything is fine</html>")
    assert not found
    assert sig is None


def test_sql_error_handles_empty_body():
    found, _ = detection.detectSQLError("")
    assert not found


def test_blind_timing_flags_slow_response():
    # Well over both the 2x factor and the 700ms threshold
    assert detection.detectSQLiBlind(baseMs=100, testMs=1200)


def test_blind_timing_ignores_fast_response():
    assert not detection.detectSQLiBlind(baseMs=100, testMs=150)


def test_blind_timing_requires_both_factor_and_threshold():
    # 2x the baseline, but the absolute delta is far below 700ms.
    assert not detection.detectSQLiBlind(baseMs=50, testMs=110)


def test_blind_timing_respects_custom_arguments():
    assert detection.detectSQLiBlind(baseMs=100, testMs=250, thresholdMs=100, factor=2.0)
    assert not detection.detectSQLiBlind(baseMs=100, testMs=250, thresholdMs=100, factor=3.0)