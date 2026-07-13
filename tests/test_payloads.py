"""
    Tests for the SQLi payload helpers in core.utility
"""
from fuzzer.core import utility


def test_blind_payload_detects_time_functions():
    assert utility.isBlindPayload("1 AND SLEEP(5)")
    assert utility.isBlindPayload("'; WAITFOR DELAY '0:0:5'--")
    assert utility.isBlindPayload("1 OR pg_sleep(5)")


def test_blind_payload_ignores_error_based():
    assert not utility.isBlindPayload("' OR 1=1--")
    assert not utility.isBlindPayload("' UNION SELECT NULL--")


def test_blind_payload_handles_empty_and_none():
    assert not utility.isBlindPayload("")
    assert not utility.isBlindPayload(None)


def test_expand_time_token_substitutes_seconds():
    assert utility.expandTimeToken("SLEEP(__TIME__)", 9) == "SLEEP(9)"


def test_expand_time_token_leaves_untemplated_payload_untouched():
    assert utility.expandTimeToken("SLEEP(5)", 9) == "SLEEP(5)"


def test_expand_time_token_handles_none():
    assert utility.expandTimeToken(None, 5) == ""


def test_boolean_payloads_are_paired_and_non_empty():
    pairs = utility.buildBooleanPayloads()
    assert pairs, "expected at least one true/false pair"
    for true_payload, false_payload in pairs:
        assert true_payload != false_payload
        assert "--" in true_payload or "#" in true_payload