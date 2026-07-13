"""
    Tests for reflected-XSS detection and canary payload construction.
"""
from fuzzer.fuzzers import detection
from fuzzer.core import utility

TOKEN = "xq7z9"

def test_xss_detected_in_script_context():
    body = f'<script>var t = "{TOKEN}"; window.__xss_canary__="{TOKEN}"</script>'
    found, ctx = detection.detectXSS(body, TOKEN)
    assert found
    assert ctx == "script_ctx"


def test_xss_not_flagged_when_token_absent():
    found, ctx = detection.detectXSS("<p>nothing to see</p>", TOKEN)
    assert not found
    assert ctx is None


def test_xss_not_flagged_for_escaped_reflection():
    # Token only appears HTML-escaped in text, not in an executable context
    body = f"<p>you searched for &lt;script&gt;{TOKEN}&lt;/script&gt;</p>"
    found, _ = detection.detectXSS(body, TOKEN)
    assert not found


def test_xss_handles_empty_body():
    found, _ = detection.detectXSS("", TOKEN)
    assert not found


def test_canary_injects_into_script_block():
    out = utility.canary("<script>alert(1)</script>", TOKEN)
    assert "__XSS_CANARY__" in out
    assert TOKEN in out
    assert out.lower().startswith("<script")


def test_canary_injects_into_javascript_uri():
    out = utility.canary("javascript:alert(1)", TOKEN)
    assert "__XSS_CANARY__" in out
    assert TOKEN in out

def test_canary_roundtrips_through_detector():
    # A canary payload should be recognised by the XSS detector when reflected raw.
    payload = utility.canary("<script>alert(1)</script>", TOKEN)
    found, ctx = detection.detectXSS(payload, TOKEN)
    assert found
    assert ctx == "script_ctx"