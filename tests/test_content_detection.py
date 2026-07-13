"""
    Tests for content-difference SQLi and path-traversal detection

    detectPathTraversal only touches ``.text`` and ``.status_code`` on the
    response, so a tiny stand-in avoids any real HTTP dependency
"""
from fuzzer.fuzzers import detection


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

BASE = "<html><body><p>welcome</p></body></html>"


def test_sqli_diff_flags_large_content_growth():
    injected = BASE + "<pre>dumped</pre>" * 3 + "x" * 300
    assert detection.detectSQLiDiff(BASE, injected, payload=None)

def test_sqli_diff_ignores_identical_pages():
    assert not detection.detectSQLiDiff(BASE, BASE, payload=None)


def test_sqli_diff_boolean_success_failure_divergence():
    # True page shows a success marker, false page shows a failure marker
    assert detection.detectSQLiDiff(
        "your login failed", "welcome back user", isNotSQLIBlind=False
    )


def test_path_traversal_flags_passwd_indicator():
    resp = FakeResponse("root:x:0:0:root:/root:/bin/bash")
    verdict, indicator = detection.detectPathTraversal(resp)
    assert verdict == "vulnerable"
    assert indicator


def test_path_traversal_reports_none_on_clean_404():
    resp = FakeResponse("not found", status_code=404)
    verdict, _ = detection.detectPathTraversal(resp)
    assert verdict == "none"

def test_path_traversal_skips_response_matching_baseline():
    resp = FakeResponse("identical page body", status_code=200)
    baseline = {"content": "identical page body", "status_code": 200}
    verdict, _ = detection.detectPathTraversal(resp, baseline=baseline)
    assert verdict == "skip_similar"