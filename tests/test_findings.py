"""
    Tests for finding de-duplication and report serialisation.
"""
from fuzzer.core import utility
from fuzzer.core.reporting import Finding


def _finding(**overrides):
    base = dict(
        type="xss",
        url="http://target/search",
        method="GET",
        param="q",
        indicator="reflected",
        payload="<script>1</script>"
    )
    base.update(overrides)
    return Finding(**base)


def test_collapse_merges_findings_on_same_page():
    findings = [_finding(payload="p1"), _finding(payload="p2")]
    collapsed = utility.collapseDuplicates(findings)
    assert len(collapsed) == 1
    assert collapsed[0].count == 2


def test_collapse_keeps_distinct_findings_separate():
    findings = [
        _finding(type="xss", indicator="reflected"),
        _finding(type="sqli", indicator="error-based"),
    ]
    collapsed = utility.collapseDuplicates(findings)
    assert len(collapsed) == 2


def test_collapse_handles_empty_input():
    assert utility.collapseDuplicates([]) == []


def test_finding_to_dict_truncates_snippet():
    finding = _finding(response_snippet="A" * 500)
    assert len(finding.to_dict()["response_snippet"]) == 200


def test_finding_to_dict_preserves_core_fields():
    data = _finding().to_dict()
    assert data["type"] == "xss"
    assert data["url"] == "http://target/search"
    assert data["param"] == "q"