"""
    Tests for the URL and path helpers in core.utility.
"""
from fuzzer.core import utility


def test_get_directories_strips_trailing_filename():
    result = utility.getDirectories("/uploads/images/logo.php")
    assert result.endswith("/uploads/images")
    assert "logo.php" not in result


def test_get_directories_keeps_directory_only_path():
    result = utility.getDirectories("/uploads/images/")
    assert result.endswith("/uploads/images")


def test_get_parents_includes_full_path_and_ancestors():
    parents = utility.getParents("http://target/app/admin/panel")
    assert "/app/admin/panel" in parents
    assert "/app/admin" in parents
    assert "/app" in parents
    assert "/" in parents


def test_get_parents_deduplicates():
    parents = utility.getParents("http://target/a/b")
    assert len(parents) == len(set(parents))


def test_fuzzable_field_allows_normal_inputs():
    assert utility.isFuzzableField("username")
    assert utility.isFuzzableField("comment")


def test_fuzzable_field_skips_configured_noise():
    assert not utility.isFuzzableField("login")
    assert not utility.isFuzzableField("captcha")


def test_fuzzable_field_rejects_empty():
    assert not utility.isFuzzableField("")
    assert not utility.isFuzzableField(None)