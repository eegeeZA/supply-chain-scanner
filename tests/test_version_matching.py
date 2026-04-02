"""Tests for _version_matches — exact-pin detection only, no range operators."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import _version_matches


def test_exact_pin_matches():
    assert _version_matches("1.14.1", "1.14.1")


def test_exact_pin_wrong_version():
    assert not _version_matches("1.14.0", "1.14.1")


def test_caret_range_does_not_match():
    assert not _version_matches("^1.14.1", "1.14.1")


def test_tilde_range_does_not_match():
    assert not _version_matches("~1.14.1", "1.14.1")


def test_gte_range_does_not_match():
    assert not _version_matches(">=1.14.1", "1.14.1")


def test_gt_range_does_not_match():
    assert not _version_matches(">1.14.0", "1.14.1")


def test_lte_range_does_not_match():
    assert not _version_matches("<=1.14.1", "1.14.1")


def test_eq_prefix_matches():
    # npm canonical exact-pin form (e.g. from `npm install axios@=1.14.1`) should
    # be treated as an exact match, not a floating range.
    assert _version_matches("=1.14.1", "1.14.1")


def test_whitespace_stripped():
    assert _version_matches("  1.14.1  ", "1.14.1")


def test_empty_string():
    assert not _version_matches("", "1.14.1")


def test_latest_tag():
    assert not _version_matches("latest", "1.14.1")


def test_star_wildcard():
    assert not _version_matches("*", "1.14.1")
