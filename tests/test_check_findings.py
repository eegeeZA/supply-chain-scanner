"""Tests for check_findings.py: to_sarif round-trip, uriBaseId, exit codes."""

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from check_findings import main as cf_main, to_sarif

SCAN_ROOT = "/home/runner/work/myrepo/myrepo"

FINDING_IN_ROOT = {
    "path": f"{SCAN_ROOT}/node_modules/axios/package.json",
    "severity": "CRITICAL",
    "detail": "axios@1.0.11 is installed",
    "remediation": "Remove and rotate credentials.",
    "incident_id": "axios-2026-03-31",
    "category": "node_modules",
}

FINDING_OUT_OF_ROOT = {
    "path": "/home/runner/.npm/_logs/2026-04-01T00_00_00_000Z-debug-0.log",
    "severity": "HIGH",
    "detail": "npm log records tarball download",
    "remediation": None,
    "incident_id": "axios-2026-03-31",
    "category": "file_artifact",
}

SCAN_RESULT = {
    "root": SCAN_ROOT,
    "summary": {"critical_high": 1, "warning": 0, "total": 1},
    "findings": [FINDING_IN_ROOT],
}


def test_to_sarif_schema_version():
    sarif = to_sarif(SCAN_RESULT)
    assert sarif["version"] == "2.1.0"


def test_in_root_path_uses_srcroot():
    sarif = to_sarif(SCAN_RESULT)
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc.get("uriBaseId") == "%SRCROOT%"
    # URI should be relative, not absolute
    assert not loc["uri"].startswith("/")


def test_out_of_root_path_no_srcroot():
    result = {**SCAN_RESULT, "findings": [FINDING_OUT_OF_ROOT]}
    sarif = to_sarif(result)
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in loc
    assert loc["uri"].startswith("/")


def test_fingerprint_stability():
    """Same finding must produce the same fingerprint across calls."""
    sarif1 = to_sarif(SCAN_RESULT)
    sarif2 = to_sarif(SCAN_RESULT)
    fp1 = sarif1["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    fp2 = sarif2["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
    assert fp1 == fp2


def test_remediation_appended_to_message():
    sarif = to_sarif(SCAN_RESULT)
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "Remove and rotate credentials." in msg


def test_no_remediation_no_extra_text():
    result = {**SCAN_RESULT, "findings": [FINDING_OUT_OF_ROOT]}
    sarif = to_sarif(result)
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "Remediation:" not in msg


def test_rule_deduplication():
    """Two findings with the same rule ID produce exactly one rule entry."""
    result = {
        **SCAN_RESULT,
        "findings": [FINDING_IN_ROOT, {**FINDING_IN_ROOT, "path": f"{SCAN_ROOT}/other.json"}],
    }
    sarif = to_sarif(result)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1, f"Expected 1 deduplicated rule, got {len(rules)}"


# ── check_findings.main() exit codes ─────────────────────────────────────────


def _run_main(tmp_path, scan_data: dict, extra_args: list[str] = []) -> int:
    result_file = tmp_path / "result.json"
    result_file.write_text(json.dumps(scan_data))
    with patch("sys.argv", ["check_findings.py", str(result_file)] + extra_args):
        return cf_main()


CLEAN_SCAN = {
    "root": SCAN_ROOT,
    "summary": {"critical_high": 0, "warning": 2, "total": 2},
    "findings": [],
}

CRITICAL_SCAN = {
    "root": SCAN_ROOT,
    "summary": {"critical_high": 1, "warning": 0, "total": 1},
    "findings": [FINDING_IN_ROOT],
}


def test_main_clean_exits_0(tmp_path):
    assert _run_main(tmp_path, CLEAN_SCAN) == 0


def test_main_critical_exits_1(tmp_path, capsys):
    assert _run_main(tmp_path, CRITICAL_SCAN) == 1


def test_main_sarif_clean_exits_0(tmp_path, capsys):
    assert _run_main(tmp_path, CLEAN_SCAN, ["--sarif"]) == 0


def test_main_sarif_critical_exits_1(tmp_path, capsys):
    assert _run_main(tmp_path, CRITICAL_SCAN, ["--sarif"]) == 1


def test_main_missing_file_exits_2(tmp_path):
    with patch("sys.argv", ["check_findings.py", str(tmp_path / "does_not_exist.json")]):
        assert cf_main() == 2


def test_main_bad_json_exits_2(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json {{{")
    with patch("sys.argv", ["check_findings.py", str(bad_file)]):
        assert cf_main() == 2
