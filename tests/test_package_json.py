"""Tests for check_package_json — floating range, no-lockfile, and duplicate-section handling."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_package_json

INCIDENT = {
    "id": "axios-2026-03-31",
    "malicious_packages": [{"name": "axios", "version": "1.0.11", "sha1": "abc"}],
    "safe_versions": ["1.8.4"],
    "package_manager": "npm",
}
INCIDENTS = [INCIDENT]


# ── Floating range WARNING ────────────────────────────────────────────────────

def test_caret_range_produces_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "^1.0.0"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.severity == "WARNING" and "axios" in f.detail for f in findings)


def test_tilde_range_produces_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "~1.0.0"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.severity == "WARNING" and "axios" in f.detail for f in findings)


def test_gte_range_produces_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": ">=1.0.0"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.severity == "WARNING" for f in findings)


def test_lt_range_produces_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "<2.0.0"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.severity == "WARNING" for f in findings)


def test_lte_range_produces_warning(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "<=1.0.11"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.severity == "WARNING" for f in findings)


# ── No-lockfile WARNING ───────────────────────────────────────────────────────

def test_no_lockfile_in_git_project_warns(tmp_path):
    """Project root with .git but no lockfile produces WARNING."""
    (tmp_path / ".git").mkdir()
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "1.8.4"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert any(f.incident_id == "config-risk" and "No lockfile" in f.detail for f in findings)


def test_lockfile_present_no_config_risk(tmp_path):
    """Project with a lockfile does not produce config-risk warning."""
    (tmp_path / ".git").mkdir()
    (tmp_path / "package-lock.json").write_text("{}")
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"axios": "1.8.4"}}))
    findings = check_package_json(str(pkg), INCIDENTS)
    assert not any(f.incident_id == "config-risk" for f in findings)


# ── Duplicate dep section handling (M1) ──────────────────────────────────────

def test_critical_pin_in_dependencies_not_masked_by_devdeps(tmp_path):
    """CRITICAL in dependencies must not be lost when devDependencies floats the same package."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {"axios": "1.0.11"},       # exact bad version → CRITICAL
        "devDependencies": {"axios": "^1.0.0"},    # floating → WARNING only
    }))
    findings = check_package_json(str(pkg), INCIDENTS)
    severities = {f.severity for f in findings if "axios" in f.detail}
    assert "CRITICAL" in severities, "CRITICAL finding was masked by devDependencies entry"
