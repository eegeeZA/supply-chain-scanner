"""Tests for check_hidden_lockfile — GHOST, STUB, and nested transitive detection."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_hidden_lockfile

INCIDENT = {
    "id": "axios-2026-03-31",
    "malicious_packages": [{"name": "axios", "version": "1.0.11", "sha1": "abc"}],
    "package_manager": "npm",
}
INCIDENTS = [INCIDENT]


def _lockfile(tmp_path, packages: dict) -> Path:
    """Write a .package-lock.json with the given packages dict."""
    lf = tmp_path / "node_modules" / ".package-lock.json"
    lf.parent.mkdir(parents=True, exist_ok=True)
    lf.write_text(json.dumps({"lockfileVersion": 2, "packages": packages}))
    return lf


def test_ghost_detection(tmp_path):
    """Package dir gone after bad version in lockfile — GHOST finding."""
    lf = _lockfile(tmp_path, {"node_modules/axios": {"version": "1.0.11"}})
    # Do NOT create the axios directory — simulate GHOST
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert any("GONE" in f.detail and f.severity == "CRITICAL" for f in findings)


def test_stub_detection(tmp_path):
    """Package dir exists with a swapped version — STUB finding."""
    lf = _lockfile(tmp_path, {"node_modules/axios": {"version": "1.0.11"}})
    pkg_dir = tmp_path / "node_modules" / "axios"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text(json.dumps({"name": "axios", "version": "1.8.4"}))
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert any("stub replacement" in f.detail and f.severity == "CRITICAL" for f in findings)


def test_matching_version_no_finding_from_hidden_lockfile(tmp_path):
    """When installed version matches, check_installed handles it; check_hidden_lockfile skips."""
    lf = _lockfile(tmp_path, {"node_modules/axios": {"version": "1.0.11"}})
    pkg_dir = tmp_path / "node_modules" / "axios"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.json").write_text(json.dumps({"name": "axios", "version": "1.0.11"}))
    # check_installed handles the HIT case; check_hidden_lockfile intentionally produces no finding
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert not findings


def test_safe_version_no_finding(tmp_path):
    """Lockfile records a safe version — no finding."""
    lf = _lockfile(tmp_path, {"node_modules/axios": {"version": "1.8.4"}})
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert not findings


def test_nested_transitive_install_ghost_detected(tmp_path):
    """Malicious package as nested transitive dep (GHOST) is detected via its lockfile path."""
    lf = _lockfile(tmp_path, {
        "node_modules/foo": {"version": "2.0.0"},
        "node_modules/foo/node_modules/axios": {"version": "1.0.11"},
    })
    # Do NOT create the nested axios directory — simulate GHOST for nested dep
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert any("GONE" in f.detail and f.severity == "CRITICAL" for f in findings)


def test_nested_safe_version_no_finding(tmp_path):
    """Nested transitive dep at a safe version produces no finding."""
    lf = _lockfile(tmp_path, {
        "node_modules/foo/node_modules/axios": {"version": "1.8.4"},
    })
    findings = check_hidden_lockfile(str(lf), INCIDENTS)
    assert not findings
