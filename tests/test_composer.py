"""Tests for check_composer_installed."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_composer_installed

INCIDENT = {
    "id": "malicious-lib-2026",
    "malicious_packages": [{"name": "vendor/evil-lib", "version": "2.0.0"}],
    "package_manager": "composer",
}
INCIDENTS = [INCIDENT]


def _write_installed(tmp_path, packages: list[dict], v2: bool = True) -> Path:
    """Write a vendor/composer/installed.json and return its path."""
    installed_dir = tmp_path / "vendor" / "composer"
    installed_dir.mkdir(parents=True)
    installed_path = installed_dir / "installed.json"
    if v2:
        installed_path.write_text(json.dumps({"packages": packages}))
    else:
        installed_path.write_text(json.dumps(packages))
    return installed_path


def test_ghost_detection_scoped_package(tmp_path):
    """Malicious scoped package in installed.json but vendor dir missing — GHOST CRITICAL."""
    path = _write_installed(tmp_path, [{"name": "vendor/evil-lib", "version": "2.0.0"}])
    # Do NOT create vendor/evil-lib — simulate self-deleting malware
    findings = check_composer_installed(str(path), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "MISSING" in f.detail for f in findings)


def test_package_present_no_ghost(tmp_path):
    """Package dir exists — no ghost finding (still installed)."""
    path = _write_installed(tmp_path, [{"name": "vendor/evil-lib", "version": "2.0.0"}])
    pkg_dir = tmp_path / "vendor" / "evil-lib"
    pkg_dir.mkdir(parents=True)
    findings = check_composer_installed(str(path), INCIDENTS)
    # Should still fire — package is installed at bad version
    assert any(f.severity == "CRITICAL" for f in findings)


def test_safe_version_no_finding(tmp_path):
    """Safe version in installed.json produces no finding."""
    path = _write_installed(tmp_path, [{"name": "vendor/evil-lib", "version": "1.0.0"}])
    findings = check_composer_installed(str(path), INCIDENTS)
    assert not findings


def test_v1_format_list(tmp_path):
    """Composer v1 format (bare list, not wrapped in packages key) is handled."""
    path = _write_installed(tmp_path, [{"name": "vendor/evil-lib", "version": "2.0.0"}], v2=False)
    findings = check_composer_installed(str(path), INCIDENTS)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_npm_incident_skipped(tmp_path):
    """npm incidents are skipped by check_composer_installed."""
    path = _write_installed(tmp_path, [{"name": "vendor/evil-lib", "version": "2.0.0"}])
    npm_incident = {**INCIDENT, "package_manager": "npm"}
    findings = check_composer_installed(str(path), [npm_incident])
    assert not findings
