"""Tests for check_pnpm_modules_yaml."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_pnpm_modules_yaml

INCIDENT = {
    "id": "axios-2026-03-31",
    "malicious_packages": [{"name": "axios", "version": "1.0.11", "sha1": "abc"}],
    "safe_versions": ["1.8.4"],
    "package_manager": "npm",
}
INCIDENTS = [INCIDENT]


def test_pnpm_modules_yaml_match_fires_critical(tmp_path):
    """Matching package+version in .modules.yaml produces CRITICAL."""
    modules_yaml = tmp_path / ".modules.yaml"
    modules_yaml.write_text(
        "hoistedDependencies: {}\n"
        "hoistPattern:\n"
        "  - '*'\n"
        "included:\n"
        "  dependencies: true\n"
        "packages:\n"
        "  axios: 1.0.11\n"
        "  lodash: 4.17.21\n"
    )
    findings = check_pnpm_modules_yaml(str(modules_yaml), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


def test_pnpm_modules_yaml_safe_version_no_finding(tmp_path):
    """Safe version in .modules.yaml produces no finding."""
    modules_yaml = tmp_path / ".modules.yaml"
    modules_yaml.write_text("packages:\n  axios: 1.8.4\n")
    findings = check_pnpm_modules_yaml(str(modules_yaml), INCIDENTS)
    assert not findings


def test_pnpm_modules_yaml_non_npm_incident_skipped(tmp_path):
    """Non-npm incidents are skipped by check_pnpm_modules_yaml."""
    modules_yaml = tmp_path / ".modules.yaml"
    modules_yaml.write_text("packages:\n  axios: 1.0.11\n")
    composer_incident = {**INCIDENT, "package_manager": "composer"}
    findings = check_pnpm_modules_yaml(str(modules_yaml), [composer_incident])
    assert not findings


def test_pnpm_modules_yaml_partial_name_no_match(tmp_path):
    """Partial package name match (e.g. 'axio') must not fire."""
    modules_yaml = tmp_path / ".modules.yaml"
    modules_yaml.write_text("packages:\n  axio: 1.0.11\n")
    findings = check_pnpm_modules_yaml(str(modules_yaml), INCIDENTS)
    assert not findings
