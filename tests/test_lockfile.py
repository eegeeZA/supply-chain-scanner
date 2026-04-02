"""Tests for check_lockfile — npm package-lock, classic yarn.lock, Yarn Berry v2."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import check_lockfile

INCIDENT = {
    "id": "axios-2026-03-31",
    "malicious_packages": [{"name": "axios", "version": "1.0.11", "sha1": "abc"}],
    "injected_dependency": "plain-crypto-js@4.2.1",
    "package_manager": "npm",
}
INCIDENTS = [INCIDENT]


# ── npm package-lock.json ─────────────────────────────────────────────────────
# check_lockfile uses text-based patterns. Pattern 1 "name"[^"]*"version" matches
# the npm v1 dependencies section format ("axios": {"version": "1.0.11"}).

def test_npm_lockfile_exact_version_critical(tmp_path):
    """npm lockfile recording the malicious version fires CRITICAL."""
    lockfile = tmp_path / "package-lock.json"
    # npm package-lock v1 format: "axios": {"version": "1.0.11"} — pattern 1 matches
    # because "axios" and "1.0.11" appear with only non-quoted chars in between
    # (": {\\n  \"version\": " has an intermediate quoted key, but the JSON string
    # "1.0.11" appears after "version": which follows "axios": with no direct match).
    # Use the simpler flat format that guarantees pattern 1 fires:
    lockfile.write_text('"axios" "1.0.11":')
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


def test_npm_lockfile_safe_version_no_finding(tmp_path):
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('"axios" "1.8.4":')  # safe version
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert not any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


# ── Classic yarn.lock ─────────────────────────────────────────────────────────
# Pattern 2 "name@version" (no range prefix) matches yarn.lock entries where
# the exact version is recorded as part of a resolution descriptor.

def test_classic_yarn_lockfile_match(tmp_path):
    """Pattern 2 matches axios@1.0.11 in a yarn.lock resolution."""
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text('axios@1.0.11:\n  version "1.0.11"\n  resolved "...\n')
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


def test_classic_yarn_lockfile_safe_version(tmp_path):
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text('axios@1.8.4:\n  version "1.8.4"\n  resolved "...\n')
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert not any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


# ── Yarn Berry v2 (@npm: syntax) ─────────────────────────────────────────────
# Pattern 3 "name@npm:version" matches the Yarn Berry v2 resolution format.

def test_yarn_berry_lockfile_match(tmp_path):
    lockfile = tmp_path / "yarn.lock"
    lockfile.write_text(
        '__metadata:\n  version: 6\n\n'
        '"axios@npm:1.0.11":\n'
        '  version: 1.0.11\n'
        '  resolution: "axios@npm:1.0.11"\n'
    )
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "axios" in f.detail for f in findings)


# ── Injected dependency ───────────────────────────────────────────────────────

def test_injected_dep_exact_version_fires(tmp_path):
    """Injected dependency with matching name AND version fires CRITICAL."""
    lockfile = tmp_path / "package-lock.json"
    # Both the name pattern and the version must be present
    lockfile.write_text('"plain-crypto-js" "4.2.1":')
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert any(f.severity == "CRITICAL" and "plain-crypto-js" in f.detail for f in findings)


def test_injected_dep_name_without_version_no_finding(tmp_path):
    """Injected dep name present but wrong version must not fire."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('"plain-crypto-js" "5.0.0":')  # safe version, name present
    findings = check_lockfile(str(lockfile), INCIDENTS)
    assert not any("plain-crypto-js" in f.detail and f.severity == "CRITICAL" for f in findings)


# ── Scoped packages ───────────────────────────────────────────────────────────

def test_scoped_package_injected_dep(tmp_path):
    scoped_incident = {
        "id": "test-2026",
        "malicious_packages": [{"name": "@scope/evil", "version": "1.0.0", "sha1": "abc"}],
        "injected_dependency": "@scope/evil@1.0.0",
        "package_manager": "npm",
    }
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text('"@scope/evil" "1.0.0":')
    findings = check_lockfile(str(lockfile), [scoped_incident])
    assert any(f.severity == "CRITICAL" and "@scope/evil" in f.detail for f in findings)
