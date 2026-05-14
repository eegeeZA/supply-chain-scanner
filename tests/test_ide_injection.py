"""Tests for host_ide_injection() — IDE lifecycle file persistence detection."""
import hashlib
from pathlib import Path

import pytest

from scan import host_ide_injection

# A minimal incident fixture with the fields host_ide_injection consumes.
INCIDENT = {
    "id": "tanstack-2026-05-11",
    "ide_injection_iocs": [
        {"rel_path": ".claude/settings.json", "sha256": "aabbccdd" * 8},
        {"rel_path": ".claude/execution.js",  "sha256": ""},
    ],
    "wiper_warning": "CRITICAL: kill daemon first.",
}

INCIDENT_NO_INJECT = {
    "id": "other-incident",
    "malicious_packages": [],
}


def _make_repo(tmp_path: Path) -> Path:
    """Create a minimal git repo root."""
    (tmp_path / ".git").mkdir()
    return tmp_path


def test_known_bad_hash_match(tmp_path):
    repo = _make_repo(tmp_path)
    target = repo / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    content = b"malicious content"
    actual_sha = hashlib.sha256(content).hexdigest()
    target.write_bytes(content)

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/settings.json", "sha256": actual_sha},
        ],
    }
    findings = host_ide_injection([incident], repo)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].category == "ide_injection"
    assert findings[0].incident_id == "tanstack-2026-05-11"
    assert "confirmed by SHA256" in findings[0].detail


def test_path_present_hash_mismatch(tmp_path):
    repo = _make_repo(tmp_path)
    target = repo / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}")

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/settings.json", "sha256": "0" * 64},
        ],
    }
    findings = host_ide_injection([incident], repo)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "hash differs" in findings[0].detail


def test_path_presence_only_ioc(tmp_path):
    repo = _make_repo(tmp_path)
    target = repo / ".claude" / "execution.js"
    target.parent.mkdir(parents=True)
    target.write_text("some js")

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/execution.js", "sha256": ""},
        ],
    }
    findings = host_ide_injection([incident], repo)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "no known hash" in findings[0].detail


def test_clean_repo_no_findings(tmp_path):
    repo = _make_repo(tmp_path)
    findings = host_ide_injection([INCIDENT], repo)
    assert findings == []


def test_incident_without_ide_injection_iocs_skipped(tmp_path):
    repo = _make_repo(tmp_path)
    # Even if .claude/settings.json exists, an incident with no ide_injection_iocs
    # must not produce findings.
    target = repo / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}")
    findings = host_ide_injection([INCIDENT_NO_INJECT], repo)
    assert findings == []


def test_non_git_directory_not_checked(tmp_path):
    # A directory WITHOUT .git should NOT be treated as a repo root.
    non_repo = tmp_path / "not-a-repo"
    non_repo.mkdir()
    target = non_repo / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    content = b"malicious"
    sha = hashlib.sha256(content).hexdigest()
    target.write_bytes(content)

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/settings.json", "sha256": sha},
        ],
    }
    # scan root is tmp_path; non_repo has no .git — should produce no findings
    findings = host_ide_injection([incident], tmp_path)
    assert findings == []


def test_wiper_warning_in_remediation(tmp_path):
    repo = _make_repo(tmp_path)
    target = repo / ".claude" / "execution.js"
    target.parent.mkdir(parents=True)
    target.write_text("js")

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/execution.js", "sha256": ""},
        ],
        "wiper_warning": "Kill the daemon before revoking tokens.",
    }
    findings = host_ide_injection([incident], repo)
    assert len(findings) == 1
    assert "Kill the daemon" in findings[0].remediation


def test_root_itself_as_repo(tmp_path):
    # When root itself is a git repo, it must be checked too.
    (tmp_path / ".git").mkdir()
    target = tmp_path / ".claude" / "execution.js"
    target.parent.mkdir(parents=True)
    target.write_text("evil")

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/execution.js", "sha256": ""},
        ],
    }
    findings = host_ide_injection([incident], tmp_path)
    assert len(findings) == 1


def test_host_ide_injection_subdirRepo_returnsFindings(tmp_path):
    # A repo one level under root (the os.scandir path) must be discovered.
    subdir = tmp_path / "myproject"
    subdir.mkdir()
    (subdir / ".git").mkdir()
    target = subdir / ".claude" / "execution.js"
    target.parent.mkdir(parents=True)
    target.write_text("evil")

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/execution.js", "sha256": ""},
        ],
    }
    findings = host_ide_injection([incident], tmp_path)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_host_ide_injection_hashMismatch_returnsLow(tmp_path):
    # A file at a known-IOC path whose hash doesn't match must be LOW, not HIGH.
    repo = tmp_path
    (repo / ".git").mkdir()
    target = repo / ".claude" / "settings.json"
    target.parent.mkdir(parents=True)
    target.write_text("{}")  # legitimate content

    incident = {
        "id": "tanstack-2026-05-11",
        "ide_injection_iocs": [
            {"rel_path": ".claude/settings.json", "sha256": "0" * 64},
        ],
    }
    findings = host_ide_injection([incident], repo)
    assert len(findings) == 1
    assert findings[0].severity == "LOW"
    assert "likely legitimate" in findings[0].detail
