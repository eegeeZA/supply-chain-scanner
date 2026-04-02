"""Regression tests for render_html() HTML-escaping discipline.

These tests guard against two failure modes:
1. A Finding field containing HTML-special characters reaching the output raw.
2. An unrecognised severity string producing an unstyled (class-less) finding card.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scan import Finding, ScanResult, render_html

PAYLOAD = "<script>alert(1)</script>"
ESCAPED = "&lt;script&gt;alert(1)&lt;/script&gt;"


def _render(tmp_findings: list[Finding], capsys) -> str:
    result = ScanResult(root="/tmp/repo", scanned_at="2026-04-02T00:00:00")
    result.findings.extend(tmp_findings)
    render_html(result)
    return capsys.readouterr().out


def _finding(**kwargs) -> Finding:
    defaults = dict(
        incident_id="test-incident",
        category="node_modules",
        severity="CRITICAL",
        path="/tmp/node_modules/axios/package.json",
        detail="test detail",
        remediation="test remediation",
    )
    return Finding(**{**defaults, **kwargs})


# ── Escaping tests ────────────────────────────────────────────────────────────

def test_detail_is_escaped(capsys):
    """HTML payload in Finding.detail must not appear raw in the output."""
    html = _render([_finding(detail=PAYLOAD)], capsys)
    assert PAYLOAD not in html, "Raw payload found in detail — missing e() call"
    assert ESCAPED in html


def test_path_is_escaped(capsys):
    """HTML payload in Finding.path must not appear raw in the output."""
    html = _render([_finding(path=f"/tmp/{PAYLOAD}")], capsys)
    assert PAYLOAD not in html, "Raw payload found in path — missing e() call"


def test_remediation_is_escaped(capsys):
    """HTML payload in Finding.remediation must not appear raw in the output."""
    html = _render([_finding(remediation=PAYLOAD)], capsys)
    assert PAYLOAD not in html, "Raw payload found in remediation — missing e() call"


def test_incident_id_is_escaped(capsys):
    """HTML payload in Finding.incident_id must not appear raw in the output."""
    html = _render([_finding(incident_id=PAYLOAD)], capsys)
    assert PAYLOAD not in html, "Raw payload found in incident_id — missing e() call"


# ── sev_cls CSS class tests ───────────────────────────────────────────────────

def test_critical_finding_uses_correct_css_class(capsys):
    """CRITICAL severity must render with class='finding critical'."""
    html = _render([_finding(severity="CRITICAL")], capsys)
    assert 'class="finding critical"' in html


def test_high_finding_uses_correct_css_class(capsys):
    """HIGH severity must render with class='finding high'."""
    html = _render([_finding(severity="HIGH")], capsys)
    assert 'class="finding high"' in html


def test_warning_finding_uses_correct_css_class(capsys):
    """WARNING severity must render with class='finding warning'."""
    html = _render([_finding(severity="WARNING")], capsys)
    assert 'class="finding warning"' in html
