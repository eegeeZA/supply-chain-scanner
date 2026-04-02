#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""
supply-chain-scanner: detect supply-chain compromises across ecosystems and OSes.

Scans npm (package.json, lockfiles, node_modules at all depths, pnpm, Yarn Berry PnP,
global stores), Composer (vendor/composer/installed.json), and Python (site-packages
.dist-info) in parallel. Host-level checks (file artifacts, shell profiles,
persistence, network, npm cache, npm logs) run serially and cover macOS, Linux,
and Windows. Zero external dependencies — stdlib Python only.

Usage:
    python3 scan.py [ROOT] [--workers N] [--iocs FILE] [--since ISO_OR_INCIDENT_ID] [--json|--sarif|--junit|--html]
    python3 scan.py [ROOT] [--docker [IMAGE ...]] [--online]
    python3 scan.py               # full OS scan (default: /)
    python3 scan.py ~/dev         # target directory
    python3 scan.py ~/dev --since 2026-03-31T00:21:00  # incident-response mode (fast)
    python3 scan.py ~/dev --sarif > results.sarif       # GitHub Code Scanning
    python3 scan.py ~/dev --html  > report.html         # offline/email report
    python3 scan.py --docker                            # scan all local Docker images
    python3 scan.py --docker nginx:latest node:18-slim  # scan specific images
    python3 scan.py ~/dev --online                      # also query OSV.dev live advisories
"""

__version__ = "1.0.0"

import argparse
import hashlib
import html as _html
import io
import json
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import threading
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, UTC, timezone
from pathlib import Path
from typing import Any, Literal

# ── ANSI colours (suppressed when stdout is not a TTY) ───────────────────────

RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"


def styled(text: str, code: str) -> str:
    return (code + text + RESET) if sys.stdout.isatty() else text


# ── Embedded IOC database ────────────────────────────────────────────────────
#
# Bundled so scan.py is a single-file tool — one SHA256 to verify, nothing else
# to download. Override with --iocs /path/to/custom.json.
# Update URL and SHA256 here when a new iocs.json release is published.

_IOCS_UPDATE_URL = "https://raw.githubusercontent.com/eegeeZA/supply-chain-scanner/main/iocs.json"
_IOCS_UPDATE_SHA256 = "65d969ba91187499e242af40708f4e4d89d3a0913cfabde5090ed1aa69cdf9cc"

_EMBEDDED_IOCS: dict = {
    "incidents": [
        {
            "id": "axios-2026-03-31",
            "title": "Axios NPM Supply Chain Compromise",
            "published": "2026-03-31",
            "severity": "CRITICAL",
            "source": "https://www.sans.org/blog/axios-npm-supply-chain-compromise-malicious-packages-remote-access-trojan",
            "summary": (
                "TeamPCP compromised axios@1.14.1 and axios@0.30.4 via a malicious "
                "dependency (plain-crypto-js). Deployed credential harvester + "
                "cross-platform RAT. Live on npm for ~2-3 hours."
            ),
            "package_manager": "npm",
            "malicious_packages": [
                {"name": "axios",          "version": "1.14.1", "sha1": "2553649f232204966871cea80a5d0d6adc700ca"},
                {"name": "axios",          "version": "0.30.4", "sha1": "d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71"},
                {"name": "plain-crypto-js","version": "4.2.1",  "sha1": "07d889e2dadce6f3910dcbc253317d28ca61c766"},
            ],
            "injected_dependency": "plain-crypto-js@4.2.1",
            "safe_versions": ["1.14.0", "0.30.3"],
            "network_iocs": [
                {"type": "domain", "value": "sfrclak.com"},
                {"type": "ip",     "value": "142.11.206.73", "port": 8000},
                {"type": "url",    "value": "packages.npm.org/product0", "platform": "macOS"},
                {"type": "url",    "value": "packages.npm.org/product1", "platform": "Windows"},
                {"type": "url",    "value": "packages.npm.org/product2", "platform": "Linux"},
            ],
            "file_iocs": [
                {"platform": "macOS",   "path": "/Library/Caches/com.apple.act.mond"},
                {"platform": "macOS",   "path": "~/Library/Caches/com.apple.act.mond"},
                {"platform": "Windows", "path": "%PROGRAMDATA%/wt.exe"},
                {"platform": "Windows", "path": "%TEMP%/6202033.vbs"},
                {"platform": "Windows", "path": "%TEMP%/6202033.ps1"},
                {"platform": "Linux",   "path": "/tmp/ld.py"},
            ],
            "what_to_rotate": [
                "NPM tokens", "AWS/Azure/GCP cloud keys", "SSH keys",
                "Database credentials", "API tokens",
            ],
            # also_compromised: informational metadata only — lists other tools/packages
            # that were reported as compromised in the same incident. Not scanned by this
            # tool; included for operator context and to support future advisory enrichment.
            "also_compromised": ["trivy", "kics", "litellm", "telnyx"],
            "attack_window_start_utc": "2026-03-31T00:21:00",
            "attack_window_end_utc":   "2026-03-31T03:15:00",
        },
    ]
}


# ── Constants ────────────────────────────────────────────────────────────────

# Directories pruned from the os.walk tree (matched by name at any depth).
# Rationale by group:
#   macOS system     — sealed read-only volume, no user npm
#   macOS metadata   — volume-root hidden dirs, not files
#   Apple dev infra  — CoreSimulator alone can be 100 GB+
#   Windows system   — OS binaries, recycle bin, WinSxS
#   Linux vfs        — proc/sys/run are virtual, not real files
#   Python tooling   — venvs and caches, not npm
#   VCS internals    — pack objects only, no source
#   Build outputs    — generated artefacts, not npm project roots
#
# NOT pruned: /Library, /Applications, /opt, /usr, node_modules (depth-aware)
PRUNE_DIRS: frozenset[str] = frozenset({
    # macOS system
    "System", "private", "cores",
    # macOS filesystem metadata
    ".Spotlight-V100", ".fseventsd", ".Trashes",
    ".DocumentRevisions-V100", ".TemporaryItems", ".vol",
    # Apple developer infrastructure
    "CoreSimulator", "DerivedData",
    "iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport",
    # Windows system
    "Windows", "$Recycle.Bin", "System Volume Information",
    "WindowsApps", "WinSxS", "SoftwareDistribution",
    # Linux virtual filesystems
    "dev", "proc", "sys", "run",
    # Python tooling / venvs
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    ".venv", "venv",
    # VCS internals
    ".git", ".svn", ".hg",
    # Build outputs
    "dist", "build", "target", ".next", ".nuxt",
    # Java
    ".gradle",
    # Editors
    ".idea",
})

LOCKFILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json",    # npm
    "yarn.lock",            # yarn classic + Berry
    "pnpm-lock.yaml",       # pnpm
    "bun.lock",             # Bun v1.2+
    "bun.lockb",            # Bun < v1.2 (binary — parsed as lockfile presence only)
    "deno.lock",            # Deno
    "npm-shrinkwrap.json",  # legacy npm shrinkwrap
})

# LaunchAgent plists from these vendors are considered trusted
KNOWN_VENDOR_PLIST = re.compile(
    r'^(com\.apple|com\.google|com\.microsoft|com\.adobe|'
    r'org\.|homebrew|io\.|com\.jetbrains|com\.lwouis|com\.handy)',
    re.IGNORECASE,
)

# Semver range prefixes that mean "resolve to latest matching, not exact"
_RISKY_RANGE = re.compile(r'^(\^|~|\*|>=|>|<=?|latest)', re.IGNORECASE)

# Lifecycle script keys that execute code at install time
_DANGEROUS_SCRIPT_KEYS = frozenset({"preinstall", "install", "postinstall", "prepare"})

# Patterns in lifecycle script values that strongly suggest malicious intent.
# Heuristic signal only — not exhaustive; a sufficiently obfuscated script
# will not match. Truncate input to 4 KB before matching to prevent ReDoS on
# attacker-crafted package.json (re.DOTALL + unbounded quantifiers).
_SUSPICIOUS_SCRIPT_MAX_LEN = 4096
_SUSPICIOUS_SCRIPT = re.compile(
    r'(curl\s+.+\|\s*(ba)?sh'        # pipe-to-shell download (curl | sh)
    r'|wget\s+.+\|\s*(ba)?sh'         # pipe-to-shell download (wget | sh)
    r'|base64\s+(-d|--decode)'        # base64-encoded payload decode
    r'|Buffer\.from\(.+base64'        # Node.js base64 decode
    r'|\beval\s*\([^)]{40,}\)'        # eval of a long expression (obfuscated execution)
    r'|child_process.*exec\('         # direct subprocess execution via Node.js
    r'|\$\{?(AWS_|NPM_TOKEN|GITHUB_TOKEN|CI_|GH_TOKEN|DOCKER_)'  # env-var credential exfiltration
    r'|fetch\s*\(\s*["\']https?://(?!registry\.npmjs\.org))',     # outbound fetch to non-registry URL
    re.IGNORECASE | re.DOTALL,
)


# ── Data model ───────────────────────────────────────────────────────────────

Category = Literal[
    "package", "lockfile", "node_modules", "installed_package",
    "file_artifact", "network", "shell_profile", "launch_agent", "config", "docker",
]
Severity = Literal["CRITICAL", "HIGH", "WARNING"]


@dataclass
class Finding:
    incident_id: str
    category: Category
    severity: Severity
    path: str
    detail: str
    remediation: str = ""


@dataclass
class ScanResult:
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    root: str = ""
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=lambda: {
        "dirs_visited": 0,
        "package_json_checked": 0,
        "lockfiles_checked": 0,
        "node_modules_checked": 0,
        "hidden_lockfiles_checked": 0,
    })

    @property
    def critical_high(self) -> list["Finding"]:
        return [f for f in self.findings if f.severity in ("CRITICAL", "HIGH")]

    @property
    def warnings(self) -> list["Finding"]:
        return [f for f in self.findings if f.severity == "WARNING"]

    @property
    def clean(self) -> bool:
        """True only when there are no CRITICAL or HIGH findings."""
        return not self.critical_high

    @property
    def warning_count(self) -> int:
        return len(self.warnings)


# ── Pure checker functions (called in worker threads) ────────────────────────
#
# Stateless: read arguments, write to a local list, return it.
# Thread-safe because incidents is read-only and no shared state is mutated.

def _version_matches(declared: str, target: str) -> bool:
    """True when declared is an exact pin (no range operators) matching the target version.

    Only a bare version string (e.g. "1.14.1") or an npm canonical exact-pin
    (e.g. "=1.14.1") matches. Any other range operator prefix (^, ~, >=, >,
    <=, <) causes this to return False so the caller can route the declaration
    to the appropriate WARNING-level floating-range check instead.
    """
    return declared.strip().lstrip("=") == target


def _is_project_root(directory: Path, max_depth: int = 4) -> bool:
    """True when a .git entry exists, walking upward toward the filesystem root.

    Walks up to max_depth parent directories from directory. Returns True on the
    first ancestor that contains a .git entry (directory for normal clones; file
    for git worktrees and submodules), False if none is found within the depth
    limit.
    """
    current = directory
    for _ in range(max_depth):
        if (current / ".git").exists():
            return True
        parent = current.parent
        if parent == current:
            break
        current = parent
    return False


def check_package_json(path: str, incidents: list[dict]) -> list[Finding]:
    """Check a package.json for declared dependencies pinned to malicious versions.

    Produces CRITICAL for exact-version pins matching a known-bad package version.
    Produces WARNING for floating-range declarations (^ver, ~ver, >=ver) that include
    the bad version, and for missing lockfile configuration (package-lock=false with
    no lockfile present, indicating installs are not reproducible).
    """
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
    except Exception:
        return []

    # Build a mapping of package name → deduplicated list of declared versions
    # across all dependency sections. A plain dict merge (last section wins) can
    # silently mask a CRITICAL exact-pin in `dependencies` when the same package
    # also appears with a floating range in `devDependencies`.
    all_dep_versions: dict[str, list[str]] = {}
    for _section in ("dependencies", "devDependencies", "peerDependencies"):
        for _dep_name, _dep_ver in data.get(_section, {}).items():
            versions = all_dep_versions.setdefault(_dep_name, [])
            if _dep_ver not in versions:
                versions.append(_dep_ver)

    findings = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            if name not in all_dep_versions:
                continue
            safe = ", ".join(incident.get("safe_versions", ["see advisory"]))
            for declared in all_dep_versions[name]:
                if _version_matches(declared, bad_ver):
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="package",
                        severity="CRITICAL",
                        path=path,
                        detail=f'{name}@{declared} matches compromised version {bad_ver}',
                        remediation=f'Pin to safe version ({safe}). Rotate all credentials.',
                    ))
                elif _RISKY_RANGE.match(declared.strip()):
                    # Floating range for a package with a known malicious release
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="package",
                        severity="WARNING",
                        path=path,
                        detail=(
                            f'{name}@{declared} is a floating range — could have resolved to '
                            f'compromised {bad_ver} during the attack window'
                        ),
                        remediation=f'Pin to exact version ({safe}). Use npm ci (not npm install) in CI.',
                    ))

    # Config risk: no lockfile in a genuine project root (gated by .git presence to
    # avoid false positives on system/application package.json manifests)
    parent_dir = Path(path).parent
    if (
        all_dep_versions
        and not any((parent_dir / lf).exists() for lf in LOCKFILE_NAMES)
        and _is_project_root(parent_dir)
    ):
        findings.append(Finding(
            incident_id="config-risk",
            category="config",
            severity="WARNING",
            path=path,
            detail="No lockfile — npm install resolves versions live from the registry on every run",
            remediation="Commit a lockfile and use npm ci (not npm install) in CI.",
        ))

    return findings


def check_lockfile(path: str, incidents: list[dict]) -> list[Finding]:
    """Check a lockfile for malicious package versions and injected dependencies.

    Supports three formats: npm package-lock.json, classic yarn.lock, and
    Yarn Berry v2 (name@npm:version syntax). For each npm incident, checks:
    - Named malicious packages by exact version (CRITICAL)
    - Injected dependencies by name + version (CRITICAL)
    Binary lockfiles (bun.lockb) are skipped.
    """
    # Binary lockfiles (bun.lockb) cannot be scanned as text — skip safely
    if path.endswith(".lockb"):
        return []
    try:
        content = Path(path).read_text(errors="replace")
    except Exception:
        return []

    findings = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            for pattern in (
                rf'"{re.escape(name)}"[^"]*"{re.escape(bad_ver)}"',
                rf'{re.escape(name)}@{re.escape(bad_ver)}',
                rf'{re.escape(name)}@npm:{re.escape(bad_ver)}',  # Yarn Berry v2 format
            ):
                if re.search(pattern, content):
                    safe = ", ".join(incident.get("safe_versions", ["see advisory"]))
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="lockfile",
                        severity="CRITICAL",
                        path=path,
                        detail=f'Lockfile pins {name} to compromised version {bad_ver}',
                        remediation=(
                            f'Delete node_modules + lockfile, reinstall at {name}@{safe}. '
                            'Remove node_modules/plain-crypto-js. Rotate credentials.'
                        ),
                    ))
                    break

        injected = incident.get("injected_dependency", "")
        if injected:
            # Strip trailing @version — handles both scoped (@scope/pkg@ver) and unscoped (pkg@ver).
            # injected.split("@")[0] is wrong for scoped packages: "@scope/pkg@1.0.0" → ""
            if injected.startswith("@"):
                at_idx = injected.rfind("@", 1)  # find @ after the leading one
                dep_name = injected[:at_idx] if at_idx > 0 else injected
            else:
                dep_name = injected.split("@")[0]
            # Extract the injected version to match exactly (name-only match would fire
            # on any safe version of the same package).
            inj_ver = injected.split("@")[-1] if "@" in injected[1:] else ""
            # Match both classic (`dep_name`) and Yarn Berry v2 (`"dep_name@npm:...":`) formats;
            # use word-boundary delimiters to avoid substring false positives.
            name_pattern = re.search(
                r'(?:^|[\s"\'/@])' + re.escape(dep_name) + r'(?:@|["\':\s])',
                content,
                re.MULTILINE,
            )
            # Require the version to appear close to the dep name rather than
            # anywhere in the file. A bare full-file substring match on a short
            # version string like "4.2.1" produces false positives when another
            # package in the same lockfile happens to share that version. A 200-
            # character window covers all real lockfile formats (npm v2, yarn v1,
            # yarn v2) while being far more restrictive than a whole-file search.
            ver_present = not inj_ver or bool(re.search(
                r'(?:^|[\s"\'/@])' + re.escape(dep_name) + r'[\s\S]{0,200}'
                + re.escape(inj_ver),
                content,
            ))
            if dep_name and name_pattern and ver_present:
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="lockfile",
                    severity="CRITICAL",
                    path=path,
                    detail=(
                        f'Malicious injected dependency "{dep_name}@{inj_ver}" present in lockfile'
                        if inj_ver else
                        f'Malicious injected dependency "{dep_name}" present in lockfile'
                    ),
                    remediation=(
                        incident.get("remediation") or
                        f'Remove node_modules/{dep_name}, rebuild, rotate all credentials immediately.'
                    ),
                ))
    return findings


def check_installed(path: str, incidents: list[dict]) -> list[Finding]:
    """Check a package.json (from node_modules or a global store) against known-bad versions."""
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
        installed_ver = data.get("version", "")
        pkg_name = data.get("name", "")
    except Exception:
        return []

    findings = []

    # IOC match: known-bad installed version
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            if pkg["name"] == pkg_name and pkg["version"] == installed_ver:
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="node_modules",
                    severity="CRITICAL",
                    path=str(Path(path).parent),
                    detail=f'{pkg_name}@{installed_ver} is INSTALLED — credential theft may have already occurred',
                    remediation='URGENT: rotate ALL credentials. Remove this dir. Rebuild from clean lockfile.',
                ))

    # WARNING: suspicious lifecycle scripts (install-time code execution vector)
    scripts = data.get("scripts", {})
    for script_key, script_cmd in scripts.items():
        if script_key in _DANGEROUS_SCRIPT_KEYS and _SUSPICIOUS_SCRIPT.search(
            script_cmd[:_SUSPICIOUS_SCRIPT_MAX_LEN]
        ):
            findings.append(Finding(
                incident_id="supply-chain-risk",
                category="node_modules",
                severity="WARNING",
                path=str(Path(path).parent),
                detail=(
                    f'{pkg_name}@{installed_ver}: suspicious {script_key} script — '
                    f'{script_cmd[:100]}'
                ),
                remediation=(
                    'Review this script. If unexpected, this package may be malicious. '
                    'Remove and rotate credentials if in doubt. Set ignore-scripts=true in ~/.npmrc.'
                ),
            ))
            break  # one warning per package is enough

    return findings


def check_pnp_zip(path: str, incidents: list[dict]) -> list[Finding]:
    """Check a Yarn Berry PnP ZIP cache entry for known-bad installed package versions."""
    findings = []
    try:
        with zipfile.ZipFile(path, "r") as archive:
            # Package.json is at node_modules/<pkg>/package.json inside the ZIP
            candidates = [n for n in archive.namelist() if n.endswith("/package.json")]
            for zip_entry in candidates:
                try:
                    data = json.loads(archive.read(zip_entry).decode(errors="replace"))
                except Exception:
                    continue
                pkg_name = data.get("name", "")
                installed_ver = data.get("version", "")
                for incident in incidents:
                    for pkg in incident["malicious_packages"]:
                        if pkg["name"] == pkg_name and pkg["version"] == installed_ver:
                            findings.append(Finding(
                                incident_id=incident["id"],
                                category="node_modules",
                                severity="CRITICAL",
                                path=f"{path}::{zip_entry}",
                                detail=(
                                    f'{pkg_name}@{installed_ver} in Yarn PnP cache — '
                                    'likely executed at install time'
                                ),
                                remediation='Run yarn cache clean, rebuild. Rotate ALL credentials immediately.',
                            ))
    except Exception as exc:
        print(f"Warning: could not read Yarn PnP zip {path}: {exc}", file=sys.stderr)
    return findings


def _pkg_in_lockfile_packages(packages: dict, name: str, bad_ver: str) -> list[str]:
    """Return matching keys for name@bad_ver in a .package-lock.json packages dict.

    Handles both the top-level key ("node_modules/name") and nested transitive
    install keys ("node_modules/foo/node_modules/name"). The two patterns do not
    overlap: the top-level form never starts with "/" so it would not match the
    endswith("/node_modules/name") check alone.
    """
    suffix = f"/node_modules/{name}"
    return [
        k for k, v in packages.items()
        if (k == f"node_modules/{name}" or k.endswith(suffix))
        and v.get("version") == bad_ver
    ]


def check_hidden_lockfile(path: str, incidents: list[dict]) -> list[Finding]:
    """
    Scan node_modules/.package-lock.json — the hidden lockfile npm arborist writes
    BEFORE postinstall scripts run (verified from arborist/lib/arborist/reify.js).

    This file is written even when `package-lock=false` is in .npmrc (only the
    visible package-lock.json is suppressed by that flag). It survives self-
    destructing malware because it is written before the malware executes.

    Three distinct findings:
      GHOST         — hidden lockfile recorded bad version but directory is gone
                      (self-deleting malware almost certainly ran)
      STUB          — hidden lockfile recorded bad version but package.json now
                      reports a different version (stub replacement detected)
      LOCKFILE_HIT  — hidden lockfile pins to bad version (package may still run)
    """
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
    except Exception:
        return []

    packages = data.get("packages", {})
    node_modules_dir = Path(path).parent

    findings = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]

            # Check all install paths: top-level and transitive/nested installs.
            matching_keys = _pkg_in_lockfile_packages(packages, name, bad_ver)
            if not matching_keys:
                continue

            # Use the first matching key to derive the install directory.
            # Keys look like "node_modules/foo" or "node_modules/foo/node_modules/bar".
            # Strip the leading "node_modules/" prefix since node_modules_dir is already
            # pointing at the node_modules directory.
            recorded_key = matching_keys[0]
            rel = recorded_key[len("node_modules/"):]  # e.g. "foo" or "foo/node_modules/bar"
            pkg_dir = node_modules_dir / rel

            if not pkg_dir.exists():
                # GHOST: directory removed — clearest self-destruct signal
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="node_modules",
                    severity="CRITICAL",
                    path=str(node_modules_dir),
                    detail=(
                        f'{name}@{bad_ver} in hidden lockfile but directory is GONE — '
                        'self-destructing malware almost certainly executed'
                    ),
                    remediation=(
                        'URGENT: rotate ALL credentials immediately. '
                        'Malware ran and removed itself. Engage incident response.'
                    ),
                ))
            else:
                # Check for stub replacement: directory exists but version was swapped
                try:
                    current_ver = json.loads(
                        (pkg_dir / "package.json").read_text(errors="replace")
                    ).get("version", "")
                    if current_ver and current_ver != bad_ver:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="node_modules",
                            severity="CRITICAL",
                            path=str(pkg_dir / "package.json"),
                            detail=(
                                f'{name}: hidden lockfile recorded {bad_ver} but '
                                f'package.json now reports {current_ver} — '
                                'stub replacement detected (malware self-cleaned)'
                            ),
                            remediation=(
                                'URGENT: rotate ALL credentials. '
                                'Malware ran and replaced its own package.json.'
                            ),
                        ))
                    # If versions match, check_installed already covers this case
                except Exception:
                    pass

    return findings


def check_pnpm_modules_yaml(path: str, incidents: list[dict]) -> list[Finding]:
    """
    Scan node_modules/.modules.yaml — pnpm's internal state file.
    Records resolved versions for all direct dependencies. Written by pnpm
    during install (after extraction, before postinstall). No YAML parser
    needed: we only match exact version strings via regex.
    """
    try:
        content = Path(path).read_text(errors="replace")
    except Exception:
        return []

    findings = []
    for incident in incidents:
        if incident.get("package_manager", "npm") != "npm":
            continue
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            # Matches lines like:   axios: 1.14.1
            if re.search(
                rf'^\s+{re.escape(name)}:\s+{re.escape(bad_ver)}\s*$',
                content, re.MULTILINE,
            ):
                safe = ", ".join(incident.get("safe_versions", ["see advisory"]))
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="lockfile",
                    severity="CRITICAL",
                    path=path,
                    detail=f'pnpm .modules.yaml records {name}@{bad_ver} as resolved version',
                    remediation=f'Delete node_modules, reinstall at {name}@{safe}. Rotate credentials.',
                ))
    return findings


def check_composer_installed(path: str, incidents: list[dict]) -> list[Finding]:
    """
    Scan vendor/composer/installed.json — written by Composer BEFORE post-install-cmd
    scripts run, outside any individual package directory.

    Provides ghost detection: if the malicious package self-deleted its vendor/
    subdirectory after running, the installed.json entry is still present.
    """
    try:
        data = json.loads(Path(path).read_text(errors="replace"))
    except Exception:
        return []

    # installed.json format: {"packages": [...]} in Composer v2, or [...] in v1
    packages: list[dict] = data.get("packages", data) if isinstance(data, dict) else data

    findings = []
    for incident in incidents:
        if incident.get("package_manager") != "composer":
            continue
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            for entry in packages:
                if entry.get("name") != name or entry.get("version") != bad_ver:
                    continue
                # Determine vendor directory from installed.json location
                vendor_dir = Path(path).parent.parent
                if "/" in name:
                    vendor, pkg_dir_name = name.split("/", 1)
                    pkg_dir = vendor_dir / vendor / pkg_dir_name
                else:
                    pkg_dir = vendor_dir / name

                if not pkg_dir.exists():
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="node_modules",
                        severity="CRITICAL",
                        path=path,
                        detail=(
                            f'{name}@{bad_ver} in installed.json but vendor directory MISSING — '
                            'self-destructing malware almost certainly executed'
                        ),
                        remediation='URGENT: rotate ALL credentials. Malware ran and removed itself.',
                    ))
                else:
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="node_modules",
                        severity="CRITICAL",
                        path=str(pkg_dir),
                        detail=f'{name}@{bad_ver} is INSTALLED via Composer — malicious code may execute on composer install',
                        remediation='Run: composer remove ' + name + '. Rotate all credentials.',
                    ))
    return findings


# ── Docker layer scanning helpers ───────────────────────────────────────────
#
# scan_docker_images() (on Scanner) streams docker save to a TemporaryFile so
# the entire image is never held in RAM.  Layer tars are read into memory up
# to _MAX_DOCKER_LAYER_BYTES; oversized layers emit a WARNING finding rather
# than being silently skipped (fail-closed).
#
# Ghost/stub detection is omitted for Docker layers because the image
# filesystem is not mounted — directory-existence checks would give false
# positives against the host filesystem.

_MAX_DOCKER_LAYER_BYTES = 512 * 1024 * 1024  # 512 MB per-layer cap

def _docker_check_hidden_lockfile(
    content: bytes,
    virtual_path: str,
    incidents: list[dict],
) -> list[Finding]:
    """
    Version-only check for node_modules/.package-lock.json inside a Docker layer.
    Skips GHOST/STUB detection (image filesystem not mounted on the host).
    """
    try:
        data = json.loads(content.decode(errors="replace"))
    except Exception:
        return []
    packages = data.get("packages", {})
    findings = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            for key in _pkg_in_lockfile_packages(packages, name, bad_ver):
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="node_modules",
                    severity="CRITICAL",
                    path=virtual_path,
                    detail=(
                        f'{name}@{bad_ver} recorded in hidden lockfile inside Docker image '
                        '— malicious code likely ran during the image build'
                    ),
                    remediation='Rebuild image with a clean lockfile. Rotate ALL credentials.',
                ))
    return findings


def _docker_scan_layer(
    layer_bytes: bytes,
    image_label: str,
    layer_hash: str,
    incidents: list[dict],
    npm_incidents: list[dict],
    stats: dict[str, int],
) -> list[Finding]:
    """
    Scan a single Docker layer (raw tar bytes) for supply chain IOCs.

    Checks for:
      - node_modules/<pkg>/package.json   (IOC version match + suspicious scripts)
      - node_modules/.package-lock.json   (hidden lockfile, version-only)
      - node_modules/.modules.yaml        (pnpm state)
      - vendor/composer/installed.json    (Composer, version-only, no ghost detection)

    npm_incidents is the npm-only subset of incidents, pre-filtered by the caller
    so this function does not rebuild it on every layer.
    """
    findings: list[Finding] = []

    try:
        with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode="r:*") as layer:
            for member in layer.getmembers():
                if not member.isfile():
                    continue
                member_name = posixpath.normpath(
                    "/" + member.name.lstrip("/")
                ).lstrip("/")
                virtual_path = f"{image_label}:{layer_hash}:{member_name}"

                # ── Installed package.json inside node_modules/<pkg>/ ─────────
                if member_name.endswith("/package.json"):
                    nm_idx = member_name.rfind("/node_modules/")
                    if nm_idx >= 0:
                        after_nm = member_name[nm_idx + len("/node_modules/"):]
                        parts = after_nm.split("/")
                        is_direct = len(parts) == 2 and not parts[0].startswith(".")
                        is_scoped = (
                            len(parts) == 3
                            and parts[0].startswith("@")
                            and not parts[1].startswith(".")
                        )
                        if is_direct or is_scoped:
                            fobj = layer.extractfile(member)
                            if fobj is not None:
                                try:
                                    data = json.loads(fobj.read().decode(errors="replace"))
                                except Exception:
                                    continue
                                pkg_name = data.get("name", "")
                                installed_ver = data.get("version", "")
                                for incident in npm_incidents:
                                    for pkg in incident["malicious_packages"]:
                                        if pkg["name"] == pkg_name and pkg["version"] == installed_ver:
                                            findings.append(Finding(
                                                incident_id=incident["id"],
                                                category="node_modules",
                                                severity="CRITICAL",
                                                path=virtual_path,
                                                detail=(
                                                    f'{pkg_name}@{installed_ver} INSTALLED in {image_label} '
                                                    '— malicious code likely ran during the image build'
                                                ),
                                                remediation=(
                                                    'Rebuild image with a clean lockfile. '
                                                    'Rotate ALL credentials immediately.'
                                                ),
                                            ))
                                scripts = data.get("scripts", {})
                                for script_key, script_cmd in scripts.items():
                                    if (
                                        script_key in _DANGEROUS_SCRIPT_KEYS
                                        and _SUSPICIOUS_SCRIPT.search(
                                            script_cmd[:_SUSPICIOUS_SCRIPT_MAX_LEN]
                                        )
                                    ):
                                        findings.append(Finding(
                                            incident_id="supply-chain-risk",
                                            category="node_modules",
                                            severity="WARNING",
                                            path=virtual_path,
                                            detail=(
                                                f'{pkg_name}@{installed_ver}: suspicious {script_key} '
                                                f'script — {script_cmd[:100]}'
                                            ),
                                            remediation=(
                                                'Review and rebuild the image if this script is unexpected.'
                                            ),
                                        ))
                                        break
                                stats["node_modules_checked"] += 1

                # ── Hidden lockfile (.package-lock.json) ─────────────────────
                elif member_name.endswith("node_modules/.package-lock.json"):
                    fobj = layer.extractfile(member)
                    if fobj is not None:
                        findings.extend(
                            _docker_check_hidden_lockfile(fobj.read(), virtual_path, npm_incidents)
                        )
                        stats["hidden_lockfiles_checked"] += 1

                # ── pnpm .modules.yaml ────────────────────────────────────────
                elif member_name.endswith("node_modules/.modules.yaml"):
                    stats["hidden_lockfiles_checked"] += 1
                    fobj = layer.extractfile(member)
                    if fobj is not None:
                        content = fobj.read().decode(errors="replace")
                        for incident in npm_incidents:
                            for pkg in incident["malicious_packages"]:
                                name, bad_ver = pkg["name"], pkg["version"]
                                if re.search(
                                    rf'^\s+{re.escape(name)}:\s+{re.escape(bad_ver)}\s*$',
                                    content, re.MULTILINE,
                                ):
                                    safe = ", ".join(incident.get("safe_versions", ["see advisory"]))
                                    findings.append(Finding(
                                        incident_id=incident["id"],
                                        category="lockfile",
                                        severity="CRITICAL",
                                        path=virtual_path,
                                        detail=(
                                            f'pnpm .modules.yaml in Docker image records '
                                            f'{name}@{bad_ver} as resolved version'
                                        ),
                                        remediation=(
                                            f'Rebuild image at {name}@{safe}. Rotate credentials.'
                                        ),
                                    ))

                # ── Composer vendor/composer/installed.json ───────────────────
                elif member_name.endswith("vendor/composer/installed.json"):
                    stats["hidden_lockfiles_checked"] += 1
                    fobj = layer.extractfile(member)
                    if fobj is not None:
                        try:
                            data = json.loads(fobj.read().decode(errors="replace"))
                            pkgs = data.get("packages", data) if isinstance(data, dict) else data
                            for incident in incidents:
                                if incident.get("package_manager") != "composer":
                                    continue
                                for pkg in incident["malicious_packages"]:
                                    name, bad_ver = pkg["name"], pkg["version"]
                                    if any(
                                        e.get("name") == name and e.get("version") == bad_ver
                                        for e in pkgs
                                    ):
                                        findings.append(Finding(
                                            incident_id=incident["id"],
                                            category="installed_package",
                                            severity="CRITICAL",
                                            path=virtual_path,
                                            detail=(
                                                f'{name}@{bad_ver} installed via Composer in Docker image'
                                            ),
                                            remediation=(
                                                'Rebuild image with clean Composer dependencies. '
                                                'Rotate ALL credentials.'
                                            ),
                                        ))
                        except Exception:
                            pass

    except Exception as exc:
        findings.append(Finding(
            incident_id="scan-error",
            category="docker",
            severity="WARNING",
            path=f"{image_label}:{layer_hash}",
            detail=f"Could not parse Docker layer — scan inconclusive: {exc}",
            remediation="Inspect the layer manually: docker save <image> | tar -tv",
        ))

    return findings


# ── Filesystem walker ────────────────────────────────────────────────────────
#
# Single os.walk pass. Yields (path, kind) tuples.
# kind values:
#   "project_pkg"         — package.json in a project directory
#   "lockfile"            — lockfile in a project directory
#   "installed"           — package.json inside node_modules/<pkg>
#   "hidden_lockfile"     — node_modules/.package-lock.json (written before postinstall)
#   "pnp_zip"             — Yarn Berry PnP cache ZIP file
#   "pnpm_modules"        — node_modules/.modules.yaml (pnpm state file)
#   "composer_installed"  — vendor/composer/installed.json (Composer, written before scripts)
#
# node_modules traversal:
#   last == "node_modules" | ".pnpm"  → dependency store; descend into packages;
#                                       also yield .package-lock.json if present
#   parent == "node_modules" | ".pnpm" → package root; yield package.json,
#                                        recurse only into nested node_modules
#   else                               → project dir or Yarn Berry PnP cache
#
# Covers: npm flat (v3+), npm nested (v2, any depth), pnpm .pnpm store,
#         Yarn Berry PnP .yarn/cache ZIPs, Yarn Berry node-modules linker.

def walk_npm_files(root: str, stats: dict[str, int], since_ts: float | None = None):
    """
    Walk root yielding (path, kind) tuples for all relevant package manager files.

    since_ts: optional Unix timestamp. When provided, any node_modules directory
    whose .package-lock.json mtime predates it is skipped entirely (incident-response
    mode — only checks installs that could have occurred during the attack window).
    """
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        stats["dirs_visited"] += 1
        parts = dirpath.split(os.sep)
        last = parts[-1]
        parent = parts[-2] if len(parts) >= 2 else ""

        if last in ("node_modules", ".pnpm"):
            # Dependency store — descend into packages; keep .pnpm visible.
            # Also yield the hidden lockfile: written before postinstall runs,
            # survives self-deleting malware, present even when package-lock=false.
            if ".package-lock.json" in filenames:
                hidden_lf = os.path.join(dirpath, ".package-lock.json")
                # --since filter: skip subtrees installed before the attack window
                if since_ts is not None:
                    try:
                        if os.stat(hidden_lf).st_mtime < since_ts:
                            dirnames[:] = []
                            continue
                        yield hidden_lf, "hidden_lockfile"
                    except OSError:
                        pass  # file disappeared between glob and stat; skip it
                else:
                    yield hidden_lf, "hidden_lockfile"
            elif since_ts is not None:
                # No hidden lockfile (npm v6 or package-lock=false) — fall back to
                # the directory mtime as the proxy timestamp for the --since filter.
                try:
                    if os.stat(dirpath).st_mtime < since_ts:
                        dirnames[:] = []
                        continue
                except OSError:
                    pass
            # Also yield pnpm state file if present
            if ".modules.yaml" in filenames:
                yield os.path.join(dirpath, ".modules.yaml"), "pnpm_modules"
            dirnames[:] = [d for d in dirnames if not d.startswith(".") or d == ".pnpm"]

        elif parent in ("node_modules", ".pnpm"):
            if last.startswith("@"):
                # Scope directory (e.g. @vue, @babel) — not a package root; recurse
                # into its children without filtering so @scope/pkg dirs are visited.
                pass
            else:
                # Package root — yield its package.json, only recurse into nested node_modules
                if "package.json" in filenames:
                    yield os.path.join(dirpath, "package.json"), "installed"
                dirnames[:] = [d for d in dirnames if d == "node_modules"]

        elif parent.startswith("@"):
            # Package root inside a scope directory (e.g. node_modules/@vue/reactivity).
            # The scope dir was already allowed to recurse; now handle the package itself.
            if "package.json" in filenames:
                yield os.path.join(dirpath, "package.json"), "installed"
            dirnames[:] = [d for d in dirnames if d == "node_modules"]

        elif last == "cache" and parent == ".yarn":
            # Yarn Berry PnP cache — yield all ZIPs, do not recurse
            for fname in filenames:
                if fname.endswith(".zip"):
                    yield os.path.join(dirpath, fname), "pnp_zip"
            dirnames[:] = []

        else:
            # Normal project directory — prune system/build/tooling dirs in-place
            dirnames[:] = [d for d in dirnames if d not in PRUNE_DIRS]
            for fname in filenames:
                if fname == "package.json":
                    file_kind = "project_pkg"
                elif fname in LOCKFILE_NAMES:
                    file_kind = "lockfile"
                else:
                    continue  # not a file we care about; skip the stat call
                fpath = os.path.join(dirpath, fname)
                if since_ts is not None:
                    try:
                        if os.stat(fpath).st_mtime < since_ts:
                            continue
                    except OSError:
                        continue
                yield fpath, file_kind
            # Composer: yield vendor/composer/installed.json when present
            # (written by Composer before post-install-cmd scripts run)
            composer_installed = os.path.join(dirpath, "vendor", "composer", "installed.json")
            if os.path.isfile(composer_installed):
                if since_ts is None or (
                    os.stat(composer_installed).st_mtime >= since_ts
                ):
                    yield composer_installed, "composer_installed"


# ── Global package store scanning ────────────────────────────────────────────
#
# Global stores (Volta, nvm, fnm, Deno, Bun) sit outside ~/dev and are missed
# when --root is a project subdirectory. They are always scanned unless they
# fall inside the user-specified root (in which case the main walk covers them).

def _global_store_roots() -> list[Path]:
    """Return paths to global package stores, skipping non-existent ones."""
    system = platform.system()
    candidates: list[Path] = []

    # Volta (cross-platform: ~/.volta/)
    candidates.append(Path.home() / ".volta/tools/image/packages")

    # nvm (macOS / Linux)
    candidates.append(Path.home() / ".nvm/versions/node")

    # fnm — base dir is platform-specific
    if system == "Darwin":
        candidates.append(Path.home() / "Library/Application Support/fnm/node-versions")
    elif system == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            candidates.append(Path(local_app) / "fnm/node-versions")
    else:
        candidates.append(Path.home() / ".local/share/fnm/node-versions")

    # Deno npm cache
    deno_dir_env = os.environ.get("DENO_DIR")
    if deno_dir_env:
        candidates.append(Path(deno_dir_env) / "npm/registry.npmjs.org")
    elif system == "Darwin":
        candidates.append(Path.home() / "Library/Caches/deno/npm/registry.npmjs.org")
    elif system == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            candidates.append(Path(local_app) / "deno/npm/registry.npmjs.org")
    else:
        candidates.append(Path.home() / ".cache/deno/npm/registry.npmjs.org")

    # Bun global install cache
    candidates.append(Path.home() / ".bun/install/cache")

    return [p for p in candidates if p.exists()]


def _walk_global_store(store: Path):
    """Walk a global store yielding every package.json as an installed package."""
    for dirpath, dirnames, filenames in os.walk(str(store), followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        if "package.json" in filenames:
            yield os.path.join(dirpath, "package.json")


def check_npx_global_store(incidents: list[dict]) -> list[Finding]:
    """
    Scan ~/.npm/_npx for post-cleanup evidence of malicious npx invocations.

    Each subdirectory under _npx/ is an npx invocation context containing its
    own node_modules/.package-lock.json, written by npm arborist BEFORE
    postinstall scripts run. This survives self-deleting malware and is missed
    entirely by a project-level scan that only looks at project node_modules.

    Applies the same GHOST/STUB/LOCKFILE_HIT logic as check_hidden_lockfile.
    """
    npx_root = Path.home() / ".npm/_npx"
    if not npx_root.exists():
        return []
    findings = []
    for hidden_lf in npx_root.glob("*/node_modules/.package-lock.json"):
        findings.extend(check_hidden_lockfile(str(hidden_lf), incidents))
    return findings


def _pnpm_cas_root() -> Path | None:
    """Return the pnpm content-addressable store root for the current OS, or None."""
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library/pnpm/store/v3/files"
    if system == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", "")
        return Path(local_app) / "pnpm/store/v3/files" if local_app else None
    return Path.home() / ".local/share/pnpm/store/v3/files"


def check_pnpm_cas(incidents: list[dict]) -> list[Finding]:
    """
    Scan pnpm's content-addressable store for malicious package metadata.

    The store's *-index.json files are written by pnpm before postinstall runs
    and persist after `pnpm remove` (only cleared by `pnpm store prune`).
    Each index file carries top-level "name" and "version" fields (pnpm v7+
    store format). Earlier store versions omit these fields and are skipped.
    """
    cas_root = _pnpm_cas_root()
    if not cas_root or not cas_root.exists():
        return []

    npm_incidents = [i for i in incidents if i.get("package_manager", "npm") == "npm"]
    if not npm_incidents:
        return []

    # Map (name, version) → incident for O(1) matching and finding construction.
    incident_by_pkg: dict[tuple[str, str], dict] = {
        (pkg["name"], pkg["version"]): inc
        for inc in npm_incidents
        for pkg in inc["malicious_packages"]
    }

    findings = []
    for index_file in cas_root.glob("**/*-index.json"):
        try:
            meta = json.loads(index_file.read_text(errors="replace"))
        except Exception:
            continue
        name = meta.get("name", "")
        version = meta.get("version", "")
        if not name or not version:
            continue
        key = (name, version)
        if key in incident_by_pkg:
            incident = incident_by_pkg[key]
            findings.append(Finding(
                incident_id=incident["id"],
                category="node_modules",
                severity="CRITICAL",
                path=str(index_file),
                detail=(
                    f'{name}@{version} found in pnpm CAS store — '
                    'package metadata written before postinstall; persists after pnpm remove'
                ),
                remediation=(
                    'Run: pnpm store prune. '
                    'Rotate ALL credentials — pnpm CAS entry predates postinstall execution. '
                    'Engage incident response.'
                ),
            ))
    return findings


# ── Host-level checks (serial, fast) ─────────────────────────────────────────
#
# Each function reads a small number of files or runs a single subprocess.
# Not worth parallelising: lsof is ~0.5 s; all file checks are sub-ms.

def _expand(path: str) -> Path:
    """Expand env vars (%VAR% / $VAR) and ~ then resolve to an absolute path."""
    return Path(os.path.expandvars(path)).expanduser().resolve()


_ioc_terms_cache: dict[str, list[str]] = {}


def _ioc_search_terms(incident: dict) -> list[str]:
    """Return all IOC values from a single incident for plain-text scanning.

    Results are cached by incident ID: the expansion calls (_expand involves
    os.path.expandvars/expanduser/resolve) are pure functions of the IOC data
    and should not be recomputed on every call site invocation.
    """
    incident_id = incident["id"]
    if incident_id not in _ioc_terms_cache:
        terms = [ioc["value"] for ioc in incident.get("network_iocs", [])]
        terms += [str(_expand(ioc["path"])) for ioc in incident.get("file_iocs", [])]
        _ioc_terms_cache[incident_id] = terms
    return _ioc_terms_cache[incident_id]


def _shell_profile_paths() -> list[Path]:
    """Return the shell profile file paths for the current OS."""
    if platform.system() == "Windows":
        user_profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        return [
            user_profile / "Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1",
            user_profile / "Documents/PowerShell/Microsoft.PowerShell_profile.ps1",  # PS 7+
        ]
    # macOS and Linux share the same POSIX profile locations
    return [
        Path.home() / p for p in (
            ".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile",
            ".config/fish/config.fish",
        )
    ]


def host_file_artifacts(incidents: list[dict]) -> list[Finding]:
    """Check for RAT/dropper artifacts on the filesystem.

    Iterates file_iocs from all incidents, filtering to entries whose platform
    field matches the current OS, then checks whether each expanded path exists.
    Reports CRITICAL if any artifact is found (its presence confirms post-install
    execution, not just download).
    """
    sys_platform = {"Darwin": "macOS", "Windows": "Windows", "Linux": "Linux"}.get(
        platform.system(), platform.system()
    )
    findings = []
    for incident in incidents:
        for ioc in incident.get("file_iocs", []):
            if ioc["platform"] != sys_platform:
                continue
            path = _expand(ioc["path"])
            if path.exists():
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="file_artifact",
                    severity="CRITICAL",
                    path=str(path),
                    detail=f'RAT artifact found: {ioc["path"]}',
                    remediation=(
                        'System likely compromised. Isolate machine, rotate ALL credentials, '
                        'engage incident response. Remove file and check for persistence.'
                    ),
                ))
    return findings


def host_shell_profiles(incidents: list[dict]) -> list[Finding]:
    """Scan shell profile files for IOC strings that indicate persistence injection.

    IOC search terms include network IOC values (domains, IPs) and expanded
    file IOC paths from all incidents. A term appearing in a shell profile
    suggests the malware injected a loader or exfiltration hook on first run.
    Reports CRITICAL when any term is found in any profile.
    """
    profiles = _shell_profile_paths()
    findings = []
    for incident in incidents:
        terms = _ioc_search_terms(incident)
        for profile in profiles:
            if not profile.exists():
                continue
            try:
                content = profile.read_text(errors="replace")
            except OSError:
                continue
            matched_terms = [t for t in terms if t in content]
            if matched_terms:
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="shell_profile",
                    severity="CRITICAL",
                    path=str(profile),
                    detail=(
                        f'IOC term(s) found in shell profile — possible persistence: '
                        + ", ".join(f'"{t}"' for t in matched_terms[:3])
                        + (" …" if len(matched_terms) > 3 else "")
                    ),
                    remediation='Remove the injected line, rotate credentials, check scheduled tasks.',
                ))
    return findings


# ── Platform-specific persistence checks ─────────────────────────────────────

def _persistence_macos(incidents: list[dict]) -> list[Finding]:
    """Check macOS LaunchAgent/LaunchDaemon plist files for IOC string matches.

    Scans ~/Library/LaunchAgents, /Library/LaunchAgents, and /Library/LaunchDaemons.
    Known-vendor plists (com.apple.*, com.google.*, homebrew, etc.) are skipped to
    reduce false positives. Reports CRITICAL when a plist references any IOC term.
    """
    launch_dirs = [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ]
    findings = []
    for incident in incidents:
        terms = _ioc_search_terms(incident)
        for launch_dir in launch_dirs:
            if not launch_dir.exists():
                continue
            for plist in launch_dir.glob("*.plist"):
                if KNOWN_VENDOR_PLIST.match(plist.name):
                    continue
                try:
                    content = plist.read_text(errors="replace")
                except OSError:
                    continue
                for term in terms:
                    if term in content:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="launch_agent",
                            severity="CRITICAL",
                            path=str(plist),
                            detail=f'LaunchAgent references C2 IOC "{term}" — persistent RAT likely installed',
                            remediation='launchctl unload + delete plist + reboot. Rotate all credentials.',
                        ))
                        break
    return findings


def _persistence_linux(incidents: list[dict]) -> list[Finding]:
    """Check Linux crontab, systemd user units, and XDG autostart entries for IOC strings.

    Checks: user crontab (`crontab -l`), ~/.config/systemd/user/*.service,
    and ~/.config/autostart/*.desktop. Reports CRITICAL when any entry references
    an IOC term from the incident's network or file IOC lists.
    """
    findings = []

    # User crontab — read once; output is static for the life of this process
    cron_out = ""
    try:
        cron_out = subprocess.check_output(
            ["crontab", "-l"], text=True, stderr=subprocess.DEVNULL, timeout=5
        )
    except Exception:
        pass

    for incident in incidents:
        terms = _ioc_search_terms(incident)

        if cron_out:
            for term in terms:
                if term in cron_out:
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="launch_agent",
                        severity="CRITICAL",
                        path="crontab",
                        detail=f'Crontab contains IOC "{term}" — scheduled persistence',
                        remediation='Run crontab -e and remove the malicious entry. Rotate credentials.',
                    ))

        # systemd user services
        systemd_user = Path.home() / ".config/systemd/user"
        if systemd_user.exists():
            for unit in systemd_user.glob("*.service"):
                try:
                    content = unit.read_text(errors="replace")
                except OSError:
                    continue
                for term in terms:
                    if term in content:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="launch_agent",
                            severity="CRITICAL",
                            path=str(unit),
                            detail=f'systemd user service references IOC "{term}"',
                            remediation='systemctl --user disable <unit>, delete file, rotate credentials.',
                        ))
                        break

        # XDG autostart
        autostart = Path.home() / ".config/autostart"
        if autostart.exists():
            for desktop_file in autostart.glob("*.desktop"):
                try:
                    content = desktop_file.read_text(errors="replace")
                except OSError:
                    continue
                for term in terms:
                    if term in content:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="launch_agent",
                            severity="CRITICAL",
                            path=str(desktop_file),
                            detail=f'XDG autostart entry references IOC "{term}"',
                            remediation='Delete the .desktop file. Rotate credentials.',
                        ))
                        break

    return findings


def _persistence_windows(incidents: list[dict]) -> list[Finding]:
    """Check Windows startup folders and Registry Run keys for IOC string references.

    Checks: %APPDATA%/Microsoft/Windows/Start Menu/Programs/Startup,
    %PROGRAMDATA%/Microsoft/Windows/Start Menu/Programs/Startup, and
    HKCU/HKLM Run/RunOnce registry keys (read via `reg query`). Reports
    CRITICAL when any entry references an IOC term.
    """
    startup_dirs = []
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        startup_dirs.append(
            Path(user_profile) / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        )
    program_data = os.environ.get("PROGRAMDATA", "")
    if program_data:
        startup_dirs.append(
            Path(program_data) / "Microsoft/Windows/Start Menu/Programs/StartUp"
        )

    # Registry Run keys — read once; content is static for the life of this process
    reg_outputs: dict[str, str] = {}
    for reg_key in (
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ):
        try:
            reg_outputs[reg_key] = subprocess.check_output(
                ["reg", "query", reg_key],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
        except Exception:
            pass

    findings = []
    for incident in incidents:
        terms = _ioc_search_terms(incident)

        # Startup folder — scripts that run at login
        for startup_dir in startup_dirs:
            if not startup_dir.exists():
                continue
            for item in startup_dir.iterdir():
                if item.suffix.lower() not in (".vbs", ".ps1", ".cmd", ".bat", ".exe"):
                    continue
                try:
                    content = item.read_text(errors="replace")
                except OSError:
                    continue
                for term in terms:
                    if term in content:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="launch_agent",
                            severity="CRITICAL",
                            path=str(item),
                            detail=f'Startup item references IOC "{term}"',
                            remediation='Delete the startup item and check registry Run keys. Rotate credentials.',
                        ))
                        break

        # Registry Run keys
        for reg_key, out in reg_outputs.items():
            for line in out.splitlines():
                for term in terms:
                    if term in line:
                        findings.append(Finding(
                            incident_id=incident["id"],
                            category="launch_agent",
                            severity="CRITICAL",
                            path=reg_key,
                            detail=f'Registry Run key references IOC "{term}": {line.strip()[:80]}',
                            remediation='Delete the registry value with regedit or reg delete. Rotate credentials.',
                        ))
                        break

    return findings


def host_persistence(incidents: list[dict]) -> list[Finding]:
    """Dispatch to the platform-specific persistence check."""
    system = platform.system()
    if system == "Darwin":
        return _persistence_macos(incidents)
    if system == "Linux":
        return _persistence_linux(incidents)
    if system == "Windows":
        return _persistence_windows(incidents)
    return []


def host_windows_prefetch(incidents: list[dict]) -> list[Finding]:
    """
    Check Windows Prefetch for node.exe execution within the attack window.

    Prefetch files live in C:\\Windows\\Prefetch\\ which requires admin to delete,
    so this artifact CANNOT be removed by a user-space postinstall script.
    NODE.EXE-*.pf mtime = the most recent execution time of node.exe.

    Limitation: any npm usage during the window triggers this, not just the
    malicious install. Treat as a corroborating signal, not a standalone proof.
    """
    if platform.system() != "Windows":
        return []

    prefetch_dir = Path(r"C:\Windows\Prefetch")
    if not prefetch_dir.exists():
        return []

    findings = []
    for incident in incidents:
        window_start = incident.get("attack_window_start_utc")
        window_end   = incident.get("attack_window_end_utc")
        if not window_start or not window_end:
            continue

        try:
            start = datetime.fromisoformat(window_start).replace(tzinfo=timezone.utc)
            end = datetime.fromisoformat(window_end).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        for pf_file in prefetch_dir.glob("NODE.EXE-*.pf"):
            try:
                mtime = datetime.fromtimestamp(pf_file.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if start <= mtime <= end:
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="file_artifact",
                    severity="HIGH",
                    path=str(pf_file),
                    detail=(
                        f'node.exe Prefetch entry last modified {mtime.isoformat()} — '
                        f'within attack window ({window_start} – {window_end}). '
                        'Node ran during the period the malicious package was live on npm.'
                    ),
                    remediation=(
                        'Corroborating signal: node ran during the attack window. '
                        'Check hidden lockfile and npm cache for confirmation. '
                        'Rotate credentials if other checks confirm the malicious package was installed.'
                    ),
                ))

    return findings


def host_network(incidents: list[dict]) -> list[Finding]:
    """Check for active connections to known C2 IPs (cross-platform)."""
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output(
                ["netstat", "-an"], stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
        else:
            try:
                output = subprocess.check_output(
                    ["lsof", "-i", "TCP", "-n", "-P"],
                    stderr=subprocess.DEVNULL, text=True, timeout=10,
                )
            except FileNotFoundError:
                # lsof absent on some minimal Linux installs — fall back to ss
                output = subprocess.check_output(
                    ["ss", "-tn"], stderr=subprocess.DEVNULL, text=True, timeout=10,
                )
    except Exception:
        return []

    findings = []
    for incident in incidents:
        for ioc in incident.get("network_iocs", []):
            if ioc.get("type") != "ip":
                continue
            search = f'{ioc["value"]}:{ioc["port"]}' if ioc.get("port") else ioc["value"]
            for line in output.splitlines():
                if search in line and "LISTEN" not in line:
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="network",
                        severity="CRITICAL",
                        path="network",
                        detail=f'Active connection to C2 {search}: {line.strip()}',
                        remediation='Isolate machine immediately. RAT is live. Engage IR.',
                    ))
    return findings


def host_npm_cache(incidents: list[dict]) -> list[Finding]:
    """
    Check npm's content-addressable cache for evidence that a malicious tarball
    was downloaded. Written at download time — before postinstall runs — and
    persists even after the malware self-destructs from node_modules.

    Cache key format (verified from make-fetch-happen source):
      "make-fetch-happen:request-cache:https://registry.npmjs.org/<pkg>/-/<pkg>-<ver>.tgz"
    SHA1 of that key → path is index-v5/[0:2]/[2:4]/[4:].
    """
    npm_cache = Path.home() / ".npm/_cacache/index-v5"
    if not npm_cache.exists():
        return []

    findings = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            # Scoped packages (@scope/pkg) use the unscoped name in the tarball
            # filename: registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz
            unscoped_name = name.split("/")[-1]
            cache_key = (
                f"make-fetch-happen:request-cache:"
                f"https://registry.npmjs.org/{name}/-/{unscoped_name}-{bad_ver}.tgz"
            )
            key_hash = hashlib.sha1(cache_key.encode()).hexdigest()
            cache_path = npm_cache / key_hash[:2] / key_hash[2:4] / key_hash[4:]
            if cache_path.exists():
                findings.append(Finding(
                    incident_id=incident["id"],
                    category="file_artifact",
                    severity="HIGH",
                    path=str(cache_path),
                    detail=(
                        f'npm cache entry for {name}@{bad_ver} found — '
                        'tarball was fetched to this machine (download confirmed; postinstall not verified)'
                    ),
                    remediation=(
                        'Check npm logs and hidden lockfile for postinstall execution evidence '
                        'before rotating credentials. Run: npm cache clean --force.'
                    ),
                ))
    return findings


def host_npm_logs(incidents: list[dict]) -> list[Finding]:
    """
    Check npm debug logs for two distinct signals:

    1. HTTP fetch line (pre-extraction, written at download time — same temporal
       position as the cache entry and before postinstall runs):
         "http fetch GET 200 https://registry.npmjs.org/<pkg>/-/<pkg>-<ver>.tgz"

    2. Lifecycle execution line (written during postinstall — direct proof of
       code execution, but written after the malware is already running):
         "info run <pkg>@<ver> postinstall ..."

    Signal 1 is the stronger forensic artifact: it cannot have been written by
    the malware itself (the malware hadn't run yet), so it cannot be a planted
    false positive.
    """
    npm_logs_dir = Path.home() / ".npm/_logs"
    if not npm_logs_dir.exists():
        return []

    findings = []
    all_log_files = sorted(npm_logs_dir.glob("*.log"), reverse=True)
    log_files = all_log_files[:20]
    if len(all_log_files) > 20:
        findings.append(Finding(
            incident_id="scan-info",
            category="file_artifact",
            severity="WARNING",
            path=str(npm_logs_dir),
            detail=(
                f"npm log scan capped at 20 of {len(all_log_files)} log files "
                "— older logs not checked; the malicious install may predate the scanned window"
            ),
            remediation=(
                "Manually grep older logs: "
                "grep -r 'axios\\|plain-crypto-js' ~/.npm/_logs/"
            ),
        ))

    # Pre-compile per-(incident, pkg) patterns outside the log-file loop to avoid
    # redundant compilation on every log file (up to 20 × N_incidents × N_pkgs).
    compiled_patterns: list[tuple[re.Pattern, re.Pattern, dict, dict]] = []
    for incident in incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            unscoped = name.split("/")[-1]
            compiled_patterns.append((
                re.compile(
                    rf'http fetch GET \d+ https://registry\.npmjs\.org/'
                    rf'{re.escape(name)}/-/{re.escape(unscoped)}-{re.escape(bad_ver)}\.tgz',
                    re.IGNORECASE,
                ),
                re.compile(
                    rf'info run {re.escape(name)}@{re.escape(bad_ver)} postinstall',
                    re.IGNORECASE,
                ),
                incident,
                pkg,
            ))

    for fetch_pattern, run_pattern, incident, pkg in compiled_patterns:
        name, bad_ver = pkg["name"], pkg["version"]

        # Scan all log files before emitting — npm may rotate logs between the
        # download and the postinstall run, so a CRITICAL run_pattern match in an
        # older file must not be masked by a HIGH fetch_pattern match in a newer one.
        best_severity: str | None = None
        best_log: Path | None = None
        for log_file in log_files:
                try:
                    content = log_file.read_text(errors="replace")
                except OSError:
                    continue

                if run_pattern.search(content):
                    best_severity = "CRITICAL"
                    best_log = log_file
                    break  # can't improve; stop scanning
                elif fetch_pattern.search(content) and best_severity is None:
                    best_severity = "HIGH"
                    best_log = log_file
                    # keep scanning — a CRITICAL may still be found in an older file

        if best_severity == "CRITICAL":
            findings.append(Finding(
                incident_id=incident["id"],
                category="file_artifact",
                severity="CRITICAL",
                path=str(best_log),
                detail=(
                    f'npm log records postinstall execution of {name}@{bad_ver} — '
                    'malicious code ran on this machine (execution-time signal)'
                ),
                remediation='Rotate ALL credentials immediately. Engage incident response.',
            ))
        elif best_severity == "HIGH":
            findings.append(Finding(
                incident_id=incident["id"],
                category="file_artifact",
                severity="HIGH",
                path=str(best_log),
                detail=(
                    f'npm log records tarball download of {name}@{bad_ver} '
                    '(pre-execution signal — postinstall not confirmed in logs)'
                ),
                remediation=(
                    'Corroborate with hidden lockfile or file artifact checks. '
                    'Rotate credentials only if installation is confirmed.'
                ),
            ))

    return findings


def host_npmrc_hygiene() -> list[Finding]:
    """
    Check .npmrc for configurations that increase supply chain attack risk.

    Two key susceptibilities:
    - ignore-scripts not enabled: postinstall scripts in ANY dependency run
      automatically on npm install — this is the exact vector the axios RAT used.
    - strict-ssl=false: disables TLS verification, enabling MITM package substitution.
    """
    findings = []
    npmrc_paths = [Path.home() / ".npmrc", Path(".npmrc")]
    ignore_scripts_set = False

    for npmrc in npmrc_paths:
        if not npmrc.exists():
            continue
        try:
            content = npmrc.read_text(errors="replace")
        except OSError:
            continue
        if re.search(r'^\s*ignore-scripts\s*=\s*true', content, re.MULTILINE):
            ignore_scripts_set = True
        if re.search(r'^\s*strict-ssl\s*=\s*false', content, re.MULTILINE):
            findings.append(Finding(
                incident_id="config-risk",
                category="config",
                severity="WARNING",
                path=str(npmrc),
                detail="strict-ssl=false disables TLS verification — MITM package substitution is possible",
                remediation="Remove strict-ssl=false from .npmrc.",
            ))

    if not ignore_scripts_set:
        npmrc_exists = any(p.exists() for p in npmrc_paths)
        # Report the path of the first extant .npmrc if any; otherwise point to
        # the conventional global location so the user knows where to create it.
        report_npmrc = next(
            (str(p) for p in npmrc_paths if p.exists()),
            str(Path.home() / ".npmrc"),
        )
        findings.append(Finding(
            incident_id="config-risk",
            category="config",
            severity="WARNING",
            path=report_npmrc,
            detail=(
                "ignore-scripts is not enabled — postinstall/preinstall scripts in ANY "
                "dependency execute automatically during npm install (the axios RAT used this vector)"
                + ("" if npmrc_exists else " — no .npmrc found")
            ),
            remediation=(
                "Add 'ignore-scripts=true' to ~/.npmrc, or use @lavamoat/allow-scripts "
                "for a per-package allowlist of packages that legitimately need install scripts."
            ),
        ))

    return findings


# ── Cross-ecosystem host checks ───────────────────────────────────────────────
#
# Each function scans a specific package ecosystem for known-malicious versions.
# These are serial host-level checks (fast, O(N) where N is installed packages).

def _pip_site_packages() -> list[Path]:
    """Return all Python site-packages directories present on this machine."""
    paths: set[Path] = set()
    for scheme in sysconfig.get_scheme_names():
        try:
            p = sysconfig.get_path("purelib", scheme)
            if p:
                paths.add(Path(p))
        except (KeyError, TypeError):
            pass
    return [p for p in paths if p.exists()]


def host_pip_packages(incidents: list[dict]) -> list[Finding]:
    """
    Scan Python site-packages for known-malicious package versions.

    Primary artifact: <pkg>-<ver>.dist-info/RECORD — written by pip/uv/Poetry
    after wheel extraction, outside the package directory. GHOST detection: if
    the .dist-info directory exists but the package directory is gone, the
    malware ran and self-deleted.

    Also checks uv archive cache (~/.cache/uv/archive-v0/) and Poetry's artifact
    cache (~/.cache/pypoetry/artifacts/) for download evidence.
    """
    pip_incidents = [i for i in incidents if i.get("package_manager") == "pip"]
    if not pip_incidents:
        return []

    def _normalise(name: str) -> str:
        return re.sub(r"[-_.]+", "_", name).lower()

    findings = []
    site_packages_dirs = _pip_site_packages()

    for incident in pip_incidents:
        for pkg in incident["malicious_packages"]:
            name, bad_ver = pkg["name"], pkg["version"]
            norm = _normalise(name)

            # Check each site-packages directory
            for sp in site_packages_dirs:
                dist_info = sp / f"{norm}-{bad_ver}.dist-info"
                pkg_dir = sp / norm
                if not dist_info.exists():
                    continue
                if not pkg_dir.exists():
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="installed_package",
                        severity="CRITICAL",
                        path=str(dist_info),
                        detail=(
                            f'{name}@{bad_ver} .dist-info exists but package directory MISSING — '
                            'self-destructing malware almost certainly executed'
                        ),
                        remediation='URGENT: rotate ALL credentials. Malware ran and removed itself.',
                    ))
                else:
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="installed_package",
                        severity="CRITICAL",
                        path=str(pkg_dir),
                        detail=f'{name}@{bad_ver} is INSTALLED (pip) — malicious code may execute on import',
                        remediation=f'pip uninstall {name}. Rotate credentials.',
                    ))

            # uv archive cache (persists after uninstall)
            uv_cache = Path.home() / ".cache/uv/archive-v0"
            if platform.system() == "Darwin":
                uv_cache = Path.home() / "Library/Caches/uv/archive-v0"
            if uv_cache.exists():
                for dist_info in uv_cache.glob(f"*/{norm}-{bad_ver}.dist-info"):
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="file_artifact",
                        severity="CRITICAL",
                        path=str(dist_info),
                        detail=f'{name}@{bad_ver} found in uv archive cache — was downloaded and installed',
                        remediation='Run: uv cache clean. Rotate credentials.',
                    ))

            # Poetry artifact cache (persists after removal)
            poetry_cache = Path.home() / ".cache/pypoetry/artifacts"
            if platform.system() == "Darwin":
                poetry_cache = Path.home() / "Library/Caches/pypoetry/artifacts"
            if poetry_cache.exists():
                for whl in poetry_cache.glob(f"*/{name}-{bad_ver}-*.whl"):
                    findings.append(Finding(
                        incident_id=incident["id"],
                        category="file_artifact",
                        severity="CRITICAL",
                        path=str(whl),
                        detail=f'{name}@{bad_ver} wheel found in Poetry cache — was downloaded',
                        remediation='Run: poetry cache clear . --all. Rotate credentials.',
                    ))

    return findings


def host_other_ecosystems(incidents: list[dict]) -> list[Finding]:
    """
    Check forensic artifacts for gem, Cargo, Go modules, Maven, Gradle,
    Homebrew, and Chocolatey package installations.
    Each uses the package manager's own metadata cache as the primary artifact.
    """
    findings = []

    for incident in incidents:
        pm = incident.get("package_manager", "")
        pkgs = incident["malicious_packages"]

        if pm == "gem":
            # RubyGems: specifications/<pkg>-<ver>.gemspec survives package dir removal
            for pkg in pkgs:
                name, bad_ver = pkg["name"], pkg["version"]
                for gemspec in Path.home().glob(f".gem/ruby/*/specifications/{name}-{bad_ver}.gemspec"):
                    pkg_dir = gemspec.parent.parent / "gems" / f"{name}-{bad_ver}"
                    status = "GHOST (self-destructed)" if not pkg_dir.exists() else "INSTALLED"
                    findings.append(Finding(
                        incident_id=incident["id"], category="installed_package",
                        severity="CRITICAL", path=str(gemspec),
                        detail=f'gem {name}-{bad_ver} gemspec found — {status}',
                        remediation=f'gem uninstall {name} -v {bad_ver}. Rotate credentials.',
                    ))
                # rbenv
                for gemspec in Path.home().glob(f".rbenv/versions/*/lib/ruby/gems/*/specifications/{name}-{bad_ver}.gemspec"):
                    findings.append(Finding(
                        incident_id=incident["id"], category="installed_package",
                        severity="CRITICAL", path=str(gemspec),
                        detail=f'gem {name}-{bad_ver} gemspec found in rbenv',
                        remediation=f'gem uninstall {name} -v {bad_ver}. Rotate credentials.',
                    ))

        elif pm == "cargo":
            # Cargo: .crate files in registry/cache are read-only — cannot be self-deleted
            for pkg in pkgs:
                name, bad_ver = pkg["name"], pkg["version"]
                for crate in Path.home().glob(f".cargo/registry/cache/*/{name}-{bad_ver}.crate"):
                    findings.append(Finding(
                        incident_id=incident["id"], category="file_artifact",
                        severity="CRITICAL", path=str(crate),
                        detail=f'Cargo crate {name}-{bad_ver} in registry cache (read-only, cannot be self-deleted)',
                        remediation='cargo clean. Check Cargo.toml. Rotate credentials if build.rs ran.',
                    ))

        elif pm == "go":
            # Go modules: .info files written at download time, before any build
            for pkg in pkgs:
                name, bad_ver = pkg["name"], pkg["version"]
                encoded = re.sub(r'[A-Z]', lambda m: '!' + m.group(0).lower(), name)
                info = Path.home() / "go" / "pkg" / "mod" / "cache" / "download" / encoded / "@v" / f"{bad_ver}.info"
                if info.exists():
                    findings.append(Finding(
                        incident_id=incident["id"], category="file_artifact",
                        severity="CRITICAL", path=str(info),
                        detail=f'Go module {name}@{bad_ver} download info found — was fetched',
                        remediation='go clean -modcache. Check go.sum. Rotate credentials if init() ran.',
                    ))

        elif pm == "maven":
            for pkg in pkgs:
                name, bad_ver = pkg["name"], pkg["version"]
                group_id = pkg.get("group_id", "")
                if not group_id:
                    continue
                group_path = group_id.replace(".", os.sep)
                marker = Path.home() / ".m2" / "repository" / group_path / name / bad_ver / "_remote.repositories"
                if marker.exists():
                    findings.append(Finding(
                        incident_id=incident["id"], category="file_artifact",
                        severity="CRITICAL", path=str(marker),
                        detail=f'Maven artifact {group_id}:{name}:{bad_ver} in local repository',
                        remediation='Delete ~/.m2/repository/' + group_path + '/' + name + '/' + bad_ver,
                    ))

        elif pm == "homebrew" and platform.system() == "Darwin":
            for pkg in pkgs:
                name, bad_ver = pkg["name"], pkg["version"]
                # Try to find brew prefix
                brew_bin = shutil.which("brew")
                brew_prefix = Path(brew_bin).parent.parent if brew_bin else (
                    Path("/opt/homebrew") if Path("/opt/homebrew").exists() else Path("/usr/local")
                )
                receipt = brew_prefix / "Cellar" / name / bad_ver / "INSTALL_RECEIPT.json"
                if receipt.exists():
                    findings.append(Finding(
                        incident_id=incident["id"], category="file_artifact",
                        severity="CRITICAL", path=str(receipt),
                        detail=f'Homebrew formula {name}-{bad_ver} INSTALL_RECEIPT.json found',
                        remediation=f'brew uninstall {name}. Rotate credentials.',
                    ))
                # Download cache (outside keg, more persistent).
                brew_dl_cache = Path.home() / "Library/Caches/Homebrew/downloads"
                for dl in brew_dl_cache.glob(f"*--{name}-{bad_ver}.*"):
                    findings.append(Finding(
                        incident_id=incident["id"], category="file_artifact",
                        severity="CRITICAL", path=str(dl),
                        detail=f'Homebrew download cache entry for {name}-{bad_ver}',
                        remediation=f'brew cleanup. Rotate credentials.',
                    ))

        elif pm == "chocolatey" and platform.system() == "Windows":
            choco_log = Path(r"C:\ProgramData\chocolatey\logs\chocolatey.log")
            if choco_log.exists():
                # Read once and pre-compile patterns outside the per-package loop.
                try:
                    choco_content = choco_log.read_text(errors="replace").splitlines()
                except OSError:
                    choco_content = []
                for pkg in pkgs:
                    name, bad_ver = pkg["name"], pkg["version"]
                    pattern = re.compile(rf'{re.escape(name)}.*{re.escape(bad_ver)}', re.IGNORECASE)
                    for line in choco_content:
                        if pattern.search(line):
                            findings.append(Finding(
                                incident_id=incident["id"], category="file_artifact",
                                severity="CRITICAL", path=str(choco_log),
                                detail=f'Chocolatey log records install of {name} {bad_ver}: {line.strip()[:80]}',
                                remediation=f'choco uninstall {name}. Rotate credentials.',
                            ))
                            break

    return findings


# ── OSV.dev live advisory query (--online) ───────────────────────────────────

def _query_osv(packages: list[tuple[str, str, str]]) -> tuple[list[Finding], int]:
    """
    Batch-query OSV.dev for known vulnerabilities in discovered packages.

    packages: list of (name, version, ecosystem) tuples.
    Returns (findings, queried_count) where queried_count is the number of packages
    successfully sent to OSV (batches that failed are excluded from the count).
    Reports CRITICAL for MAL-* advisories, HIGH for all others.
    Batches in groups of ≤1000 per request (OSV API limit).
    Uses urllib.request (stdlib) — zero external dependencies.
    """
    if not packages:
        return [], 0

    # Deduplicate while preserving order
    deduped = list(dict.fromkeys(packages))

    findings: list[Finding] = []
    batch_size = 1000
    queried = 0  # tracks packages in batches that were successfully sent

    for i in range(0, len(deduped), batch_size):
        batch = deduped[i : i + batch_size]
        queries = [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version, ecosystem in batch
        ]
        payload = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/querybatch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read(4 * 1024 * 1024))  # 4 MB cap
        except Exception as exc:
            print(f"Warning: OSV query failed: {exc}", file=sys.stderr)
            continue

        results = data.get("results", [])
        if len(results) < len(batch):
            print(
                f"Warning: OSV returned {len(results)} results for {len(batch)} queries"
                " — coverage may be incomplete",
                file=sys.stderr,
            )

        queried += len(batch)

        for j, osv_result in enumerate(results):
            if j >= len(batch):
                break  # API returned more results than queries — defensive stop
            vulns = osv_result.get("vulns", [])
            if not vulns:
                continue
            name, version, ecosystem = batch[j]
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                if not vuln_id:
                    continue
                sev: Severity = "CRITICAL" if vuln_id.startswith("MAL-") else "HIGH"
                summary = vuln.get("summary", "")
                aliases = vuln.get("aliases", [])
                detail = f'{name}@{version} ({ecosystem}): {vuln_id}'
                if aliases:
                    detail += f' (also: {", ".join(aliases[:3])})'
                if summary:
                    detail += f' — {summary[:200]}'
                findings.append(Finding(
                    incident_id=f"osv-live:{vuln_id}",
                    category="node_modules",
                    severity=sev,
                    path=f"{ecosystem}/{name}@{version}",
                    detail=detail,
                    remediation=f"See https://osv.dev/vulnerability/{vuln_id}",
                ))

    return findings, queried


# ── Scanner orchestrator ─────────────────────────────────────────────────────

class Scanner:
    def __init__(self, root: Path, iocs: dict[str, Any]) -> None:
        self.root = root
        self.incidents = iocs["incidents"]  # all incidents; each checker gates on package_manager

    def run(
        self,
        workers: int,
        show_progress: bool = True,
        since_ts: float | None = None,
        online: bool = False,
        host: bool = True,
    ) -> ScanResult:
        result = ScanResult(root=str(self.root))
        incidents = self.incidents

        # ── Parallel file scan ────────────────────────────────────────────────
        # Main thread walks the filesystem (producer).
        # Workers parse files and check against the IOC database (consumers).
        # add_done_callback keeps memory O(workers) — no list of all futures needed.

        findings: list[Finding] = []
        findings_lock = threading.Lock()
        stats = result.stats
        installed_for_osv: list[tuple[str, str]] = []  # (path, ecosystem) for --online

        # Subset of incidents by package manager for type-specific checkers
        npm_incidents = [i for i in incidents if i.get("package_manager", "npm") == "npm"]

        def collect(future):
            try:
                found = future.result()
                if found:
                    with findings_lock:
                        findings.extend(found)
            except Exception as exc:
                print(f"Warning: worker error during scan: {exc}", file=sys.stderr)

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scanner") as pool:
            # Main filesystem walk
            for path, kind in walk_npm_files(str(self.root), stats, since_ts):
                if kind == "project_pkg":
                    stats["package_json_checked"] += 1
                    pool.submit(check_package_json, path, npm_incidents).add_done_callback(collect)
                elif kind == "lockfile":
                    stats["lockfiles_checked"] += 1
                    pool.submit(check_lockfile, path, npm_incidents).add_done_callback(collect)
                elif kind == "installed":
                    stats["node_modules_checked"] += 1
                    pool.submit(check_installed, path, npm_incidents).add_done_callback(collect)
                    if online:
                        installed_for_osv.append((path, "npm"))
                elif kind == "pnp_zip":
                    stats["node_modules_checked"] += 1
                    pool.submit(check_pnp_zip, path, npm_incidents).add_done_callback(collect)
                elif kind == "hidden_lockfile":
                    stats["hidden_lockfiles_checked"] += 1
                    pool.submit(check_hidden_lockfile, path, npm_incidents).add_done_callback(collect)
                elif kind == "pnpm_modules":
                    stats["lockfiles_checked"] += 1
                    pool.submit(check_pnpm_modules_yaml, path, npm_incidents).add_done_callback(collect)
                elif kind == "composer_installed":
                    stats["lockfiles_checked"] += 1
                    pool.submit(check_composer_installed, path, incidents).add_done_callback(collect)

                if show_progress and stats["dirs_visited"] % 500 == 0:
                    total_files = (
                        stats["package_json_checked"]
                        + stats["lockfiles_checked"]
                        + stats["node_modules_checked"]
                    )
                    print(
                        f"\r  {styled('Scanning...', DIM)} "
                        f"{stats['dirs_visited']:,} dirs | {total_files:,} files",
                        end="", flush=True,
                    )

            # Global package stores not covered by the user-specified root
            for store_root in _global_store_roots():
                if not store_root.is_relative_to(self.root):
                    for path in _walk_global_store(store_root):
                        stats["node_modules_checked"] += 1
                        pool.submit(check_installed, path, npm_incidents).add_done_callback(collect)

        if show_progress:
            print("\r" + " " * 70 + "\r", end="", flush=True)

        result.findings.extend(findings)

        if host:
            # Serial host-level checks (all platforms)
            for host_check in (
                host_file_artifacts,
                host_shell_profiles,
                host_persistence,
                host_windows_prefetch,
                host_network,
            ):
                result.findings.extend(host_check(incidents))

            # npm forensic evidence (written before postinstall; survives self-deleting malware)
            for host_check in (host_npm_cache, host_npm_logs):
                result.findings.extend(host_check(npm_incidents))

            # Global store forensics with dedicated parsers (not routed through _walk_global_store)
            npx_root = Path.home() / ".npm/_npx"
            if not npx_root.is_relative_to(self.root):
                result.findings.extend(check_npx_global_store(npm_incidents))
            pnpm_cas_root = _pnpm_cas_root()
            if pnpm_cas_root is not None and not pnpm_cas_root.is_relative_to(self.root):
                result.findings.extend(check_pnpm_cas(npm_incidents))

            # Cross-ecosystem checks (pip, conda, gem, cargo, go, homebrew, chocolatey)
            result.findings.extend(host_pip_packages(incidents))
            result.findings.extend(host_other_ecosystems(incidents))

        # Susceptibility / configuration hygiene checks
        result.findings.extend(host_npmrc_hygiene())

        # ── Live OSV.dev advisory query (--online) ────────────────────────────
        if online and installed_for_osv:
            if show_progress:
                print(
                    f"  {styled('Querying OSV.dev...', DIM)} "
                    f"{len(installed_for_osv):,} packages",
                    flush=True,
                )
            pkg_tuples: list[tuple[str, str, str]] = []
            for pkg_path, ecosystem in installed_for_osv:
                try:
                    data = json.loads(Path(pkg_path).read_text(errors="replace"))
                    pkg_name = data.get("name", "")
                    pkg_ver = data.get("version", "")
                    if pkg_name and pkg_ver:
                        pkg_tuples.append((pkg_name, pkg_ver, ecosystem))
                except Exception:
                    pass
            if pkg_tuples:
                osv_findings, osv_count = _query_osv(pkg_tuples)
                result.findings.extend(osv_findings)
                stats["online_advisories_checked"] = osv_count
            else:
                stats["online_advisories_checked"] = 0

        return result

    def scan_docker_images(
        self,
        images: list[str],
        stats: dict[str, int],
        since_ts: float | None = None,
        top_layers: int = 5,
        show_progress: bool = True,
    ) -> list[Finding]:
        """
        Scan Docker images for supply chain IOCs using `docker save`.

        images: list of image names/tags to scan. Pass [] to scan all local images.
        top_layers: only scan the N most-recently added layers (base OS layers are trusted).
            Pass 0 to scan all layers.
        since_ts: skip layers whose mtime predates this Unix timestamp (--since filter).

        Requires `docker` CLI in PATH. Returns [] and emits a warning if unavailable.
        """
        if shutil.which("docker") is None:
            print("Warning: 'docker' not found in PATH — skipping Docker scan.", file=sys.stderr)
            return []

        if not images:
            # List all local images
            try:
                proc = subprocess.run(
                    ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True, text=True, check=True,
                )
                images = [
                    line.strip()
                    for line in proc.stdout.splitlines()
                    if line.strip()
                    and not line.strip().endswith(":<none>")
                    and not line.strip().startswith("<none>")
                ]
            except subprocess.CalledProcessError as exc:
                print(
                    f"Warning: could not list Docker images: "
                    f"{exc.stderr.strip() if exc.stderr else exc}",
                    file=sys.stderr,
                )
                return []

        if not images:
            return []

        stats.setdefault("docker_images_scanned", 0)
        stats.setdefault("docker_layers_scanned", 0)
        # Pre-filter once; _docker_scan_layer receives this instead of recomputing
        # the filtered list on every layer across every image.
        npm_incidents = [i for i in self.incidents if i.get("package_manager", "npm") == "npm"]

        all_findings: list[Finding] = []

        for image_name in images:
            if show_progress:
                print(
                    f"\r  {styled('Docker:', DIM)} {image_name:<50}",
                    end="", flush=True,
                )

            try:
                with tempfile.TemporaryFile() as _save_tmp:
                    try:
                        subprocess.run(
                            ["docker", "save", image_name],
                            stdout=_save_tmp,
                            stderr=subprocess.PIPE,
                            check=True,
                        )
                    except subprocess.CalledProcessError as exc:
                        stderr = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
                        print(f"\nWarning: docker save {image_name} failed: {stderr}", file=sys.stderr)
                        continue
                    _save_tmp.seek(0)
                    with tarfile.open(fileobj=_save_tmp) as outer:
                        # Parse manifest.json for layer order and image name
                        try:
                            manifest_bytes = outer.extractfile(outer.getmember("manifest.json"))
                            if manifest_bytes is None:
                                print(f"\nWarning: no manifest.json in {image_name}", file=sys.stderr)
                                continue
                        except Exception:
                            print(f"\nWarning: no manifest.json in {image_name}", file=sys.stderr)
                            continue
                        try:
                            manifest = json.loads(manifest_bytes.read())
                        except Exception as exc:
                            print(f"\nWarning: could not parse manifest.json in {image_name}: {exc}", file=sys.stderr)
                            continue

                        if not manifest:
                            print(f"\nWarning: empty manifest.json in {image_name}", file=sys.stderr)
                            continue
                        all_layer_paths: list[str] = manifest[0].get("Layers", [])
                        repo_tags: list[str] = manifest[0].get("RepoTags") or [image_name]
                        image_label = repo_tags[0]

                        # Only scan the top N layers; base OS layers are trusted.
                        # top_layers==0 means scan all layers.
                        layers_to_scan = (
                            all_layer_paths if top_layers == 0
                            else all_layer_paths[-top_layers:]
                        )

                        for layer_rel in layers_to_scan:
                            # Use the directory component (hash) as the label; fall back to
                            # the full path for flat layer paths (no "/" present).
                            layer_hash = (layer_rel.rpartition("/")[0] or layer_rel)[:12]
                            try:
                                layer_member = outer.getmember(layer_rel)
                            except KeyError:
                                continue

                            # --since filter: check layer creation time.
                            # mtime==0 means a reproducible/BuildKit build stripped timestamps;
                            # skip the filter and scan unconditionally (emit an info warning).
                            if since_ts is not None and layer_member.mtime < since_ts:
                                if layer_member.mtime == 0:
                                    all_findings.append(Finding(
                                        incident_id="scan-info",
                                        category="docker",
                                        severity="WARNING",
                                        path=f"{image_label}:{layer_hash}",
                                        detail=(
                                            "Layer mtime is zero (reproducible/BuildKit build) — "
                                            "--since filter cannot apply; layer scanned unconditionally"
                                        ),
                                        remediation="No action needed; this is informational.",
                                    ))
                                    # Fall through — scan the layer despite zero mtime
                                else:
                                    continue

                            fobj = outer.extractfile(layer_member)
                            if fobj is None:
                                continue

                            if layer_member.size > _MAX_DOCKER_LAYER_BYTES:
                                all_findings.append(Finding(
                                    incident_id="scan-error",
                                    category="docker",
                                    severity="WARNING",
                                    path=f"{image_label}:{layer_hash}",
                                    detail=(
                                        f"Docker layer is {layer_member.size // (1024 * 1024)} MB"
                                        f" — exceeds {_MAX_DOCKER_LAYER_BYTES // (1024 * 1024)} MB"
                                        " per-layer limit; scan inconclusive for this layer"
                                    ),
                                    remediation="Inspect the layer manually: docker save <image> | tar -tv",
                                ))
                                continue

                            layer_bytes = fobj.read()
                            stats["docker_layers_scanned"] += 1

                            all_findings.extend(
                                _docker_scan_layer(
                                    layer_bytes, image_label, layer_hash,
                                    self.incidents, npm_incidents, stats,
                                )
                            )

            except Exception as exc:
                all_findings.append(Finding(
                    incident_id="scan-error",
                    category="docker",
                    severity="WARNING",
                    path=image_name,
                    detail=f"Error scanning Docker image — scan inconclusive: {exc}",
                    remediation="Inspect the image manually with 'docker save | tar -tv'.",
                ))
                continue

            stats["docker_images_scanned"] += 1

        if show_progress:
            print("\r" + " " * 70 + "\r", end="", flush=True)

        return all_findings


# ── Renderers ────────────────────────────────────────────────────────────────

def render_text(result: ScanResult) -> None:
    bar = "─" * 62
    print(styled(f"\n{bar}", DIM))
    print(styled("  Supply Chain Compromise Scanner", BOLD))
    print(styled(f"  Root:    {result.root}", DIM))
    print(styled(f"  At:      {result.scanned_at}", DIM))
    print(styled(bar, DIM))

    print(f"\n  {styled('Stats', BOLD)}")
    for key, value in result.stats.items():
        print(f"    {key.replace('_', ' '):<30} {value:,}")

    critical_high = result.critical_high
    warnings = result.warnings

    # ── CRITICAL / HIGH ───────────────────────────────────────────────────────
    if result.clean:
        print(f"\n  {styled('✓  No CRITICAL/HIGH IOC matches — system appears clean', GREEN)}\n")
    else:
        print(f"\n  {styled(f'⚠  {len(critical_high)} CRITICAL/HIGH finding(s)', RED + BOLD)}\n")
        for finding in critical_high:
            print(styled(f"  [{finding.severity}] {finding.category.upper()}", RED + BOLD))
            print(f"    Incident : {finding.incident_id}")
            print(f"    Location : {finding.path}")
            print(f"    Detail   : {finding.detail}")
            if finding.remediation:
                print(styled(f"    Action   : {finding.remediation}", CYAN))
            print()

    # ── WARNING (susceptibility) ──────────────────────────────────────────────
    if warnings:
        label = f"  ⚠  {len(warnings)} configuration risk(s) — not yet compromised but vulnerable"
        print(f"{styled(label, YELLOW + BOLD)}\n")
        for finding in warnings:
            print(styled(f"  [WARNING] {finding.category.upper()}", YELLOW))
            print(f"    Location : {finding.path}")
            print(f"    Detail   : {finding.detail}")
            if finding.remediation:
                print(styled(f"    Action   : {finding.remediation}", CYAN))
            print()

    print(styled(bar + "\n", DIM))


def render_json(result: ScanResult) -> None:
    critical_high = result.critical_high
    warnings = result.warnings
    print(json.dumps({
        "scanned_at": result.scanned_at,
        "root": result.root,
        "clean": result.clean,
        "summary": {
            "critical_high": len(critical_high),
            "warning": len(warnings),
            "total": len(result.findings),
        },
        "stats": result.stats,
        "findings": [
            {
                "incident_id": finding.incident_id,
                "category": finding.category,
                "severity": finding.severity,
                "path": finding.path,
                "detail": finding.detail,
                "remediation": finding.remediation,
            }
            for finding in result.findings
        ],
    }, indent=2))


def render_sarif(result: ScanResult) -> None:
    """SARIF 2.1.0 output — accepted by GitHub Code Scanning and VS Code."""
    _LEVEL = {"CRITICAL": "error", "HIGH": "error", "WARNING": "warning"}
    rules_seen: dict[str, dict] = {}  # keyed by rule_id for O(1) dedup (vs O(N²) list scan)
    sarif_results: list[dict] = []

    for finding in result.findings:
        rule_id = f"SC/{finding.incident_id}/{finding.category}"
        level = _LEVEL.get(finding.severity, "note")

        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding.detail[:200]},
                "defaultConfiguration": {"level": level},
            }

        try:
            uri = str(Path(finding.path).relative_to(result.root))
            artifact_location: dict = {"uri": uri, "uriBaseId": "%SRCROOT%"}
        except ValueError:
            uri = finding.path  # host-level or absolute path outside root
            artifact_location = {"uri": uri}

        sarif_results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": finding.detail
                + (f" Remediation: {finding.remediation}" if finding.remediation else "")
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact_location
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.sha256(
                    f"{rule_id}:{finding.path}:{finding.detail}".encode()
                ).hexdigest()[:16]
            },
        })

    print(json.dumps({
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [{
            "tool": {
                "driver": {
                    "name": "supply-chain-scanner",
                    "version": __version__,
                    "rules": list(rules_seen.values()),
                }
            },
            "results": sarif_results,
        }],
    }, indent=2))


def render_junit(result: ScanResult) -> None:
    """JUnit XML output — accepted by GitLab CI test reports and Jenkins JUnit plugin."""
    critical_high = result.critical_high
    all_findings = result.findings

    suites = ET.Element("testsuites")
    suite = ET.SubElement(suites, "testsuite",
        name="supply-chain-scanner",
        timestamp=result.scanned_at,
        tests=str(len(all_findings) or 1),  # at least 1 so CI shows a result
        failures=str(len(critical_high)),
        errors="0",
        skipped="0",
    )

    if not all_findings:
        tc = ET.SubElement(suite, "testcase",
            classname="supply-chain.all", name="No findings — system clean")
        ET.SubElement(tc, "system-out").text = "No IOC matches or configuration risks found."
    else:
        for finding in all_findings:
            tc = ET.SubElement(suite, "testcase",
                classname=f"supply-chain.{finding.category}",
                name=f"{finding.incident_id}: {finding.detail[:120]}",
            )
            if finding.severity in ("CRITICAL", "HIGH"):
                fail = ET.SubElement(tc, "failure",
                    message=finding.detail, type=finding.severity)
                fail.text = f"Location: {finding.path}\n\nRemediation: {finding.remediation}"
            else:
                sout = ET.SubElement(tc, "system-out")
                sout.text = f"WARNING: {finding.detail}\nLocation: {finding.path}"

    print('<?xml version="1.0" encoding="UTF-8"?>')
    print(ET.tostring(suites, encoding="unicode"))


# Maps Finding.severity (case-insensitive) to the CSS class name that has a
# corresponding stylesheet rule. Validated at use so an unexpected severity
# string (e.g. from a future IOC field) produces a styled card, not a raw div.
_SEV_CSS: dict[str, str] = {
    "critical": "critical",
    "high":     "high",
    "warning":  "warning",
}


def render_html(result: ScanResult) -> None:
    """Single-file HTML report with inline styles — shareable offline or by email."""
    def e(s: str) -> str:
        return _html.escape(str(s), quote=True)

    critical_high = result.critical_high
    warnings = result.warnings

    def finding_card(finding: Finding) -> str:
        sev_cls = _SEV_CSS.get(finding.severity.lower(), "warning")
        return (
            f'<div class="finding {sev_cls}">'
            f'<div class="fh"><span class="badge {sev_cls}">{e(finding.severity)}</span>'
            f' <span class="cat">{e(finding.category.upper())}</span>'
            f' <span class="inc">{e(finding.incident_id)}</span></div>'
            f'<div class="detail">{e(finding.detail)}</div>'
            f'<div class="loc">Location: <code>{e(finding.path)}</code></div>'
            + (f'<div class="rem">Action: {e(finding.remediation)}</div>' if finding.remediation else "")
            + "</div>"
        )

    critical_cards = "\n".join(finding_card(f) for f in critical_high)
    warning_cards  = "\n".join(finding_card(f) for f in warnings)
    status_cls     = "clean" if result.clean else "comp"
    status_txt     = "✓ CLEAN" if result.clean else f"⚠ {len(critical_high)} CRITICAL/HIGH FINDING(S)"

    print(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Supply Chain Scan — {e(result.scanned_at[:10])}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;max-width:920px;margin:0 auto;padding:2rem;background:#0d1117;color:#c9d1d9}}
h1{{color:#58a6ff}}h2{{border-bottom:1px solid #30363d;padding-bottom:.4rem}}
.clean{{color:#3fb950;font-size:1.3rem;font-weight:700}}
.comp{{color:#f85149;font-size:1.3rem;font-weight:700}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;margin:1rem 0}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:.8rem}}
.stat .v{{font-size:1.8rem;font-weight:700;color:#58a6ff}}
.finding{{background:#161b22;border-radius:6px;padding:.9rem;margin:.4rem 0}}
.finding.critical{{border-left:4px solid #f85149}}
.finding.high{{border-left:4px solid #d29922}}
.finding.warning{{border-left:4px solid #d29922}}
.badge{{padding:2px 7px;border-radius:4px;font-size:.72rem;color:#fff}}
.badge.critical,.badge.high{{background:#f85149}}
.badge.warning{{background:#d29922}}
.cat{{font-weight:600}}.inc{{color:#8b949e;font-size:.85rem}}
.detail{{margin:.4rem 0}}.loc code{{background:#0d1117;padding:1px 4px;border-radius:3px;font-size:.83rem}}
.rem{{margin-top:.4rem;padding:.4rem;background:#0d1117;border-radius:4px;color:#79c0ff}}
footer{{margin-top:2rem;color:#6e7681;font-size:.78rem}}
</style></head><body>
<h1>Supply Chain Compromise Scan</h1>
<p>Scanned: <strong>{e(result.scanned_at)}</strong> &nbsp;|&nbsp; Root: <code>{e(result.root)}</code></p>
<p class="{status_cls}">{e(status_txt)}</p>
<h2>Summary</h2>
<div class="grid">
<div class="stat"><div class="v">{len(critical_high)}</div>Critical / High</div>
<div class="stat"><div class="v">{len(warnings)}</div>Warnings</div>
<div class="stat"><div class="v">{result.stats.get("package_json_checked",0)}</div>package.json</div>
<div class="stat"><div class="v">{result.stats.get("lockfiles_checked",0)}</div>Lockfiles</div>
<div class="stat"><div class="v">{result.stats.get("node_modules_checked",0)}</div>Packages</div>
<div class="stat"><div class="v">{result.stats.get("dirs_visited",0):,}</div>Dirs visited</div>
</div>
<h2>Critical / High Findings</h2>
{critical_cards if critical_cards else '<p style="color:#3fb950">None.</p>'}
<h2>Configuration Risks</h2>
{warning_cards if warning_cards else '<p style="color:#3fb950">None.</p>'}
<h2>Remediation Checklist</h2>
<ul>
<li>Rotate NPM tokens, AWS/GCP/Azure keys, SSH keys, DB credentials, API tokens</li>
<li>Delete <code>node_modules</code> and reinstall via <code>npm ci</code> from a known-good lockfile</li>
<li>Add <code>ignore-scripts=true</code> to <code>~/.npmrc</code></li>
<li>Pin all version ranges to exact versions and commit a lockfile</li>
<li>Use <code>npm ci</code> (not <code>npm install</code>) in CI pipelines</li>
</ul>
<footer>Generated by supply-chain-scanner &nbsp;|&nbsp; {e(result.scanned_at)}</footer>
</body></html>""")


# ── CLI ──────────────────────────────────────────────────────────────────────

def _parse_since(value: str, iocs: dict) -> float | None:
    """
    Parse --since argument to a Unix timestamp.
    Accepts:
      - ISO datetime string: "2026-03-31T00:21:00"
      - Incident ID shorthand: "axios-2026-03-31" → looks up attack_window_start_utc
    """
    # Try incident ID shorthand first
    for incident in iocs.get("incidents", []):
        if incident["id"] == value:
            start = incident.get("attack_window_start_utc")
            if start:
                dt = datetime.fromisoformat(start)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            # Incident found but has no attack window — return None immediately so the
            # caller emits a meaningful error rather than a confusing "not a valid ISO
            # date" message (the incident ID is not a valid ISO datetime string).
            return None
    # Fall back to ISO datetime
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def _cmd_update_iocs(ioc_path: Path) -> int:
    """Download a fresh iocs.json from the upstream URL and verify its SHA256."""
    if not _IOCS_UPDATE_URL:
        print("Error: no upstream IOC URL configured in this build of scan.py.", file=sys.stderr)
        return 2
    print(f"Fetching {_IOCS_UPDATE_URL} ...", file=sys.stderr)
    try:
        with urllib.request.urlopen(_IOCS_UPDATE_URL, timeout=30) as resp:
            data = resp.read()
    except Exception as exc:
        print(f"Error: download failed: {exc}", file=sys.stderr)
        return 2
    actual = hashlib.sha256(data).hexdigest()
    if _IOCS_UPDATE_SHA256 and actual != _IOCS_UPDATE_SHA256:
        print(
            f"Error: SHA256 mismatch — refusing to write.\n"
            f"  Expected: {_IOCS_UPDATE_SHA256}\n"
            f"  Got:      {actual}\n"
            "Update scan.py to get a newer _IOCS_UPDATE_SHA256.",
            file=sys.stderr,
        )
        return 2
    try:
        json.loads(data)  # validate JSON before writing
    except json.JSONDecodeError as exc:
        print(f"Error: upstream returned malformed JSON: {exc}", file=sys.stderr)
        return 2
    canonical = Path(__file__).with_name("iocs.json")
    canonical.write_bytes(data)
    print(f"IOCs updated: {canonical} (sha256: {actual[:16]}...)", file=sys.stderr)
    return 0


def main() -> int:
    default_workers = min(os.cpu_count() or 4, 8)

    parser = argparse.ArgumentParser(
        description="Detect supply-chain compromises across ecosystems and operating systems.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Exit codes:
  0  — fully clean (no findings of any severity)
  1  — CRITICAL or HIGH finding(s): act immediately
  2  — scan error (bad arguments, missing files)
  3  — WARNING-only: susceptible configuration, not confirmed compromised

Output formats:
  (default)   human-readable text with colour
  --json      machine-readable JSON with summary block
  --sarif     SARIF 2.1.0 for GitHub Code Scanning / VS Code
  --junit     JUnit XML for GitLab CI / Jenkins test reports
  --html      self-contained HTML report (offline, email-attachable)

Examples:
  python3 scan.py                                     # full OS scan
  python3 scan.py ~/dev                               # dev repos only
  python3 scan.py / --since 2026-03-31T00:21:00       # incident-response (fast)
  python3 scan.py / --since axios-2026-03-31          # same, using incident ID
  python3 scan.py ~/dev --sarif > results.sarif       # GitHub Code Scanning
  python3 scan.py ~/dev --html  > report.html         # offline report
  python3 scan.py ~/dev --json  | jq '.findings[] | select(.severity=="CRITICAL")'
  python3 scan.py --docker                            # scan all local Docker images
  python3 scan.py --docker nginx:latest node:18-slim  # scan specific images
  python3 scan.py ~/dev --docker --since 2026-03-31   # filesystem + Docker, date-filtered
  python3 scan.py ~/dev --online                      # also query OSV.dev live
  python3 scan.py --update-iocs                       # refresh IOC database
        """,
    )
    parser.add_argument(
        "root", nargs="?", default=None,
        metavar="ROOT",
        help="Directory to scan (default: / — full OS; omit with --docker to skip filesystem scan)",
    )
    parser.add_argument(
        "--workers", type=int, default=default_workers, metavar="N",
        help=f"Worker threads for file parsing (default: {default_workers})",
    )
    parser.add_argument(
        "--iocs", default=None,
        help="Custom IOC database JSON (default: use embedded database)",
    )
    parser.add_argument(
        "--since", default=None, metavar="ISO_OR_INCIDENT_ID",
        help=(
            "Only scan node_modules modified on or after this timestamp. "
            "Accepts ISO datetime (2026-03-31T00:21:00) or incident ID "
            "(axios-2026-03-31). Dramatically speeds up incident-response scans."
        ),
    )
    parser.add_argument("--update-iocs", action="store_true",
                        help="Download a fresh iocs.json from the configured upstream URL")
    parser.add_argument(
        "--docker", nargs="*", metavar="IMAGE",
        help=(
            "Scan Docker images via 'docker save'. "
            "Pass image names/tags to scan specific images, or no names to scan all local images. "
            "When used without ROOT, skips the filesystem scan."
        ),
    )
    parser.add_argument(
        "--top-layers", type=int, default=5, metavar="N",
        help=(
            "Number of most-recent Docker layers to scan (default: 5). "
            "Use 0 to scan all layers. Base OS layers are typically trusted, so "
            "scanning only the top N is faster for well-known base images."
        ),
    )
    parser.add_argument(
        "--online", action="store_true",
        help=(
            "After scanning, batch-query OSV.dev for advisories on all discovered npm packages. "
            "MAL-* advisories are reported as CRITICAL. "
            "(npm only — other ecosystems not yet supported). "
            "Package names and versions are transmitted to api.osv.dev."
        ),
    )
    parser.add_argument(
        "--host", action=argparse.BooleanOptionalAction, default=None,
        help=(
            "Enable host-level forensic checks (shell profiles, npm/pip caches, persistence, "
            "network state, global package stores). Default: on when ROOT is / or omitted "
            "(full system scan), off for all other ROOT values. Use --host to force on for "
            "repo scans, or --no-host to suppress for full-system scans."
        ),
    )
    # Output format flags (mutually exclusive)
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json",  action="store_true", help="Machine-readable JSON output")
    fmt.add_argument("--sarif", action="store_true", help="SARIF 2.1.0 for GitHub Code Scanning")
    fmt.add_argument("--junit", action="store_true", help="JUnit XML for GitLab CI / Jenkins")
    fmt.add_argument("--html",  action="store_true", help="Self-contained HTML report")
    args = parser.parse_args()

    # Load IOC database
    if args.iocs:
        ioc_path = Path(args.iocs).expanduser().resolve()
        if not ioc_path.is_file():
            print(f"Error: IOC database not found: {ioc_path}", file=sys.stderr)
            return 2
        try:
            iocs = json.loads(ioc_path.read_text())
        except json.JSONDecodeError as exc:
            print(f"Error: malformed IOC database: {exc}", file=sys.stderr)
            return 2
    else:
        iocs = _EMBEDDED_IOCS
        ioc_path = Path(__file__).parent / "iocs.json"

    # --update-iocs: download fresh database and exit
    if args.update_iocs:
        return _cmd_update_iocs(ioc_path)

    # When --docker is given without an explicit ROOT, skip the filesystem scan
    docker_only = args.docker is not None and args.root is None
    root = Path(args.root or "/").expanduser().resolve()
    if not docker_only and not root.is_dir():
        print(f"Error: directory not found: {root}", file=sys.stderr)
        return 2

    if args.workers < 1:
        print("Error: --workers must be >= 1", file=sys.stderr)
        return 2

    if args.top_layers < 0:
        print("Error: --top-layers must be >= 0 (use 0 to scan all layers)", file=sys.stderr)
        return 2

    # Parse --since timestamp
    since_ts: float | None = None
    if args.since:
        since_ts = _parse_since(args.since, iocs)
        if since_ts is None:
            print(
                f"Error: could not parse --since value '{args.since}'. "
                "Use an ISO datetime (2026-03-31T00:21:00) or an incident ID.",
                file=sys.stderr,
            )
            return 2

    any_output_flag = args.json or args.sarif or args.junit or args.html
    show_progress = sys.stdout.isatty() and not any_output_flag
    if show_progress:
        since_note = f"  since={args.since}" if args.since else ""
        docker_note = f"  docker={'all' if args.docker == [] else ','.join(args.docker or [])}" if args.docker is not None else ""
        online_note = "  online=osv.dev" if args.online else ""
        root_note = f"root={root}" if not docker_only else ""
        print(styled(
            f"  workers={args.workers}  {root_note}  os={platform.system()}"
            f"{since_note}{docker_note}{online_note}".strip(),
            DIM,
        ))

    scanner = Scanner(root, iocs)

    # Default --host based on scan scope: on for full-system scans (root == /),
    # off for targeted repo/directory scans to avoid leaking runner state into CI results.
    if args.host is not None:
        run_host = args.host
    else:
        run_host = (root == Path("/") or args.root is None)

    if docker_only:
        result = ScanResult(root="docker")
    else:
        result = scanner.run(
            workers=args.workers,
            show_progress=show_progress,
            since_ts=since_ts,
            online=args.online,
            host=run_host,
        )

    # Docker image scan (runs in addition to filesystem scan when ROOT is given)
    if args.docker is not None:
        docker_findings = scanner.scan_docker_images(
            images=args.docker,
            stats=result.stats,
            since_ts=since_ts,
            top_layers=args.top_layers,
            show_progress=show_progress,
        )
        result.findings.extend(docker_findings)

    if args.json:
        render_json(result)
    elif args.sarif:
        render_sarif(result)
    elif args.junit:
        render_junit(result)
    elif args.html:
        render_html(result)
    else:
        render_text(result)

    # Exit code 3 = warnings only (susceptible, not confirmed compromised)
    if result.clean:
        return 3 if result.warning_count > 0 else 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
