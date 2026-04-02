#!/usr/bin/env python3
"""
Post-process scan.py --json output: check for findings and optionally emit SARIF.

Usage:
    check_findings.py result.json           # print summary; exit 1 if CRITICAL/HIGH
    check_findings.py result.json --sarif   # emit SARIF 2.1.0 to stdout; exit 1 if CRITICAL/HIGH
"""

__version__ = "1.0.0"

import argparse
import hashlib
import json
import sys
from pathlib import Path


def to_sarif(data: dict) -> dict:
    """Convert scan.py --json output to a SARIF 2.1.0 document.

    data: the parsed JSON dict produced by scan.py --json. Expected keys:
      - "root" (str): absolute path of the scan root
      - "findings" (list): each finding has "incident_id", "category",
        "severity" (CRITICAL|HIGH|WARNING), "path", "detail", "remediation"

    Paths inside the scan root are emitted as relative URIs with
    uriBaseId: "%SRCROOT%". Paths outside (host-level artifacts, npm cache,
    shell profiles) are emitted as absolute URIs without uriBaseId to avoid
    misleading GitHub Code Scanning into treating them as repo-relative files.
    """
    _level = {"CRITICAL": "error", "HIGH": "error", "WARNING": "warning"}
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    root = Path(data.get("root", ""))

    for finding in data.get("findings", []):
        rule_id = f"SC/{finding['incident_id']}/{finding['category']}"
        level = _level.get(finding["severity"], "note")

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": finding["detail"][:200]},
                "defaultConfiguration": {"level": level},
            }

        path = finding["path"]
        try:
            rel = str(Path(path).relative_to(root))
            artifact = {"uri": rel, "uriBaseId": "%SRCROOT%"}
        except ValueError:
            # Path is outside the scan root (e.g. a host/global cache path).
            # Do not set uriBaseId — Code Scanning would misinterpret it as
            # a repo-relative path and produce misleading or invalid locations.
            artifact = {"uri": path}

        message = finding["detail"]
        if finding.get("remediation"):
            message += f" Remediation: {finding['remediation']}"

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact,
                }
            }],
            "partialFingerprints": {
                "primaryLocationLineHash": hashlib.sha256(
                    f"{rule_id}:{path}:{finding['detail']}".encode()
                ).hexdigest()[:16],
            },
        })

    return {
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
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
        }],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_json", help="JSON output file from scan.py --json")
    parser.add_argument(
        "--sarif", action="store_true",
        help="Emit SARIF 2.1.0 to stdout and exit 0",
    )
    args = parser.parse_args()

    try:
        data = json.loads(Path(args.result_json).read_text())
    except FileNotFoundError:
        print(f"Error: result file not found: {args.result_json}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Error: malformed JSON in {args.result_json}: {exc}", file=sys.stderr)
        return 2

    summary = data.get("summary", {})

    if args.sarif:
        print(json.dumps(to_sarif(data), indent=2))
        return 1 if summary.get("critical_high", 0) else 0
    critical_high = summary.get("critical_high", 0)
    warnings = summary.get("warning", 0)

    if critical_high:
        print(f"FAIL: {critical_high} CRITICAL/HIGH finding(s)", file=sys.stderr)
        for f in data.get("findings", []):
            if f["severity"] in ("CRITICAL", "HIGH"):
                print(f'  [{f["severity"]}] {f["detail"]}', file=sys.stderr)
        return 1

    print(f"CLEAN: {warnings} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
