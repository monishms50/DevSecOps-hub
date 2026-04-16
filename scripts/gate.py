#!/usr/bin/env python3
"""
gate.py — Security pipeline severity gate.

Reads SARIF files from SAST tools and pip-audit JSON from SCA.
Fails (exit 1) if any finding meets or exceeds the configured severity threshold.

Usage:
    python gate.py --sarif bandit.sarif semgrep.sarif \
                   --pip-audit pip-audit.json \
                   --fail-on HIGH

Severity order (lowest → highest): LOW → MEDIUM → HIGH → CRITICAL
"""

import argparse
import json
import sys
from pathlib import Path

# Map severity strings to numeric levels for comparison
SEVERITY_LEVELS = {
    "none":     0,
    "note":     1,
    "low":      1,
    "warning":  2,
    "medium":   2,
    "error":    3,
    "high":     3,
    "critical": 4,
}

def parse_args():
    parser = argparse.ArgumentParser(description="Security gate — fail on severity threshold")
    parser.add_argument("--sarif",     nargs="*", default=[], help="SARIF files to evaluate")
    parser.add_argument("--pip-audit", dest="pip_audit", default=None, help="pip-audit JSON file")
    parser.add_argument("--fail-on",   dest="fail_on", default="HIGH",
                        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                        help="Minimum severity that triggers pipeline failure")
    return parser.parse_args()


def load_sarif(filepath: str) -> list[dict]:
    """Extract findings from a SARIF file. Returns list of {tool, rule_id, severity, message, location}."""
    findings = []
    path = Path(filepath)

    if not path.exists():
        print(f"  [WARN] SARIF file not found, skipping: {filepath}")
        return findings

    with open(path) as f:
        sarif = json.load(f)

    for run in sarif.get("runs", []):
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules = {
            r["id"]: r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")

            # Severity: prefer result-level, fall back to rule-level
            raw_severity = (
                result.get("level")
                or rules.get(rule_id, {})
                       .get("defaultConfiguration", {})
                       .get("level", "warning")
            )

            message = result.get("message", {}).get("text", "")

            locations = result.get("locations", [])
            location = ""
            if locations:
                pl = locations[0].get("physicalLocation", {})
                uri = pl.get("artifactLocation", {}).get("uri", "")
                line = pl.get("region", {}).get("startLine", "")
                location = f"{uri}:{line}" if line else uri

            findings.append({
                "tool":     tool_name,
                "rule_id":  rule_id,
                "severity": raw_severity.upper(),
                "message":  message[:120],
                "location": location,
            })

    return findings


def load_pip_audit(filepath: str) -> list[dict]:
    """Extract findings from a pip-audit JSON file."""
    findings = []
    path = Path(filepath)

    if not path.exists():
        print(f"  [WARN] pip-audit file not found, skipping: {filepath}")
        return findings

    with open(path) as f:
        audit = json.load(f)

    for dep in audit.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            # pip-audit doesn't always include severity — default to HIGH
            # since any known CVE in a direct dependency is serious
            severity = vuln.get("severity", "HIGH").upper()
            findings.append({
                "tool":     "pip-audit",
                "rule_id":  vuln.get("id", "unknown"),
                "severity": severity,
                "message":  vuln.get("description", "")[:120],
                "location": f"{dep.get('name')}=={dep.get('version')}",
            })

    return findings


def evaluate(findings: list[dict], fail_on: str) -> bool:
    """Print findings table and return True if pipeline should fail."""
    threshold = SEVERITY_LEVELS[fail_on.lower()]
    blocking = []
    warnings = []

    for f in findings:
        level = SEVERITY_LEVELS.get(f["severity"].lower(), 0)
        if level >= threshold:
            blocking.append(f)
        else:
            warnings.append(f)

    # Print warnings
    if warnings:
        print(f"\n{'─'*70}")
        print(f"  WARNINGS ({len(warnings)} findings below threshold — not blocking)")
        print(f"{'─'*70}")
        for f in warnings:
            print(f"  [{f['severity']:8}] {f['tool']} | {f['rule_id']}")
            print(f"             {f['location']}")
            print(f"             {f['message'][:100]}")
            print()

    # Print blocking findings
    if blocking:
        print(f"\n{'─'*70}")
        print(f"  BLOCKING ({len(blocking)} findings at or above {fail_on})")
        print(f"{'─'*70}")
        for f in blocking:
            print(f"  [{f['severity']:8}] {f['tool']} | {f['rule_id']}")
            print(f"             {f['location']}")
            print(f"             {f['message'][:100]}")
            print()

    return len(blocking) > 0


def main():
    args = parse_args()
    all_findings = []

    print(f"\n{'='*70}")
    print(f"  Security Gate — fail-on: {args.fail_on}")
    print(f"{'='*70}\n")

    # Load SARIF files
    for sarif_file in (args.sarif or []):
        print(f"  Reading SARIF: {sarif_file}")
        all_findings.extend(load_sarif(sarif_file))

    # Load pip-audit
    if args.pip_audit:
        print(f"  Reading pip-audit: {args.pip_audit}")
        all_findings.extend(load_pip_audit(args.pip_audit))

    print(f"\n  Total findings: {len(all_findings)}\n")

    should_fail = evaluate(all_findings, args.fail_on)

    if should_fail:
        print(f"\n  ❌  GATE FAILED — {args.fail_on}+ severity findings detected.\n")
        sys.exit(1)
    else:
        print(f"\n  ✅  GATE PASSED — no findings at or above {args.fail_on}.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
