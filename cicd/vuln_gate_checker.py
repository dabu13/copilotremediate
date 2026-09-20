#!/usr/bin/env python3
"""
Vulnerability Gate Script for Trivy & Snyk JSON reports.

Filters for:
  - Severity: CRITICAL or HIGH
  - Fix available: Yes (FixedVersion / isUpgradable / isPatchable)
  - CVSS score: >= 8.0

Exits with:
  - 0: No blocking vulnerabilities found
  - 1: Matching vulnerabilities detected
"""

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def get_trivy_cvss(vuln: Dict[str, Any]) -> float:
    """Extracts the highest available CVSS v3 / v2 score from a Trivy vulnerability object."""
    cvss_obj = vuln.get("CVSS", {})
    scores = []
    if isinstance(cvss_obj, dict):
        for _, details in cvss_obj.items():
            if isinstance(details, dict):
                for key in ["V3Score", "V2Score"]:
                    score = details.get(key)
                    if score is not None:
                        try:
                            scores.append(float(score))
                        except (ValueError, TypeError):
                            pass
    return max(scores) if scores else 0.0


def parse_trivy(data: Dict[str, Any], min_cvss: float) -> List[Dict[str, Any]]:
    """Parses Trivy JSON report."""
    results = []
    for result in data.get("Results", []):
        target = result.get("Target", "Unknown")
        for vuln in result.get("Vulnerabilities", []):
            severity = vuln.get("Severity", "").upper()
            fixed_version = vuln.get("FixedVersion")

            # Check: Severity HIGH/CRITICAL and fix exists
            if severity not in ["CRITICAL", "HIGH"] or not fixed_version:
                continue

            cvss = get_trivy_cvss(vuln)
            if cvss >= min_cvss:
                results.append({
                    "id": vuln.get("VulnerabilityID", "N/A"),
                    "package": vuln.get("PkgName", "N/A"),
                    "installed": vuln.get("InstalledVersion", "N/A"),
                    "fixed": fixed_version,
                    "severity": severity,
                    "cvss": cvss,
                    "target": target
                })
    return results


def get_snyk_cvss(vuln: Dict[str, Any]) -> float:
    """Extracts CVSS score from a Snyk vulnerability object."""
    score = vuln.get("cvssScore")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    for detail in vuln.get("cvssDetails", []):
        score = detail.get("cvssV3_baseScore") or detail.get("cvssV2_baseScore")
        if score is not None:
            try:
                return float(score)
            except (ValueError, TypeError):
                pass
    return 0.0


def parse_snyk(data: Any, min_cvss: float) -> List[Dict[str, Any]]:
    """Parses Snyk JSON report (single project dict or list of projects)."""
    results = []
    projects = data if isinstance(data, list) else [data]

    for proj in projects:
        target = proj.get("displayTargetFile") or proj.get("path") or "Unknown"
        for vuln in proj.get("vulnerabilities", []):
            severity = vuln.get("severity", "").upper()

            is_fixable = (
                vuln.get("isUpgradable", False)
                or vuln.get("isPatchable", False)
                or bool(vuln.get("fixedIn"))
            )

            if severity not in ["CRITICAL", "HIGH"] or not is_fixable:
                continue

            cvss = get_snyk_cvss(vuln)
            if cvss >= min_cvss:
                fixed_ver = "Available"
                if vuln.get("fixedIn"):
                    fixed_ver = ", ".join(vuln["fixedIn"])
                elif vuln.get("upgradePath"):
                    fixed_ver = f"Upgrade: {vuln['upgradePath'][-1]}"

                results.append({
                    "id": vuln.get("id", "N/A"),
                    "package": vuln.get("packageName", "N/A"),
                    "installed": vuln.get("version", "N/A"),
                    "fixed": fixed_ver,
                    "severity": severity,
                    "cvss": cvss,
                    "target": target
                })
    return results


def print_table(items: List[Dict[str, Any]]):
    """Renders a clean ASCII table."""
    headers = ["CVE / ID", "Package", "Installed", "Fixed In", "Severity", "CVSS", "Target"]

    rows = []
    for item in items:
        rows.append([
            str(item["id"]),
            str(item["package"]),
            str(item["installed"]),
            str(item["fixed"]),
            str(item["severity"]),
            f"{item['cvss']:.1f}",
            str(item["target"])
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    separator = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    header_row = "| " + " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers)) + " |"

    print("\n" + "=" * len(separator))
    print("🚨 VULNERABILITY GATE REPORT: Actionable Critical/High Flaws (CVSS >= 8.0)")
    print("=" * len(separator))
    print(separator)
    print(header_row)
    print(separator)
    for row in rows:
        print("| " + " | ".join(f"{val:<{col_widths[i]}}" for i, val in enumerate(row)) + " |")
    print(separator)
    print(f"\nTotal Matching Vulnerabilities: {len(rows)}\n")


def main():
    parser = argparse.ArgumentParser(description="Check Trivy/Snyk report for actionable High/Critical CVEs.")
    parser.add_argument("report", help="Path to Trivy or Snyk JSON report file")
    parser.add_argument(
        "--min-cvss",
        type=float,
        default=8.0,
        help="Minimum CVSS threshold (default: 8.0)"
    )

    args = parser.parse_args()

    if not os.path.isfile(args.report):
        print(f"Error: File not found: {args.report}", file=sys.stderr)
        sys.exit(2)

    with open(args.report, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON file ({e})", file=sys.stderr)
            sys.exit(2)

    if isinstance(data, dict) and "Results" in data:
        matched_vulns = parse_trivy(data, args.min_cvss)
    elif (isinstance(data, dict) and "vulnerabilities" in data) or (isinstance(data, list) and len(data) > 0 and "vulnerabilities" in data[0]):
        matched_vulns = parse_snyk(data, args.min_cvss)
    else:
        print("Error: Unrecognized report format (neither Trivy nor Snyk).", file=sys.stderr)
        sys.exit(2)

    seen = set()
    deduped_vulns = []
    for v in matched_vulns:
        key = (v["id"], v["package"], v["target"])
        if key not in seen:
            seen.add(key)
            deduped_vulns.append(v)

    if deduped_vulns:
        print_table(deduped_vulns)
        print("❌ BUILD FAILED: Vulnerabilities found exceeding threshold with available fixes.\n")
        sys.exit(1)
    else:
        print("\n✅ PASSED: No CRITICAL or HIGH fixable vulnerabilities with CVSS >= 8.0 found.\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
