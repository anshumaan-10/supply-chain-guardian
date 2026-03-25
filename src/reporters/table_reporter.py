#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Table Reporter
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
Table Reporter — prints formatted scan results as tables to stdout
for GitHub Actions workflow logs and terminal output.
"""

import sys
from typing import List, Dict, Any

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

from utils.logger import C, SEV_MARKERS, SEV_COLORS


SEVERITY_COLORS = SEV_COLORS


class TableReporter:
    """Generate formatted table output for scan results."""

    @staticmethod
    def print_findings_table(
        findings: List[Dict[str, Any]],
        scan_results: Dict[str, Dict],
        report_data: Dict[str, Any],
    ):
        """Print findings as a formatted table."""
        summary = report_data.get("summary", {})
        status = report_data.get("overall_status", "UNKNOWN")

        # Scanner summary
        print(f"\n  {C.BLD}Scanner Results:{C.RST}")
        print(f"  {'─' * 58}")

        scanner_rows = []
        for scanner_name, result in scan_results.items():
            status_str = result.get("status", "unknown")
            count = result.get("findings_count", 0)

            if status_str == "error":
                status_display = f"{C.R}ERROR{C.RST}"
            elif count > 0:
                status_display = f"{C.Y}{count} finding(s){C.RST}"
            else:
                status_display = f"{C.G}CLEAN{C.RST}"

            scanner_rows.append([f"  {scanner_name}", status_display])

        if HAS_TABULATE:
            print(tabulate(scanner_rows, headers=["  Scanner", "Result"],
                           tablefmt="simple", stralign="left"))
        else:
            for row in scanner_rows:
                print(f"  {row[0]:<40} {row[1]}")

        print(f"  {'─' * 58}\n")

        if not findings:
            print(f"  {C.G}{C.BLD}No findings detected!{C.RST}\n")
            return

        # Findings table
        print(f"  {C.BLD}Findings ({len(findings)} total):{C.RST}")
        print(f"  {'─' * 78}")

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        rows = []
        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, C.DIM)

            sev_display = f"{color}{sev.upper():>8}{C.RST}"
            title = finding.get("title", "Unknown")[:60]
            file_info = finding.get("file", "")
            line = finding.get("line", 0)
            location = f"{file_info}:{line}" if file_info else ""
            location = location[:35]

            rows.append([f"  {i:>3}", sev_display, title, location])

        if HAS_TABULATE:
            print(tabulate(
                rows,
                headers=["  #", "Severity", "Finding", "Location"],
                tablefmt="simple",
                stralign="left",
            ))
        else:
            print(f"  {'#':>3}  {'Severity':>10}  {'Finding':<60}  {'Location':<35}")
            for row in rows:
                print(f"  {row[0]}  {row[1]:>10}  {row[2]:<60}  {row[3]:<35}")

        print(f"  {'─' * 78}\n")

        # Print detailed findings for critical/high
        critical_high = [f for f in sorted_findings if f.get("severity") in ("critical", "high")]
        if critical_high:
            print(f"  {C.BLD}{C.R}Detailed Critical/High Findings:{C.RST}\n")

            for finding in critical_high:
                sev = finding.get("severity", "info")
                color = SEVERITY_COLORS.get(sev, C.DIM)

                print(f"  {color}+--------------------------------------------------------------+{C.RST}")
                print(f"  {color}| [{sev.upper()}] {finding.get('title', 'Unknown')[:56]:<56} |{C.RST}")
                print(f"  {color}+--------------------------------------------------------------+{C.RST}")

                file_info = finding.get("file", "")
                line = finding.get("line", 0)
                if file_info:
                    print(f"  {color}|{C.RST} File: {file_info}:{line}")

                desc = finding.get("description", "")
                for desc_line in _wrap_text(desc, 58):
                    print(f"  {color}|{C.RST} {desc_line}")

                remediation = finding.get("remediation", "")
                if remediation:
                    print(f"  {color}|{C.RST}")
                    print(f"  {color}|{C.RST} {C.G}Remediation:{C.RST}")
                    for rem_line in _wrap_text(remediation, 58):
                        print(f"  {color}|{C.RST}   {rem_line}")

                evidence = finding.get("evidence", "")
                if evidence:
                    print(f"  {color}|{C.RST}")
                    print(f"  {color}|{C.RST} {C.DIM}Evidence: {evidence[:56]}{C.RST}")

                print(f"  {color}+--------------------------------------------------------------+{C.RST}\n")

        # Summary
        print(f"\n  {C.BLD}Summary:{C.RST}")
        print(f"  {C.R}{C.BLD}  Critical: {summary.get('critical', 0)}{C.RST}")
        print(f"  {C.R}  High:     {summary.get('high', 0)}{C.RST}")
        print(f"  {C.Y}  Medium:   {summary.get('medium', 0)}{C.RST}")
        print(f"  {C.B}  Low:      {summary.get('low', 0)}{C.RST}")
        print(f"  {C.DIM}  Info:     {summary.get('info', 0)}{C.RST}")
        print()


def _wrap_text(text: str, width: int) -> List[str]:
    """Simple text wrapping."""
    words = text.split()
    lines = []
    current_line = ""

    for word in words:
        if len(current_line) + len(word) + 1 <= width:
            current_line += (" " if current_line else "") + word
        else:
            if current_line:
                lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    return lines or [""]
