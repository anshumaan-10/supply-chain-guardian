#!/usr/bin/env python3
"""
Table Reporter
==============
Prints formatted scan results as tables to stdout for
GitHub Actions workflow logs.
"""

import sys
from typing import List, Dict, Any

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


class Colors:
    """ANSI colors for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


SEVERITY_COLORS = {
    "critical": Colors.RED + Colors.BOLD,
    "high": Colors.RED,
    "medium": Colors.YELLOW,
    "low": Colors.BLUE,
    "info": Colors.DIM,
}


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
        print(f"\n  {Colors.BOLD}Scanner Results:{Colors.RESET}")
        print(f"  {'─' * 58}")

        scanner_rows = []
        for scanner_name, result in scan_results.items():
            status_str = result.get("status", "unknown")
            count = result.get("findings_count", 0)

            if status_str == "error":
                status_display = f"{Colors.RED}ERROR{Colors.RESET}"
            elif count > 0:
                status_display = f"{Colors.YELLOW}{count} finding(s){Colors.RESET}"
            else:
                status_display = f"{Colors.GREEN}CLEAN{Colors.RESET}"

            scanner_rows.append([f"  {scanner_name}", status_display])

        if HAS_TABULATE:
            print(tabulate(scanner_rows, headers=["  Scanner", "Result"],
                           tablefmt="simple", stralign="left"))
        else:
            for row in scanner_rows:
                print(f"  {row[0]:<40} {row[1]}")

        print(f"  {'─' * 58}\n")

        if not findings:
            print(f"  {Colors.GREEN}{Colors.BOLD}No findings detected!{Colors.RESET}\n")
            return

        # Findings table
        print(f"  {Colors.BOLD}Findings ({len(findings)} total):{Colors.RESET}")
        print(f"  {'─' * 78}")

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        rows = []
        for i, finding in enumerate(sorted_findings, 1):
            sev = finding.get("severity", "info")
            color = SEVERITY_COLORS.get(sev, Colors.DIM)

            sev_display = f"{color}{sev.upper():>8}{Colors.RESET}"
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
            print(f"  {Colors.BOLD}{Colors.RED}Detailed Critical/High Findings:{Colors.RESET}\n")

            for finding in critical_high:
                sev = finding.get("severity", "info")
                color = SEVERITY_COLORS.get(sev, Colors.DIM)

                print(f"  {color}┌──────────────────────────────────────────────────────────────┐{Colors.RESET}")
                print(f"  {color}│ [{sev.upper()}] {finding.get('title', 'Unknown')[:56]:<56} │{Colors.RESET}")
                print(f"  {color}├──────────────────────────────────────────────────────────────┤{Colors.RESET}")

                file_info = finding.get("file", "")
                line = finding.get("line", 0)
                if file_info:
                    print(f"  {color}│{Colors.RESET} File: {file_info}:{line}")

                desc = finding.get("description", "")
                # Wrap description
                for desc_line in _wrap_text(desc, 58):
                    print(f"  {color}│{Colors.RESET} {desc_line}")

                remediation = finding.get("remediation", "")
                if remediation:
                    print(f"  {color}│{Colors.RESET}")
                    print(f"  {color}│{Colors.RESET} {Colors.GREEN}Remediation:{Colors.RESET}")
                    for rem_line in _wrap_text(remediation, 58):
                        print(f"  {color}│{Colors.RESET}   {rem_line}")

                evidence = finding.get("evidence", "")
                if evidence:
                    print(f"  {color}│{Colors.RESET}")
                    print(f"  {color}│{Colors.RESET} {Colors.DIM}Evidence: {evidence[:56]}{Colors.RESET}")

                print(f"  {color}└──────────────────────────────────────────────────────────────┘{Colors.RESET}\n")

        # Summary
        print(f"\n  {Colors.BOLD}Summary:{Colors.RESET}")
        print(f"  {Colors.RED}{Colors.BOLD}  Critical: {summary.get('critical', 0)}{Colors.RESET}")
        print(f"  {Colors.RED}  High:     {summary.get('high', 0)}{Colors.RESET}")
        print(f"  {Colors.YELLOW}  Medium:   {summary.get('medium', 0)}{Colors.RESET}")
        print(f"  {Colors.BLUE}  Low:      {summary.get('low', 0)}{Colors.RESET}")
        print(f"  {Colors.DIM}  Info:     {summary.get('info', 0)}{Colors.RESET}")
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
