#!/usr/bin/env python3
"""
SARIF Reporter
==============
Generates Static Analysis Results Interchange Format (SARIF)
reports compatible with GitHub Advanced Security code scanning.
"""

import json
import os
from typing import Dict, Any, List


class SarifReporter:
    """Generate SARIF 2.1.0 report for GitHub Code Scanning."""

    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    SECURITY_SEVERITY_MAP = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }

    @staticmethod
    def write_report(report_data: Dict[str, Any], output_path: str) -> bool:
        """Write SARIF report to file."""
        try:
            sarif = SarifReporter._build_sarif(report_data)
            with open(output_path, "w") as f:
                json.dump(sarif, f, indent=2)
            return True
        except Exception as e:
            print(f"  Error writing SARIF report: {e}")
            return False

    @staticmethod
    def _build_sarif(report_data: Dict[str, Any]) -> Dict:
        """Build SARIF 2.1.0 document."""
        findings = report_data.get("findings", [])

        # Collect unique rules
        rules = {}
        results = []

        for finding in findings:
            rule_id = finding.get("id", "SCA-UNKNOWN")
            severity = finding.get("severity", "info")

            # Create rule if not seen
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("title", "Unknown Finding"),
                    "shortDescription": {
                        "text": finding.get("title", "Unknown")
                    },
                    "fullDescription": {
                        "text": finding.get("description", "No description available.")[:1000]
                    },
                    "helpUri": "https://github.com/anshumaan-10/supply-chain-guardian",
                    "help": {
                        "text": finding.get("remediation", "Review and remediate."),
                        "markdown": f"**Remediation:** {finding.get('remediation', 'Review and remediate.')}"
                    },
                    "properties": {
                        "tags": ["security", "supply-chain", finding.get("scanner", "unknown")],
                        "security-severity": SarifReporter.SECURITY_SEVERITY_MAP.get(severity, "5.0"),
                    },
                    "defaultConfiguration": {
                        "level": SarifReporter.SEVERITY_MAP.get(severity, "note"),
                    },
                }

            # Build result
            file_path = finding.get("file", "")
            line = finding.get("line", 1) or 1

            result = {
                "ruleId": rule_id,
                "ruleIndex": list(rules.keys()).index(rule_id),
                "level": SarifReporter.SEVERITY_MAP.get(severity, "note"),
                "message": {
                    "text": finding.get("description", "")[:2000],
                },
                "properties": {
                    "severity": severity,
                    "scanner": finding.get("scanner", ""),
                    "evidence": finding.get("evidence", ""),
                },
            }

            # Add location if we have a file
            if file_path:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(line, 1),
                            "startColumn": 1,
                        },
                    },
                }]

            results.append(result)

        # Build SARIF document
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Supply Chain Guardian",
                        "version": report_data.get("version", "1.0.0"),
                        "semanticVersion": report_data.get("version", "1.0.0"),
                        "informationUri": "https://github.com/anshumaan-10/supply-chain-guardian",
                        "rules": list(rules.values()),
                        "properties": {
                            "attack_database_version": report_data.get("attack_database_version", ""),
                            "attacks_checked": report_data.get("attacks_checked", 0),
                        },
                    },
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "properties": {
                        "scan_mode": report_data.get("scan_mode", "standard"),
                        "scan_timestamp": report_data.get("scan_timestamp", ""),
                        "scan_duration_seconds": report_data.get("scan_duration_seconds", 0),
                    },
                }],
                "properties": {
                    "overall_status": report_data.get("overall_status", "UNKNOWN"),
                    "repository": report_data.get("repository", ""),
                    "commit_sha": report_data.get("commit_sha", ""),
                },
            }],
        }

        return sarif
