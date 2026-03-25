#!/usr/bin/env python3
"""
Supply Chain Guardian — Main Entry Point
Enterprise-grade GitHub Actions supply chain security scanner.
Detects 60+ real-world supply chain attack patterns and behavioral
indicators of future compromises. Alerts and blocks pipelines on
true-positive threats.
"""

import os
import sys
import json
import time
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.config import ScanConfig
from utils.logger import Logger, Colors
from scanners.workflow_scanner import WorkflowScanner
from scanners.dependency_scanner import DependencyScanner
from scanners.secret_scanner import SecretScanner
from scanners.network_scanner import NetworkScanner
from scanners.permission_scanner import PermissionScanner
from scanners.provenance_scanner import ProvenanceScanner
from scanners.runtime_scanner import RuntimeScanner
from scanners.compromised_action_scanner import CompromisedActionScanner
from scanners.pwn_request_scanner import PwnRequestScanner
from scanners.cache_poisoning_scanner import CachePoisoningScanner
from scanners.typosquat_scanner import TyposquatScanner
from scanners.behavioral_scanner import BehavioralScanner
from reporters.table_reporter import TableReporter
from reporters.json_reporter import JsonReporter
from reporters.sarif_reporter import SarifReporter
from reporters.github_reporter import GitHubReporter
from alerting.slack_alerter import SlackAlerter
from alerting.teams_alerter import TeamsAlerter
from db.attack_db import AttackDatabase


BANNER = f"""{Colors.RED}
╔═══════════════════════════════════════════════════════════════╗
║         _____ _   _ ___  ____  ____  ___    _    _   _       ║
║        / ____| | | |/ _ \\|  _ \\|  _ \\|_ _|  / \\  | \\ | |     ║
║       | |  __| | | | |_| | |_) | | | || |  / _ \\ |  \\| |     ║
║       | | |_ | | | |  _  |  _ <| | | || | / ___ \\| . ` |     ║
║       | |__| | |_| | | | | |_) | |_| || |/ /   \\ \\ |\\  |     ║
║        \\_____|\\___/|_| |_|____/|____/___/_/     \\_\\_| \\_|     ║
║                                                               ║
║           Supply Chain Guardian v1.0.0                        ║
║       Enterprise Supply Chain Security Scanner                ║
║                                                               ║
║  Detects 60+ attack patterns + behavioral future indicators   ║
║  Scans • Alerts • Blocks pipelines on true-positive threats    ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.RESET}"""


def main():
    start_time = time.time()
    print(BANNER)

    # Load configuration from environment variables (set by action.yml)
    config = ScanConfig.from_environment()
    logger = Logger(config.verbose)

    logger.info(f"Scan Mode: {config.scan_mode}")
    logger.info(f"Fail on Severity: {config.fail_on_severity}")
    logger.info(f"Target Directory: {config.workspace_dir}")
    logger.info(f"Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    print("")

    # Initialize attack database
    attack_db = AttackDatabase()
    logger.info(f"Loaded {attack_db.total_attacks()} known supply chain attack patterns")
    print("")

    # Initialize all scanners
    all_findings = []
    scan_results = {}
    scanners = []

    if config.scan_workflows:
        scanners.append(("Compromised Actions", CompromisedActionScanner(config, attack_db)))
        scanners.append(("Pwn Request Detection", PwnRequestScanner(config, attack_db)))
        scanners.append(("Workflow Analysis", WorkflowScanner(config, attack_db)))
        scanners.append(("Cache Poisoning", CachePoisoningScanner(config, attack_db)))

    if config.scan_permissions:
        scanners.append(("Permission Audit", PermissionScanner(config, attack_db)))

    if config.scan_secrets:
        scanners.append(("Secret Exposure", SecretScanner(config, attack_db)))

    if config.scan_network:
        scanners.append(("Network Exfiltration", NetworkScanner(config, attack_db)))

    if config.scan_dependencies:
        scanners.append(("Dependency Integrity", DependencyScanner(config, attack_db)))
        scanners.append(("Typosquatting", TyposquatScanner(config, attack_db)))

    if config.scan_provenance:
        scanners.append(("Provenance Verification", ProvenanceScanner(config, attack_db)))

    if config.scan_runtime:
        scanners.append(("Runtime Monitor", RuntimeScanner(config, attack_db)))

    # Behavioral / predictive scanner always runs
    scanners.append(("Behavioral Analysis", BehavioralScanner(config, attack_db)))

    # Run each scanner
    for name, scanner in scanners:
        logger.section(f"Running: {name}")
        try:
            findings = scanner.scan()
            scan_results[name] = {
                "status": "completed",
                "findings_count": len(findings),
                "findings": findings
            }
            all_findings.extend(findings)
            if findings:
                logger.warning(f"  {len(findings)} finding(s) detected")
            else:
                logger.success(f"  No issues detected")
        except Exception as e:
            logger.error(f"  Scanner error: {e}")
            if config.verbose:
                traceback.print_exc()
            scan_results[name] = {
                "status": "error",
                "error": str(e),
                "findings_count": 0,
                "findings": []
            }

    # Categorize findings
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high = [f for f in all_findings if f.get("severity") == "high"]
    medium = [f for f in all_findings if f.get("severity") == "medium"]
    low = [f for f in all_findings if f.get("severity") == "low"]
    info = [f for f in all_findings if f.get("severity") == "info"]

    elapsed = time.time() - start_time

    # ─── True-Positive Blocking Logic ───────────────────────────────
    # Only block on findings that have near-certain confidence.
    # Signature matches (known SHAs, known patterns) = definite TP.
    # Behavioral/heuristic findings = alert only unless critical.
    SIGNATURE_SCANNERS = {
        "compromised_actions", "pwn_request", "network_exfiltration",
        "secret_exposure", "runtime_monitor",
    }
    HEURISTIC_SCANNERS = {"behavioral_analysis"}

    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    fail_threshold = severity_order.get(config.fail_on_severity, 4)

    # Max severity from signature-based (high-confidence) scanners
    sig_max = 0
    for f in all_findings:
        if f.get("scanner") in SIGNATURE_SCANNERS:
            sev = severity_order.get(f.get("severity", "info"), 1)
            if sev > sig_max:
                sig_max = sev

    # Heuristic findings only block at critical (e.g., curl|sh, base64|sh)
    bhv_max = 0
    for f in all_findings:
        if f.get("scanner") in HEURISTIC_SCANNERS:
            sev = severity_order.get(f.get("severity", "info"), 1)
            if sev > bhv_max:
                bhv_max = sev

    # Overall max (for other scanners like workflow, permissions, etc.)
    all_max = 0
    for f in all_findings:
        sev = severity_order.get(f.get("severity", "info"), 1)
        if sev > all_max:
            all_max = sev

    # Block if:
    #   - Any signature scanner finding >= fail_threshold
    #   - Behavioral critical finding (curl|sh, base64|sh are always TP)
    #   - Any other scanner finding >= fail_threshold
    should_block = (
        sig_max >= fail_threshold
        or (bhv_max >= severity_order["critical"])
        or all_max >= fail_threshold
    )

    if should_block:
        overall_status = "FAILED"
    elif all_max >= 2:
        overall_status = "WARNING"
    else:
        overall_status = "PASSED"

    # Generate reports
    report_data = {
        "version": "1.0.0",
        "scan_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "scan_duration_seconds": round(elapsed, 2),
        "scan_mode": config.scan_mode,
        "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
        "commit_sha": os.environ.get("GITHUB_SHA", "unknown"),
        "ref": os.environ.get("GITHUB_REF", "unknown"),
        "event": os.environ.get("GITHUB_EVENT_NAME", "manual"),
        "overall_status": overall_status,
        "summary": {
            "total_findings": len(all_findings),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "info": len(info)
        },
        "scan_results": scan_results,
        "findings": all_findings,
        "attack_database_version": attack_db.version,
        "attacks_checked": attack_db.total_attacks()
    }

    # Table output
    if config.table_output:
        logger.section("SCAN RESULTS")
        TableReporter.print_findings_table(all_findings, scan_results, report_data)

    # JSON output
    if config.json_output:
        JsonReporter.write_report(report_data, config.json_output_path)
        logger.info(f"JSON report written to: {config.json_output_path}")

    # SARIF output
    if config.sarif_output:
        SarifReporter.write_report(report_data, "supply-chain-guardian.sarif")
        logger.info(f"SARIF report written to: supply-chain-guardian.sarif")

    # GitHub Actions annotations and PR comments
    github_token = os.environ.get("INPUT_GITHUB_TOKEN", "")
    if github_token and os.environ.get("GITHUB_ACTIONS") == "true":
        gh_reporter = GitHubReporter(config, github_token)
        gh_reporter.annotate_findings(all_findings)

        if config.auto_comment_pr and os.environ.get("GITHUB_EVENT_NAME") in ("pull_request", "pull_request_target"):
            gh_reporter.comment_pr(report_data)

        if config.create_issue and overall_status == "FAILED":
            gh_reporter.create_issue(report_data)

    # Send alerts — use all_max for alert threshold
    if config.slack_webhook_url and all_max >= severity_order.get(config.alert_on_severity, 4):
        SlackAlerter(config.slack_webhook_url).send_alert(report_data)
        logger.info("Slack alert sent")

    if config.teams_webhook_url and all_max >= severity_order.get(config.alert_on_severity, 4):
        TeamsAlerter(config.teams_webhook_url).send_alert(report_data)
        logger.info("Teams alert sent")

    # Write GitHub Actions outputs
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"scan-status={overall_status}\n")
            f.write(f"total-findings={len(all_findings)}\n")
            f.write(f"critical-findings={len(critical)}\n")
            f.write(f"high-findings={len(high)}\n")
            f.write(f"medium-findings={len(medium)}\n")
            f.write(f"low-findings={len(low)}\n")
            f.write(f"report-path={config.json_output_path}\n")
            f.write(f"sarif-path=supply-chain-guardian.sarif\n")

    # Final summary
    print("")
    logger.section("SCAN COMPLETE")
    logger.info(f"Duration: {elapsed:.2f}s")
    logger.info(f"Attacks Database: {attack_db.total_attacks()} patterns checked")
    logger.info(f"Total Findings: {len(all_findings)}")
    logger.info(f"  Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)} | Info: {len(info)}")

    if overall_status == "PASSED":
        logger.success(f"\n  ✅ SCAN PASSED — No findings at or above '{config.fail_on_severity}' severity\n")
        sys.exit(0)
    elif overall_status == "WARNING":
        logger.warning(f"\n  ⚠️  SCAN WARNING — Findings detected but below fail threshold\n")
        sys.exit(0)
    else:
        logger.error(f"\n  ❌ SCAN FAILED — {len(critical)} critical, {len(high)} high severity finding(s) detected\n")
        logger.error(f"  Action Required: Review findings and remediate before merging.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
