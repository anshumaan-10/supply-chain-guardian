#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian v2.0.0
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  Enterprise-grade supply chain security scanner for GitHub Actions.
#  This tool is the original work and intellectual property of
#  Anshumaan Singh (github.com/anshumaan-10).
#
#  LICENSE: This software is distributed as a GitHub Action.
#  Unauthorized reproduction, reverse engineering, or redistribution
#  of the source detection logic is strictly prohibited.
#  Use only via: anshumaan-10/supply-chain-guardian@v2
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import sys
import json
import time
import hashlib
import traceback
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from utils.config import ScanConfig
from utils.logger import Logger, C, SEV_MARKERS, SEV_COLORS
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

# Try to load live threat feed module
try:
    from db.threat_feed import fetch_live_patterns, merge_live_patterns
    _HAS_THREAT_FEED = True
except ImportError:
    _HAS_THREAT_FEED = False

# ── Version & Metadata ──────────────────────────────────────────────────────
__version__ = "2.0.0"
__author__ = "Anshumaan Singh"
__github__ = "anshumaan-10"
__tool_id__ = "supply-chain-guardian"

# Try to load new scanners (fail gracefully for backward compatibility)
try:
    from scanners.oidc_scanner import OIDCScanner
    _HAS_OIDC = True
except ImportError:
    _HAS_OIDC = False

try:
    from scanners.artifact_scanner import ArtifactScanner
    _HAS_ARTIFACT = True
except ImportError:
    _HAS_ARTIFACT = False

try:
    from scanners.container_scanner import ContainerScanner
    _HAS_CONTAINER = True
except ImportError:
    _HAS_CONTAINER = False

try:
    from scanners.reusable_workflow_scanner import ReusableWorkflowScanner
    _HAS_REUSABLE = True
except ImportError:
    _HAS_REUSABLE = False


def _banner():
    """Print the Supply Chain Guardian banner — clean, no AI, author branded."""
    print(f"""
{C.R}{C.BLD}  +================================================================+
  |                                                                |
  |   ███████╗ ██████╗ ██████╗     Supply Chain Guardian           |
  |   ██╔════╝██╔════╝██╔════╝     v{__version__:<30s}|
  |   ███████╗██║     ██║  ███╗    Enterprise Security Scanner     |
  |   ╚════██║██║     ██║   ██║    for GitHub Actions & CI/CD      |
  |   ███████║╚██████╗╚██████╔╝                                    |
  |   ╚══════╝ ╚═════╝ ╚═════╝    By {__author__:<25s}|
  |                                github.com/{__github__:<18s}|
  +================================================================+{C.RST}
{C.DIM}  Detects 75+ attack signatures | 80+ behavioral indicators
  Scans >> Alerts >> Blocks pipelines on true-positive threats
  ----------------------------------------------------------------{C.RST}
""")


def _integrity_check():
    """Self-integrity verification — detect tampering of scanner core."""
    core_files = [
        "db/attack_db.py",
        "scanners/compromised_action_scanner.py",
        "scanners/pwn_request_scanner.py",
        "scanners/behavioral_scanner.py",
    ]
    src_dir = Path(__file__).parent
    for cf in core_files:
        fpath = src_dir / cf
        if not fpath.exists():
            return False, f"Missing core module: {cf}"
    return True, "OK"


def _build_scanner_registry(config, attack_db):
    """
    Build the ordered scanner registry.
    Each scanner runs in a specific DevSecOps pipeline phase:
      Phase 1: Source Code Analysis (pre-build)
      Phase 2: Dependency & Supply Chain (pre-build)
      Phase 3: Runtime & Behavioral (build-time / post-build)
    """
    scanners = []

    # ── Phase 1: Source Code & Workflow Analysis ─────────────────────────
    if config.scan_workflows:
        scanners.append(("Compromised Actions", CompromisedActionScanner(config, attack_db), 1))
        scanners.append(("Pwn Request Detection", PwnRequestScanner(config, attack_db), 1))
        scanners.append(("Workflow Analysis", WorkflowScanner(config, attack_db), 1))
        scanners.append(("Cache Poisoning", CachePoisoningScanner(config, attack_db), 1))
        if _HAS_REUSABLE:
            scanners.append(("Reusable Workflow Trust", ReusableWorkflowScanner(config, attack_db), 1))

    if config.scan_permissions:
        scanners.append(("Permission Audit", PermissionScanner(config, attack_db), 1))

    if config.scan_secrets:
        scanners.append(("Secret Exposure", SecretScanner(config, attack_db), 1))

    if config.scan_network:
        scanners.append(("Network Exfiltration", NetworkScanner(config, attack_db), 1))

    # ── Phase 2: Dependency & Supply Chain ───────────────────────────────
    if config.scan_dependencies:
        scanners.append(("Dependency Integrity", DependencyScanner(config, attack_db), 2))
        scanners.append(("Typosquatting", TyposquatScanner(config, attack_db), 2))

    if config.scan_provenance:
        scanners.append(("Provenance Verification", ProvenanceScanner(config, attack_db), 2))

    if _HAS_OIDC and config.scan_workflows:
        scanners.append(("OIDC Token Audit", OIDCScanner(config, attack_db), 2))

    if _HAS_ARTIFACT and config.scan_workflows:
        scanners.append(("Artifact Integrity", ArtifactScanner(config, attack_db), 2))

    if _HAS_CONTAINER and config.scan_workflows:
        scanners.append(("Container Security", ContainerScanner(config, attack_db), 2))

    # ── Phase 3: Runtime & Behavioral ────────────────────────────────────
    if config.scan_runtime:
        scanners.append(("Runtime Monitor", RuntimeScanner(config, attack_db), 3))

    # Behavioral always runs — it catches what signatures miss
    scanners.append(("Behavioral Analysis", BehavioralScanner(config, attack_db), 3))

    return scanners


def main():
    start_time = time.time()
    _banner()

    # ── Configuration ────────────────────────────────────────────────────
    config = ScanConfig.from_environment()
    logger = Logger(config.verbose)

    logger.section("SCAN CONFIGURATION")
    logger.kv("  Tool", f"Supply Chain Guardian v{__version__}")
    logger.kv("  Author", __author__)
    logger.kv("  Mode", config.scan_mode.upper())
    logger.kv("  Fail Threshold", config.fail_on_severity.upper())
    logger.kv("  Target", config.workspace_dir)
    logger.kv("  Timestamp", time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
    repo = os.environ.get("GITHUB_REPOSITORY", "local")
    sha = os.environ.get("GITHUB_SHA", "unknown")[:12]
    logger.kv("  Repository", repo)
    logger.kv("  Commit", sha)
    logger.blank()

    # ── Integrity Check ──────────────────────────────────────────────────
    ok, integrity_msg = _integrity_check()
    if not ok:
        logger.critical(f"INTEGRITY FAILURE: {integrity_msg}")
        logger.error("Scanner core files have been tampered with or are missing.")
        logger.error("Re-install from: anshumaan-10/supply-chain-guardian@v2")
        sys.exit(2)
    logger.debug(f"Integrity check: {integrity_msg}")

    # ── Attack Database ──────────────────────────────────────────────────
    attack_db = AttackDatabase()
    bundled_count = attack_db.total_attacks()
    logger.info(f"Attack database loaded: {bundled_count} bundled patterns (v{attack_db.version})")

    # ── Live Threat Feed ─────────────────────────────────────────────────
    if _HAS_THREAT_FEED:
        try:
            live_patterns, feed_meta = fetch_live_patterns(verbose=config.verbose)
            if live_patterns:
                added = merge_live_patterns(attack_db, live_patterns, feed_meta)
                if added > 0:
                    logger.info(
                        f"Live threat feed: +{added} patterns from {feed_meta.get('feed_source', 'unknown')} "
                        f"({feed_meta.get('fetch_time_ms', 0)}ms)"
                    )
                else:
                    logger.debug(f"Live threat feed: no new patterns (source={feed_meta.get('feed_source', 'none')})")
            else:
                logger.debug("Live threat feed: no patterns fetched (bundled DB is authoritative)")
        except Exception as e:
            logger.debug(f"Live threat feed unavailable: {e} (using bundled DB)")

    logger.info(f"Total patterns available: {attack_db.total_attacks()}")
    logger.blank()

    # ── Build Scanner Registry ───────────────────────────────────────────
    scanners = _build_scanner_registry(config, attack_db)
    total_scanners = len(scanners)
    logger.info(f"Registered {total_scanners} scanner modules")
    logger.blank()

    # ── Execute Scanners ─────────────────────────────────────────────────
    all_findings = []
    scan_results = {}
    current_phase = 0

    phase_names = {
        1: ("SOURCE & WORKFLOW ANALYSIS", "Pre-build static analysis of workflows, actions, and configs"),
        2: ("DEPENDENCY & SUPPLY CHAIN", "Package integrity, provenance, OIDC, artifact trust"),
        3: ("RUNTIME & BEHAVIORAL", "Behavioral heuristics and runtime anomaly detection"),
    }

    for name, scanner, phase in scanners:
        # Print phase header if entering new phase
        if phase != current_phase:
            current_phase = phase
            pname, pdesc = phase_names.get(phase, (f"PHASE {phase}", ""))
            logger.phase(phase, pname, pdesc)

        logger.scanner_start(name)
        scanner_start = time.time()

        try:
            findings = scanner.scan()
            scanner_elapsed = time.time() - scanner_start
            scan_results[name] = {
                "status": "completed",
                "findings_count": len(findings),
                "findings": findings,
                "elapsed_seconds": round(scanner_elapsed, 2),
                "phase": phase,
            }
            all_findings.extend(findings)
            logger.scanner_done(name, len(findings), scanner_elapsed)

        except Exception as e:
            scanner_elapsed = time.time() - scanner_start
            logger.scanner_error(name, str(e))
            if config.verbose:
                traceback.print_exc()
            scan_results[name] = {
                "status": "error",
                "error": str(e),
                "findings_count": 0,
                "findings": [],
                "elapsed_seconds": round(scanner_elapsed, 2),
                "phase": phase,
            }

    # ── Categorize Findings ──────────────────────────────────────────────
    critical = [f for f in all_findings if f.get("severity") == "critical"]
    high     = [f for f in all_findings if f.get("severity") == "high"]
    medium   = [f for f in all_findings if f.get("severity") == "medium"]
    low      = [f for f in all_findings if f.get("severity") == "low"]
    info     = [f for f in all_findings if f.get("severity") == "info"]

    elapsed = time.time() - start_time

    # ── True-Positive Blocking Logic ─────────────────────────────────────
    # Signature matches = definite true positive (block on threshold)
    # Behavioral/heuristic = alert only unless critical
    SIGNATURE_SCANNERS = {
        "compromised_actions", "pwn_request", "network_exfiltration",
        "secret_exposure", "runtime_monitor", "oidc_audit",
        "artifact_integrity", "container_security",
    }
    HEURISTIC_SCANNERS = {"behavioral_analysis"}

    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    fail_threshold = severity_order.get(config.fail_on_severity, 4)

    sig_max = 0
    for f in all_findings:
        if f.get("scanner") in SIGNATURE_SCANNERS:
            sev = severity_order.get(f.get("severity", "info"), 1)
            if sev > sig_max:
                sig_max = sev

    bhv_max = 0
    for f in all_findings:
        if f.get("scanner") in HEURISTIC_SCANNERS:
            sev = severity_order.get(f.get("severity", "info"), 1)
            if sev > bhv_max:
                bhv_max = sev

    all_max = 0
    for f in all_findings:
        sev = severity_order.get(f.get("severity", "info"), 1)
        if sev > all_max:
            all_max = sev

    # Block conditions:
    #   1. Signature scanner finding >= fail_threshold
    #   2. Behavioral critical (curl|sh, base64|sh are always TP)
    #   3. Any scanner finding >= fail_threshold
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

    # ── Report Generation ────────────────────────────────────────────────
    report_data = {
        "tool": {
            "name": "Supply Chain Guardian",
            "version": __version__,
            "author": __author__,
            "github": f"https://github.com/{__github__}/{__tool_id__}",
        },
        "scan_timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "scan_duration_seconds": round(elapsed, 2),
        "scan_mode": config.scan_mode,
        "repository": repo,
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
            "info": len(info),
            "scanners_run": total_scanners,
        },
        "scan_results": scan_results,
        "findings": all_findings,
        "attack_database_version": attack_db.version,
        "attacks_checked": attack_db.total_attacks(),
    }

    # Table output
    if config.table_output:
        logger.section("SCAN RESULTS")
        TableReporter.print_findings_table(all_findings, scan_results, report_data)

    # JSON output
    if config.json_output:
        JsonReporter.write_report(report_data, config.json_output_path)
        logger.info(f"JSON report >> {config.json_output_path}")

    # SARIF output
    if config.sarif_output:
        SarifReporter.write_report(report_data, "supply-chain-guardian.sarif")
        logger.info(f"SARIF report >> supply-chain-guardian.sarif")

    # GitHub Actions annotations and PR comments
    github_token = os.environ.get("INPUT_GITHUB_TOKEN", "")
    if github_token and os.environ.get("GITHUB_ACTIONS") == "true":
        gh_reporter = GitHubReporter(config, github_token)
        gh_reporter.annotate_findings(all_findings)

        if config.auto_comment_pr and os.environ.get("GITHUB_EVENT_NAME") in ("pull_request", "pull_request_target"):
            gh_reporter.comment_pr(report_data)

        if config.create_issue and overall_status == "FAILED":
            gh_reporter.create_issue(report_data)

    # Alerts
    if config.slack_webhook_url and all_max >= severity_order.get(config.alert_on_severity, 4):
        SlackAlerter(config.slack_webhook_url).send_alert(report_data)
        logger.info("Slack alert dispatched")

    if config.teams_webhook_url and all_max >= severity_order.get(config.alert_on_severity, 4):
        TeamsAlerter(config.teams_webhook_url).send_alert(report_data)
        logger.info("Teams alert dispatched")

    # ── GitHub Actions Outputs ───────────────────────────────────────────
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

    # ── Final Verdict ────────────────────────────────────────────────────
    logger.blank()
    logger.section("SCAN COMPLETE")
    logger.kv("  Duration", f"{elapsed:.2f}s")
    logger.kv("  Patterns Checked", str(attack_db.total_attacks()))
    logger.kv("  Scanners Run", str(total_scanners))
    logger.kv("  Total Findings", str(len(all_findings)))
    print(f"  {C.R}{C.BLD}  Critical: {len(critical)}{C.RST}  "
          f"{C.R}High: {len(high)}{C.RST}  "
          f"{C.Y}Medium: {len(medium)}{C.RST}  "
          f"{C.B}Low: {len(low)}{C.RST}  "
          f"{C.DIM}Info: {len(info)}{C.RST}")
    logger.blank()

    if overall_status == "PASSED":
        print(f"  {C.BG_G}{C.W}{C.BLD} PASSED {C.RST} {C.G}No findings at or above '{config.fail_on_severity}' severity{C.RST}")
        print(f"  {C.DIM}Pipeline gate: OPEN -- safe to proceed{C.RST}")
        logger.blank()
        sys.exit(0)
    elif overall_status == "WARNING":
        print(f"  {C.BG_Y}{C.W}{C.BLD} WARNING {C.RST} {C.Y}Findings detected but below fail threshold{C.RST}")
        print(f"  {C.DIM}Pipeline gate: OPEN -- review recommended{C.RST}")
        logger.blank()
        sys.exit(0)
    else:
        print(f"  {C.BG_R}{C.W}{C.BLD} FAILED {C.RST} {C.R}{len(critical)} critical, {len(high)} high severity finding(s){C.RST}")
        print(f"  {C.R}{C.BLD}Pipeline gate: BLOCKED -- remediate before merging{C.RST}")
        print(f"  {C.DIM}Review findings above and apply remediations.{C.RST}")
        logger.blank()
        sys.exit(1)


if __name__ == "__main__":
    main()
