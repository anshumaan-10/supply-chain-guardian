#!/usr/bin/env python3
"""
Cache Poisoning Scanner
=======================
Detects GitHub Actions cache configurations that are
vulnerable to cache poisoning attacks (Ultralytics-style).
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, parse_yaml_safe, read_file_lines


class CachePoisoningScanner(BaseScanner):
    """Detect cache poisoning vulnerabilities in workflows."""

    scanner_name = "cache_poisoning"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)

        for filepath in workflow_files:
            if not self.should_scan_file(filepath):
                continue

            workflow = parse_yaml_safe(filepath)
            if not workflow:
                continue

            lines = read_file_lines(filepath)
            content = "".join(lines)

            self._check_cache_usage(filepath, workflow, lines, content)

        return self.findings

    def _check_cache_usage(self, filepath, workflow, lines, content):
        """Analyze cache patterns for poisoning risk."""
        triggers = workflow.get("on", workflow.get(True, {}))
        is_pr_target = False
        if isinstance(triggers, dict):
            is_pr_target = "pull_request_target" in triggers

        jobs = workflow.get("jobs", {})
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step_idx, step in enumerate(steps or []):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                with_block = step.get("with", {}) or {}

                # Check actions/cache usage
                if "actions/cache" in uses:
                    key = str(with_block.get("key", ""))
                    restore_keys = str(with_block.get("restore-keys", ""))

                    issues = []

                    # Check 1: Broad restore-keys
                    if restore_keys and not re.search(r'\$\{\{.*hashFiles', restore_keys):
                        issues.append("restore-keys don't include hashFiles() - cache content could be stale or poisoned")

                    # Check 2: Cache key doesn't include lockfile hash
                    if key and not re.search(r'hashFiles\(.*lock', key, re.IGNORECASE):
                        issues.append("Cache key doesn't include lockfile hash - vulnerable to dependency substitution")

                    # Check 3: Used with pull_request_target
                    if is_pr_target:
                        issues.append("CRITICAL: Cache used with pull_request_target - "
                                      "PR authors can poison the cache for the base branch (Ultralytics attack pattern)")

                    # Check 4: Cache key uses runner.os only
                    if key and re.match(r'^\$\{\{.*runner\.os\s*\}\}-\w+$', key):
                        issues.append("Cache key only uses runner.os - too broad, allows cross-branch cache poisoning")

                    if issues:
                        line = self._find_uses_line(lines, "actions/cache", step_idx)
                        severity = "critical" if is_pr_target else "medium"
                        self.add_finding(
                            attack_id="SCA-040",
                            title=f"Cache poisoning risk in job '{job_name}'",
                            severity=severity,
                            description="Potential cache poisoning vulnerability detected. " + " ".join(issues) +
                                        " This is the same attack vector used in the Ultralytics supply chain attack "
                                        "where attackers poisoned the GitHub Actions cache with a cryptominer.",
                            file=filepath,
                            line=line,
                            remediation="1. Include lockfile hashes in cache keys: hashFiles('**/package-lock.json')\n"
                                        "2. Don't use restore-keys with broad prefixes\n"
                                        "3. Never use actions/cache with pull_request_target\n"
                                        "4. Verify cache integrity after restore",
                            evidence=f"key: {key}, restore-keys: {restore_keys}",
                        )

                # Check setup-* actions with built-in caching
                if any(x in uses for x in ["setup-node", "setup-python", "setup-go", "setup-java"]):
                    cache_val = with_block.get("cache", "")
                    if cache_val and is_pr_target:
                        line = self._find_uses_line(lines, uses.split("@")[0], step_idx)
                        self.add_finding(
                            attack_id="SCA-040",
                            title=f"Setup action caching + pull_request_target in '{job_name}'",
                            severity="high",
                            description=f"Setup action '{uses}' has built-in caching enabled alongside "
                                        f"pull_request_target trigger. PR authors can poison the dependency cache.",
                            file=filepath,
                            line=line,
                            remediation="Disable caching in setup actions when using pull_request_target. "
                                        "Use explicit cache actions with lockfile-based keys instead.",
                            evidence=f"uses: {uses}, cache: {cache_val}",
                        )

    def _find_uses_line(self, lines, action_name, step_idx):
        """Find the line number for a specific uses statement."""
        count = 0
        for i, line in enumerate(lines, 1):
            if action_name in line and "uses:" in line:
                if count == step_idx:
                    return i
                count += 1
        # Fallback: find first occurrence
        for i, line in enumerate(lines, 1):
            if action_name in line:
                return i
        return 0
