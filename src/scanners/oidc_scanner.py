#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — OIDC Token Scanner
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
OIDC Token Scanner
==================
Detects misuse and abuse patterns of OIDC (OpenID Connect) tokens in
GitHub Actions workflows. OIDC tokens are a keyless authentication
mechanism that can be abused if:

  - Tokens are requested with overly permissive audiences
  - Tokens are forwarded to untrusted endpoints
  - id-token: write permission is granted unnecessarily
  - OIDC tokens are logged, exported, or exfiltrated
  - Tokens are used in pull_request_target contexts (identity confusion)

Attack vector: An attacker who compromises a workflow step can mint
OIDC tokens to impersonate the repository and gain access to cloud
resources (AWS, GCP, Azure) configured to trust GitHub OIDC.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files,
    find_action_files,
    parse_yaml_safe,
    read_file_lines,
    extract_run_blocks,
)


class OIDCScanner(BaseScanner):
    """Detect OIDC token misuse in GitHub Actions workflows."""

    scanner_name = "oidc_audit"

    # Patterns that indicate OIDC token exfiltration
    OIDC_EXFIL_PATTERNS = [
        r"ACTIONS_ID_TOKEN_REQUEST_URL",
        r"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        r"curl.*\$.*ACTIONS_ID_TOKEN",
        r"wget.*ACTIONS_ID_TOKEN",
        r"getIDToken\(",
        r"actions/github-script.*getIDToken",
        r"core\.getIDToken\(",
    ]

    # Patterns that suggest token forwarding to external services
    TOKEN_FORWARD_PATTERNS = [
        r"curl\s+.*-[dH].*id.token",
        r"curl\s+.*--data.*oidc",
        r"wget\s+.*oidc.*token",
        r"fetch\(.*oidc.*token",
        r"requests\.post.*id.token",
    ]

    # Cloud providers that accept GitHub OIDC
    CLOUD_OIDC_ACTIONS = [
        "aws-actions/configure-aws-credentials",
        "google-github-actions/auth",
        "azure/login",
        "hashicorp/vault-action",
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)
        all_files = workflow_files + action_files

        if not all_files:
            return self.findings

        for filepath in all_files:
            if not self.should_scan_file(filepath):
                continue

            data = parse_yaml_safe(filepath)
            lines = read_file_lines(filepath)

            if not data:
                continue

            self._check_id_token_permission(data, filepath, lines)
            self._check_oidc_exfiltration(filepath)
            self._check_oidc_audience(filepath, lines)
            self._check_oidc_in_pr_context(data, filepath, lines)
            self._check_unnecessary_oidc(data, filepath, lines)

        return self.findings

    def _check_id_token_permission(self, data: dict, filepath: str, lines: list):
        """Check for id-token: write at the workflow level (overly permissive)."""
        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            if permissions.get("id-token") == "write":
                # Check if there are jobs that don't need OIDC
                jobs = data.get("jobs", {})
                oidc_jobs = 0
                total_jobs = len(jobs)

                for job_name, job_data in jobs.items():
                    if not isinstance(job_data, dict):
                        continue
                    steps = job_data.get("steps", [])
                    uses_oidc = False
                    for step in steps:
                        if not isinstance(step, dict):
                            continue
                        uses = step.get("uses", "")
                        if any(ca in str(uses) for ca in self.CLOUD_OIDC_ACTIONS):
                            uses_oidc = True
                            break
                    if uses_oidc:
                        oidc_jobs += 1

                if oidc_jobs < total_jobs and total_jobs > 1:
                    # Find the line number
                    ln = self._find_line(lines, "id-token")
                    self.add_finding(
                        attack_id="SCA-061",
                        title="Workflow-level id-token:write grants OIDC to all jobs",
                        severity="high",
                        description=(
                            f"id-token: write is set at the workflow level but only "
                            f"{oidc_jobs}/{total_jobs} jobs appear to use OIDC authentication. "
                            f"Compromising any job step grants the attacker OIDC token minting."
                        ),
                        file=filepath,
                        line=ln,
                        remediation="Move id-token: write to job-level permissions only for jobs that need cloud auth.",
                    )

    def _check_oidc_exfiltration(self, filepath: str):
        """Check for patterns that exfiltrate OIDC tokens."""
        run_blocks = extract_run_blocks(filepath)
        for block in run_blocks:
            content = block["content"]
            line = block["line"]

            for pattern in self.OIDC_EXFIL_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    # Check if it's a legitimate cloud auth use
                    if self._is_legitimate_oidc_use(content):
                        continue
                    self.add_finding(
                        attack_id="SCA-062",
                        title="OIDC token accessed in run block",
                        severity="high",
                        description=(
                            "An OIDC token request URL or token is accessed directly in a run block. "
                            "OIDC tokens should only be consumed by trusted cloud auth actions, "
                            "not shell scripts. An attacker could forward this token to impersonate "
                            "the repository."
                        ),
                        file=filepath,
                        line=line,
                        remediation="Use official cloud auth actions (aws-actions/configure-aws-credentials, google-github-actions/auth) instead of manual OIDC token handling.",
                        evidence=content[:200],
                    )
                    break

            for pattern in self.TOKEN_FORWARD_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(
                        attack_id="SCA-063",
                        title="Possible OIDC token forwarding to external endpoint",
                        severity="critical",
                        description=(
                            "A workflow step appears to forward an OIDC token to an external service. "
                            "This could allow an attacker to assume the GitHub OIDC identity and "
                            "access cloud resources (AWS, GCP, Azure) trusted by this repository."
                        ),
                        file=filepath,
                        line=line,
                        remediation="Never forward OIDC tokens manually. Use official cloud provider actions for authentication.",
                        evidence=content[:200],
                    )
                    break

    def _check_oidc_audience(self, filepath: str, lines: list):
        """Check for custom OIDC audiences that could be overly permissive."""
        for i, line_text in enumerate(lines, 1):
            stripped = line_text.strip()
            # Check for audience configuration
            if re.search(r'audience:\s*["\']?\*', stripped, re.IGNORECASE):
                self.add_finding(
                    attack_id="SCA-064",
                    title="Wildcard OIDC audience configured",
                    severity="critical",
                    description=(
                        "The OIDC token audience is set to wildcard (*). This means the token "
                        "can be used to authenticate against any service that trusts GitHub OIDC, "
                        "not just the intended target."
                    ),
                    file=filepath,
                    line=i,
                    remediation="Set a specific audience value matching only your intended cloud provider.",
                    evidence=stripped,
                )

    def _check_oidc_in_pr_context(self, data: dict, filepath: str, lines: list):
        """Check for OIDC token use in pull_request_target (identity confusion)."""
        triggers = data.get("on", data.get(True, {}))
        if isinstance(triggers, dict):
            has_prt = "pull_request_target" in triggers
        elif isinstance(triggers, list):
            has_prt = "pull_request_target" in triggers
        else:
            has_prt = False

        if not has_prt:
            return

        permissions = data.get("permissions", {})
        if isinstance(permissions, dict) and permissions.get("id-token") == "write":
            ln = self._find_line(lines, "pull_request_target")
            self.add_finding(
                attack_id="SCA-065",
                title="OIDC token available in pull_request_target context",
                severity="critical",
                description=(
                    "This workflow triggers on pull_request_target AND grants id-token: write. "
                    "A malicious PR can modify workflow behavior to mint OIDC tokens, "
                    "gaining access to cloud resources protected by OIDC federation."
                ),
                file=filepath,
                line=ln,
                remediation="Do NOT grant id-token: write in pull_request_target workflows. Use a separate trusted workflow for cloud auth.",
                evidence="pull_request_target + id-token: write",
            )

    def _check_unnecessary_oidc(self, data: dict, filepath: str, lines: list):
        """Detect id-token: write when no cloud auth action is used."""
        permissions = data.get("permissions", {})
        has_id_token = False
        if isinstance(permissions, dict):
            has_id_token = permissions.get("id-token") == "write"

        if not has_id_token:
            # Check job-level permissions
            jobs = data.get("jobs", {})
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                job_perms = job_data.get("permissions", {})
                if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
                    # Check if this job actually uses cloud auth
                    steps = job_data.get("steps", [])
                    uses_cloud = False
                    for step in steps:
                        if not isinstance(step, dict):
                            continue
                        uses = str(step.get("uses", ""))
                        if any(ca in uses for ca in self.CLOUD_OIDC_ACTIONS):
                            uses_cloud = True
                            break
                    if not uses_cloud:
                        ln = self._find_line(lines, "id-token")
                        self.add_finding(
                            attack_id="SCA-066",
                            title=f"Unnecessary id-token: write in job '{job_name}'",
                            severity="medium",
                            description=(
                                f"Job '{job_name}' has id-token: write permission but does not appear to use "
                                f"any cloud authentication action. Unnecessary OIDC permissions increase the "
                                f"attack surface if a step is compromised."
                            ),
                            file=filepath,
                            line=ln,
                            remediation="Remove id-token: write from jobs that don't need cloud OIDC authentication.",
                        )

    def _is_legitimate_oidc_use(self, content: str) -> bool:
        """Check if OIDC token access is for legitimate cloud authentication."""
        legitimate = [
            "configure-aws-credentials",
            "google-github-actions/auth",
            "azure/login",
            "vault-action",
        ]
        return any(leg in content.lower() for leg in legitimate)

    def _find_line(self, lines: list, keyword: str) -> int:
        """Find the first line containing a keyword."""
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1
