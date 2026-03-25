#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Reusable Workflow Scanner
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
Reusable Workflow Scanner
=========================
Detects trust boundary issues in reusable workflows (workflow_call).

Reusable workflows are a powerful GitHub Actions feature but introduce
unique supply chain risks:

  - Calling external reusable workflows with mutable refs
  - Passing secrets to untrusted reusable workflows
  - Input injection in reusable workflow inputs
  - Over-permissive permissions inherited by reusable workflows
  - Reusable workflows from forks or untrusted organizations
  - Missing input validation / sanitization in called workflows
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files,
    parse_yaml_safe,
    read_file_lines,
)


class ReusableWorkflowScanner(BaseScanner):
    """Scan for reusable workflow trust boundary issues."""

    scanner_name = "reusable_workflow"

    # Trusted GitHub organizations for reusable workflows
    TRUSTED_ORGS = [
        "actions", "github", "google-github-actions",
        "aws-actions", "azure", "docker",
        "slsa-framework", "sigstore",
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)
        if not workflow_files:
            return self.findings

        for filepath in workflow_files:
            if not self.should_scan_file(filepath):
                continue

            data = parse_yaml_safe(filepath)
            lines = read_file_lines(filepath)

            if not data:
                continue

            # Check caller workflows (uses: .../workflow.yml)
            self._check_caller_workflows(data, filepath, lines)

            # Check called (reusable) workflow definitions
            self._check_reusable_definition(data, filepath, lines)

        return self.findings

    def _check_caller_workflows(self, data: dict, filepath: str, lines: list):
        """Check for security issues in calling reusable workflows."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            uses = job_data.get("uses", "")
            if not uses or not isinstance(uses, str):
                continue

            # This job calls a reusable workflow
            self._check_reusable_ref(uses, job_name, job_data, filepath, lines)
            self._check_secret_inheritance(job_data, job_name, filepath, lines)
            self._check_input_injection(job_data, job_name, filepath, lines)

    def _check_reusable_ref(self, uses: str, job_name: str, job_data: dict, filepath: str, lines: list):
        """Check if the reusable workflow reference is secure."""
        # Local references (./.github/workflows/) are trusted
        if uses.startswith("./"):
            return

        # Parse owner/repo/.github/workflows/workflow.yml@ref
        match = re.match(r'^([^/]+)/([^/]+)/\.github/workflows/([^@]+)@(.+)$', uses)
        if not match:
            return

        owner = match.group(1)
        repo = match.group(2)
        workflow_file = match.group(3)
        ref = match.group(4)

        ln = self._find_line(lines, uses[:30]) or self._find_line(lines, job_name)

        # Check 1: Mutable ref (not a SHA)
        if not re.match(r'^[0-9a-f]{40}$', ref):
            severity = "high" if owner.lower() not in [o.lower() for o in self.TRUSTED_ORGS] else "medium"
            self.add_finding(
                attack_id="SCA-084",
                title=f"Reusable workflow called with mutable ref: {uses}",
                severity=severity,
                description=(
                    f"Job '{job_name}' calls a reusable workflow with mutable ref '{ref}'. "
                    "The workflow owner can change the code at this ref without your knowledge. "
                    "This is the reusable workflow equivalent of using mutable action tags."
                ),
                file=filepath,
                line=ln,
                remediation=f"Pin to a full commit SHA: {owner}/{repo}/.github/workflows/{workflow_file}@<sha>",
                evidence=uses,
            )

        # Check 2: Untrusted organization
        if owner.lower() not in [o.lower() for o in self.TRUSTED_ORGS]:
            # Check if it's the same org as the repo
            repo_owner = self._get_repo_owner()
            if repo_owner and owner.lower() != repo_owner.lower():
                self.add_finding(
                    attack_id="SCA-085",
                    title=f"Reusable workflow from external organization: {owner}",
                    severity="medium",
                    description=(
                        f"Job '{job_name}' calls a reusable workflow from organization '{owner}', "
                        "which is outside your organization. External reusable workflows can access "
                        "inherited secrets and OIDC tokens. Verify the workflow is trustworthy."
                    ),
                    file=filepath,
                    line=ln,
                    remediation=(
                        f"Audit the external workflow at {owner}/{repo}. "
                        "If possible, fork and maintain your own copy. Pin to a SHA."
                    ),
                    evidence=uses,
                )

    def _check_secret_inheritance(self, job_data: dict, job_name: str, filepath: str, lines: list):
        """Check for dangerous secret passing patterns."""
        secrets = job_data.get("secrets", {})

        # inherit keyword passes ALL secrets
        if secrets == "inherit" or (isinstance(secrets, str) and secrets.strip() == "inherit"):
            ln = self._find_line(lines, "inherit")
            self.add_finding(
                attack_id="SCA-086",
                title=f"All secrets inherited by reusable workflow in '{job_name}'",
                severity="high",
                description=(
                    "The 'secrets: inherit' keyword passes ALL repository secrets to the "
                    "reusable workflow. If the external workflow is compromised, all secrets "
                    "are exposed. A malicious update to the workflow can exfiltrate every secret."
                ),
                file=filepath,
                line=ln,
                remediation="Pass only the specific secrets needed: secrets: { MY_SECRET: ${{ secrets.MY_SECRET }} }",
            )

        # Check if too many secrets are passed
        if isinstance(secrets, dict) and len(secrets) > 5:
            ln = self._find_line(lines, "secrets:")
            self.add_finding(
                attack_id="SCA-087",
                title=f"Excessive secrets passed to reusable workflow in '{job_name}'",
                severity="medium",
                description=(
                    f"{len(secrets)} secrets are passed to the reusable workflow. "
                    "Passing many secrets increases the blast radius if the external "
                    "workflow is compromised."
                ),
                file=filepath,
                line=ln,
                remediation="Minimize secrets passed to external workflows. Use OIDC for cloud auth instead of long-lived secrets.",
            )

    def _check_input_injection(self, job_data: dict, job_name: str, filepath: str, lines: list):
        """Check for potential input injection in reusable workflow calls."""
        with_inputs = job_data.get("with", {})
        if not isinstance(with_inputs, dict):
            return

        injection_patterns = [
            r"github\.event\..*\.title",
            r"github\.event\..*\.body",
            r"github\.event\..*\.name",
            r"github\.event\.comment\.body",
            r"github\.event\.issue\.title",
            r"github\.event\.pull_request\.title",
            r"github\.event\.pull_request\.body",
            r"github\.head_ref",
        ]

        for input_name, input_value in with_inputs.items():
            input_str = str(input_value)
            for pattern in injection_patterns:
                if re.search(pattern, input_str, re.IGNORECASE):
                    ln = self._find_line(lines, input_name)
                    self.add_finding(
                        attack_id="SCA-088",
                        title=f"Untrusted data in reusable workflow input '{input_name}'",
                        severity="high",
                        description=(
                            f"Input '{input_name}' in job '{job_name}' contains attacker-controllable data "
                            f"({pattern}). If the reusable workflow uses this input in a run: block "
                            "or script context, it creates a script injection vulnerability."
                        ),
                        file=filepath,
                        line=ln,
                        remediation=(
                            "Sanitize inputs before passing to reusable workflows. Use intermediate "
                            "environment variables instead of direct expression interpolation."
                        ),
                        evidence=input_str[:200],
                    )
                    break

    def _check_reusable_definition(self, data: dict, filepath: str, lines: list):
        """Check reusable workflow definitions for security issues."""
        triggers = data.get("on", data.get(True, {}))
        if not isinstance(triggers, dict):
            return

        workflow_call = triggers.get("workflow_call", {})
        if not workflow_call:
            return

        # This IS a reusable workflow — check its security posture
        inputs = workflow_call.get("inputs", {}) if isinstance(workflow_call, dict) else {}

        # Check for inputs used unsafely
        if isinstance(inputs, dict):
            for input_name, input_config in inputs.items():
                if not isinstance(input_config, dict):
                    continue

                # Check if input type is not constrained
                if input_config.get("type") not in ("boolean", "number"):
                    # This is a string input — check if it's used in run blocks
                    self._check_input_used_in_run(
                        input_name, data, filepath, lines
                    )

        # Check permissions
        permissions = data.get("permissions", {})
        if isinstance(permissions, str) and permissions == "write-all":
            ln = self._find_line(lines, "permissions")
            self.add_finding(
                attack_id="SCA-089",
                title="Reusable workflow with write-all permissions",
                severity="high",
                description=(
                    "This reusable workflow has write-all permissions. Any caller that "
                    "invokes this workflow grants it maximum permissions, which increases "
                    "the impact of any vulnerability in the workflow."
                ),
                file=filepath,
                line=ln,
                remediation="Apply least-privilege permissions. Specify only the permissions this workflow needs.",
            )

    def _check_input_used_in_run(self, input_name: str, data: dict, filepath: str, lines: list):
        """Check if a reusable workflow input is used directly in run blocks."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run_content = str(step.get("run", ""))
                # Check for direct input interpolation in run blocks
                if re.search(rf'inputs\.{re.escape(input_name)}', run_content):
                    ln = self._find_line(lines, f"inputs.{input_name}")
                    self.add_finding(
                        attack_id="SCA-090",
                        title=f"Reusable workflow input '{input_name}' used in run block",
                        severity="medium",
                        description=(
                            f"Input '{input_name}' is interpolated directly in a run block in job '{job_name}'. "
                            "If the caller passes attacker-controlled data, this creates a script injection. "
                            "Reusable workflow inputs should be passed through environment variables."
                        ),
                        file=filepath,
                        line=ln,
                        remediation=f"Use env variable: env:\\n  INPUT_VAL: ${{{{ inputs.{input_name} }}}}\\nrun: echo \"$INPUT_VAL\"",
                        evidence=run_content[:200],
                    )

    def _get_repo_owner(self) -> str:
        """Get the repository owner from environment."""
        import os
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if "/" in repo:
            return repo.split("/")[0]
        return ""

    def _find_line(self, lines: list, keyword: str) -> int:
        """Find the first line containing a keyword."""
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1
