#!/usr/bin/env python3
"""
Permission Scanner
==================
Audits GitHub Actions workflow permissions for least-privilege violations.
Detects over-privileged tokens, missing permissions blocks, and
dangerous permission configurations.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, parse_yaml_safe, read_file_lines


class PermissionScanner(BaseScanner):
    """Audit workflow permissions for security issues."""

    scanner_name = "permission_audit"

    # Scopes that are particularly dangerous
    DANGEROUS_SCOPES = {
        "contents": "write",
        "packages": "write",
        "actions": "write",
        "security-events": "write",
        "id-token": "write",
    }

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
            self._check_permissions(filepath, workflow, lines)

        return self.findings

    def _check_permissions(self, filepath, workflow, lines):
        """Check workflow and job-level permissions."""
        top_permissions = workflow.get("permissions", None)
        jobs = workflow.get("jobs", {})

        # Check 1: No permissions block at all (defaults to read-write for all)
        if top_permissions is None:
            has_any_job_perms = False
            for job_name, job_data in (jobs or {}).items():
                if isinstance(job_data, dict) and "permissions" in job_data:
                    has_any_job_perms = True
                    break

            if not has_any_job_perms:
                self.add_finding(
                    attack_id="SCA-034",
                    title="Missing permissions block - defaults to read-write all",
                    severity="medium",
                    description="This workflow has no 'permissions' block at either the workflow or job level. "
                                "This means the GITHUB_TOKEN has read-write access to all scopes by default. "
                                "If the token is exfiltrated, an attacker gains write access to the repository.",
                    file=filepath,
                    line=1,
                    remediation="Add a top-level 'permissions' block with only the minimum required scopes:\n"
                                "  permissions:\n"
                                "    contents: read\n"
                                "    # add other scopes as needed",
                )

        # Check 2: Write-all permissions
        if isinstance(top_permissions, str) and top_permissions.strip() == "write-all":
            line = self._find_line(lines, "permissions")
            self.add_finding(
                attack_id="SCA-034",
                title="Workflow uses 'permissions: write-all'",
                severity="high",
                description="This workflow grants write access to ALL permission scopes. "
                            "This is the most permissive setting and should almost never be used.",
                file=filepath,
                line=line,
                remediation="Replace 'write-all' with specific scopes needed by the workflow.",
            )

        # Check 3: Granular permission analysis
        if isinstance(top_permissions, dict):
            self._analyze_permissions_dict(filepath, top_permissions, lines, "workflow")

        # Check 4: Job-level permissions
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            job_perms = job_data.get("permissions", None)
            if isinstance(job_perms, dict):
                self._analyze_permissions_dict(filepath, job_perms, lines, f"job '{job_name}'")

            # Check for OIDC tokens
            if isinstance(job_perms, dict) and job_perms.get("id-token") == "write":
                self._check_oidc_config(filepath, job_data, lines, job_name)

    def _analyze_permissions_dict(self, filepath, perms, lines, context):
        """Analyze a permissions dict for dangerous settings."""
        dangerous_combos = []

        for scope, level in perms.items():
            if level == "write" and scope in self.DANGEROUS_SCOPES:
                dangerous_combos.append(f"{scope}: write")

        if len(dangerous_combos) >= 3:
            line = self._find_line(lines, "permissions")
            self.add_finding(
                attack_id="SCA-034",
                title=f"Over-permissive token in {context}",
                severity="medium",
                description=f"The {context} has write permissions for {len(dangerous_combos)} scopes: "
                            f"{', '.join(dangerous_combos)}. Consider reducing to only the necessary scopes.",
                file=filepath,
                line=line,
                remediation="Review each permission and remove write access unless specifically needed.",
            )

    def _check_oidc_config(self, filepath, job_data, lines, job_name):
        """Check OIDC token configurations for misconfiguration."""
        steps = job_data.get("steps", [])
        has_cloud_auth = False

        for step in (steps or []):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "")
            if any(x in uses for x in [
                "aws-actions/configure-aws-credentials",
                "azure/login",
                "google-github-actions/auth"
            ]):
                has_cloud_auth = True
                with_block = step.get("with", {}) or {}
                # Check for overly permissive role
                role = with_block.get("role-to-assume", "")
                if role and "admin" in str(role).lower():
                    line = self._find_line(lines, "role-to-assume")
                    self.add_finding(
                        attack_id="SCA-050",
                        title=f"OIDC token uses admin role in job '{job_name}'",
                        severity="high",
                        description=f"The OIDC configuration assumes an admin role: {role}. "
                                    f"If the OIDC trust policy is misconfigured, any workflow or branch "
                                    f"could assume this powerful role.",
                        file=filepath,
                        line=line,
                        remediation="Use a least-privilege IAM role. Configure OIDC trust with specific "
                                    "repo, branch, and environment constraints.",
                    )

        if not has_cloud_auth:
            line = self._find_line(lines, "id-token")
            self.add_finding(
                attack_id="SCA-050",
                title=f"id-token:write without recognized cloud provider in '{job_name}'",
                severity="low",
                description=f"Job '{job_name}' requests OIDC token (id-token: write) but doesn't use "
                            f"a recognized cloud authentication action. Verify this is intentional.",
                file=filepath,
                line=line,
                remediation="If not using OIDC for cloud auth, remove id-token: write permission.",
            )

    def _find_line(self, lines, text):
        """Find line number containing text."""
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 0
