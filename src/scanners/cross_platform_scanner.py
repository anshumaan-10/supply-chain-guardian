#!/usr/bin/env python3
"""
Cross-Platform CI/CD Scanner
=============================
Scans CI/CD configurations across multiple platforms:
- Jenkins (Jenkinsfile)
- GitLab CI (.gitlab-ci.yml)
- CircleCI (.circleci/config.yml)
- Azure DevOps (azure-pipelines.yml)

Detects credential exposure, insecure practices, and supply chain
attack patterns across all major CI/CD platforms.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_jenkinsfiles,
    find_gitlab_ci_files,
    find_circleci_files,
    find_azure_pipelines,
    read_file_lines,
)


class CrossPlatformScanner(BaseScanner):
    """Scan CI/CD configurations across Jenkins, GitLab CI, CircleCI, Azure DevOps."""

    scanner_name = "cross_platform_ci"

    # ── Jenkins patterns ──
    JENKINS_SECRET_EXPOSURE = [
        (r"echo\s+.*\$\{?\w*(PASSWORD|TOKEN|SECRET|KEY|CREDENTIAL)\w*\}?", "Echo of secret variable", "critical"),
        (r"sh\s+.*curl.*\$\{?\w*(PASSWORD|TOKEN|SECRET|KEY|CREDENTIAL)\w*\}?", "Secret passed to curl", "critical"),
        (r"sh\s+.*wget.*\$\{?\w*(PASSWORD|TOKEN|SECRET|KEY|CREDENTIAL)\w*\}?", "Secret passed to wget", "critical"),
        (r"println\s+.*\$\{?\w*(PASSWORD|TOKEN|SECRET|KEY)\w*\}?", "Secret printed to log", "critical"),
        (r"writeFile.*\$\{?\w*(PASSWORD|TOKEN|SECRET|KEY)\w*\}?", "Secret written to file", "high"),
    ]

    JENKINS_INSECURE_PATTERNS = [
        (r"script\s*\{", "Scripted pipeline block (less restricted)", "medium"),
        (r"agent\s+any", "Agent: any (runs on any available node)", "low"),
        (r"sh\s+['\"]curl.*\|\s*(ba)?sh", "Pipe-to-shell pattern", "critical"),
        (r"checkout\s+scm\s*$", "Checkout SCM without options", "low"),
        (r"library\s+['\"].*@.*['\"]", "Shared library with mutable reference", "medium"),
    ]

    # ── GitLab CI patterns ──
    GITLAB_SECRET_EXPOSURE = [
        (r"echo\s+.*\$CI_JOB_TOKEN", "Echo of CI_JOB_TOKEN", "critical"),
        (r"echo\s+.*\$CI_REGISTRY_PASSWORD", "Echo of CI_REGISTRY_PASSWORD", "critical"),
        (r"echo\s+.*\$CI_DEPLOY_PASSWORD", "Echo of CI_DEPLOY_PASSWORD", "critical"),
        (r"curl.*\$CI_JOB_TOKEN", "CI_JOB_TOKEN passed to curl", "critical"),
        (r"curl.*\$PRIVATE_TOKEN", "PRIVATE_TOKEN passed to curl", "critical"),
        (r"echo\s+.*\$\w*(SECRET|TOKEN|KEY|PASSWORD)\w*", "Secret variable in echo", "high"),
    ]

    GITLAB_INSECURE_PATTERNS = [
        (r"when:\s*manual", "Manual gate (ensure authorized approvers)", "info"),
        (r"allow_failure:\s*true", "Allow failure (may hide security issues)", "low"),
        (r"include:\s*\n\s*-\s*remote:", "Remote include (external dependency)", "medium"),
        (r"image:\s*[^\n]*latest", "Docker image using :latest tag", "medium"),
        (r"variables:\s*\n[^#]*\n\s*\w+:\s*['\"]?[A-Za-z0-9+/=]{32,}", "Potential hardcoded secret in variables", "high"),
    ]

    # ── CircleCI patterns ──
    CIRCLECI_SECRET_EXPOSURE = [
        (r"echo\s+.*\$CIRCLE_TOKEN", "Echo of CIRCLE_TOKEN", "critical"),
        (r"echo\s+.*\$\w*(SECRET|TOKEN|KEY|PASSWORD)\w*", "Secret variable in echo", "high"),
        (r"curl.*\$CIRCLE_TOKEN", "CIRCLE_TOKEN passed to curl", "critical"),
    ]

    CIRCLECI_INSECURE_PATTERNS = [
        (r"docker:\s*\n\s*-\s*image:.*latest", "Docker image using :latest tag", "medium"),
        (r"save_cache:.*paths:.*node_modules", "Caching node_modules (supply chain risk)", "low"),
        (r"restore_cache:", "Cache restore (verify cache integrity)", "info"),
        (r"add_ssh_keys:", "SSH keys added (ensure proper rotation)", "medium"),
    ]

    # ── Azure DevOps patterns ──
    AZURE_SECRET_EXPOSURE = [
        (r"echo\s+.*\$\(System\.AccessToken\)", "Echo of System.AccessToken", "critical"),
        (r"echo\s+.*\$\(secret\.\w+\)", "Echo of secret variable", "critical"),
        (r"curl.*\$\(System\.AccessToken\)", "System.AccessToken in curl", "critical"),
        (r"echo\s+.*\$\w*(SECRET|TOKEN|KEY|PASSWORD)\w*", "Secret variable in echo", "high"),
    ]

    AZURE_INSECURE_PATTERNS = [
        (r"pool:\s*\n\s*vmImage:.*latest", "Pool using :latest image", "medium"),
        (r"checkout:\s*self", "Checkout self (default, review fetch depth)", "info"),
        (r"script:\s*curl.*\|\s*(ba)?sh", "Pipe-to-shell in script", "critical"),
        (r"task:\s*PowerShell@", "PowerShell task (review script contents)", "info"),
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        self._scan_jenkins()
        self._scan_gitlab_ci()
        self._scan_circleci()
        self._scan_azure_devops()

        return self.findings

    def _scan_jenkins(self):
        """Scan Jenkinsfile configurations."""
        jenkinsfiles = find_jenkinsfiles(self.config.workspace_dir)
        if not jenkinsfiles:
            return

        self.logger.info(f"Scanning {len(jenkinsfiles)} Jenkins pipeline file(s)")

        for filepath in jenkinsfiles:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)
            content = "".join(lines)

            # Check for credentials not wrapped in withCredentials
            self._check_patterns(filepath, lines, self.JENKINS_SECRET_EXPOSURE, "SCA-105",
                                 "Jenkins Secret Exposure", "jenkins")
            self._check_patterns(filepath, lines, self.JENKINS_INSECURE_PATTERNS, "SCA-105",
                                 "Jenkins Insecure Practice", "jenkins")

            # Check for withCredentials misuse
            if "withCredentials" in content:
                for i, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if "withCredentials" in stripped and "echo" in stripped:
                        self.add_finding(
                            attack_id="SCA-105",
                            title="Credentials block with echo statement",
                            severity="critical",
                            description="A withCredentials block contains an echo statement, "
                                        "which may expose secrets to build logs.",
                            file=filepath,
                            line=i,
                            remediation="Remove echo statements from withCredentials blocks.",
                            evidence=stripped[:200],
                        )

            # Check for shared library references with mutable versions
            for i, line in enumerate(lines, 1):
                m = re.search(r"library\s+['\"]([^'\"]+)@(main|master|dev|latest)['\"]", line)
                if m:
                    self.add_finding(
                        attack_id="SCA-105",
                        title=f"Jenkins shared library with mutable ref: {m.group(1)}@{m.group(2)}",
                        severity="high",
                        description=f"Shared library '{m.group(1)}' uses mutable reference '{m.group(2)}'. "
                                    f"This could be changed to inject malicious code, similar to GitHub Action tag hijacking.",
                        file=filepath,
                        line=i,
                        remediation="Pin shared libraries to specific commit SHAs or release tags.",
                        evidence=line.strip()[:200],
                    )

    def _scan_gitlab_ci(self):
        """Scan GitLab CI configurations."""
        gitlab_files = find_gitlab_ci_files(self.config.workspace_dir)
        if not gitlab_files:
            return

        self.logger.info(f"Scanning {len(gitlab_files)} GitLab CI file(s)")

        for filepath in gitlab_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)

            self._check_patterns(filepath, lines, self.GITLAB_SECRET_EXPOSURE, "SCA-106",
                                 "GitLab CI Secret Exposure", "gitlab")
            self._check_patterns(filepath, lines, self.GITLAB_INSECURE_PATTERNS, "SCA-106",
                                 "GitLab CI Insecure Practice", "gitlab")

            # Check for remote includes (external dependency risk)
            for i, line in enumerate(lines, 1):
                m = re.search(r"remote:\s+['\"]?(https?://[^'\"#\s]+)", line)
                if m:
                    self.add_finding(
                        attack_id="SCA-106",
                        title=f"Remote CI include: {m.group(1)[:80]}",
                        severity="medium",
                        description=f"GitLab CI includes a remote template from: {m.group(1)}. "
                                    f"Remote includes are an external dependency that could be compromised.",
                        file=filepath,
                        line=i,
                        remediation="Vendor remote includes locally or pin to specific commits.",
                        evidence=line.strip()[:200],
                    )

    def _scan_circleci(self):
        """Scan CircleCI configurations."""
        circleci_files = find_circleci_files(self.config.workspace_dir)
        if not circleci_files:
            return

        self.logger.info(f"Scanning {len(circleci_files)} CircleCI file(s)")

        for filepath in circleci_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)

            self._check_patterns(filepath, lines, self.CIRCLECI_SECRET_EXPOSURE, "SCA-107",
                                 "CircleCI Secret Exposure", "circleci")
            self._check_patterns(filepath, lines, self.CIRCLECI_INSECURE_PATTERNS, "SCA-107",
                                 "CircleCI Insecure Practice", "circleci")

            # Check for orb usage with mutable versions
            for i, line in enumerate(lines, 1):
                m = re.search(r"(\w+/\w+)@volatile", line)
                if m:
                    self.add_finding(
                        attack_id="SCA-107",
                        title=f"CircleCI orb with volatile version: {m.group(1)}",
                        severity="high",
                        description=f"Orb '{m.group(1)}' uses @volatile, meaning it always uses the latest version. "
                                    f"This is equivalent to using a mutable tag in GitHub Actions.",
                        file=filepath,
                        line=i,
                        remediation="Pin orbs to specific versions or SHA digests.",
                        evidence=line.strip()[:200],
                    )

    def _scan_azure_devops(self):
        """Scan Azure DevOps pipeline configurations."""
        azure_files = find_azure_pipelines(self.config.workspace_dir)
        if not azure_files:
            return

        self.logger.info(f"Scanning {len(azure_files)} Azure DevOps pipeline file(s)")

        for filepath in azure_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)

            self._check_patterns(filepath, lines, self.AZURE_SECRET_EXPOSURE, "SCA-108",
                                 "Azure DevOps Secret Exposure", "azure")
            self._check_patterns(filepath, lines, self.AZURE_INSECURE_PATTERNS, "SCA-108",
                                 "Azure DevOps Insecure Practice", "azure")

            # Check for template references from external repos
            for i, line in enumerate(lines, 1):
                m = re.search(r"template:\s+(.+)@(.+)", line)
                if m:
                    self.add_finding(
                        attack_id="SCA-108",
                        title=f"External template reference: {m.group(1)}@{m.group(2)}",
                        severity="medium",
                        description=f"Pipeline uses an external template from repo '{m.group(2)}'. "
                                    f"External templates are a supply chain dependency.",
                        file=filepath,
                        line=i,
                        remediation="Pin external templates to specific commits. Vendor critical templates.",
                        evidence=line.strip()[:200],
                    )

    def _check_patterns(self, filepath, lines, patterns, attack_id, category, platform):
        """Helper to check a list of regex patterns against file lines."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern, name, severity in patterns:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id=attack_id,
                            title=f"[{platform.upper()}] {name}",
                            severity=severity,
                            description=f"{category}: {name}. "
                                        f"Detected in {platform} CI/CD configuration.",
                            file=filepath,
                            line=i,
                            remediation=f"Review and remediate this {platform} configuration issue.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue
