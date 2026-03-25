#!/usr/bin/env python3
"""
Workflow Scanner
================
General-purpose GitHub Actions workflow analysis.
Detects insecure patterns, dangerous configurations, and
suspicious commands in workflow files.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files, find_action_files, parse_yaml_safe,
    read_file_lines, extract_run_blocks
)


class WorkflowScanner(BaseScanner):
    """Comprehensive workflow security analysis."""

    scanner_name = "workflow_analysis"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)

        for filepath in workflow_files:
            if not self.should_scan_file(filepath):
                continue
            self._scan_workflow(filepath)

        for filepath in action_files:
            if not self.should_scan_file(filepath):
                continue
            self._scan_action_file(filepath)

        return self.findings

    def _scan_workflow(self, filepath):
        """Scan a single workflow file."""
        lines = read_file_lines(filepath)
        content = "".join(lines)

        # YAML parsing may fail on files with ${{ }} expressions
        workflow = parse_yaml_safe(filepath)

        # YAML-dependent checks
        if workflow:
            self._check_self_hosted_runners(filepath, workflow, lines)
            self._check_container_refs(filepath, workflow, lines)

        # Text-based checks (always run)
        self._check_dangerous_commands(filepath, lines)
        self._check_curl_pipe_bash(filepath, lines)
        self._check_env_manipulation(filepath, lines)
        self._check_unknown_actions(filepath, lines)

    def _scan_action_file(self, filepath):
        """Scan composite action files."""
        action = parse_yaml_safe(filepath)
        if not action:
            return

        lines = read_file_lines(filepath)

        # Composite actions can also have run blocks
        self._check_dangerous_commands(filepath, lines)
        self._check_curl_pipe_bash(filepath, lines)

    def _check_self_hosted_runners(self, filepath, workflow, lines):
        """Check for self-hosted runner usage."""
        jobs = workflow.get("jobs", {})
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            runs_on = job_data.get("runs-on", "")
            runs_on_str = str(runs_on).lower()

            if "self-hosted" in runs_on_str:
                line = self._find_pattern_line(lines, r"runs-on:.*self-hosted")
                self.add_finding(
                    attack_id="SCA-035",
                    title=f"Self-hosted runner in job '{job_name}'",
                    severity="high",
                    description="Self-hosted runners persist state between jobs. An attacker who compromises one "
                                "workflow run can plant backdoors that persist across future runs. "
                                "This is especially dangerous on public repositories.",
                    file=filepath,
                    line=line,
                    remediation="Use ephemeral runners (GitHub-hosted or auto-scaling). "
                                "Never use self-hosted runners for public repositories. "
                                "If self-hosted runners are required, use container isolation.",
                    evidence=f"runs-on: {runs_on}",
                )

    def _check_dangerous_commands(self, filepath, lines):
        """Check for dangerous commands in run blocks."""
        dangerous_patterns = [
            (r"curl\s+.*\|\s*sh", "Piping curl to shell", "critical"),
            (r"curl\s+.*\|\s*bash", "Piping curl to bash", "critical"),
            (r"wget\s+.*\|\s*sh", "Piping wget to shell", "critical"),
            (r"wget\s+.*\|\s*bash", "Piping wget to bash", "critical"),
            (r"bash\s*<\(curl", "Process substitution from curl", "critical"),
            (r"eval\s+\$\(curl", "Eval of curl output", "critical"),
            (r"eval\s+\$\(wget", "Eval of wget output", "critical"),
            (r"python\s+-c.*import\s+os.*system", "Python system command execution", "high"),
            (r"python\s+-c.*import\s+subprocess", "Python subprocess execution", "high"),
            (r"chmod\s+\+x\s+.*&&\s*\./", "Download-chmod-execute pattern", "high"),
            (r"base64\s+(-d|--decode)", "Base64 decoding (potential obfuscation)", "medium"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, desc, severity in dangerous_patterns:
                if re.search(pattern, stripped, re.IGNORECASE):
                    self.add_finding(
                        attack_id="SCA-055",
                        title=f"Dangerous command: {desc}",
                        severity=severity,
                        description=f"Detected a potentially dangerous command pattern. "
                                    f"Pattern '{desc}' is commonly used in supply chain attacks to download "
                                    f"and execute malicious payloads without verification.",
                        file=filepath,
                        line=i,
                        remediation="Download files, verify checksums, then execute. "
                                    "Never pipe remote content directly to a shell interpreter.",
                        evidence=stripped[:200],
                    )

    def _check_curl_pipe_bash(self, filepath, lines):
        """Check for curl-pipe-bash anti-patterns."""
        for i, line in enumerate(lines, 1):
            # Already checked in dangerous_commands but look for more subtle ones
            if re.search(r'curl\s+-[sfSL]*\s+https?://\S+\s*\|\s*(ba)?sh', line):
                self.add_finding(
                    attack_id="SCA-055",
                    title="curl|bash anti-pattern detected",
                    severity="critical",
                    description="Downloading and immediately executing a remote script without verification. "
                                "The script can be modified at any time by the server, and TLS doesn't protect "
                                "against a compromised server (as seen in the Codecov bash uploader attack).",
                    file=filepath,
                    line=i,
                    remediation="1. Download the script to a file\n"
                                "2. Verify its SHA-256 hash against a known value\n"
                                "3. Then execute it",
                    evidence=line.strip()[:200],
                )

    def _check_env_manipulation(self, filepath, lines):
        """Check for suspicious environment variable manipulation."""
        for i, line in enumerate(lines, 1):
            # Writing to GITHUB_ENV with unsanitized data
            if re.search(r'echo\s+.*\$\{\{.*\}\}.*>>\s*\$?GITHUB_ENV', line):
                self.add_finding(
                    attack_id="SCA-027",
                    title="Unsanitized data written to GITHUB_ENV",
                    severity="high",
                    description="Expression data is being written to GITHUB_ENV without sanitization. "
                                "This could allow environment variable injection if the expression "
                                "contains untrusted input (like PR body, issue title, etc.).",
                    file=filepath,
                    line=i,
                    remediation="Use heredoc delimiters for multi-line values. Sanitize input before writing to GITHUB_ENV.",
                    evidence=line.strip()[:200],
                )

    def _check_container_refs(self, filepath, workflow, lines):
        """Check for insecure container references."""
        jobs = workflow.get("jobs", {})
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            container = job_data.get("container", "")
            if isinstance(container, dict):
                image = container.get("image", "")
            else:
                image = str(container)

            if image:
                # Check for :latest or untagged
                if image.endswith(":latest") or (":" not in image and "/" in image):
                    line = self._find_pattern_line(lines, f"image:.*{re.escape(image[:20])}")
                    if not line:
                        line = self._find_pattern_line(lines, f"container:.*{re.escape(image[:20])}")
                    self.add_finding(
                        attack_id="SCA-024",
                        title=f"Mutable container image: {image}",
                        severity="medium",
                        description=f"Container image '{image}' uses a mutable tag or no tag. "
                                    f"This means the image content can change without notice.",
                        file=filepath,
                        line=line or 0,
                        remediation="Pin container images to SHA digests: image@sha256:...",
                        evidence=f"container image: {image}",
                    )

    def _check_unknown_actions(self, filepath, lines):
        """Flag actions from lesser-known sources."""
        # Well-known trusted action owners
        trusted_owners = {
            "actions", "github", "docker", "azure", "aws-actions",
            "google-github-actions", "hashicorp", "cachix",
            "peter-evans", "softprops", "peaceiris", "JamesIves",
        }

        for i, line in enumerate(lines, 1):
            match = re.search(r'uses:\s*([^/]+)/([^@\s#]+)@(\S+)', line)
            if match:
                owner = match.group(1)
                repo = match.group(2)
                version = match.group(3)

                # Only flag in deep/paranoid mode for lesser-known actions
                if self.config.scan_mode in ("deep", "paranoid"):
                    if owner not in trusted_owners:
                        self.add_finding(
                            attack_id="SCA-051",
                            title=f"Third-party action: {owner}/{repo}",
                            severity="info",
                            description=f"Action '{owner}/{repo}@{version}' is from a non-standard source. "
                                        f"Verify this action is legitimate and actively maintained.",
                            file=filepath,
                            line=i,
                            remediation="Review the action's source code. Check its stars, maintainer, and update history.",
                            evidence=line.strip()[:200],
                        )

    def _find_pattern_line(self, lines, pattern):
        """Find line number matching a regex pattern."""
        for i, line in enumerate(lines, 1):
            try:
                if re.search(pattern, line, re.IGNORECASE):
                    return i
            except re.error:
                if pattern in line:
                    return i
        return 0
