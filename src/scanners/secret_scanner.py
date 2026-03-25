#!/usr/bin/env python3
"""
Secret Scanner
==============
Detects hardcoded secrets, credential exfiltration patterns,
and unsafe secret handling in workflows and code.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files, find_action_files, read_file_lines,
    find_package_files
)


class SecretScanner(BaseScanner):
    """Scan for secret exposure and credential exfiltration patterns."""

    scanner_name = "secret_exposure"

    # Pattern tuples: (regex, name, severity)
    HARDCODED_SECRET_PATTERNS = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "critical"),
        (r"(?:^|[^a-zA-Z0-9])ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])github_pat_[A-Za-z0-9_]{22,}", "GitHub Fine-grained PAT", "critical"),
        (r"(?:^|[^a-zA-Z0-9])gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])ghs_[A-Za-z0-9]{36}", "GitHub App Installation Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])ghr_[A-Za-z0-9]{36}", "GitHub Refresh Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])npm_[A-Za-z0-9]{36}", "npm Access Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI API Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])sk-ant-[a-zA-Z0-9_-]{90,}", "Anthropic API Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])xox[bpsar]-[A-Za-z0-9-]+", "Slack Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])sk_live_[A-Za-z0-9]{24,}", "Stripe Secret Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])rk_live_[A-Za-z0-9]{24,}", "Stripe Restricted Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])hf_[A-Za-z0-9]{34}", "Hugging Face Token", "critical"),
        (r"(?:^|[^a-zA-Z0-9])r8_[A-Za-z0-9]{20,}", "Replicate API Token", "high"),
        (r"AIzaSy[A-Za-z0-9_-]{33}", "Google API Key", "critical"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", "critical"),
        (r"(?:^|[^a-zA-Z0-9])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.", "JWT Token", "high"),
    ]

    EXFIL_PATTERNS = [
        (r"curl\s+.*\$\{\{.*secrets\.", "Secret sent to curl", "critical"),
        (r"wget\s+.*\$\{\{.*secrets\.", "Secret sent to wget", "critical"),
        (r"echo\s+.*\$\{\{.*secrets\.", "Secret echoed to stdout", "high"),
        (r"printenv\s*\|\s*curl", "Environment variables piped to curl", "critical"),
        (r"printenv\s*\|\s*wget", "Environment variables piped to wget", "critical"),
        (r"env\s*>\s*/tmp", "Environment dumped to file", "critical"),
        (r"env\s*\|\s*base64", "Environment base64 encoded", "critical"),
        (r"cat\s+/proc/[0-9]+/mem", "Process memory read (tj-actions pattern)", "critical"),
        (r"cat\s+/proc/self/environ", "Process environment read", "critical"),
        (r"/proc/[0-9]+/maps", "Process memory maps (credential scraping)", "critical"),
        (r"Runner\.Worker", "GitHub Actions runner process (tj-actions pattern)", "critical"),
        (r"isSecret", "Secret detection bypass (tj-actions pattern)", "critical"),
        (r"base64.*base64", "Double base64 encoding (obfuscated exfil)", "critical"),
        (r"b64encode.*b64encode", "Double base64 encoding (Python)", "critical"),
        (r"ACTIONS_RUNTIME_TOKEN", "Actions runtime token access", "high"),
        (r"ACTIONS_CACHE_URL", "Actions cache URL access", "high"),
        (r"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "OIDC token request access", "high"),
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Scan workflow files
        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)

        for filepath in workflow_files + action_files:
            if not self.should_scan_file(filepath):
                continue
            self._scan_file_for_secrets(filepath)
            self._scan_file_for_exfil(filepath)

        # In deep/paranoid mode, also scan scripts and config
        if self.config.scan_mode in ("deep", "paranoid"):
            self._scan_repo_scripts()

        return self.findings

    def _scan_file_for_secrets(self, filepath):
        """Scan a file for hardcoded secrets."""
        lines = read_file_lines(filepath)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            for pattern, name, severity in self.HARDCODED_SECRET_PATTERNS:
                try:
                    match = re.search(pattern, stripped)
                    if match:
                        # Don't flag if it's a reference to secrets context
                        if "${{ secrets." in stripped or "secrets." in stripped.lower():
                            if not re.search(r'["\']' + re.escape(match.group(0)[:10]), stripped):
                                continue

                        # Mask the secret in evidence
                        evidence = stripped
                        secret_val = match.group(0)
                        if len(secret_val) > 8:
                            masked = secret_val[:4] + "*" * (len(secret_val) - 8) + secret_val[-4:]
                            evidence = evidence.replace(secret_val, masked)

                        self.add_finding(
                            attack_id="SCA-044",
                            title=f"Hardcoded {name} detected",
                            severity=severity,
                            description=f"A hardcoded {name} was found in the file. "
                                        f"Hardcoded secrets in repository files can be extracted by anyone with read access. "
                                        f"This is a common supply chain attack vector.",
                            file=filepath,
                            line=i,
                            remediation=f"Move this {name} to GitHub Secrets and reference it as ${{{{ secrets.SECRET_NAME }}}}. "
                                        f"Rotate the exposed credential immediately.",
                            evidence=evidence[:200],
                        )
                except re.error:
                    continue

    def _scan_file_for_exfil(self, filepath):
        """Scan for credential exfiltration patterns."""
        lines = read_file_lines(filepath)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            for pattern, name, severity in self.EXFIL_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-022",
                            title=f"Credential exfiltration: {name}",
                            severity=severity,
                            description=f"Detected a pattern commonly used for credential exfiltration: {name}. "
                                        f"This pattern matches techniques used in real attacks like tj-actions (SCA-001), "
                                        f"Codecov (SCA-008), and others.",
                            file=filepath,
                            line=i,
                            remediation="Never pass secrets to external services or output them to logs. "
                                        "Use OIDC for cloud authentication. Review this code carefully.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _scan_repo_scripts(self):
        """In deep mode, scan shell scripts and common config files."""
        import os

        script_extensions = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".js", ".ts")

        for root, dirs, files in os.walk(self.config.workspace_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "vendor")]

            for f in files:
                filepath = os.path.join(root, f)
                if not self.should_scan_file(filepath):
                    continue

                # Check scripts
                if f.endswith(script_extensions):
                    self._scan_file_for_secrets(filepath)

                # Check .env files
                if f in (".env", ".env.local", ".env.production", ".env.development"):
                    self._scan_file_for_secrets(filepath)
                    self.add_finding(
                        attack_id="SCA-049",
                        title=f"Environment file committed: {f}",
                        severity="high",
                        description=f"Environment file '{f}' is committed to the repository. "
                                    f"These files often contain secrets and should be in .gitignore.",
                        file=filepath,
                        line=1,
                        remediation=f"Add '{f}' to .gitignore. Remove from git history. Rotate any secrets it contains.",
                    )
