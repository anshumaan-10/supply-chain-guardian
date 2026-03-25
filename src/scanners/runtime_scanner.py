#!/usr/bin/env python3
"""
Runtime Scanner
===============
Monitors for runtime indicators of compromise during
workflow execution (credential dumping, suspicious processes, etc.).
"""

import os
import re
import subprocess
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner


class RuntimeScanner(BaseScanner):
    """Runtime monitoring for credential exposure during CI execution."""

    scanner_name = "runtime_monitor"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        if not os.environ.get("GITHUB_ACTIONS") == "true":
            self.logger.debug("Runtime scanner only works in GitHub Actions environment")
            return self.findings

        self._check_credential_files()
        self._check_environment_leaks()
        self._check_suspicious_processes()
        self._check_network_connections()

        return self.findings

    def _check_credential_files(self):
        """Check for credential files that shouldn't exist in CI."""
        sensitive_files = [
            ("~/.npmrc", "npm credentials"),
            ("~/.pypirc", "PyPI credentials"),
            ("~/.docker/config.json", "Docker credentials"),
            ("~/.aws/credentials", "AWS credentials"),
            ("~/.kube/config", "Kubernetes config"),
            ("~/.ssh/id_rsa", "SSH private key"),
            ("~/.ssh/id_ed25519", "SSH private key"),
            ("~/.gitconfig", "Git config (may contain tokens)"),
            ("/tmp/.env", "Dumped env file"),
        ]

        for filepath, description in sensitive_files:
            expanded = os.path.expanduser(filepath)
            if os.path.exists(expanded):
                # Check if file was recently created (within this job)
                try:
                    stat = os.stat(expanded)
                    # Don't flag docker config in CI (commonly created by login)
                    if "docker" in filepath:
                        continue

                    self.add_finding(
                        attack_id="SCA-RT-CRED",
                        title=f"Credential file found: {filepath}",
                        severity="high",
                        description=f"Sensitive file detected at runtime: {description} ({filepath}). "
                                    f"Credential files in CI can be read by malicious actions or scripts.",
                        file=expanded,
                        line=0,
                        remediation=f"Remove {filepath} after use. Use OIDC authentication where possible. "
                                    f"Ensure the file is not persisted in cache or artifacts.",
                    )
                except OSError:
                    pass

    def _check_environment_leaks(self):
        """Check for suspicious environment variable patterns."""
        env = dict(os.environ)

        # Check for secrets accidentally in non-secret env vars
        secret_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key in environment"),
            (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT in environment"),
            (r"npm_[A-Za-z0-9]{36}", "npm token in environment"),
            (r"sk-[A-Za-z0-9]{20,}", "API key (OpenAI/Stripe) in environment"),
        ]

        for var_name, var_value in env.items():
            # Skip known secret variables
            if any(x in var_name.upper() for x in ["SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL"]):
                continue

            for pattern, description in secret_patterns:
                try:
                    if re.search(pattern, str(var_value)):
                        masked_value = var_value[:4] + "****" + var_value[-4:]
                        self.add_finding(
                            attack_id="SCA-RT-ENV",
                            title=f"Secret leaked in env var: {var_name}",
                            severity="critical",
                            description=f"{description}. The environment variable '{var_name}' contains "
                                        f"what appears to be a secret but is not marked as a secret. "
                                        f"Non-secret env vars are visible to all actions and log output.",
                            file="",
                            line=0,
                            remediation=f"Move the value in '{var_name}' to GitHub Secrets. "
                                        f"Rotate the credential immediately.",
                            evidence=f"{var_name}={masked_value}",
                        )
                except re.error:
                    continue

    def _check_suspicious_processes(self):
        """Check for suspicious processes running during CI."""
        suspicious = [
            "xmrig", "minergate", "minerd", "cpuminer",
            "nc ", "ncat ", "socat ",
            "ngrok", "cloudflared",
        ]

        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line_lower = line.lower()
                    for pattern in suspicious:
                        if pattern in line_lower:
                            self.add_finding(
                                attack_id="SCA-RT-PROC",
                                title=f"Suspicious process detected: {pattern.strip()}",
                                severity="critical",
                                description=f"A suspicious process matching '{pattern.strip()}' was found running. "
                                            f"This could indicate cryptomining, reverse shell, or tunneling activity.",
                                file="",
                                line=0,
                                remediation="Investigate the process origin. Kill it and rotate all secrets. "
                                            "Review recent workflow changes.",
                                evidence=line[:200],
                            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_network_connections(self):
        """Check for suspicious outbound network connections."""
        try:
            # Try netstat or ss
            for cmd in [["ss", "-tnp"], ["netstat", "-tnp"]]:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        suspicious_ports = {"4444", "5555", "8888", "9999", "1337", "31337"}
                        for line in result.stdout.splitlines():
                            parts = line.split()
                            for part in parts:
                                # Check for connections to suspicious ports
                                if ":" in part:
                                    port = part.split(":")[-1]
                                    if port in suspicious_ports:
                                        self.add_finding(
                                            attack_id="SCA-RT-NET",
                                            title=f"Suspicious outbound connection to port {port}",
                                            severity="high",
                                            description=f"Outbound connection to port {port} detected. "
                                                        f"These ports are commonly used for reverse shells and C2.",
                                            file="",
                                            line=0,
                                            remediation="Investigate the connection. Block outbound traffic to non-standard ports.",
                                            evidence=line[:200],
                                        )
                    break
                except FileNotFoundError:
                    continue
        except (subprocess.TimeoutExpired, OSError):
            pass
