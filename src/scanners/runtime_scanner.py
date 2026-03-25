#!/usr/bin/env python3
"""
Runtime Scanner
===============
Monitors for runtime indicators of compromise during
workflow execution. Detects credential dumping, suspicious processes,
Runner.Worker memory access (TeamPCP technique), persistence mechanisms,
tpcp-docs fallback exfiltration, and suspicious network connections.

Inspired by StepSecurity Harden-Runner's process and file monitoring.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner


class RuntimeScanner(BaseScanner):
    """Runtime monitoring for credential exposure during CI execution."""

    scanner_name = "runtime_monitor"

    # ── TeamPCP persistence paths and suspicious files ──
    PERSISTENCE_PATHS = [
        ("~/.config/systemd/user/sysmon.py", "TeamPCP systemd persistence (sysmon.py)"),
        ("~/.config/systemd/user/sysmon.service", "TeamPCP systemd service unit"),
        ("/tmp/sysmon.py", "TeamPCP sysmon.py in /tmp"),
        ("/tmp/tpcp", "TeamPCP temp working directory"),
    ]

    # ── Expanded suspicious process patterns (includes TeamPCP) ──
    SUSPICIOUS_PROCESSES = [
        ("xmrig", "Cryptominer (XMRig)"),
        ("minergate", "Cryptominer (Minergate)"),
        ("minerd", "Cryptominer (minerd)"),
        ("cpuminer", "Cryptominer (cpuminer)"),
        ("nc ", "Netcat (potential reverse shell)"),
        ("ncat ", "Ncat (potential reverse shell)"),
        ("socat ", "Socat (potential tunnel)"),
        ("ngrok", "ngrok tunnel"),
        ("cloudflared", "Cloudflare tunnel"),
        ("sysmon.py", "TeamPCP persistence daemon"),
        ("/proc/", "Process memory read (potential TeamPCP)"),
        ("Runner.Worker", "Runner Worker process targeting"),
    ]

    # Path where the background monitor daemon writes findings
    DAEMON_FINDINGS_PATH = Path(
        os.environ.get("SCG_MONITOR_DIR", "/tmp/scg-runtime-monitor")
    ) / "runtime-findings.json"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Always ingest findings from the background runtime monitor daemon
        # (if it was started earlier in the pipeline)
        self._ingest_daemon_findings()

        if not os.environ.get("GITHUB_ACTIONS") == "true":
            if not self.findings:
                self.logger.debug("Runtime scanner only works in GitHub Actions environment")
            return self.findings

        self._check_credential_files()
        self._check_environment_leaks()
        self._check_suspicious_processes()
        self._check_network_connections()
        self._check_proc_mem_access()
        self._check_persistence_mechanisms()
        self._check_tpcp_exfil()

        return self.findings

    def _ingest_daemon_findings(self):
        """
        Ingest findings from the background runtime monitoring daemon.

        The daemon (runtime_monitor.py) runs continuously from pipeline start
        to finish, writing findings to a shared JSON file. This method reads
        those findings and converts them into standard scanner findings.
        """
        if not self.DAEMON_FINDINGS_PATH.exists():
            self.logger.debug("No daemon findings file (monitor may not be running)")
            return

        try:
            daemon_findings = json.loads(self.DAEMON_FINDINGS_PATH.read_text())
            if not daemon_findings:
                return

            self.logger.info(
                f"Ingesting {len(daemon_findings)} finding(s) from runtime monitor daemon"
            )

            for df in daemon_findings:
                self.add_finding(
                    attack_id=df.get("attack_id", "SCA-RT-DAEMON"),
                    title=f"[RUNTIME] {df.get('title', 'Unknown')}",
                    severity=df.get("severity", "high"),
                    description=(
                        f"{df.get('description', '')} "
                        f"[Detected at {df.get('timestamp', 'unknown')} by continuous monitor]"
                    ),
                    file="",
                    line=0,
                    remediation=df.get("remediation", "Investigate immediately."),
                    evidence=df.get("evidence", ""),
                )

        except (json.JSONDecodeError, OSError) as e:
            self.logger.debug(f"Failed to read daemon findings: {e}")

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
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line_lower = line.lower()
                    for pattern, description in self.SUSPICIOUS_PROCESSES:
                        if pattern.lower() in line_lower:
                            self.add_finding(
                                attack_id="SCA-RT-PROC",
                                title=f"Suspicious process: {description}",
                                severity="critical",
                                description=f"A suspicious process matching '{pattern.strip()}' was found running: {description}. "
                                            f"This could indicate cryptomining, reverse shell, tunneling, or TeamPCP credential stealer activity.",
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

    def _check_proc_mem_access(self):
        """
        Detect Runner.Worker process memory access — the TeamPCP credential stealer technique.
        The malware reads /proc/<pid>/mem of the Runner.Worker process to extract secrets
        marked isSecret:true from the runner's memory.
        """
        try:
            # Check if any process is reading /proc/*/mem (the TeamPCP technique)
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Detect processes reading proc memory
                    if re.search(r'/proc/\d+/mem', line) or re.search(r'/proc/\*/mem', line):
                        self.add_finding(
                            attack_id="SCA-095",
                            title="Runner.Worker memory access detected",
                            severity="critical",
                            description="A process is reading /proc/<pid>/mem which is the exact technique "
                                        "used by TeamPCP to steal GitHub Actions secrets (CVE-2026-33634). "
                                        "The credential stealer targets Runner.Worker process memory to extract "
                                        "secrets marked isSecret:true, bypassing normal secret masking.",
                            file="",
                            line=0,
                            remediation="Kill the process immediately. Rotate ALL secrets. "
                                        "Use StepSecurity Harden-Runner to block proc memory reads.",
                            evidence=line[:200],
                        )
                    # Detect /proc/*/environ reads
                    if re.search(r'/proc/\d+/environ', line) or re.search(r'/proc/\*/environ', line):
                        self.add_finding(
                            attack_id="SCA-095",
                            title="Process environment read via /proc detected",
                            severity="critical",
                            description="A process is reading /proc/<pid>/environ which exposes all "
                                        "environment variables including secrets. Used in TeamPCP attack.",
                            file="",
                            line=0,
                            remediation="Kill the process. Rotate all secrets.",
                            evidence=line[:200],
                        )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _check_persistence_mechanisms(self):
        """Detect TeamPCP persistence mechanisms (sysmon.py, systemd units)."""
        for filepath, description in self.PERSISTENCE_PATHS:
            expanded = os.path.expanduser(filepath)
            if os.path.exists(expanded):
                self.add_finding(
                    attack_id="SCA-096",
                    title=f"TeamPCP persistence: {description}",
                    severity="critical",
                    description=f"Detected TeamPCP persistence mechanism at {filepath}: {description}. "
                                f"The TeamPCP credential stealer establishes persistence via systemd user services "
                                f"to survive reboots and continue harvesting credentials.",
                    file=expanded,
                    line=0,
                    remediation=f"Remove {filepath} immediately. Check systemd user services: "
                                f"systemctl --user list-units. Rotate ALL credentials on this machine.",
                )

        # Also check for unexpected systemd user services
        systemd_user_dir = os.path.expanduser("~/.config/systemd/user/")
        if os.path.isdir(systemd_user_dir):
            try:
                for f in os.listdir(systemd_user_dir):
                    if f.endswith((".py", ".sh", ".bash")):
                        self.add_finding(
                            attack_id="SCA-096",
                            title=f"Script in systemd user dir: {f}",
                            severity="high",
                            description=f"A script file ({f}) was found in ~/.config/systemd/user/. "
                                        f"This is unusual and may indicate persistence by a credential stealer.",
                            file=os.path.join(systemd_user_dir, f),
                            line=0,
                            remediation=f"Remove {f} and investigate its contents. Rotate credentials.",
                        )
            except OSError:
                pass

    def _check_tpcp_exfil(self):
        """Detect tpcp-docs fallback exfiltration mechanism."""
        # Check if GITHUB_TOKEN is available and if tpcp-docs repo was created
        github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if not github_token:
            return

        try:
            # Check git log for tpcp-related activity
            result = subprocess.run(
                ["git", "log", "--oneline", "-20"],
                capture_output=True, text=True, timeout=10,
                cwd=os.environ.get("GITHUB_WORKSPACE", ".")
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if re.search(r'tpcp|teampcp', line, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-097",
                            title="TeamPCP exfiltration trace in git log",
                            severity="critical",
                            description="Found 'tpcp' or 'teampcp' references in git log. "
                                        "The TeamPCP credential stealer creates a 'tpcp-docs' repo "
                                        "as a fallback exfiltration channel when the C2 is unreachable.",
                            file="",
                            line=0,
                            remediation="Check for 'tpcp-docs' repos on your GitHub account. "
                                        "Delete if found. Rotate GITHUB_TOKEN and all secrets.",
                            evidence=line[:200],
                        )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass