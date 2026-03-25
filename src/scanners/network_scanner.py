#!/usr/bin/env python3
"""
Network Scanner
===============
Detects network exfiltration patterns including reverse shells,
DNS exfiltration, suspicious domain access, and data tunneling.
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, find_action_files, read_file_lines


class NetworkScanner(BaseScanner):
    """Scan for network exfiltration patterns."""

    scanner_name = "network_exfiltration"

    REVERSE_SHELL_PATTERNS = [
        (r"nc\s+.*-e\s+/bin/(ba)?sh", "Netcat reverse shell"),
        (r"ncat\s+.*-e\s+/bin/(ba)?sh", "Ncat reverse shell"),
        (r"bash.*>&\s*/dev/tcp/", "Bash /dev/tcp reverse shell"),
        (r"bash.*-i\s*>&\s*/dev/tcp/", "Bash interactive reverse shell"),
        (r"python.*socket.*connect", "Python socket reverse shell"),
        (r"python.*pty\.spawn", "Python PTY spawn"),
        (r"perl.*socket.*connect", "Perl reverse shell"),
        (r"ruby.*TCPSocket", "Ruby reverse shell"),
        (r"php.*fsockopen", "PHP reverse shell"),
        (r"mkfifo\s+/tmp/", "FIFO-based reverse shell"),
        (r"0<&196;exec 196<>/dev/tcp/", "Exec fd reverse shell"),
        (r"socat.*TCP:", "Socat TCP connection"),
        (r"powershell.*New-Object.*Net\.Sockets", "PowerShell reverse shell"),
    ]

    DNS_EXFIL_PATTERNS = [
        (r"dig\s+.*\$", "DNS lookup with variable (potential exfil)"),
        (r"nslookup\s+.*\$", "nslookup with variable (potential exfil)"),
        (r"host\s+.*\$", "host command with variable (potential exfil)"),
        (r"curl\s+.*dns\.google", "DNS-over-HTTPS exfiltration"),
        (r"curl\s+.*cloudflare-dns", "DNS-over-HTTPS via Cloudflare"),
        (r"curl\s+.*doh\.dns", "DNS-over-HTTPS exfiltration"),
        (r"\$\(.*\)\..*\.burpcollaborator\.net", "Burp Collaborator DNS exfil"),
        (r"\$\(.*\)\..*\.oastify\.com", "OAST DNS exfiltration"),
        (r"\$\(.*\)\..*\.interact\.sh", "Interact.sh DNS exfiltration"),
    ]

    TUNNEL_PATTERNS = [
        (r"ngrok", "ngrok tunnel detected"),
        (r"cloudflared\s+tunnel", "Cloudflare tunnel"),
        (r"localtunnel", "localtunnel detected"),
        (r"serveo\.net", "Serveo tunnel"),
        (r"bore\.digital", "Bore tunnel"),
        (r"pagekite", "PageKite tunnel"),
        (r"telebit", "Telebit tunnel"),
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Get suspicious domains from attack DB
        suspicious_domains = self.attack_db.get_suspicious_domains()

        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)

        for filepath in workflow_files + action_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)
            self._check_reverse_shells(filepath, lines)
            self._check_dns_exfil(filepath, lines)
            self._check_suspicious_domains(filepath, lines, suspicious_domains)
            self._check_tunnels(filepath, lines)
            self._check_data_exfil_patterns(filepath, lines)

        # In deep/paranoid mode, scan scripts too
        if self.config.scan_mode in ("deep", "paranoid"):
            self._scan_scripts(suspicious_domains)

        return self.findings

    def _check_reverse_shells(self, filepath, lines):
        """Check for reverse shell patterns."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name in self.REVERSE_SHELL_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-037",
                            title=f"Reverse shell detected: {name}",
                            severity="critical",
                            description=f"A reverse shell pattern was detected: {name}. "
                                        f"This allows an attacker to get interactive access to the CI runner. "
                                        f"This is a strong indicator of compromise.",
                            file=filepath,
                            line=i,
                            remediation="Remove the reverse shell code. Investigate how it was introduced. "
                                        "Rotate all secrets and review recent workflow runs.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _check_dns_exfil(self, filepath, lines):
        """Check for DNS exfiltration patterns."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name in self.DNS_EXFIL_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-038",
                            title=f"DNS exfiltration: {name}",
                            severity="high",
                            description=f"Detected potential DNS-based data exfiltration: {name}. "
                                        f"Attackers encode stolen data into DNS queries to bypass network restrictions.",
                            file=filepath,
                            line=i,
                            remediation="Review DNS-related commands. Restrict DNS resolution in CI if possible.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _check_suspicious_domains(self, filepath, lines, suspicious_domains):
        """Check for access to known suspicious domains."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check known domains from DB
            for domain, attack_info in suspicious_domains.items():
                if domain in stripped.lower():
                    self.add_finding(
                        attack_id="SCA-039",
                        title=f"Suspicious domain access: {domain}",
                        severity="high",
                        description=f"Access to known suspicious domain '{domain}' "
                                    f"associated with attack: {attack_info}.",
                        file=filepath,
                        line=i,
                        remediation=f"Remove access to {domain}. Review if this was intentionally added or injected.",
                        evidence=stripped[:200],
                    )

            # Check for data exfiltration services
            exfil_domains = [
                "requestbin.com", "requestbin.net", "webhook.site",
                "pipedream.net", "pipedream.com", "hookbin.com",
                "requestcatcher.com", "beeceptor.com", "mockbin.org",
            ]
            for domain in exfil_domains:
                if domain in stripped.lower():
                    self.add_finding(
                        attack_id="SCA-039",
                        title=f"Data exfiltration endpoint: {domain}",
                        severity="critical",
                        description=f"Access to known data exfiltration service '{domain}'. "
                                    f"These services are commonly used to receive stolen credentials from compromised CI.",
                        file=filepath,
                        line=i,
                        remediation=f"Remove access to {domain}. Investigate when this was added. "
                                    f"Rotate all secrets that may have been exposed.",
                        evidence=stripped[:200],
                    )

    def _check_tunnels(self, filepath, lines):
        """Check for tunnel/proxy patterns."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name in self.TUNNEL_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-039",
                            title=f"Tunnel service detected: {name}",
                            severity="high",
                            description=f"Detected usage of tunnel service: {name}. "
                                        f"Tunnels can be used to establish persistent access to CI runners "
                                        f"or exfiltrate data bypassing network restrictions.",
                            file=filepath,
                            line=i,
                            remediation="Remove tunnel services from CI workflows. Use proper deployment pipelines instead.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _check_data_exfil_patterns(self, filepath, lines):
        """Check for general data exfiltration patterns."""
        patterns = [
            (r"curl\s+.*-d\s+.*\$\(env\)", "curl sending environment data", "critical"),
            (r"curl\s+.*-d\s+.*\$\(printenv\)", "curl sending all env vars", "critical"),
            (r"wget\s+.*--post-data.*env", "wget POSTing environment data", "critical"),
            (r"curl\s+.*-X\s+POST.*secret", "curl POSTing secret data", "high"),
            (r"tar\s+.*\|\s*curl", "tarball piped to curl", "high"),
            (r"zip\s+.*\|\s*curl", "archive piped to curl", "high"),
            (r"base64\s+.*\|\s*curl", "base64 data sent via curl", "high"),
            (r"curl\s+.*\|\s*base64", "data downloaded and decoded", "medium"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name, severity in patterns:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-022",
                            title=f"Data exfiltration pattern: {name}",
                            severity=severity,
                            description=f"Detected pattern: {name}. "
                                        f"This matches credential exfiltration techniques used in real attacks.",
                            file=filepath,
                            line=i,
                            remediation="Review this command. If legitimate, document why. Otherwise remove immediately.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _scan_scripts(self, suspicious_domains):
        """In deep mode, scan shell/Python scripts for network patterns."""
        import os

        script_extensions = (".sh", ".bash", ".py", ".js", ".rb", ".pl")

        for root, dirs, files in os.walk(self.config.workspace_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv", "vendor")]

            for f in files:
                if not f.endswith(script_extensions):
                    continue
                filepath = os.path.join(root, f)
                if not self.should_scan_file(filepath):
                    continue

                lines = read_file_lines(filepath)
                self._check_reverse_shells(filepath, lines)
                self._check_suspicious_domains(filepath, lines, suspicious_domains)
