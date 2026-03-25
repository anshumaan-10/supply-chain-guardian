#!/usr/bin/env python3
"""
Network Scanner
===============
Detects network exfiltration patterns including reverse shells,
DNS exfiltration, suspicious domain access, data tunneling,
TeamPCP C2 communication, cloud metadata endpoint (IMDS) access,
and egress anomaly patterns.

Inspired by StepSecurity Harden-Runner's network egress monitoring.
"""

import re
from typing import List, Dict, Any, Optional

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, find_action_files, read_file_lines

# Lazy-loaded at scan time
_exception_config = None


def _extract_domain(text: str) -> Optional[str]:
    """Extract the domain from a URL or network reference in text."""
    # Match URLs: https://example.com/path or http://1.2.3.4:8080
    m = re.search(r'https?://([a-zA-Z0-9._-]+)', text)
    if m:
        return m.group(1).lower()
    # Match bare domain references: curl example.com
    m = re.search(r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|dev|sh|cloud|app|co|me|info|xyz|cc|su))\b', text)
    if m:
        return m.group(1).lower()
    return None


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

    # ── TeamPCP / Trivy C2 Infrastructure (CVE-2026-33634) ──
    TEAMPCP_C2_PATTERNS = [
        (r"scan\.aquasecurtiy\.org", "TeamPCP C2 domain (typosquat of aquasecurity)", "critical"),
        (r"aquasecurtiy\.org", "TeamPCP C2 base domain", "critical"),
        (r"45\.148\.10\.212", "TeamPCP C2 IP (TECHOFF SRV LIMITED, Amsterdam)", "critical"),
        (r"tdtqy-oyaaa-aaaae-af2dq-cai\.raw\.icp0\.io", "TeamPCP ICP fallback C2", "critical"),
        (r"plug-tab-protective-relay.*trycloudflare\.com", "TeamPCP Cloudflare Tunnel exfil", "critical"),
        (r"models\.litellm\.cloud", "LiteLLM compromise exfil endpoint", "critical"),
    ]

    # ── Shai-Hulud / Scavenger C2 domains ──
    SHAI_HULUD_C2_PATTERNS = [
        (r"firebase\.su", "Shai-Hulud/Scavenger C2 domain", "critical"),
        (r"dieorsuffer\.com", "Scavenger C2 domain", "critical"),
        (r"smartscreen-api\.com", "Scavenger C2 domain (typosquat)", "critical"),
        (r"npnjs\.com", "CanisterWorm typosquat C2 (mimics npmjs)", "critical"),
    ]

    # ── Cloud IMDS endpoints (SCA-110) ──
    IMDS_PATTERNS = [
        (r"169\.254\.169\.254", "AWS/GCP/Azure Instance Metadata Service (IMDS)", "critical"),
        (r"metadata\.google\.internal", "GCP Metadata endpoint", "critical"),
        (r"metadata\.azure\.com", "Azure IMDS endpoint", "critical"),
    ]

    # ── Egress anomaly patterns (SCA-109, Harden-Runner inspired) ──
    EGRESS_ANOMALY_PATTERNS = [
        (r"curl\s+.*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "curl to raw IP address", "high"),
        (r"wget\s+.*https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "wget to raw IP address", "high"),
        (r"curl.*\|\s*(bash|sh|python|python3|node|ruby|perl)", "Pipe-to-shell pattern", "critical"),
        (r"wget.*\|\s*(bash|sh|python|python3|node|ruby|perl)", "wget pipe-to-shell", "critical"),
        (r"curl\s+-s.*\|\s*bash", "Silent curl pipe to bash", "critical"),
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Load exception config for egress allowlisting
        global _exception_config
        try:
            from utils.exceptions import load_exception_config
            _exception_config = load_exception_config(self.config.workspace_dir)
            if self.config.verbose and _exception_config.source != "defaults-only":
                self.logger.debug(f"Egress allowlist loaded: {_exception_config.source} "
                                  f"({len(_exception_config.egress_allowlist)} domains)")
        except ImportError:
            _exception_config = None

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
            self._check_teampcp_c2(filepath, lines)
            self._check_shai_hulud_c2(filepath, lines)
            self._check_imds_access(filepath, lines)
            self._check_egress_anomalies(filepath, lines)

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
                    # C2 / known-bad domains are NEVER allowlisted
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

    def _check_teampcp_c2(self, filepath, lines):
        """Check for TeamPCP/Trivy C2 communication patterns (CVE-2026-33634)."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name, severity in self.TEAMPCP_C2_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-094",
                            title=f"TeamPCP C2 communication: {name}",
                            severity=severity,
                            description=f"Detected connection to TeamPCP threat actor infrastructure: {name}. "
                                        f"This is associated with the Trivy supply chain attack (CVE-2026-33634). "
                                        f"Any access to these endpoints indicates active credential exfiltration.",
                            file=filepath,
                            line=i,
                            remediation="Block all access. Assume full credential compromise. Rotate ALL secrets immediately.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _check_shai_hulud_c2(self, filepath, lines):
        """Check for Shai-Hulud / Scavenger / CanisterWorm C2 domains."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name, severity in self.SHAI_HULUD_C2_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-103",
                            title=f"Shai-Hulud/Scavenger C2: {name}",
                            severity=severity,
                            description=f"Detected connection to C2 domain: {name}. "
                                        f"Associated with Shai-Hulud npm worm (1193+ compromised packages), "
                                        f"Scavenger malware (CVE-2025-54313), or CanisterWorm.",
                            file=filepath,
                            line=i,
                            remediation="Block domain immediately. Rotate npm tokens, SSH keys, and cloud credentials.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _check_imds_access(self, filepath, lines):
        """Check for cloud Instance Metadata Service (IMDS) access."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name, severity in self.IMDS_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        self.add_finding(
                            attack_id="SCA-110",
                            title=f"Cloud metadata endpoint access: {name}",
                            severity=severity,
                            description=f"Detected access to cloud instance metadata service: {name}. "
                                        f"IMDS endpoints expose IAM credentials, instance identity, "
                                        f"and network configuration. Attackers use this to escalate from CI to cloud.",
                            file=filepath,
                            line=i,
                            remediation="Block IMDS access (169.254.169.254). Use IMDSv2 with token requirement on AWS. "
                                        "Implement network policies to restrict metadata access in CI.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _is_allowed_egress(self, text: str) -> bool:
        """Check if a network reference targets an allowed (legitimate) domain."""
        if _exception_config is None:
            return False
        domain = _extract_domain(text)
        if domain and _exception_config.is_domain_allowed(domain):
            return True
        return False

    def _check_egress_anomalies(self, filepath, lines):
        """Check for egress anomaly patterns (Harden-Runner inspired)."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            for pattern, name, severity in self.EGRESS_ANOMALY_PATTERNS:
                try:
                    if re.search(pattern, stripped, re.IGNORECASE):
                        # Smart allowlist: skip if target domain is legitimate
                        if self._is_allowed_egress(stripped):
                            continue
                        self.add_finding(
                            attack_id="SCA-109",
                            title=f"Egress anomaly: {name}",
                            severity=severity,
                            description=f"Detected suspicious network egress: {name}. "
                                        f"This pattern is commonly used in supply chain attacks to download "
                                        f"and execute malicious payloads or exfiltrate data.",
                            file=filepath,
                            line=i,
                            remediation="Use StepSecurity Harden-Runner for network egress monitoring. "
                                        "Block outbound traffic to non-allowed endpoints. "
                                        "If this is a legitimate domain, add it to .scg-config.yml egress_allowlist.",
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
                self._check_teampcp_c2(filepath, lines)
                self._check_shai_hulud_c2(filepath, lines)
                self._check_imds_access(filepath, lines)
                self._check_egress_anomalies(filepath, lines)
