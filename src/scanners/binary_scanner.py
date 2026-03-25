#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Binary / Executable Scanner
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  One-time static scan of workspace for:
#    - Unexpected executables (ELF, PE, Mach-O, scripts with +x)
#    - Known-malicious SHA256 hashes
#    - Suspicious binary names (cryptominers, reverse shells)
#    - Binaries in locations where they shouldn't exist
#    - Obfuscated/packed executables
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import re
import stat
import hashlib
from pathlib import Path
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import read_file_lines


class BinaryScanner(BaseScanner):
    """Scan workspace for suspicious binaries/executables."""

    scanner_name = "binary_analysis"

    # File magic bytes for binary detection
    BINARY_MAGIC = {
        b"\x7fELF":       "ELF (Linux executable)",
        b"MZ":            "PE (Windows executable)",
        b"\xfe\xed\xfa": "Mach-O (macOS executable)",
        b"\xcf\xfa\xed": "Mach-O 64-bit",
        b"\xca\xfe\xba": "Universal Mach-O (fat binary)",
        b"PK\x03\x04":   "ZIP archive (may contain executables)",
    }

    # Suspicious binary names
    SUSPICIOUS_NAMES = [
        (r"^xmrig", "XMRig cryptominer"),
        (r"^minerd", "CPU miner"),
        (r"^cpuminer", "CPU miner"),
        (r"^cgminer", "GPU miner"),
        (r"^bfgminer", "FPGA/GPU miner"),
        (r"^ncat$", "Ncat (Nmap netcat)"),
        (r"^nc$", "Netcat"),
        (r"^socat$", "Socat tunnel"),
        (r"^chisel$", "Chisel tunnel"),
        (r"^frpc?$", "FRP tunnel client/server"),
        (r"^ngrok$", "ngrok tunnel"),
        (r"^cloudflared$", "Cloudflare tunnel"),
        (r"^sliver", "Sliver C2 implant"),
        (r"^beacon", "Cobalt Strike beacon"),
        (r"^msfvenom", "Metasploit payload"),
        (r"^meterpreter", "Meterpreter agent"),
        (r"^mimikatz", "Mimikatz credential dumper"),
        (r"^lazagne", "LaZagne credential harvester"),
        (r"^sysmon\.py$", "TeamPCP persistence daemon"),
        (r"^tpcp", "TeamPCP component"),
    ]

    # Directories where binaries are unexpected in a typical repo
    UNEXPECTED_BINARY_DIRS = [
        ".github/", ".gitlab/", ".circleci/", "scripts/",
        "config/", "k8s/", "terraform/", "ansible/",
        "docs/", "test/", "tests/", "spec/",
    ]

    # Directories to skip completely
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "vendor", ".tox", ".mypy_cache", ".pytest_cache",
        "dist", "build", ".eggs", "target",
    }

    # Known-safe binary patterns (won't flag these)
    SAFE_PATTERNS = [
        r"\.wasm$",          # WebAssembly
        r"\.pyc$",           # Python bytecode
        r"\.class$",         # Java bytecode
        r"\.o$",             # Object files
        r"\.a$",             # Static libraries
        r"\.so(\.\d+)*$",   # Shared libraries
        r"\.dylib$",         # macOS shared libraries
        r"\.dll$",           # Windows DLLs
        r"\.png$", r"\.jpg$", r"\.jpeg$", r"\.gif$",  # Images
        r"\.ico$", r"\.svg$", r"\.webp$",
        r"\.pdf$", r"\.doc", r"\.xls",                # Documents
        r"\.ttf$", r"\.woff", r"\.otf$", r"\.eot$",   # Fonts
        r"\.mp[34]$", r"\.wav$", r"\.ogg$",            # Media
        r"\.zip$", r"\.tar", r"\.gz$", r"\.bz2$",     # Archives (separate)
        r"\.jar$",           # Java archives
        r"\.whl$",           # Python wheels
        r"\.gem$",           # Ruby gems
        r"gradlew$",         # Gradle wrapper
        r"mvnw$",            # Maven wrapper
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workspace = Path(self.config.workspace_dir)
        if not workspace.is_dir():
            return self.findings

        self._scan_workspace_binaries(workspace)

        # In deep/paranoid mode, also scan /tmp
        if self.config.scan_mode in ("deep", "paranoid"):
            self._scan_temp_binaries()

        return self.findings

    def _is_safe_filename(self, name: str) -> bool:
        """Check if a filename matches known-safe patterns."""
        for pattern in self.SAFE_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        return False

    def _get_file_magic(self, filepath: str) -> str:
        """Read first 4 bytes and identify file type."""
        try:
            with open(filepath, "rb") as f:
                header = f.read(4)
            for magic, description in self.BINARY_MAGIC.items():
                if header[:len(magic)] == magic:
                    return description
        except (OSError, IOError):
            pass
        return ""

    def _file_sha256(self, filepath: str) -> str:
        """Calculate SHA256 of a file."""
        try:
            h = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (OSError, IOError):
            return ""

    def _scan_workspace_binaries(self, workspace: Path):
        """Walk workspace looking for unexpected executables."""
        max_files = 10000  # safety limit
        scanned = 0

        for root, dirs, files in os.walk(workspace):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]

            rel_root = os.path.relpath(root, workspace)

            for filename in files:
                if scanned >= max_files:
                    return

                filepath = os.path.join(root, filename)
                if not self.should_scan_file(filepath):
                    continue

                # Skip known-safe file types
                if self._is_safe_filename(filename):
                    continue

                scanned += 1
                rel_path = os.path.relpath(filepath, workspace)

                # Check 1: Is it executable?
                try:
                    file_stat = os.stat(filepath)
                    is_executable = bool(file_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
                    file_size = file_stat.st_size
                except OSError:
                    continue

                # Check 2: Binary magic bytes
                file_type = self._get_file_magic(filepath)

                # Check 3: Suspicious filename
                name_match = None
                for pattern, description in self.SUSPICIOUS_NAMES:
                    if re.search(pattern, filename, re.IGNORECASE):
                        name_match = description
                        break

                # Generate findings based on what we found
                if name_match:
                    sha = self._file_sha256(filepath)
                    self.add_finding(
                        attack_id="SCA-BIN-NAME",
                        title=f"Suspicious binary: {name_match}",
                        severity="critical",
                        description=f"File '{rel_path}' matches known malicious binary pattern: "
                                    f"{name_match}. This file should not exist in a source repository.",
                        file=filepath,
                        remediation="Remove this file immediately. Investigate how it appeared. "
                                    "Rotate ALL secrets.",
                        evidence=f"name={filename}, sha256={sha[:16]}..., size={file_size}",
                    )
                elif file_type and file_type.startswith(("ELF", "PE", "Mach-O")):
                    # Compiled binary in repo — suspicious unless expected
                    in_unexpected = any(rel_path.startswith(d) for d in self.UNEXPECTED_BINARY_DIRS)
                    severity = "high" if in_unexpected else "medium"

                    sha = self._file_sha256(filepath)
                    self.add_finding(
                        attack_id="SCA-BIN-EXEC",
                        title=f"Compiled binary in repo: {filename}",
                        severity=severity,
                        description=f"Compiled executable ({file_type}) found at '{rel_path}'. "
                                    f"Binaries in source repos can hide backdoors, cryptominers, "
                                    f"or credential stealers. They bypass code review.",
                        file=filepath,
                        remediation="Remove compiled binaries from source. Use package managers or "
                                    "build from source instead. If required, add to .scg-config.yml "
                                    "exemptions with a reason.",
                        evidence=f"type={file_type}, sha256={sha[:16]}..., size={file_size}",
                    )
                elif is_executable and file_size > 0:
                    # Executable script — check if it's in an unexpected location
                    in_unexpected = any(rel_path.startswith(d) for d in self.UNEXPECTED_BINARY_DIRS)
                    if in_unexpected and not filename.endswith((".sh", ".bash", ".py", ".rb", ".pl")):
                        self.add_finding(
                            attack_id="SCA-BIN-PERM",
                            title=f"Executable in unexpected location: {filename}",
                            severity="low",
                            description=f"File '{rel_path}' has executable permissions in a "
                                        f"directory where executables are unusual. Verify this is intentional.",
                            file=filepath,
                            remediation="Remove execute permission if not needed: chmod -x",
                            evidence=f"mode={oct(file_stat.st_mode)}, size={file_size}",
                        )

        # Check for known-malicious hashes from attack DB
        known_shas = set()
        try:
            compromised = self.attack_db.get_compromised_shas()
            known_shas = set(compromised.keys()) if isinstance(compromised, dict) else set()
        except (AttributeError, TypeError):
            pass

        if known_shas:
            self._check_known_malicious_hashes(workspace, known_shas)

    def _check_known_malicious_hashes(self, workspace: Path, known_shas: set):
        """Check workspace files against known-malicious SHA256 list."""
        # Only check executable/binary files to avoid performance issues
        for root, dirs, files in os.walk(workspace):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    file_stat = os.stat(filepath)
                    is_exec = bool(file_stat.st_mode & stat.S_IXUSR)
                    if not is_exec:
                        continue
                except OSError:
                    continue

                sha = self._file_sha256(filepath)
                if sha in known_shas:
                    self.add_finding(
                        attack_id="SCA-BIN-HASH",
                        title=f"Known-malicious binary: {filename}",
                        severity="critical",
                        description=f"File SHA256 matches a known-malicious hash. "
                                    f"This binary is associated with a known supply chain attack.",
                        file=filepath,
                        remediation="Delete immediately. Assume full compromise. "
                                    "Rotate ALL secrets and tokens.",
                        evidence=f"sha256={sha}",
                    )

    def _scan_temp_binaries(self):
        """Scan /tmp and /dev/shm for dropped malicious binaries."""
        temp_dirs = ["/tmp", "/dev/shm", "/var/tmp"]
        for temp_dir in temp_dirs:
            if not os.path.isdir(temp_dir):
                continue
            try:
                for entry in os.scandir(temp_dir):
                    if not entry.is_file():
                        continue
                    try:
                        if not os.access(entry.path, os.X_OK):
                            continue
                    except OSError:
                        continue

                    # Skip known-safe temp files
                    if entry.name.startswith(("npm-", "pip-", "go-build", "pytest-", ".com.google")):
                        continue

                    file_type = self._get_file_magic(entry.path)
                    if file_type:
                        self.add_finding(
                            attack_id="SCA-BIN-TMP",
                            title=f"Executable dropped in {temp_dir}: {entry.name}",
                            severity="high",
                            description=f"Executable binary ({file_type}) found in {temp_dir}. "
                                        f"Malware frequently drops executables in temp directories "
                                        f"during build or install steps.",
                            file=entry.path,
                            remediation=f"Investigate {entry.path}. Remove if suspicious. "
                                        f"Check which build step created it.",
                            evidence=f"type={file_type}, path={entry.path}",
                        )

                    # Check for suspicious names in temp
                    for pattern, description in self.SUSPICIOUS_NAMES:
                        if re.search(pattern, entry.name, re.IGNORECASE):
                            self.add_finding(
                                attack_id="SCA-BIN-TMP",
                                title=f"Suspicious binary in {temp_dir}: {description}",
                                severity="critical",
                                description=f"Known malicious binary pattern '{description}' "
                                            f"found in {temp_dir}. This is a strong indicator of compromise.",
                                file=entry.path,
                                remediation="Kill related processes. Remove file. Rotate ALL secrets.",
                                evidence=f"name={entry.name}, path={entry.path}",
                            )
                            break
            except OSError:
                continue
