#!/usr/bin/env python3
"""
Base scanner class for all Supply Chain Guardian scanners.
"""

import os
import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any

from utils.config import ScanConfig
from utils.logger import Logger
from db.attack_db import AttackDatabase


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    scanner_name = "base"

    def __init__(self, config: ScanConfig, attack_db: AttackDatabase):
        self.config = config
        self.attack_db = attack_db
        self.logger = Logger(config.verbose)
        self.findings: List[Dict[str, Any]] = []

    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """Run the scan and return a list of findings."""
        pass

    def add_finding(
        self,
        attack_id: str,
        title: str,
        severity: str,
        description: str,
        file: str = "",
        line: int = 0,
        remediation: str = "",
        cve: str = "",
        evidence: str = "",
        metadata: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Create and store a finding."""
        # Make file path relative to workspace
        if file and self.config.workspace_dir:
            try:
                file = os.path.relpath(file, self.config.workspace_dir)
            except ValueError:
                pass

        finding = {
            "id": attack_id,
            "scanner": self.scanner_name,
            "severity": severity,
            "title": title,
            "description": description,
            "file": file,
            "line": line,
            "remediation": remediation,
            "cve": cve,
            "evidence": evidence[:500] if evidence else "",
            "metadata": metadata or {},
        }
        self.findings.append(finding)

        # Log the finding
        self.logger.finding(severity, self.scanner_name, title, f"{file}:{line}" if file else "")
        return finding

    def search_file_for_patterns(
        self, filepath: str, patterns: List[str], context_name: str = ""
    ) -> List[Dict[str, Any]]:
        """Search a file for regex patterns and return matches with line numbers."""
        matches = []
        try:
            with open(filepath, "r", errors="replace") as f:
                lines = f.readlines()

            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    try:
                        if re.search(pattern, line, re.IGNORECASE):
                            matches.append({
                                "line": i,
                                "content": line.strip()[:200],
                                "pattern": pattern,
                                "file": filepath,
                                "context": context_name,
                            })
                    except re.error:
                        continue
        except (IOError, OSError):
            pass
        return matches

    def should_scan_file(self, filepath: str) -> bool:
        """Check if a file should be scanned based on config exclusions."""
        return self.config.should_scan_path(filepath)
