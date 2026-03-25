#!/usr/bin/env python3
"""
Typosquat Scanner
=================
Detects typosquatting attacks by comparing package names
against known popular packages with common misspellings.
"""

import re
import os
import json
from typing import List, Dict, Any, Set

from scanners.base_scanner import BaseScanner
from utils.files import find_package_files, read_file_lines


class TyposquatScanner(BaseScanner):
    """Detect potential typosquatting in dependencies."""

    scanner_name = "typosquatting"

    # Extended list of popular packages and their known typosquats
    POPULAR_NPM = {
        "lodash", "express", "react", "react-dom", "axios", "chalk", "commander",
        "moment", "debug", "request", "async", "bluebird", "underscore", "uuid",
        "webpack", "babel-core", "typescript", "jest", "mocha", "eslint",
        "prettier", "next", "vue", "angular", "svelte", "jquery", "d3",
        "cross-env", "dotenv", "cors", "helmet", "mongoose", "sequelize",
    }

    POPULAR_PYPI = {
        "requests", "django", "flask", "numpy", "pandas", "scipy", "matplotlib",
        "boto3", "urllib3", "cryptography", "pyyaml", "pillow", "sqlalchemy",
        "celery", "redis", "psycopg2", "pytest", "black", "mypy", "ruff",
        "fastapi", "uvicorn", "pydantic", "httpx", "aiohttp", "beautifulsoup4",
        "scrapy", "selenium", "tensorflow", "torch", "transformers", "openai",
        "anthropic", "litellm", "langchain", "streamlit", "gradio",
    }

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Get typosquat patterns from attack DB
        typosquat_db = {}
        for attack in self.attack_db.attacks:
            tp = attack.detection_signatures.get("typosquat_patterns", {})
            for ecosystem, patterns in tp.items():
                typosquat_db.setdefault(ecosystem, {}).update(patterns)

        package_files = find_package_files(self.config.workspace_dir)

        # Scan npm
        for filepath in package_files.get("npm", []):
            if not self.should_scan_file(filepath):
                continue
            if os.path.basename(filepath) == "package.json":
                self._scan_npm_typosquats(filepath, typosquat_db.get("npm", {}))

        # Scan Python
        for filepath in package_files.get("python", []):
            if not self.should_scan_file(filepath):
                continue
            if os.path.basename(filepath) == "requirements.txt":
                self._scan_pypi_typosquats(filepath, typosquat_db.get("pypi", {}))

        return self.findings

    def _scan_npm_typosquats(self, filepath, known_typosquats):
        """Scan npm dependencies for typosquatting."""
        lines = read_file_lines(filepath)
        try:
            content = "".join(lines)
            pkg_data = json.loads(content)
        except (json.JSONDecodeError, Exception):
            return

        dep_sections = ["dependencies", "devDependencies", "optionalDependencies"]
        for section in dep_sections:
            deps = pkg_data.get(section, {})
            if not isinstance(deps, dict):
                continue

            for pkg_name in deps:
                # Check against known typosquats from DB
                for legit, squats in known_typosquats.items():
                    if pkg_name in squats:
                        line = self._find_line(lines, pkg_name)
                        self.add_finding(
                            attack_id="SCA-043",
                            title=f"Typosquat detected: '{pkg_name}' (did you mean '{legit}'?)",
                            severity="critical",
                            description=f"Package '{pkg_name}' is a known typosquat of the popular package '{legit}'. "
                                        f"Typosquatting packages are designed to look like legitimate packages "
                                        f"but contain malicious code (credential stealers, cryptominers, etc.).",
                            file=filepath,
                            line=line,
                            remediation=f"Replace '{pkg_name}' with the legitimate package '{legit}'.",
                            evidence=f'"{pkg_name}"',
                        )

                # Generic typosquat detection via edit distance
                if self.config.scan_mode in ("deep", "paranoid"):
                    self._check_edit_distance(filepath, pkg_name, self.POPULAR_NPM, "npm", lines)

    def _scan_pypi_typosquats(self, filepath, known_typosquats):
        """Scan Python requirements for typosquatting."""
        lines = read_file_lines(filepath)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue

            match = re.match(r'([a-zA-Z0-9_.-]+)', stripped)
            if not match:
                continue

            pkg_name = match.group(1).lower()

            # Check against known typosquats from DB
            for legit, squats in known_typosquats.items():
                if pkg_name in [s.lower() for s in squats]:
                    self.add_finding(
                        attack_id="SCA-020",
                        title=f"Typosquat detected: '{pkg_name}' (did you mean '{legit}'?)",
                        severity="critical",
                        description=f"Package '{pkg_name}' is a known typosquat of the popular package '{legit}'. "
                                    f"This is part of widespread PyPI typosquatting campaigns.",
                        file=filepath,
                        line=i,
                        remediation=f"Replace '{pkg_name}' with '{legit}'. Use pip --require-hashes.",
                        evidence=stripped,
                    )

            # Generic typosquat detection
            if self.config.scan_mode in ("deep", "paranoid"):
                self._check_edit_distance(filepath, pkg_name, self.POPULAR_PYPI, "pypi", lines)

    def _check_edit_distance(self, filepath, pkg_name, popular_set, ecosystem, lines):
        """Check if a package name is suspiciously close to a popular package."""
        pkg_lower = pkg_name.lower().replace("-", "").replace("_", "")

        for popular in popular_set:
            pop_lower = popular.lower().replace("-", "").replace("_", "")

            if pkg_lower == pop_lower:
                continue  # Same package, different case/separator

            # Check edit distance = 1
            if self._levenshtein_distance(pkg_lower, pop_lower) == 1:
                line = self._find_line(lines, pkg_name)
                self.add_finding(
                    attack_id="SCA-020",
                    title=f"Potential typosquat: '{pkg_name}' is 1 edit from '{popular}'",
                    severity="medium",
                    description=f"Package '{pkg_name}' is only 1 character different from the popular "
                                f"{ecosystem} package '{popular}'. This could be a typosquatting attempt.",
                    file=filepath,
                    line=line,
                    remediation=f"Verify you intended to use '{pkg_name}' and not '{popular}'.",
                    evidence=f"Edit distance: 1 from '{popular}'",
                )

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return TyposquatScanner._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]

    def _find_line(self, lines, text):
        """Find line number containing text."""
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 0
