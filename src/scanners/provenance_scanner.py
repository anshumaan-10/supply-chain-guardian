#!/usr/bin/env python3
"""
Provenance Scanner
==================
Verifies dependency provenance, SLSA attestations, and
checks for supply chain trust indicators.
"""

import re
import os
import json
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_package_files, read_file_lines, find_workflow_files, parse_yaml_safe


class ProvenanceScanner(BaseScanner):
    """Verify dependency provenance and trust indicators."""

    scanner_name = "provenance_verification"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        package_files = find_package_files(self.config.workspace_dir)

        # Check npm provenance
        for filepath in package_files.get("npm", []):
            if not self.should_scan_file(filepath):
                continue
            if os.path.basename(filepath) == "package-lock.json":
                self._check_npm_provenance(filepath)

        # Check Python hash requirements
        for filepath in package_files.get("python", []):
            if not self.should_scan_file(filepath):
                continue
            if os.path.basename(filepath) == "requirements.txt":
                self._check_python_hashes(filepath)

        # Check for CDN trust (Polyfill.io, etc.)
        self._check_cdn_integrity()

        # Check workflow for SLSA provenance
        workflow_files = find_workflow_files(self.config.workspace_dir)
        for filepath in workflow_files:
            if not self.should_scan_file(filepath):
                continue
            self._check_workflow_provenance(filepath)

        return self.findings

    def _check_npm_provenance(self, filepath):
        """Check npm lockfile for integrity hashes."""
        lines = read_file_lines(filepath)
        try:
            content = "".join(lines)
            lock_data = json.loads(content)
        except (json.JSONDecodeError, Exception):
            return

        lockfile_version = lock_data.get("lockfileVersion", 1)

        # Check lockfile version (v1 is deprecated and less secure)
        if lockfile_version < 2:
            self.add_finding(
                attack_id="SCA-PROV-NPM",
                title="Outdated npm lockfile version",
                severity="low",
                description=f"package-lock.json uses lockfile version {lockfile_version}. "
                            f"Version 3 provides better integrity verification.",
                file=filepath,
                line=1,
                remediation="Run 'npm install' with npm 7+ to upgrade lockfile.",
            )

        # Check packages for missing integrity hashes
        packages = lock_data.get("packages", {})
        missing_integrity = 0
        total = 0

        for pkg_path, pkg_info in packages.items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue
            total += 1
            if not pkg_info.get("integrity"):
                missing_integrity += 1

        if total > 0 and missing_integrity > total * 0.1:
            self.add_finding(
                attack_id="SCA-PROV-NPM",
                title=f"Missing integrity hashes: {missing_integrity}/{total} packages",
                severity="medium",
                description=f"{missing_integrity} out of {total} packages in the lockfile are missing "
                            f"integrity hashes. This makes it impossible to verify package authenticity.",
                file=filepath,
                line=1,
                remediation="Regenerate the lockfile with 'npm install'. Use 'npm ci' in CI to enforce integrity checks.",
            )

    def _check_python_hashes(self, filepath):
        """Check if Python requirements use hash pinning."""
        lines = read_file_lines(filepath)
        total_deps = 0
        hashed_deps = 0

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue

            if re.match(r'[a-zA-Z]', stripped):
                total_deps += 1
                if "--hash=" in stripped:
                    hashed_deps += 1

        if total_deps > 0 and hashed_deps == 0 and self.config.scan_mode in ("deep", "paranoid"):
            self.add_finding(
                attack_id="SCA-PROV-PY",
                title="No hash pinning in requirements.txt",
                severity="medium",
                description=f"requirements.txt has {total_deps} dependencies without hash verification. "
                            f"Without hashes, pip cannot verify package integrity. This is how the "
                            f"LiteLLM credential stealer (SCA-056) was distributed - a malicious wheel "
                            f"replaced the legitimate one without detection.",
                file=filepath,
                line=1,
                remediation="Use 'pip install --require-hashes' and add hashes:\n"
                            "  requests==2.31.0 --hash=sha256:...\n"
                            "Or use pip-tools to generate hashed requirements.",
            )

    def _check_cdn_integrity(self):
        """Check HTML/JS files for CDN usage without SRI."""
        # Scan for HTML files
        for root, dirs, files in os.walk(self.config.workspace_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv")]

            for f in files:
                if not f.endswith((".html", ".htm", ".ejs", ".hbs")):
                    continue

                filepath = os.path.join(root, f)
                if not self.should_scan_file(filepath):
                    continue

                lines = read_file_lines(filepath)
                for i, line in enumerate(lines, 1):
                    # Check for Polyfill.io
                    if "polyfill.io" in line.lower():
                        self.add_finding(
                            attack_id="SCA-046",
                            title="Polyfill.io reference detected",
                            severity="critical",
                            description="Reference to polyfill.io detected. This domain was compromised in a "
                                        "supply chain attack that served malicious JavaScript to 100,000+ websites.",
                            file=filepath,
                            line=i,
                            remediation="Remove all polyfill.io references. Use modern browser APIs or "
                                        "a trusted, self-hosted polyfill alternative with SRI hashes.",
                            evidence=line.strip()[:200],
                        )

                    # Check for CDN scripts without integrity
                    cdn_match = re.search(
                        r'<script\s+[^>]*src=["\']https?://(cdn\.|unpkg|cdnjs)[^"\']+["\']',
                        line, re.IGNORECASE
                    )
                    if cdn_match and "integrity=" not in line.lower():
                        self.add_finding(
                            attack_id="SCA-025",
                            title="CDN script without Subresource Integrity (SRI)",
                            severity="medium",
                            description="A script is loaded from a CDN without an integrity hash. "
                                        "If the CDN is compromised (like Polyfill.io), malicious code "
                                        "could be served without detection.",
                            file=filepath,
                            line=i,
                            remediation="Add integrity= and crossorigin= attributes to all CDN script tags.",
                            evidence=line.strip()[:200],
                        )

    def _check_workflow_provenance(self, filepath):
        """Check workflows for SLSA/provenance best practices."""
        workflow = parse_yaml_safe(filepath)
        if not workflow:
            return

        # Only check in deep/paranoid mode
        if self.config.scan_mode not in ("deep", "paranoid"):
            return

        # Check for artifact attestation
        jobs = workflow.get("jobs", {})
        has_publish = False
        has_attestation = False

        for job_name, job_data in (jobs or {}).items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in (steps or []):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                run = step.get("run", "")

                # Check for publishing steps
                if any(x in uses for x in ["pypa/gh-action-pypi-publish", "JS-DevTools/npm-publish"]):
                    has_publish = True
                if isinstance(run, str) and any(x in run for x in ["npm publish", "twine upload", "cargo publish"]):
                    has_publish = True

                # Check for attestation
                if "attest" in uses.lower() or "slsa" in uses.lower() or "sigstore" in uses.lower():
                    has_attestation = True

        if has_publish and not has_attestation:
            self.add_finding(
                attack_id="SCA-PROV-SLSA",
                title="Package published without attestation",
                severity="low",
                description="This workflow publishes a package but doesn't generate SLSA attestations or "
                            "provenance metadata. Attestations help users verify the package was built "
                            "from the claimed source repository.",
                file=filepath,
                line=1,
                remediation="Add SLSA provenance generation. For npm, use --provenance flag. "
                            "For PyPI, use Trusted Publishing. Consider actions/attest-build-provenance.",
            )
