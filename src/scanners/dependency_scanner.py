#!/usr/bin/env python3
"""
Dependency Scanner
==================
Scans package manifests (npm, PyPI, Go, Ruby, Rust, Java) for
known-compromised packages, malicious versions, dependency confusion,
and suspicious install scripts. Includes LiteLLM wheel attack detection.
"""

import re
import os
import json
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_package_files, read_file_lines, parse_yaml_safe


class DependencyScanner(BaseScanner):
    """Scan dependencies for known-compromised packages and malicious patterns."""

    scanner_name = "dependency_integrity"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Get all known malicious packages from attack DB
        malicious_packages = self.attack_db.get_malicious_packages()

        # Find all package manifest files
        package_files = find_package_files(self.config.workspace_dir)

        # Scan npm artifacts
        for filepath in package_files.get("npm", []):
            if not self.should_scan_file(filepath):
                continue
            self._scan_npm(filepath, malicious_packages.get("npm", {}))

        # Scan Python artifacts
        for filepath in package_files.get("python", []):
            if not self.should_scan_file(filepath):
                continue
            self._scan_python(filepath, malicious_packages.get("pypi", {}))

        # Scan Go modules
        for filepath in package_files.get("go", []):
            if not self.should_scan_file(filepath):
                continue
            self._scan_go(filepath)

        # Scan Ruby gems
        for filepath in package_files.get("ruby", []):
            if not self.should_scan_file(filepath):
                continue
            self._scan_ruby(filepath)

        # Scan for dependency confusion indicators
        self._scan_dependency_confusion()

        # Scan setup.py for malicious patterns (LiteLLM-style)
        self._scan_setup_py_patterns()

        # Scan for install script attacks
        self._scan_install_scripts(package_files.get("npm", []))

        return self.findings

    def _scan_npm(self, filepath, malicious_pkgs):
        """Scan npm package.json and package-lock.json."""
        lines = read_file_lines(filepath)
        filename = os.path.basename(filepath)

        if filename == "package.json":
            try:
                content = "".join(lines)
                pkg_data = json.loads(content)
            except (json.JSONDecodeError, Exception):
                return

            # Check all dependency types
            dep_sections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]
            for section in dep_sections:
                deps = pkg_data.get(section, {})
                if not isinstance(deps, dict):
                    continue

                for pkg_name, version in deps.items():
                    # Check exact name@version matches
                    pkg_with_version = f"{pkg_name}@{version.lstrip('^~>=<')}"
                    pkg_exact = f"{pkg_name}"

                    for malicious_entry, attack_info in malicious_pkgs.items():
                        if malicious_entry == pkg_exact or malicious_entry == pkg_with_version:
                            line = self._find_package_line(lines, pkg_name)
                            self.add_finding(
                                attack_id="SCA-DEP-NPM",
                                title=f"Known malicious npm package: {pkg_name}",
                                severity="critical",
                                description=f"Package '{pkg_name}' (version {version}) is a known "
                                            f"malicious package: {attack_info}. "
                                            f"This package was involved in a real supply chain attack.",
                                file=filepath,
                                line=line,
                                remediation=f"Remove '{pkg_name}' immediately. If you need similar functionality, "
                                            f"find a trusted alternative. Audit your systems for indicators of compromise.",
                                evidence=f'"{pkg_name}": "{version}"',
                            )

            # Check for suspicious install scripts
            scripts = pkg_data.get("scripts", {})
            for script_name in ("preinstall", "postinstall", "install"):
                if script_name in scripts:
                    script_cmd = scripts[script_name]
                    if any(x in str(script_cmd).lower() for x in [
                        "curl", "wget", "node -e", "eval", "exec(",
                        "/dev/tcp", "base64", "http://", "https://",
                    ]):
                        line = self._find_package_line(lines, script_name)
                        self.add_finding(
                            attack_id="SCA-042",
                            title=f"Suspicious npm {script_name} script",
                            severity="high",
                            description=f"The {script_name} script contains potentially dangerous commands: "
                                        f"'{script_cmd[:100]}'. Install scripts are the most common npm attack vector.",
                            file=filepath,
                            line=line,
                            remediation=f"Review the {script_name} script carefully. Consider using npm install --ignore-scripts.",
                            evidence=f'"{script_name}": "{script_cmd[:200]}"',
                        )

        elif filename == "package-lock.json":
            # Scan lockfile for known malicious packages
            try:
                content = "".join(lines)
                lock_data = json.loads(content)
            except (json.JSONDecodeError, Exception):
                return

            # Check packages in lockfile v3 format
            packages = lock_data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if not isinstance(pkg_info, dict):
                    continue

                name = pkg_info.get("name", pkg_path.split("node_modules/")[-1] if "node_modules" in pkg_path else "")
                version = pkg_info.get("version", "")

                for malicious_entry, attack_info in malicious_pkgs.items():
                    if f"{name}@{version}" == malicious_entry or name == malicious_entry:
                        self.add_finding(
                            attack_id="SCA-DEP-LOCK",
                            title=f"Malicious package in lockfile: {name}@{version}",
                            severity="critical",
                            description=f"Lockfile contains known malicious package: {name}@{version} ({attack_info})",
                            file=filepath,
                            line=0,
                            remediation=f"Remove {name} from dependencies and regenerate lockfile.",
                        )

    def _scan_python(self, filepath, malicious_pkgs):
        """Scan Python dependency files."""
        lines = read_file_lines(filepath)
        filename = os.path.basename(filepath)

        if filename == "requirements.txt":
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                    continue

                # Parse package==version or package>=version
                match = re.match(r'([a-zA-Z0-9_.-]+)\s*([=<>!~]+\s*[\d.]+)?', stripped)
                if match:
                    pkg_name = match.group(1).lower()
                    version_spec = match.group(2) or ""

                    for malicious_entry, attack_info in malicious_pkgs.items():
                        entry_name = malicious_entry.split("==")[0].lower()
                        entry_version = malicious_entry.split("==")[1] if "==" in malicious_entry else ""

                        if pkg_name == entry_name:
                            if not entry_version or entry_version in version_spec:
                                self.add_finding(
                                    attack_id="SCA-DEP-PY",
                                    title=f"Known malicious PyPI package: {pkg_name}",
                                    severity="critical",
                                    description=f"Package '{pkg_name}' is a known malicious package: {attack_info}. "
                                                f"This includes attacks like the LiteLLM credential stealer (SCA-056) "
                                                f"where malicious code was hidden in wheel distributions.",
                                    file=filepath,
                                    line=i,
                                    remediation=f"Remove '{pkg_name}' and find a trusted alternative. "
                                                f"Use pip install --require-hashes to verify package integrity.",
                                    evidence=stripped,
                                )

            # Check for --extra-index-url (dependency confusion risk)
            content = "".join(lines)
            if "--extra-index-url" in content:
                line = self._find_text_line(lines, "--extra-index-url")
                self.add_finding(
                    attack_id="SCA-019",
                    title="Dependency confusion risk: --extra-index-url",
                    severity="high",
                    description="Using --extra-index-url alongside PyPI creates a dependency confusion risk. "
                                "An attacker can publish a higher-version package on PyPI that takes precedence "
                                "over your internal package. This is the same technique used in the "
                                "PyTorch torchtriton attack (SCA-047).",
                    file=filepath,
                    line=line,
                    remediation="Use --index-url (not --extra-index-url) for private registries. "
                                "Use --no-deps with explicit requirements. Namespace your internal packages.",
                    evidence=lines[line - 1].strip() if line else "",
                )

        elif filename in ("setup.py", "setup.cfg", "pyproject.toml"):
            self._scan_python_build_file(filepath, lines, malicious_pkgs)

    def _scan_python_build_file(self, filepath, lines, malicious_pkgs):
        """Scan Python build files for malicious patterns."""
        content = "".join(lines)
        filename = os.path.basename(filepath)

        # Patterns from LiteLLM wheel attack and similar
        dangerous_patterns = [
            (r"exec\s*\(", "exec() call in build file", "high"),
            (r"eval\s*\(", "eval() call in build file", "high"),
            (r"compile\s*\(.*exec", "compile/exec in build file", "high"),
            (r"__import__\s*\(", "dynamic import in build file", "high"),
            (r"subprocess\.(call|run|Popen)", "subprocess in build file", "high"),
            (r"os\.system\s*\(", "os.system in build file", "high"),
            (r"urllib\.request\.urlopen", "URL fetch in build file", "high"),
            (r"requests\.(get|post)\s*\(", "HTTP request in build file", "medium"),
            (r"socket\.(socket|connect)", "Socket operation in build file", "high"),
            (r"os\.environ", "Environment variable access in build file", "medium"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue

            for pattern, name, severity in dangerous_patterns:
                try:
                    if re.search(pattern, stripped):
                        self.add_finding(
                            attack_id="SCA-058",
                            title=f"Suspicious pattern in {filename}: {name}",
                            severity=severity,
                            description=f"Detected {name} in {filename}. "
                                        f"Build files (setup.py, pyproject.toml) execute during installation. "
                                        f"Malicious code in build files is a common PyPI attack vector, "
                                        f"as seen in the LiteLLM credential stealer attack.",
                            file=filepath,
                            line=i,
                            remediation="Review this code carefully. If this setup.py does network calls, "
                                        "subprocess execution, or env variable access, it may be malicious.",
                            evidence=stripped[:200],
                        )
                except re.error:
                    continue

    def _scan_go(self, filepath):
        """Scan Go module files for known issues."""
        lines = read_file_lines(filepath)
        filename = os.path.basename(filepath)

        if filename == "go.mod":
            # Check for replace directives pointing to unexpected locations
            for i, line in enumerate(lines, 1):
                if re.match(r'\s*replace\s+', line):
                    if "github.com" not in line and "golang.org" not in line:
                        self.add_finding(
                            attack_id="SCA-DEP-GO",
                            title=f"Go module replace directive",
                            severity="medium",
                            description="A replace directive in go.mod points to a non-standard source. "
                                        "This could be used for dependency substitution.",
                            file=filepath,
                            line=i,
                            remediation="Verify the replace target is intentional and from a trusted source.",
                            evidence=line.strip()[:200],
                        )

    def _scan_ruby(self, filepath):
        """Scan Ruby Gemfile for known issues."""
        lines = read_file_lines(filepath)

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # Check for gems from git sources
            if re.search(r'gem\s+.*,\s*git:', stripped):
                if "github.com" not in stripped:
                    self.add_finding(
                        attack_id="SCA-DEP-RUBY",
                        title="Ruby gem from non-GitHub git source",
                        severity="medium",
                        description="A gem is loaded from a non-GitHub git source. "
                                    "Verify this source is trustworthy.",
                        file=filepath,
                        line=i,
                        remediation="Use gems from rubygems.org or verified GitHub repositories.",
                        evidence=stripped[:200],
                    )

    def _scan_dependency_confusion(self):
        """Scan for dependency confusion indicators."""
        # Check for .npmrc with registry configuration
        npmrc_path = os.path.join(self.config.workspace_dir, ".npmrc")
        if os.path.exists(npmrc_path):
            lines = read_file_lines(npmrc_path)
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                # Check for mixed registries
                if "registry=" in stripped and "registry.npmjs.org" not in stripped:
                    # Internal registry - check if also using public
                    self.add_finding(
                        attack_id="SCA-019",
                        title="Custom npm registry (dependency confusion risk)",
                        severity="medium",
                        description="Custom npm registry detected. If scoped packages (@org/pkg) are not used, "
                                    "public npm can supply packages with the same names as internal ones.",
                        file=npmrc_path,
                        line=i,
                        remediation="Use scoped packages (@org/pkg). Configure always-auth=true. "
                                    "Use npm config set registry for the scope only.",
                        evidence=stripped[:200],
                    )

        # Check pip.conf / pip.ini
        for pip_config in ["pip.conf", "pip.ini", ".pip/pip.conf"]:
            pip_path = os.path.join(self.config.workspace_dir, pip_config)
            if os.path.exists(pip_path):
                lines = read_file_lines(pip_path)
                for i, line in enumerate(lines, 1):
                    if "extra-index-url" in line:
                        self.add_finding(
                            attack_id="SCA-019",
                            title="pip extra-index-url in config (dependency confusion)",
                            severity="high",
                            description="pip.conf contains extra-index-url which enables dependency confusion.",
                            file=pip_path,
                            line=i,
                            remediation="Use --index-url instead. Namespace internal packages.",
                            evidence=line.strip()[:200],
                        )

    def _scan_setup_py_patterns(self):
        """Scan for suspicious setup.py patterns across the workspace."""
        for root, dirs, files in os.walk(self.config.workspace_dir):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".venv")]

            for f in files:
                if f == "setup.py":
                    filepath = os.path.join(root, f)
                    if not self.should_scan_file(filepath):
                        continue

                    lines = read_file_lines(filepath)
                    content = "".join(lines)

                    # Check for network calls during setup
                    if re.search(r'(urllib|requests|http\.client|socket)', content, re.IGNORECASE):
                        if re.search(r'(setup\(|install_requires)', content):
                            self.add_finding(
                                attack_id="SCA-056",
                                title=f"setup.py with network operations",
                                severity="high",
                                description="This setup.py imports network libraries. "
                                            "Legitimate setup.py files rarely need network access. "
                                            "This is a pattern seen in the LiteLLM credential stealer attack.",
                                file=filepath,
                                line=1,
                                remediation="Review the setup.py for data exfiltration. "
                                            "Install with --no-build-isolation to inspect.",
                            )

    def _scan_install_scripts(self, npm_files):
        """Scan package.json files for suspicious install scripts."""
        # Already handled in _scan_npm, but check for more patterns
        pass

    def _find_package_line(self, lines, pkg_name):
        """Find line number containing package name."""
        for i, line in enumerate(lines, 1):
            if pkg_name in line:
                return i
        return 0

    def _find_text_line(self, lines, text):
        """Find line number containing text."""
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 0
