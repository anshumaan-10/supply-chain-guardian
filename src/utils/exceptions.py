#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Exception / Exemption Engine
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  Enterprise-grade rule exemption system:
#    1. Per-repo config:  .scg-config.yml in repo root
#    2. Central config:   via action input (SCG_EXCEPTIONS_URL or inline)
#    3. Inline suppress:  # scg-ignore:SCA-042 comments in code
#
#  Exempted findings are STILL reported but marked status=exempted
#  so the audit trail is preserved (compliance requirement).
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import re
import fnmatch
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class ExemptionRule:
    """A single exemption rule."""
    rule_id: str                          # SCA-042, SCA-*, or '*'
    reason: str = ""                      # Why exempted (audit trail)
    expires: str = ""                     # ISO date — auto-expires
    scope: str = "repo"                   # 'repo', 'file', 'line'
    file_pattern: str = ""               # Glob: '*.test.yml', 'scripts/*'
    approved_by: str = ""                 # Who approved the exemption
    created: str = ""                     # When created


@dataclass
class ExceptionConfig:
    """Loaded exception configuration."""
    # Rule-based exemptions
    exemptions: List[ExemptionRule] = field(default_factory=list)
    # Egress allowlist — domains that are legitimate and should not trigger
    egress_allowlist: List[str] = field(default_factory=list)
    # Scanner-level disables
    disabled_scanners: List[str] = field(default_factory=list)
    # Severity override: treat specific rules at lower severity
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    # Source of the config
    source: str = "none"

    def is_exempted(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if a finding is exempted.
        Returns (is_exempted, reason).
        """
        rule_id = finding.get("id", "")
        file_path = finding.get("file", "")
        scanner = finding.get("scanner", "")

        # Check scanner-level disable
        if scanner in self.disabled_scanners:
            return True, f"Scanner '{scanner}' disabled in .scg-config.yml"

        for rule in self.exemptions:
            # Check expiry
            if rule.expires:
                try:
                    from datetime import datetime
                    exp = datetime.fromisoformat(rule.expires.replace("Z", "+00:00"))
                    if datetime.now(exp.tzinfo or None) > exp:
                        continue  # Expired exemption, skip
                except (ValueError, TypeError):
                    pass

            # Match rule ID (supports wildcards: SCA-*, SCA-04?)
            if rule.rule_id != "*" and not fnmatch.fnmatch(rule_id, rule.rule_id):
                continue

            # Match file scope
            if rule.scope == "file" and rule.file_pattern:
                if not fnmatch.fnmatch(file_path, rule.file_pattern):
                    continue

            # Match! Return exemption reason
            reason = rule.reason or f"Exempted by rule {rule.rule_id}"
            if rule.approved_by:
                reason += f" (approved by {rule.approved_by})"
            return True, reason

        return False, ""

    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is in the egress allowlist."""
        domain_lower = domain.lower().strip(".")
        for allowed in self.egress_allowlist:
            allowed_lower = allowed.lower().strip(".")
            # Exact match
            if domain_lower == allowed_lower:
                return True
            # Wildcard subdomain match: *.google.com matches apis.google.com
            if allowed_lower.startswith("*."):
                suffix = allowed_lower[2:]
                if domain_lower == suffix or domain_lower.endswith("." + suffix):
                    return True
            # Suffix match: google.com matches sub.google.com
            if domain_lower.endswith("." + allowed_lower):
                return True
        return False

    def get_severity_override(self, rule_id: str) -> Optional[str]:
        """Get severity override for a rule ID, if configured."""
        return self.severity_overrides.get(rule_id)


# ── Default Egress Allowlist ─────────────────────────────────────────────────
# These are always allowed unless explicitly blocked.
# They represent infrastructure domains that CI/CD runners legitimately contact.

DEFAULT_EGRESS_ALLOWLIST = [
    # GitHub
    "*.github.com", "*.githubusercontent.com", "*.github.io",
    "*.actions.githubusercontent.com", "*.pkg.github.com",
    "github.com", "api.github.com", "uploads.github.com",
    "objects.githubusercontent.com", "codeload.github.com",
    "pipelines.actions.githubusercontent.com",
    # Package registries
    "registry.npmjs.org", "*.npmjs.org", "*.npmjs.com",
    "pypi.org", "files.pythonhosted.org", "*.pypi.org",
    "repo1.maven.org", "*.maven.org", "repo.maven.apache.org",
    "plugins.gradle.org", "services.gradle.org",
    "rubygems.org", "*.rubygems.org",
    "pkg.go.dev", "proxy.golang.org", "sum.golang.org",
    "crates.io", "static.crates.io",
    "packagist.org", "*.packagist.org",
    "pub.dev", "storage.googleapis.com",
    "nuget.org", "api.nuget.org", "*.nuget.org",
    "cocoapods.org", "cdn.cocoapods.org",
    # Container registries
    "*.docker.io", "*.docker.com", "docker.io",
    "registry.hub.docker.com", "production.cloudflare.docker.com",
    "ghcr.io", "*.ghcr.io",
    "*.gcr.io", "gcr.io",
    "*.azurecr.io",
    "*.ecr.aws", "*.amazonaws.com",
    "*.pkg.dev",
    "quay.io", "*.quay.io",
    # Cloud providers (legitimate API endpoints)
    "*.googleapis.com", "*.google.com", "*.gstatic.com",
    "*.azure.com", "*.microsoft.com", "*.windows.net",
    "*.aws.amazon.com",
    # Code analysis / security tools
    "*.codeql.com", "*.semmle.com",
    "*.snyk.io",
    "*.sonarcloud.io", "*.sonarqube.org",
    "*.codecov.io", "*.coveralls.io",
    "*.deepsource.io",
    # CI/CD platforms
    "*.circleci.com", "*.travis-ci.com",
    "*.gitlab.com",
    "*.bitbucket.org", "*.atlassian.com",
    "*.jenkins.io",
    # OS package repos
    "*.ubuntu.com", "*.debian.org",
    "*.centos.org", "*.fedoraproject.org",
    "*.archlinux.org",
    "*.alpinelinux.org",
    "dl-cdn.alpinelinux.org",
    "deb.nodesource.com",
    # Common legitimate tools
    "*.hashicorp.com",
    "*.terraform.io",
    "*.helm.sh",
    "*.kubernetes.io",
    "nodejs.org", "*.nodejs.org",
    "*.rust-lang.org",
    # CDNs
    "*.cloudfront.net", "*.akamaihd.net",
    "*.fastly.net", "*.cloudflare.com",
]


def load_exception_config(workspace_dir: str,
                           config_path: str = "",
                           inline_rules: str = "") -> ExceptionConfig:
    """
    Load exception config from multiple sources (merged):
      1. .scg-config.yml in workspace root
      2. Custom config path (via action input)
      3. Inline rules (via environment variable)

    Returns an ExceptionConfig with all rules merged.
    """
    config = ExceptionConfig()
    config.egress_allowlist = list(DEFAULT_EGRESS_ALLOWLIST)
    sources = []

    # ── Source 1: .scg-config.yml in repo root ───────────────────────────
    repo_config = Path(workspace_dir) / ".scg-config.yml"
    if not repo_config.exists():
        repo_config = Path(workspace_dir) / ".scg-config.yaml"

    if repo_config.exists() and _HAS_YAML:
        try:
            data = yaml.safe_load(repo_config.read_text())
            if data and isinstance(data, dict):
                _merge_config(config, data)
                sources.append(f"repo:{repo_config.name}")
        except (yaml.YAMLError, OSError) as e:
            pass  # Silently skip bad config

    # ── Source 2: Custom config path (central/org-level) ─────────────────
    if config_path:
        custom = Path(config_path)
        if custom.exists() and _HAS_YAML:
            try:
                data = yaml.safe_load(custom.read_text())
                if data and isinstance(data, dict):
                    _merge_config(config, data)
                    sources.append(f"custom:{custom.name}")
            except (yaml.YAMLError, OSError):
                pass

    # ── Source 3: Environment variable (SCG_EXCEPTIONS) ──────────────────
    env_rules = os.environ.get("SCG_EXCEPTIONS", inline_rules)
    if env_rules and _HAS_YAML:
        try:
            data = yaml.safe_load(env_rules)
            if data and isinstance(data, dict):
                _merge_config(config, data)
                sources.append("env:SCG_EXCEPTIONS")
        except yaml.YAMLError:
            pass

    config.source = ", ".join(sources) if sources else "defaults-only"
    return config


def _merge_config(config: ExceptionConfig, data: dict):
    """Merge a parsed YAML config dict into an ExceptionConfig."""

    # Exemptions
    for rule_data in data.get("exemptions", []):
        if isinstance(rule_data, dict) and "rule" in rule_data:
            config.exemptions.append(ExemptionRule(
                rule_id=str(rule_data["rule"]),
                reason=str(rule_data.get("reason", "")),
                expires=str(rule_data.get("expires", "")),
                scope=str(rule_data.get("scope", "repo")),
                file_pattern=str(rule_data.get("file", "")),
                approved_by=str(rule_data.get("approved_by", "")),
                created=str(rule_data.get("created", "")),
            ))

    # Egress allowlist (additive)
    for domain in data.get("egress_allowlist", []):
        if isinstance(domain, str) and domain.strip():
            config.egress_allowlist.append(domain.strip())

    # Egress blocklist (remove from allowlist)
    for domain in data.get("egress_blocklist", []):
        if isinstance(domain, str):
            domain_lower = domain.strip().lower()
            config.egress_allowlist = [
                d for d in config.egress_allowlist
                if d.lower().strip(".") != domain_lower.strip(".")
            ]

    # Disabled scanners
    for scanner in data.get("disabled_scanners", []):
        if isinstance(scanner, str):
            config.disabled_scanners.append(scanner.strip())

    # Severity overrides
    for override in data.get("severity_overrides", []):
        if isinstance(override, dict) and "rule" in override and "severity" in override:
            config.severity_overrides[str(override["rule"])] = str(override["severity"])


def check_inline_suppression(filepath: str, line_num: int, lines: list) -> Optional[str]:
    """
    Check if a finding at a specific line has an inline suppression comment.
    Supports:
      # scg-ignore:SCA-042
      # scg-ignore:SCA-042 reason: this is a false positive
      # scg-ignore-next-line:SCA-*
    """
    # Check the line itself
    if line_num > 0 and line_num <= len(lines):
        line = lines[line_num - 1]
        match = re.search(r'#\s*scg-ignore(?:-next-line)?:(\S+)(?:\s+reason:\s*(.+))?', line)
        if match:
            return match.group(2) or f"Inline suppression: {match.group(1)}"

    # Check the line above (scg-ignore-next-line)
    if line_num > 1 and line_num <= len(lines):
        prev_line = lines[line_num - 2]
        match = re.search(r'#\s*scg-ignore-next-line:(\S+)(?:\s+reason:\s*(.+))?', prev_line)
        if match:
            return match.group(2) or f"Inline suppression (next-line): {match.group(1)}"

    return None


def apply_exemptions(findings: List[Dict[str, Any]],
                     exception_config: ExceptionConfig) -> Tuple[List[Dict[str, Any]], int]:
    """
    Apply exemptions to findings list.
    Exempted findings are NOT removed — they are marked status=exempted.
    Returns (modified_findings, exempted_count).
    """
    exempted_count = 0

    for finding in findings:
        is_exempt, reason = exception_config.is_exempted(finding)

        # Check severity override
        override_sev = exception_config.get_severity_override(finding.get("id", ""))
        if override_sev:
            finding["original_severity"] = finding["severity"]
            finding["severity"] = override_sev
            finding.setdefault("metadata", {})["severity_overridden"] = True

        if is_exempt:
            finding["status"] = "exempted"
            finding["exemption_reason"] = reason
            exempted_count += 1
        else:
            finding["status"] = "active"

    return findings, exempted_count
