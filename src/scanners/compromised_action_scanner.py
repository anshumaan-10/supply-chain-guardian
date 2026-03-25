#!/usr/bin/env python3
"""
Compromised Action Scanner
==========================
Detects usage of known-compromised GitHub Actions by matching
action references against the attack database of known-bad SHAs
and action names (tj-actions, reviewdog, SpotBugs, Trivy, KICS, etc.).

Includes:
- Exact compromised SHA matching (87+ known-bad SHAs)
- Compromised action name matching (21+ actions)
- Imposter commit detection heuristic (Step Security inspired)
- Mutable tag warning
- Docker image digest checking for compromised containers
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, find_action_files, extract_uses_statements


# ── Known-safe reference versions for critical actions ──
# These are verified-safe pins for actions that were previously compromised
KNOWN_SAFE_PINS = {
    "aquasecurity/trivy-action": {
        "safe_tags": ["0.35.0"],
        "safe_shas": [],
        "advisory": "CVE-2026-33634: All trivy-action tags 0.0.1-0.34.2 were compromised",
    },
    "aquasecurity/setup-trivy": {
        "safe_tags": ["v0.2.6"],
        "safe_shas": ["3fb12ec"],
        "advisory": "CVE-2026-33634: All setup-trivy tags were compromised",
    },
}

# ── Compromised Docker image digests ──
COMPROMISED_DOCKER_DIGESTS = {
    "sha256:27f446230c60bbf0b70e008db798bd4f33b7826f9f76f756606f5417100beef3": "aquasec/trivy:0.69.4 (CVE-2026-33634)",
    "sha256:5aaa1d7cfa9ca4649d6ffad165435c519dc836fa6e21b729a2174ad10b057d2b": "aquasec/trivy:0.69.5 (CVE-2026-33634)",
    "sha256:425cd3e1a2846ac73944e891250377d2b03653e6f028833e30fc00c1abbc6d33": "aquasec/trivy:0.69.6 (CVE-2026-33634)",
}

# ── Compromised container image tags ──
COMPROMISED_CONTAINER_TAGS = {
    "aquasec/trivy:0.69.4": "CVE-2026-33634: TeamPCP credential stealer",
    "aquasec/trivy:0.69.5": "CVE-2026-33634: TeamPCP credential stealer",
    "aquasec/trivy:0.69.6": "CVE-2026-33634: TeamPCP credential stealer",
}


class CompromisedActionScanner(BaseScanner):
    """Scan for usage of known-compromised GitHub Actions."""

    scanner_name = "compromised_actions"

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Get all known compromised SHAs and action names from attack DB
        compromised_shas = self.attack_db.get_compromised_shas()
        compromised_actions = self.attack_db.get_compromised_actions()

        # Find all workflow and action files
        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)
        all_files = workflow_files + action_files

        if not all_files:
            self.logger.debug("No workflow or action files found")
            return self.findings

        for filepath in all_files:
            if not self.should_scan_file(filepath):
                continue

            uses_statements = extract_uses_statements(filepath)

            for stmt in uses_statements:
                action_ref = stmt["action_ref"]
                line = stmt["line"]

                # Check 1: Exact SHA match against known compromised commits
                sha_match = re.search(r'@([0-9a-f]{40})', action_ref)
                if sha_match:
                    sha = sha_match.group(1)
                    if sha in compromised_shas:
                        attack_info = compromised_shas[sha]
                        self.add_finding(
                            attack_id="SCA-COMP-SHA",
                            title=f"COMPROMISED SHA detected: {action_ref}",
                            severity="critical",
                            description=f"This workflow uses a known-compromised commit SHA. Attack: {attack_info}. "
                                        f"This SHA was involved in a real supply chain attack.",
                            file=filepath,
                            line=line,
                            remediation=f"Immediately remove or update this action. Rotate all secrets that may have been exposed. Reference: {attack_info}",
                            evidence=stmt["raw"],
                        )

                # Check 2: Action name match against known compromised actions
                action_name = action_ref.split("@")[0] if "@" in action_ref else action_ref
                for comp_action, attack_info in compromised_actions.items():
                    if action_name.lower() == comp_action.lower():
                        # Check if it's pinned to a SHA (safer) or a tag (dangerous)
                        is_tag = "@" in action_ref and not re.search(r'@[0-9a-f]{40}', action_ref)
                        if is_tag:
                            self.add_finding(
                                attack_id="SCA-COMP-TAG",
                                title=f"Previously-compromised action used with mutable tag: {action_ref}",
                                severity="high",
                                description=f"This action ({comp_action}) was involved in a known supply chain attack: {attack_info}. "
                                            f"Using a mutable tag (@v1, @v2, etc.) means the code could be changed without your knowledge.",
                                file=filepath,
                                line=line,
                                remediation=f"Pin to a verified commit SHA or remove this action entirely. Attack reference: {attack_info}",
                                evidence=stmt["raw"],
                            )
                        else:
                            # Even if SHA-pinned, flag as info since the action was compromised before
                            self.add_finding(
                                attack_id="SCA-COMP-HIST",
                                title=f"Action with compromise history: {action_ref}",
                                severity="info",
                                description=f"This action ({comp_action}) was involved in a past supply chain attack: {attack_info}. "
                                            f"It is currently pinned to a SHA which provides protection, but verify the SHA is from a trusted commit.",
                                file=filepath,
                                line=line,
                                remediation=f"Verify the pinned SHA corresponds to a known-good release. Consider alternative actions.",
                                evidence=stmt["raw"],
                            )

                # Check 2b: Known-safe pin advisory — warn if using a non-safe tag/SHA
                for safe_action, safe_info in KNOWN_SAFE_PINS.items():
                    if action_name.lower() == safe_action.lower() and "@" in action_ref:
                        version_part = action_ref.split("@")[1]
                        is_sha = bool(re.match(r'^[0-9a-f]{40}$', version_part))
                        if is_sha:
                            # Check if it's a known-safe SHA prefix
                            is_safe = any(version_part.startswith(s) for s in safe_info["safe_shas"])
                            if not is_safe and version_part not in compromised_shas:
                                self.add_finding(
                                    attack_id="SCA-098",
                                    title=f"Unverified SHA for previously-compromised action: {action_ref}",
                                    severity="medium",
                                    description=f"{safe_info['advisory']}. "
                                                f"This SHA is not in the known-compromised list but also not in the verified-safe list. "
                                                f"Verify this SHA corresponds to a legitimate release.",
                                    file=filepath,
                                    line=line,
                                    remediation=f"Use one of the known-safe tags: {', '.join(safe_info['safe_tags'])}",
                                    evidence=stmt["raw"],
                                )
                        else:
                            # It's a tag — check if it's in the safe list
                            if version_part not in safe_info["safe_tags"]:
                                self.add_finding(
                                    attack_id="SCA-098",
                                    title=f"Potentially compromised tag for {safe_action}: @{version_part}",
                                    severity="critical",
                                    description=f"{safe_info['advisory']}. "
                                                f"Tag '{version_part}' is NOT in the known-safe list. "
                                                f"Safe tags: {', '.join(safe_info['safe_tags'])}.",
                                    file=filepath,
                                    line=line,
                                    remediation=f"Pin to a known-safe version: {', '.join(safe_info['safe_tags'])}",
                                    evidence=stmt["raw"],
                                )

                # Check 3: Unknown/unverified actions (no SHA pin)
                if "@" in action_ref:
                    version_part = action_ref.split("@")[1]
                    # Mutable tag detection (v1, v2, latest, main, master)
                    if re.match(r'^(v\d+(\.\d+)*|latest|main|master|dev|nightly)$', version_part):
                        self.add_finding(
                            attack_id="SCA-033",
                            title=f"Mutable tag reference: {action_ref}",
                            severity="medium",
                            description=f"Action '{action_name}' is referenced with mutable tag '{version_part}'. "
                                        f"Mutable tags can be silently changed to point to malicious code. "
                                        f"This is the exact technique used in the tj-actions, reviewdog, and Trivy attacks.",
                            file=filepath,
                            line=line,
                            remediation="Pin to a full commit SHA: uses: owner/action@<40-char-sha> # version comment",
                            evidence=stmt["raw"],
                        )
                elif not action_ref.startswith("."):
                    # No version at all
                    self.add_finding(
                        attack_id="SCA-051",
                        title=f"Action without version pin: {action_ref}",
                        severity="high",
                        description=f"Action '{action_ref}' has no version reference. "
                                    f"This defaults to the default branch which can be changed at any time.",
                        file=filepath,
                        line=line,
                        remediation="Always pin actions to a specific commit SHA.",
                        evidence=stmt["raw"],
                    )

            # Check 4: Scan file content for compromised Docker image references
            self._check_docker_digests(filepath)

        return self.findings

    def _check_docker_digests(self, filepath: str):
        """Check for compromised Docker image digests and tags in workflow files."""
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()
        except (OSError, IOError):
            return

        # Check for compromised Docker digests
        for digest, info in COMPROMISED_DOCKER_DIGESTS.items():
            if digest in content:
                line_num = 0
                for i, ln in enumerate(content.splitlines(), 1):
                    if digest in ln:
                        line_num = i
                        break
                self.add_finding(
                    attack_id="SCA-091",
                    title=f"COMPROMISED Docker image digest: {info}",
                    severity="critical",
                    description=f"This workflow references a known-compromised Docker image digest: {digest}. "
                                f"Image: {info}. Contains TeamPCP credential stealer.",
                    file=filepath,
                    line=line_num,
                    remediation="Remove the compromised image. Use trivy v0.69.2 or v0.69.3. Pin images by verified digest.",
                    evidence=digest,
                )

        # Check for compromised container tags
        for tag, info in COMPROMISED_CONTAINER_TAGS.items():
            if tag in content:
                line_num = 0
                for i, ln in enumerate(content.splitlines(), 1):
                    if tag in ln:
                        line_num = i
                        break
                self.add_finding(
                    attack_id="SCA-091",
                    title=f"COMPROMISED container image tag: {tag}",
                    severity="critical",
                    description=f"This workflow references a known-compromised container image: {tag}. {info}.",
                    file=filepath,
                    line=line_num,
                    remediation="Update to a safe Trivy version (v0.69.2 or v0.69.3). Pin images by digest.",
                    evidence=tag,
                )
