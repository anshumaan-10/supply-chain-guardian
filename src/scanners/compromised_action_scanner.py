#!/usr/bin/env python3
"""
Compromised Action Scanner
==========================
Detects usage of known-compromised GitHub Actions by matching
action references against the attack database of known-bad SHAs
and action names (tj-actions, reviewdog, SpotBugs, etc.).
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import find_workflow_files, find_action_files, extract_uses_statements


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
                                        f"This is the exact technique used in the tj-actions and reviewdog attacks.",
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

        return self.findings
