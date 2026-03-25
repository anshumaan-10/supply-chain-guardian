#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Artifact Integrity Scanner
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
Artifact Integrity Scanner
==========================
Detects artifact tampering, TOCTOU attacks, unsigned releases, and
insecure artifact handling in GitHub Actions workflows.

Attack vectors:
  - Artifact substitution between build and publish jobs
  - download-artifact without integrity verification
  - Unsigned artifact uploads (no attestation/provenance)
  - Artifacts from untrusted workflow_run events
  - TOCTOU (time-of-check-to-time-of-use) on artifacts
  - Artifact path traversal in download configurations
"""

import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files,
    find_action_files,
    parse_yaml_safe,
    read_file_lines,
    extract_uses_statements,
    extract_run_blocks,
)


class ArtifactScanner(BaseScanner):
    """Scan for artifact integrity issues in GitHub Actions."""

    scanner_name = "artifact_integrity"

    # Actions that handle artifacts
    UPLOAD_ACTIONS = [
        "actions/upload-artifact",
    ]

    DOWNLOAD_ACTIONS = [
        "actions/download-artifact",
    ]

    ATTEST_ACTIONS = [
        "actions/attest-build-provenance",
        "slsa-framework/slsa-github-generator",
        "sigstore/cosign-installer",
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)
        all_files = workflow_files + action_files

        if not all_files:
            return self.findings

        for filepath in all_files:
            if not self.should_scan_file(filepath):
                continue

            data = parse_yaml_safe(filepath)
            lines = read_file_lines(filepath)

            if not data:
                continue

            self._check_unsigned_artifacts(data, filepath, lines)
            self._check_artifact_download_no_verify(data, filepath, lines)
            self._check_workflow_run_artifacts(data, filepath, lines)
            self._check_artifact_path_traversal(data, filepath, lines)
            self._check_artifact_overwrite(data, filepath, lines)
            self._check_build_publish_separation(data, filepath, lines)

        return self.findings

    def _check_unsigned_artifacts(self, data: dict, filepath: str, lines: list):
        """Check for artifact uploads without attestation or signing."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            has_upload = False
            has_attest = False
            upload_line = 0

            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))

                if any(ua in uses for ua in self.UPLOAD_ACTIONS):
                    has_upload = True
                    # Find line number
                    step_name = step.get("name", step.get("id", ""))
                    upload_line = self._find_step_line(lines, uses, step_name)

                if any(aa in uses for aa in self.ATTEST_ACTIONS):
                    has_attest = True

            if has_upload and not has_attest:
                self.add_finding(
                    attack_id="SCA-067",
                    title=f"Artifact upload without provenance attestation in '{job_name}'",
                    severity="medium",
                    description=(
                        f"Job '{job_name}' uploads artifacts but does not generate a provenance attestation. "
                        "Without attestation, downstream consumers cannot verify the artifact was built "
                        "by this CI pipeline and has not been tampered with."
                    ),
                    file=filepath,
                    line=upload_line,
                    remediation=(
                        "Add actions/attest-build-provenance@v2 after the upload step "
                        "to generate SLSA provenance for published artifacts."
                    ),
                )

    def _check_artifact_download_no_verify(self, data: dict, filepath: str, lines: list):
        """Check for artifact downloads without integrity verification."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for idx, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))

                if any(da in uses for da in self.DOWNLOAD_ACTIONS):
                    # Check if subsequent steps verify checksums
                    has_verify = False
                    for subsequent in steps[idx + 1: idx + 4]:
                        if not isinstance(subsequent, dict):
                            continue
                        run_content = str(subsequent.get("run", ""))
                        if re.search(r'sha256sum|sha512sum|checksum|cosign\s+verify|slsa-verifier', run_content, re.IGNORECASE):
                            has_verify = True
                            break
                        sub_uses = str(subsequent.get("uses", ""))
                        if "slsa-verifier" in sub_uses or "cosign" in sub_uses or "attest" in sub_uses:
                            has_verify = True
                            break

                    if not has_verify:
                        step_name = step.get("name", step.get("id", ""))
                        ln = self._find_step_line(lines, uses, step_name)
                        self.add_finding(
                            attack_id="SCA-068",
                            title=f"Artifact download without integrity verification in '{job_name}'",
                            severity="medium",
                            description=(
                                "An artifact is downloaded but there is no subsequent integrity check "
                                "(checksum verification, cosign verify, or SLSA verification). "
                                "A compromised artifact could introduce malicious code into the pipeline."
                            ),
                            file=filepath,
                            line=ln,
                            remediation="Verify downloaded artifact integrity with sha256sum, cosign verify, or slsa-verifier before use.",
                        )

    def _check_workflow_run_artifacts(self, data: dict, filepath: str, lines: list):
        """Check for dangerous artifact handling in workflow_run context."""
        triggers = data.get("on", data.get(True, {}))
        is_workflow_run = False
        if isinstance(triggers, dict):
            is_workflow_run = "workflow_run" in triggers
        elif isinstance(triggers, list):
            is_workflow_run = "workflow_run" in triggers

        if not is_workflow_run:
            return

        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                run_content = str(step.get("run", ""))

                # Check for gh api to download artifacts from workflow_run
                if re.search(r'gh\s+api.*artifacts|gh\s+run\s+download', run_content, re.IGNORECASE):
                    ln = self._find_line(lines, "artifacts")
                    self.add_finding(
                        attack_id="SCA-069",
                        title="Untrusted artifact consumption in workflow_run context",
                        severity="high",
                        description=(
                            "This workflow_run event downloads artifacts from a triggering workflow. "
                            "Artifacts from fork PRs run in the untrusted pull_request context. "
                            "Using these artifacts without verification can lead to code injection "
                            "in the privileged workflow_run context."
                        ),
                        file=filepath,
                        line=ln,
                        remediation=(
                            "Validate artifact contents before use. Never execute downloaded artifacts directly. "
                            "Verify the triggering workflow conclusion and head_sha before consuming artifacts."
                        ),
                        evidence=run_content[:200],
                    )

    def _check_artifact_path_traversal(self, data: dict, filepath: str, lines: list):
        """Check for potential path traversal in artifact download paths."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                with_block = step.get("with", {}) or {}

                if any(da in uses for da in self.DOWNLOAD_ACTIONS):
                    path = str(with_block.get("path", ""))
                    if ".." in path or path.startswith("/"):
                        step_name = step.get("name", step.get("id", ""))
                        ln = self._find_step_line(lines, uses, step_name)
                        self.add_finding(
                            attack_id="SCA-070",
                            title="Artifact download with path traversal risk",
                            severity="high",
                            description=(
                                f"Artifact download path contains traversal pattern: '{path}'. "
                                "This could allow artifact contents to overwrite critical files "
                                "outside the intended directory."
                            ),
                            file=filepath,
                            line=ln,
                            remediation="Use a relative, non-traversal path for artifact downloads. Validate paths before use.",
                            evidence=path,
                        )

    def _check_artifact_overwrite(self, data: dict, filepath: str, lines: list):
        """Check for 'overwrite: true' on artifact uploads (artifact poisoning)."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                with_block = step.get("with", {}) or {}

                if any(ua in uses for ua in self.UPLOAD_ACTIONS):
                    if str(with_block.get("overwrite", "")).lower() == "true":
                        step_name = step.get("name", step.get("id", ""))
                        ln = self._find_step_line(lines, uses, step_name)
                        self.add_finding(
                            attack_id="SCA-071",
                            title=f"Artifact overwrite enabled in '{job_name}'",
                            severity="medium",
                            description=(
                                "Artifact upload has overwrite: true. A compromised parallel job could "
                                "replace a legitimate artifact with a malicious one before it is consumed "
                                "by downstream jobs."
                            ),
                            file=filepath,
                            line=ln,
                            remediation="Avoid overwrite: true. Use unique artifact names per run. Verify artifact checksums after download.",
                        )

    def _check_build_publish_separation(self, data: dict, filepath: str, lines: list):
        """Check if build and publish happen in the same job (TOCTOU risk)."""
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            steps = job_data.get("steps", [])
            has_build = False
            has_publish = False
            build_line = 0

            publish_patterns = [
                r"npm\s+publish", r"twine\s+upload", r"gem\s+push",
                r"cargo\s+publish", r"docker\s+push", r"gh\s+release\s+create",
                r"goreleaser", r"pypi", r"nuget\s+push",
            ]

            build_patterns = [
                r"npm\s+run\s+build", r"make\s+build", r"go\s+build",
                r"cargo\s+build", r"docker\s+build", r"mvn\s+package",
                r"gradle\s+build", r"python\s+setup\.py\s+build",
            ]

            for step in steps:
                if not isinstance(step, dict):
                    continue
                run_content = str(step.get("run", ""))
                for bp in build_patterns:
                    if re.search(bp, run_content, re.IGNORECASE):
                        has_build = True
                        build_line = self._find_line(lines, run_content[:30]) or build_line
                for pp in publish_patterns:
                    if re.search(pp, run_content, re.IGNORECASE):
                        has_publish = True

            if has_build and has_publish:
                self.add_finding(
                    attack_id="SCA-072",
                    title=f"Build and publish in same job '{job_name}' (TOCTOU risk)",
                    severity="medium",
                    description=(
                        "Build and publish steps are in the same job. A compromised build step "
                        "could modify artifacts before they are published. Separating these into "
                        "different jobs with artifact transfer provides an integrity boundary."
                    ),
                    file=filepath,
                    line=build_line,
                    remediation=(
                        "Separate build and publish into different jobs. Upload artifacts from the build job, "
                        "verify checksums, then download in the publish job."
                    ),
                )

    def _find_step_line(self, lines: list, uses: str, step_name: str = "") -> int:
        """Find the line number of a step by its uses or name."""
        action_short = uses.split("@")[0] if "@" in uses else uses
        for i, line in enumerate(lines, 1):
            if action_short in line:
                return i
        if step_name:
            for i, line in enumerate(lines, 1):
                if step_name in line:
                    return i
        return 1

    def _find_line(self, lines: list, keyword: str) -> int:
        """Find the first line containing a keyword."""
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1
