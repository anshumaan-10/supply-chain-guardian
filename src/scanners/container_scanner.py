#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Container Supply Chain Scanner
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
Container Supply Chain Scanner
==============================
Detects container security issues in GitHub Actions workflows that build,
push, or run Docker containers. Focus areas:

  - Unpinned base images (FROM ubuntu:latest)
  - Docker build with --no-verify, --insecure-registry
  - Containers running as root or with --privileged
  - Missing image signing (cosign, notation)
  - Pulling from untrusted registries
  - Docker socket mount in CI (container escape)
  - Multi-stage build data leakage
  - Build arg secrets exposure
  - Hadolint / Trivy / Grype not in pipeline
"""

import os
import re
from typing import List, Dict, Any

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files,
    find_action_files,
    parse_yaml_safe,
    read_file_lines,
    extract_run_blocks,
)


class ContainerScanner(BaseScanner):
    """Scan for container supply chain security issues."""

    scanner_name = "container_security"

    # Official trusted registries
    TRUSTED_REGISTRIES = [
        "ghcr.io",
        "docker.io",
        "registry.hub.docker.com",
        "public.ecr.aws",
        "mcr.microsoft.com",
        "gcr.io",
        "quay.io",
    ]

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        # Scan workflow files for Docker usage
        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)
        all_files = workflow_files + action_files

        for filepath in all_files:
            if not self.should_scan_file(filepath):
                continue
            data = parse_yaml_safe(filepath)
            lines = read_file_lines(filepath)
            if data:
                self._check_workflow_containers(data, filepath, lines)

        # Scan Dockerfiles
        dockerfiles = self._find_dockerfiles(self.config.workspace_dir)
        for dockerfile in dockerfiles:
            if not self.should_scan_file(dockerfile):
                continue
            self._check_dockerfile(dockerfile)

        return self.findings

    def _find_dockerfiles(self, workspace: str) -> List[str]:
        """Find all Dockerfiles in the workspace (incl. prefixed names like 26-Dockerfile)."""
        dockerfiles = []
        for root, dirs, files in os.walk(workspace):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', '__pycache__', '.venv')]
            for f in files:
                if f == "Dockerfile" or f.startswith("Dockerfile.") or f.endswith(".Dockerfile") \
                        or (f.endswith("Dockerfile") and "-" in f):
                    dockerfiles.append(os.path.join(root, f))
        return dockerfiles

    def _check_workflow_containers(self, data: dict, filepath: str, lines: list):
        """Check for container security issues in workflows."""
        jobs = data.get("jobs", {})

        for job_name, job_data in jobs.items():
            if not isinstance(job_data, dict):
                continue

            # Check job-level container config
            container = job_data.get("container", {})
            if isinstance(container, str):
                self._check_container_image(container, job_name, filepath, lines)
            elif isinstance(container, dict):
                image = container.get("image", "")
                if image:
                    self._check_container_image(image, job_name, filepath, lines)
                # Check for privileged containers
                options = str(container.get("options", ""))
                if "--privileged" in options:
                    ln = self._find_line(lines, "--privileged")
                    self.add_finding(
                        attack_id="SCA-073",
                        title=f"Privileged container in job '{job_name}'",
                        severity="critical",
                        description=(
                            "Job container runs with --privileged flag. A compromised step "
                            "can escape the container and access the host system, including "
                            "other jobs' secrets and the Docker daemon."
                        ),
                        file=filepath,
                        line=ln,
                        remediation="Remove --privileged. Use specific capabilities with --cap-add if needed.",
                    )

            # Check service containers
            services = job_data.get("services", {})
            for svc_name, svc_data in (services or {}).items():
                if isinstance(svc_data, dict):
                    image = svc_data.get("image", "")
                    if image:
                        self._check_container_image(image, f"{job_name}/service/{svc_name}", filepath, lines)

            # Check steps for Docker commands
            steps = job_data.get("steps", [])
            for step in steps:
                if not isinstance(step, dict):
                    continue
                run_content = str(step.get("run", ""))
                self._check_docker_commands(run_content, filepath, step, lines)

    def _check_container_image(self, image: str, context: str, filepath: str, lines: list):
        """Check a container image reference for security issues."""
        image_str = str(image)

        # Check for unpinned images (using :latest or no tag)
        if ":" not in image_str or image_str.endswith(":latest"):
            ln = self._find_line(lines, image_str.split(":")[0])
            self.add_finding(
                attack_id="SCA-074",
                title=f"Unpinned container image in '{context}': {image_str}",
                severity="high",
                description=(
                    f"Container image '{image_str}' is not pinned to a specific digest. "
                    "The :latest tag or untagged images are mutable and can be replaced "
                    "with a malicious image on the registry."
                ),
                file=filepath,
                line=ln,
                remediation="Pin container images to SHA256 digests: image@sha256:<digest>",
                evidence=image_str,
            )

        # Check for untrusted registries
        if "/" in image_str and "." in image_str.split("/")[0]:
            registry = image_str.split("/")[0]
            if not any(tr in registry for tr in self.TRUSTED_REGISTRIES):
                ln = self._find_line(lines, image_str[:20])
                self.add_finding(
                    attack_id="SCA-075",
                    title=f"Image from unrecognized registry in '{context}'",
                    severity="medium",
                    description=(
                        f"Container image is pulled from '{registry}' which is not a well-known trusted registry. "
                        "Untrusted registries may serve malicious images or lack integrity verification."
                    ),
                    file=filepath,
                    line=ln,
                    remediation="Use trusted registries (ghcr.io, docker.io, public.ecr.aws). Verify image signatures with cosign.",
                    evidence=image_str,
                )

    def _check_docker_commands(self, run_content: str, filepath: str, step: dict, lines: list):
        """Check Docker CLI commands in run blocks for security issues."""
        if not run_content:
            return

        step_name = step.get("name", "")

        # Docker socket mount
        if re.search(r'-v\s+/var/run/docker\.sock', run_content):
            ln = self._find_line(lines, "docker.sock")
            self.add_finding(
                attack_id="SCA-076",
                title="Docker socket mount detected (container escape risk)",
                severity="critical",
                description=(
                    "The Docker socket is mounted into a container. This gives the container "
                    "full control over the Docker daemon, enabling container escape, "
                    "image manipulation, and host access."
                ),
                file=filepath,
                line=ln,
                remediation="Avoid mounting the Docker socket. Use Docker-in-Docker (dind) with proper isolation or rootless Docker.",
                evidence=run_content[:200],
            )

        # Build with --build-arg containing secrets
        build_arg_match = re.findall(r'--build-arg\s+(\w+)=\$\{?\{?(\w+)', run_content)
        for arg_name, env_ref in build_arg_match:
            secret_keywords = ["token", "key", "secret", "password", "credential", "auth"]
            if any(kw in arg_name.lower() or kw in env_ref.lower() for kw in secret_keywords):
                ln = self._find_line(lines, "--build-arg")
                self.add_finding(
                    attack_id="SCA-077",
                    title=f"Secret passed via --build-arg: {arg_name}",
                    severity="high",
                    description=(
                        f"Secret '{arg_name}' is passed as a Docker build argument. "
                        "Build arguments are stored in image layers and can be extracted "
                        "from the image history. Use Docker BuildKit secrets instead."
                    ),
                    file=filepath,
                    line=ln,
                    remediation="Use --secret flag with BuildKit: docker build --secret id=mysecret,src=/path/to/secret",
                    evidence=f"--build-arg {arg_name}=...",
                )

        # Docker push without signing
        if re.search(r'docker\s+push\b', run_content, re.IGNORECASE):
            # Check if cosign sign is nearby
            if not re.search(r'cosign\s+sign|notation\s+sign|docker\s+trust\s+sign', run_content, re.IGNORECASE):
                ln = self._find_line(lines, "docker push") or self._find_line(lines, "docker  push")
                self.add_finding(
                    attack_id="SCA-078",
                    title="Docker image pushed without signing",
                    severity="medium",
                    description=(
                        "A Docker image is pushed to a registry without signing. "
                        "Unsigned images cannot be verified for integrity by consumers. "
                        "An attacker with registry access could replace the image."
                    ),
                    file=filepath,
                    line=ln,
                    remediation="Sign images after push with cosign: cosign sign --key <key> <image>@<digest>",
                    evidence=run_content[:150],
                )

        # Insecure registry flag
        if re.search(r'--insecure-registry|--tls-verify=false|DOCKER_TLS_VERIFY=0', run_content):
            ln = self._find_line(lines, "insecure")
            self.add_finding(
                attack_id="SCA-079",
                title="Insecure Docker registry configuration",
                severity="high",
                description=(
                    "Docker is configured to use insecure (non-TLS) registry communication. "
                    "This enables man-in-the-middle attacks where an attacker can substitute "
                    "malicious images during pull or push operations."
                ),
                file=filepath,
                line=ln,
                remediation="Always use TLS for registry communication. Remove --insecure-registry flags.",
                evidence=run_content[:150],
            )

    def _check_dockerfile(self, filepath: str):
        """Scan a Dockerfile for supply chain security issues."""
        lines = read_file_lines(filepath)

        has_user_instruction = False
        has_healthcheck = False

        for i, line_text in enumerate(lines, 1):
            stripped = line_text.strip()

            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Check for unpinned FROM
            from_match = re.match(r'^FROM\s+(.+?)(\s+AS\s+.+)?$', stripped, re.IGNORECASE)
            if from_match:
                image_ref = from_match.group(1).strip()
                if image_ref.lower() != "scratch":
                    # Check if pinned to digest
                    if "@sha256:" not in image_ref:
                        if image_ref.endswith(":latest") or ":" not in image_ref:
                            self.add_finding(
                                attack_id="SCA-080",
                                title=f"Unpinned Dockerfile base image: {image_ref}",
                                severity="high",
                                description=(
                                    f"Base image '{image_ref}' is not pinned to a specific digest. "
                                    "Supply chain attackers can poison base images on public registries."
                                ),
                                file=filepath,
                                line=i,
                                remediation=f"Pin to digest: {image_ref}@sha256:<digest>",
                                evidence=stripped,
                            )

            # Check for USER instruction
            if re.match(r'^USER\s', stripped, re.IGNORECASE):
                has_user_instruction = True

            # Check for HEALTHCHECK
            if re.match(r'^HEALTHCHECK\s', stripped, re.IGNORECASE):
                has_healthcheck = True

            # Check for ADD from remote URLs (supply chain risk)
            add_match = re.match(r'^ADD\s+(https?://\S+)', stripped, re.IGNORECASE)
            if add_match:
                url = add_match.group(1)
                self.add_finding(
                    attack_id="SCA-081",
                    title=f"Remote URL in Dockerfile ADD instruction",
                    severity="high",
                    description=(
                        f"Dockerfile uses ADD to fetch remote content from '{url}'. "
                        "Remote URLs can be changed after Dockerfile creation, introducing "
                        "malicious content. Use COPY with pre-verified files instead."
                    ),
                    file=filepath,
                    line=i,
                    remediation="Use COPY with pre-downloaded and verified files. Verify checksums after download.",
                    evidence=stripped,
                )

            # Check for curl|sh patterns in RUN
            if re.match(r'^RUN\s', stripped, re.IGNORECASE):
                if re.search(r'curl.*\|\s*(bash|sh|python)', stripped):
                    self.add_finding(
                        attack_id="SCA-082",
                        title="Pipe-to-shell in Dockerfile RUN",
                        severity="critical",
                        description=(
                            "Dockerfile RUN instruction pipes downloaded content directly to a shell. "
                            "This is a primary supply chain attack vector — the remote script "
                            "can be changed at any time."
                        ),
                        file=filepath,
                        line=i,
                        remediation="Download scripts first, verify their checksum, then execute.",
                        evidence=stripped[:200],
                    )

        # Check if running as root (no USER instruction)
        if lines and not has_user_instruction:
            self.add_finding(
                attack_id="SCA-083",
                title="Dockerfile runs as root (no USER instruction)",
                severity="low",
                description=(
                    "The Dockerfile does not set a non-root USER. Running as root inside "
                    "a container increases the impact of container escape vulnerabilities."
                ),
                file=filepath,
                line=1,
                remediation="Add a USER instruction to run as a non-root user: USER 1001:1001",
            )

    def _find_line(self, lines: list, keyword: str) -> int:
        """Find the first line containing a keyword."""
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1
