#!/usr/bin/env python3
"""
Behavioral / Predictive Scanner
================================
Detects PATTERNS and BEHAVIORAL INDICATORS of supply chain compromise
rather than matching known signatures. This scanner is designed to catch
future, never-before-seen attacks by identifying the techniques and
anomalies that precede or accompany a supply chain compromise.

Detection Philosophy:
    Every supply chain attack in GitHub Actions follows a predictable
    lifecycle:  Infiltrate → Persist → Exfiltrate → Weaponise.
    This scanner targets the *behavioral invariants* of that lifecycle
    so that even a novel attack triggers detection.

Behavioral Categories:
    1. Obfuscation / Anti-Analysis      — base64 chains, hex encoding, eval()
    2. Dynamic Code Loading              — curl|sh, wget|python, fetch+exec
    3. Credential Harvesting Setup       — mass env dump, token enumeration
    4. Persistence Mechanisms            — cron injection, git hook injection
    5. Action Mutation Indicators        — tag force-push patterns, ghost commits
    6. Anomalous Control Flow            — conditional exfil, time-delayed payloads
    7. Trust Boundary Violations         — self-hosted runner abuse, container escape
    8. Build Artifact Tampering          — post-build injection, checksum bypass
    9. Shadow Dependency Injection       — install-script overrides, resolution hijack
   10. Steganographic / Covert Channels  — image/font payloads, unicode smuggling
"""

import os
import re
from typing import List, Dict, Any, Tuple

from scanners.base_scanner import BaseScanner
from utils.files import (
    find_workflow_files,
    find_action_files,
    read_file_lines,
    parse_yaml_safe,
    extract_run_blocks,
)


class BehavioralScanner(BaseScanner):
    """
    Predict and detect future supply chain compromises by identifying
    behavioral patterns common to all known and theoretical attacks.
    """

    scanner_name = "behavioral_analysis"

    # ── 1. Obfuscation / Anti-Analysis ──────────────────────────────
    OBFUSCATION_PATTERNS: List[Tuple[str, str, str, str]] = [
        # (regex, title, severity, description)
        (
            r"(base64\s+(--)?-?d(ecode)?|base64\s+-D)\s*.*\|\s*(ba)?sh",
            "Base64-decoded payload piped to shell",
            "critical",
            "A base64-encoded payload is decoded and immediately executed. "
            "This is the single most common technique in GitHub Actions compromises — "
            "it was the delivery mechanism in the tj-actions/changed-files, "
            "reviewdog, and Ultralytics incidents.",
        ),
        (
            r"echo\s+['\"]?[A-Za-z0-9+/=]{40,}['\"]?\s*\|\s*base64",
            "Long base64 literal decoded at runtime",
            "critical",
            "A long base64-encoded string is being decoded. This hides malicious "
            "content from static analysis and code review.",
        ),
        (
            r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}",
            "Hex-encoded byte sequence (8+ bytes)",
            "high",
            "A long sequence of hex-encoded bytes may be hiding a URL, command, "
            "or encryption key from casual inspection.",
        ),
        (
            r"eval\s*\(\s*(base64|atob|Buffer\.from|decode|decompress)",
            "eval() with encoded input",
            "critical",
            "Code is evaluating a decoded/decompressed payload at runtime. "
            "This pattern allows arbitrary code execution from obfuscated input.",
        ),
        (
            r"python[23]?\s+-c\s+['\"].*(__import__|exec|eval|compile).*['\"]",
            "Python one-liner with dynamic execution",
            "high",
            "An inline Python command uses dynamic code execution primitives. "
            "Attackers use python -c with exec/eval to run obfuscated payloads.",
        ),
        (
            r"node\s+-e\s+['\"].*eval\(.*\)['\"]",
            "Node.js one-liner with eval()",
            "high",
            "An inline Node.js command uses eval to execute dynamic code.",
        ),
        (
            r"printf\s+['\"]\\x[0-9a-fA-F]",
            "printf hex escape sequence",
            "medium",
            "Shell printf with hex escapes can reconstruct binary payloads or "
            "commands character by character to evade pattern matching.",
        ),
        (
            r"\$\(\s*echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+(--)?-?d(ecode)?",
            "Command substitution with base64 decode",
            "critical",
            "A command substitution decodes base64 to produce a value used "
            "inline. This hides URLs, tokens, or commands.",
        ),
        (
            r"(rev|xxd\s+-r|openssl\s+enc\s+-d)",
            "Data decoding / deobfuscation utility",
            "medium",
            "Usage of rev, xxd reverse, or openssl decrypt may indicate "
            "obfuscation of a payload to avoid detection.",
        ),
        (
            r"gzip\s+-d.*\|\s*(ba)?sh|zcat.*\|\s*(ba)?sh|gunzip.*\|\s*(ba)?sh",
            "Compressed payload executed via shell",
            "critical",
            "A compressed payload is decompressed and piped directly to a shell. "
            "This hides the payload from text-based scanning.",
        ),
    ]

    # ── 2. Dynamic Code Loading ─────────────────────────────────────
    DYNAMIC_LOADING_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"curl\s+[^|]*\|\s*(ba)?sh",
            "Remote script fetched and executed (curl|sh)",
            "critical",
            "A remote script is downloaded and piped directly to a shell. "
            "An attacker who compromises the hosting server can inject "
            "arbitrary code into every CI run.",
        ),
        (
            r"wget\s+[^|]*\|\s*(ba)?sh",
            "Remote script fetched and executed (wget|sh)",
            "critical",
            "Same as curl|sh, remote code execution from an unverified source.",
        ),
        (
            r"curl\s+.*-o\s+\S+.*&&\s*(chmod\s+\+x|bash|sh|python|node)\s",
            "Download-then-execute pattern",
            "critical",
            "A file is downloaded and then immediately executed. Without "
            "integrity verification, this is a code injection vector.",
        ),
        (
            r"wget\s+.*-O\s+\S+.*&&\s*(chmod\s+\+x|bash|sh|python|node)\s",
            "Download-then-execute pattern (wget)",
            "critical",
            "A file is downloaded and then immediately executed.",
        ),
        (
            r"(pip|pip3)\s+install\s+.*https?://",
            "pip install from URL",
            "high",
            "A Python package is installed directly from a URL. This bypasses "
            "registry integrity checks and SLSA provenance.",
        ),
        (
            r"npm\s+install\s+.*https?://",
            "npm install from URL",
            "high",
            "An npm package is installed directly from a URL, bypassing "
            "registry audit and provenance verification.",
        ),
        (
            r"gem\s+install\s+.*--source\s+https?://(?!rubygems\.org)",
            "gem install from non-official source",
            "high",
            "A Ruby gem is installed from a non-official source.",
        ),
        (
            r"go\s+install\s+.*@latest",
            "Go install @latest (unpinned)",
            "medium",
            "A Go tool is installed at @latest with no version pin. "
            "A maintainer takeover could inject malicious code.",
        ),
        (
            r"docker\s+run\s+.*--privileged",
            "Privileged Docker container execution",
            "high",
            "Running a Docker container in privileged mode during CI "
            "allows container escape and host compromise.",
        ),
        (
            r"(source|\.)\s+<\(\s*curl",
            "Process substitution with remote fetch",
            "critical",
            "Shell process substitution sources a remotely-fetched script, "
            "executing it in the current shell context.",
        ),
    ]

    # ── 3. Credential Harvesting Setup ──────────────────────────────
    CREDENTIAL_HARVEST_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"(env|printenv|set)\s*\|?\s*>",
            "Full environment dump to file",
            "critical",
            "The entire environment (including secrets) is being written to a file. "
            "This is the first step of credential exfiltration.",
        ),
        (
            r"(env|printenv|set)\s*\|\s*(sort|grep|base64|curl|wget|nc)",
            "Environment piped through processing",
            "critical",
            "The environment is piped through a data-processing or network tool. "
            "This is a strong indicator of credential exfiltration.",
        ),
        (
            r"cat\s+(/home/runner/)?\.env",
            "Reading .env file (may contain secrets)",
            "high",
            "A .env file is being read. These files often contain secrets "
            "and should not be accessible to arbitrary scripts.",
        ),
        (
            r"cat\s+\$GITHUB_ENV",
            "Reading GITHUB_ENV file directly",
            "high",
            "GITHUB_ENV is being read directly, potentially to harvest "
            "environment variables set by other steps.",
        ),
        (
            r"find\s+.*-name\s+['\"]?\*\.(pem|key|p12|pfx|jks|keystore)",
            "Searching for private key files",
            "high",
            "A search for private key files across the filesystem indicates "
            "post-exploitation credential harvesting.",
        ),
        (
            r"(cat|strings|xxd)\s+.*\.(pem|key|p12|pfx|crt|cert)",
            "Reading cryptographic material",
            "high",
            "Cryptographic key material is being read. If this data leaves "
            "the runner, it enables persistent impersonation.",
        ),
        (
            r"ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL",
            "Accessing GitHub Actions runtime token internals",
            "high",
            "The Actions runtime token or OIDC token request URL are being "
            "accessed. Compromised actions abuse these to escalate privileges.",
        ),
        (
            r"git\s+config\s+.*credential",
            "Git credential configuration manipulation",
            "medium",
            "Git credential settings are being modified, which could redirect "
            "authentication tokens to an attacker-controlled endpoint.",
        ),
    ]

    # ── 4. Persistence Mechanisms ───────────────────────────────────
    PERSISTENCE_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"crontab\s+(-l\s*;\s*echo|.*>>|.*\|)",
            "Cron job injection",
            "critical",
            "A cron job is being injected into the runner. Self-hosted "
            "runners that persist between jobs are vulnerable to this technique.",
        ),
        (
            r"\.git/hooks/(pre-commit|post-commit|pre-push|post-receive)",
            "Git hook injection",
            "critical",
            "A Git hook is being created or modified. Malicious hooks execute "
            "on every commit/push, creating persistent backdoors.",
        ),
        (
            r"(echo|cat|tee)\s+.*>>\s*~/(\.bashrc|\.bash_profile|\.profile|\.zshrc)",
            "Shell profile modification",
            "critical",
            "Shell startup files are being modified. On self-hosted runners, "
            "this persists arbitrary code across all future workflow runs.",
        ),
        (
            r"systemctl\s+(enable|start)\s",
            "Systemd service manipulation",
            "critical",
            "A systemd service is being enabled or started. This can "
            "install a persistent backdoor on self-hosted runners.",
        ),
        (
            r"(mkdir\s+-p|install\s+-d)\s+~?/\.config/autostart",
            "Desktop autostart entry creation",
            "high",
            "An autostart entry is being created, which will run on "
            "every login of self-hosted desktop runners.",
        ),
        (
            r"(ssh-keygen|authorized_keys)",
            "SSH key manipulation",
            "high",
            "SSH keys are being generated or authorized_keys modified. "
            "This can grant persistent remote access to self-hosted runners.",
        ),
    ]

    # ── 5. Anomalous Control Flow ───────────────────────────────────
    ANOMALOUS_FLOW_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"sleep\s+\d{3,}",
            "Long sleep delay (100+ seconds)",
            "medium",
            "A delay of 100+ seconds may be a time-bomb mechanism — "
            "the payload waits for logging to rotate or monitoring to stop.",
        ),
        (
            r"at\s+now\s*\+|nohup\s+.*&\s*$",
            "Deferred / background execution",
            "high",
            "A command is scheduled for deferred or background execution. "
            "This can survive step cancellation and evade detection.",
        ),
        (
            r"if\s+.*GITHUB_REF.*main.*then",
            "Branch-conditional execution",
            "medium",
            "Code executes only on specific branches. Attackers target "
            "main/release branches to maximize impact while avoiding "
            "detection during PR testing.",
        ),
        (
            r"trap\s+.*EXIT|trap\s+.*ERR",
            "Shell trap on EXIT/ERR",
            "medium",
            "A shell trap runs code on exit or error. Attackers use this "
            "to ensure exfiltration completes even if the step fails.",
        ),
        (
            r"\|\|\s*true\s*$|\|\|\s*:\s*$|2>/dev/null",
            "Error suppression",
            "low",
            "Errors are being suppressed, which can hide the side effects "
            "of malicious commands from log output.",
        ),
        (
            r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0)",
            "Shell history deletion",
            "high",
            "Shell history is being cleared. This is an anti-forensic "
            "technique to hide attacker commands.",
        ),
    ]

    # ── 6. Trust Boundary Violations ────────────────────────────────
    TRUST_BOUNDARY_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"runs-on:\s*self-hosted",
            "Self-hosted runner usage",
            "medium",
            "Self-hosted runners persist state between jobs. Without "
            "ephemeral configuration, compromises in one job affect all "
            "subsequent jobs on that runner.",
        ),
        (
            r"docker\s+.*--net=host|docker\s+.*--network\s+host",
            "Docker host network access",
            "high",
            "A container has host-level network access, allowing it to "
            "reach runner metadata endpoints and internal services.",
        ),
        (
            r"docker\s+.*-v\s+/:/",
            "Docker root filesystem mount",
            "critical",
            "The host root filesystem is mounted into a container. "
            "This grants complete access to the host system.",
        ),
        (
            r"(nsenter|chroot)\s+",
            "Container / namespace escape utility",
            "critical",
            "nsenter or chroot is being used, which can break out of "
            "container isolation to access the host system.",
        ),
        (
            r"mount\s+.*(/proc|/sys|/dev)",
            "Sensitive filesystem mount",
            "critical",
            "Sensitive kernel filesystems are being mounted. This can "
            "enable container escapes and privilege escalation.",
        ),
    ]

    # ── 7. Build Artifact Tampering ─────────────────────────────────
    ARTIFACT_TAMPERING_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"(sed|awk|perl)\s+.*-i.*\.(js|py|rb|sh|yml|yaml|json|toml)",
            "In-place file modification of code/config",
            "medium",
            "Source or configuration files are being modified in-place "
            "during the build. Post-checkout modifications can inject "
            "malicious code into build artifacts.",
        ),
        (
            r"(>>|>)\s+.*(dist|build|out|release)/",
            "Appending/writing to build output directory",
            "medium",
            "Data is being written to a build output directory after the "
            "build step. This could inject malicious payloads into "
            "distributable artifacts.",
        ),
        (
            r"npm\s+publish.*--tag|twine\s+upload|gem\s+push|cargo\s+publish",
            "Package publish command detected",
            "medium",
            "A package publish command is present. Combined with any "
            "upstream compromise, this becomes the weaponisation vector.",
        ),
        (
            r"sha256sum\s+.*>\s*/dev/null|md5sum\s+.*\|\s*true",
            "Checksum verification suppressed",
            "high",
            "Checksum verification output is discarded. This prevents "
            "detecting tampered artifacts.",
        ),
    ]

    # ── 8. Shadow Dependency Injection ──────────────────────────────
    SHADOW_DEPENDENCY_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"(pip|pip3)\s+install\s+.*--index-url\s+https?://(?!(pypi\.org|files\.pythonhosted\.org))",
            "pip install from non-PyPI index",
            "high",
            "Packages are being installed from a non-standard index. "
            "Dependency confusion attacks use private/internal package "
            "names with higher version numbers on rogue registries.",
        ),
        (
            r"npm\s+.*--registry\s+https?://(?!registry\.npmjs\.org)",
            "npm using non-default registry",
            "high",
            "npm is configured to use a non-standard registry. Verify "
            "this is an authorized internal registry.",
        ),
        (
            r"\.npmrc.*registry\s*=",
            ".npmrc registry override",
            "medium",
            "The npm registry is being overridden in .npmrc. An attacker "
            "can modify this to redirect package installations.",
        ),
        (
            r"(preinstall|postinstall|prepare)\s*[\"']?\s*:\s*[\"']",
            "Package lifecycle script",
            "medium",
            "npm/yarn lifecycle scripts (preinstall/postinstall) run "
            "arbitrary code during package installation. These are the "
            "most common vector for malicious npm packages.",
        ),
        (
            r"setup\.py.*cmdclass|setup\.cfg.*cmdclass",
            "Python setup.py custom command class",
            "medium",
            "A custom command class in setup.py can execute arbitrary "
            "code during pip install. This is a known malware vector.",
        ),
        (
            r"install_requires.*subprocess|import\s+subprocess.*setup\(",
            "subprocess in setup.py/setup.cfg",
            "critical",
            "subprocess is used in a Python package setup file. This "
            "executes system commands during installation.",
        ),
    ]

    # ── 9. Covert Channels & Steganography ──────────────────────────
    COVERT_CHANNEL_PATTERNS: List[Tuple[str, str, str, str]] = [
        (
            r"(steghide|stegano|openstego|zsteg)",
            "Steganography tool usage",
            "critical",
            "A steganography tool is being used. This can hide payloads "
            "inside image, audio, or font files.",
        ),
        (
            r"(curl|wget)\s+.*\.(png|jpg|gif|ico|woff|ttf|svg)\s*\|\s*(python|node|bash)",
            "Binary asset fetched and executed",
            "critical",
            "A media/font file is being downloaded and piped to an "
            "interpreter. This is a steganographic payload delivery.",
        ),
        (
            r"\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){4,}",
            "Unicode escape sequence chain",
            "medium",
            "A long chain of Unicode escape sequences may encode hidden "
            "commands using homoglyph or zero-width characters.",
        ),
        (
            r"(\xE2\x80[\x8B-\x8F]|\\u200[b-f]|\\u2060|\\ufeff)",
            "Zero-width / invisible Unicode characters",
            "high",
            "Zero-width or invisible Unicode characters detected. These "
            "can hide malicious code that is invisible in code review.",
        ),
    ]

    # ── 10. Workflow-Level Behavioral Anomalies ─────────────────────
    # These are checked against parsed YAML structure

    def scan(self) -> List[Dict[str, Any]]:
        self.findings = []

        workflow_files = find_workflow_files(self.config.workspace_dir)
        action_files = find_action_files(self.config.workspace_dir)

        # Scan workflow + action YAML files
        for filepath in workflow_files + action_files:
            if not self.should_scan_file(filepath):
                continue

            lines = read_file_lines(filepath)
            content = "".join(lines)

            # Text-based pattern checks (always run)
            self._scan_text_patterns(filepath, lines, content)

            # YAML-structure checks (require parsed YAML)
            workflow = parse_yaml_safe(filepath)
            if workflow:
                self._check_workflow_anomalies(filepath, workflow, lines)

        # In deep/paranoid mode, also scan scripts and source code
        if self.config.scan_mode in ("deep", "paranoid"):
            self._scan_repository_scripts()

        return self.findings

    def _scan_text_patterns(self, filepath: str, lines: List[str], content: str):
        """Run all text-based behavioral pattern checks."""
        all_pattern_groups = [
            ("SCA-BHV-OBF", self.OBFUSCATION_PATTERNS),
            ("SCA-BHV-DYN", self.DYNAMIC_LOADING_PATTERNS),
            ("SCA-BHV-CRED", self.CREDENTIAL_HARVEST_PATTERNS),
            ("SCA-BHV-PERS", self.PERSISTENCE_PATTERNS),
            ("SCA-BHV-FLOW", self.ANOMALOUS_FLOW_PATTERNS),
            ("SCA-BHV-TRUST", self.TRUST_BOUNDARY_PATTERNS),
            ("SCA-BHV-ART", self.ARTIFACT_TAMPERING_PATTERNS),
            ("SCA-BHV-DEP", self.SHADOW_DEPENDENCY_PATTERNS),
            ("SCA-BHV-COV", self.COVERT_CHANNEL_PATTERNS),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for attack_id_prefix, patterns in all_pattern_groups:
                for pattern_re, title, severity, description in patterns:
                    try:
                        if re.search(pattern_re, stripped, re.IGNORECASE):
                            self.add_finding(
                                attack_id=attack_id_prefix,
                                title=title,
                                severity=severity,
                                description=description,
                                file=filepath,
                                line=i,
                                remediation=self._remediation_for(attack_id_prefix),
                                evidence=stripped[:300],
                            )
                    except re.error:
                        continue

    def _check_workflow_anomalies(self, filepath: str, workflow: Dict, lines: List[str]):
        """Check parsed YAML for structural anomalies that indicate compromise."""

        # --- Excessive permissions ---
        perms = workflow.get("permissions", None)
        if isinstance(perms, str) and perms.strip() == "write-all":
            self.add_finding(
                attack_id="SCA-BHV-PERM",
                title="write-all permissions at workflow level",
                severity="high",
                description="The workflow requests write-all permissions. Legitimate "
                            "workflows almost never need every permission. This is the "
                            "first thing an attacker adds to maximise blast radius.",
                file=filepath,
                line=self._find_line(lines, "permissions"),
                remediation="Apply least-privilege: grant only the specific permissions "
                            "each job needs (e.g., contents: read, issues: write).",
            )

        # --- Jobs with no timeout-minutes ---
        jobs = workflow.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                if "timeout-minutes" not in job_data:
                    self.add_finding(
                        attack_id="SCA-BHV-FLOW",
                        title=f"No timeout-minutes on job '{job_name}'",
                        severity="low",
                        description="This job has no timeout. Cryptominers and "
                                    "long-running exfiltration scripts abuse "
                                    "unbounded job duration.",
                        file=filepath,
                        line=self._find_line(lines, job_name),
                        remediation="Add timeout-minutes to every job (e.g., timeout-minutes: 15).",
                    )

                # --- Multiple run blocks chained with && that include curl/wget ---
                steps = job_data.get("steps", [])
                for step in (steps or []):
                    if not isinstance(step, dict):
                        continue
                    run = step.get("run", "")
                    if not isinstance(run, str):
                        continue

                    # Count network + execution combos in single run block
                    network_ops = len(re.findall(
                        r"(curl|wget|python\s+-c.*http|node\s+-e.*http)", run, re.IGNORECASE
                    ))
                    exec_ops = len(re.findall(
                        r"(eval|exec|\|\s*(ba)?sh|chmod\s+\+x|source\s)", run, re.IGNORECASE
                    ))
                    if network_ops >= 1 and exec_ops >= 1:
                        self.add_finding(
                            attack_id="SCA-BHV-DYN",
                            title=f"Network fetch + code execution in job '{job_name}'",
                            severity="high",
                            description="A run block combines network fetching with "
                                        "code execution. This is the classic download-and-execute "
                                        "pattern used in supply chain attacks.",
                            file=filepath,
                            line=self._find_line(lines, run[:60]),
                            remediation="Pin downloads to checksums. Avoid piping "
                                        "network output directly to execution.",
                            evidence=run[:300],
                        )

                # --- Secrets passed to third-party action ---
                for step in (steps or []):
                    if not isinstance(step, dict):
                        continue
                    uses = str(step.get("uses", ""))
                    with_block = step.get("with", {})
                    env_block = step.get("env", {})

                    if uses and "/" in uses and not uses.startswith("actions/"):
                        # Third-party action
                        secret_refs = []
                        for block in [with_block, env_block]:
                            if isinstance(block, dict):
                                for k, v in block.items():
                                    if isinstance(v, str) and "GHA_EXPR:secrets." in v:
                                        secret_refs.append(k)
                        if secret_refs:
                            self.add_finding(
                                attack_id="SCA-BHV-CRED",
                                title=f"Secrets passed to third-party action: {uses}",
                                severity="medium",
                                description=f"Secrets ({', '.join(secret_refs)}) are passed to a "
                                            f"third-party action. If this action is compromised, "
                                            f"all these secrets are exposed.",
                                file=filepath,
                                line=self._find_line(lines, uses),
                                remediation="Audit the third-party action's source code. Pin to a "
                                            "full SHA. Minimise secrets passed to third-party actions.",
                                evidence=f"Action: {uses}, Secrets: {', '.join(secret_refs)}",
                            )

        # --- Environment variable injection vectors ---
        content = "\n".join(lines)
        if "GITHUB_ENV" in content or "GITHUB_OUTPUT" in content or "GITHUB_PATH" in content:
            # Check if writing to these files with unsanitised input
            env_write_patterns = [
                (r">>\s*\"?\$GITHUB_ENV\"?", "GITHUB_ENV"),
                (r">>\s*\"?\$GITHUB_OUTPUT\"?", "GITHUB_OUTPUT"),
                (r">>\s*\"?\$GITHUB_PATH\"?", "GITHUB_PATH"),
            ]
            for i, line in enumerate(lines, 1):
                for pattern, target in env_write_patterns:
                    if re.search(pattern, line):
                        # Check if there's variable interpolation in the same line
                        if re.search(r'\$\{?\w+\}?.*>>', line) or re.search(r'\$\(.*\).*>>', line):
                            self.add_finding(
                                attack_id="SCA-BHV-FLOW",
                                title=f"Unsanitised write to {target}",
                                severity="high",
                                description=f"A variable or command substitution writes to {target}. "
                                            f"If the value is influenced by untrusted input, an attacker "
                                            f"can inject arbitrary environment variables or PATH entries.",
                                file=filepath,
                                line=i,
                                remediation=f"Use heredoc delimiter syntax for multi-line values. "
                                            f"Sanitise all values before writing to {target}.",
                                evidence=line.strip()[:200],
                            )

    def _scan_repository_scripts(self):
        """In deep/paranoid mode, scan shell scripts, Python, JS files."""
        script_extensions = (".sh", ".bash", ".py", ".js", ".ts", ".rb", ".pl", ".ps1")

        for root, dirs, files in os.walk(self.config.workspace_dir):
            dirs[:] = [
                d for d in dirs
                if d not in (
                    ".git", "node_modules", "__pycache__", ".venv",
                    "vendor", ".tox", ".mypy_cache", ".pytest_cache",
                    "dist", "build", ".eggs",
                )
            ]

            for f in files:
                if not f.endswith(script_extensions):
                    continue
                filepath = os.path.join(root, f)
                if not self.should_scan_file(filepath):
                    continue

                lines = read_file_lines(filepath)
                content = "".join(lines)

                # Run the same pattern checks on scripts
                self._scan_text_patterns(filepath, lines, content)

    def _find_line(self, lines: List[str], search_text: str) -> int:
        """Find the line number containing search_text."""
        if not search_text:
            return 0
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return 0

    @staticmethod
    def _remediation_for(attack_id_prefix: str) -> str:
        """Return generic remediation guidance keyed by behavioral category."""
        remediations = {
            "SCA-BHV-OBF": (
                "Remove obfuscated code. All CI logic should be human-readable. "
                "If you must decode data, verify integrity with checksums first."
            ),
            "SCA-BHV-DYN": (
                "Never pipe downloaded content to a shell. Pin all downloads to "
                "checksums (sha256). Use official package managers instead of "
                "ad-hoc downloads."
            ),
            "SCA-BHV-CRED": (
                "Do not dump or enumerate environment variables. Use OIDC "
                "authentication instead of long-lived secrets. Restrict secret "
                "access to the minimum set of steps that need them."
            ),
            "SCA-BHV-PERS": (
                "Use ephemeral (GitHub-hosted) runners. If self-hosted runners are "
                "required, use ephemeral mode and rebuild after every job. Never "
                "persist state between workflow runs."
            ),
            "SCA-BHV-FLOW": (
                "Add timeout-minutes to all jobs. Avoid deferred execution and "
                "error suppression in CI. All commands should run synchronously "
                "with visible output."
            ),
            "SCA-BHV-TRUST": (
                "Apply least-privilege to containers. Never use --privileged or "
                "mount the host root filesystem. Use GitHub-hosted runners for "
                "untrusted workloads."
            ),
            "SCA-BHV-ART": (
                "Verify build artifact integrity with checksums. Separate build "
                "and publish steps into different jobs. Use SLSA provenance "
                "attestations for all published artifacts."
            ),
            "SCA-BHV-DEP": (
                "Use only official package registries. Pin all dependencies to "
                "exact versions with lockfiles. Enable dependency review and "
                "audit before installation."
            ),
            "SCA-BHV-COV": (
                "Do not download and execute binary assets. Verify all media "
                "files are genuine. Audit for zero-width characters in source."
            ),
            "SCA-BHV-PERM": (
                "Apply least-privilege permissions at the job level. Never use "
                "write-all. Grant specific permissions per job."
            ),
        }
        return remediations.get(attack_id_prefix, "Review and remediate the flagged pattern.")
