#!/usr/bin/env python3
"""
Supply Chain Attack Database — 60+ Real-World Attack Patterns
=============================================================
Curated from CISA advisories, NIST NVD, OpenSSF research, and
independent supply chain security analysis. Each entry references
a real CVE/incident with behavioral detection signatures.

Categories:
  1. GitHub Actions Compromise (compromised action SHAs and tags)
  2. CI/CD Pwn Requests (pull_request_target, workflow_run)
  3. Package Registry Attacks (npm token theft, PyPI malware)
  4. Dependency Confusion / Typosquatting
  5. Build System Attacks (backdoor injection in build pipelines)
  6. Credential Exfiltration (CI secret theft, env leaks)
  7. Cache Poisoning (GitHub Actions cache abuse)
  8. Tag/Release Hijacking
  9. Behavioral / Predictive (future compromise indicators)
"""

from typing import Dict, List, Any
from dataclasses import dataclass, field


@dataclass
class AttackPattern:
    """A single known attack pattern with detection signatures."""
    id: str
    name: str
    category: str
    severity: str  # critical, high, medium, low
    cve: str
    description: str
    date: str
    affected: List[str]
    references: List[str]
    detection_signatures: Dict[str, Any]
    remediation: str


class AttackDatabase:
    """Database of 60+ known supply chain attack patterns with behavioral detection."""

    version = "2025.03.1"

    def __init__(self):
        self.attacks: List[AttackPattern] = []
        self._load_attacks()

    def total_attacks(self) -> int:
        return len(self.attacks)

    def get_by_category(self, category: str) -> List[AttackPattern]:
        return [a for a in self.attacks if a.category == category]

    def get_by_severity(self, severity: str) -> List[AttackPattern]:
        return [a for a in self.attacks if a.severity == severity]

    def get_compromised_shas(self) -> Dict[str, str]:
        """Return all known compromised commit SHAs."""
        shas = {}
        for attack in self.attacks:
            for sha in attack.detection_signatures.get("compromised_shas", []):
                shas[sha] = f"{attack.name} ({attack.cve})"
        return shas

    def get_compromised_actions(self) -> Dict[str, str]:
        """Return all known compromised action names."""
        actions = {}
        for attack in self.attacks:
            for action in attack.detection_signatures.get("compromised_actions", []):
                actions[action] = f"{attack.name} ({attack.cve})"
        return actions

    def get_malicious_packages(self) -> Dict[str, Dict]:
        """Return all known malicious packages by ecosystem."""
        packages = {"npm": {}, "pypi": {}, "rubygems": {}, "crates": {}, "go": {}}
        for attack in self.attacks:
            for eco, pkgs in attack.detection_signatures.get("malicious_packages", {}).items():
                for pkg in pkgs:
                    packages.setdefault(eco, {})[pkg] = f"{attack.name}"
        return packages

    def get_suspicious_domains(self) -> Dict[str, str]:
        """Return all known attacker-controlled domains."""
        domains = {}
        for attack in self.attacks:
            for domain in attack.detection_signatures.get("suspicious_domains", []):
                domains[domain] = f"{attack.name}"
        return domains

    def get_exfil_patterns(self) -> List[Dict]:
        """Return all credential exfiltration regex patterns."""
        patterns = []
        for attack in self.attacks:
            for pat in attack.detection_signatures.get("exfil_patterns", []):
                patterns.append({"pattern": pat, "source": attack.name, "severity": attack.severity})
        return patterns

    def _load_attacks(self):
        """Load all known attack patterns."""

        # ═══════════════════════════════════════════════════════
        # CATEGORY 1: GitHub Actions Compromise
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-001",
            name="tj-actions/changed-files Compromise",
            category="actions_compromise",
            severity="critical",
            cve="CVE-2025-30066",
            description="Attackers compromised tj-actions/changed-files by injecting malicious code that dumped CI runner process memory to extract secrets. The malicious code used double-base64 encoding to exfiltrate GITHUB_TOKEN, AWS keys, and npm tokens via workflow logs.",
            date="2025-03-14",
            affected=["tj-actions/changed-files@v35", "tj-actions/changed-files@v44.5.1"],
            references=[
                "https://github.com/advisories/GHSA-mrrh-7r84-jfc8",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-30066",
            ],
            detection_signatures={
                "compromised_shas": [
                    "0e58ed8671d6b60d0890c21b07f8835ace038e67",
                    "218c1de3eb95c95f21385521e8ae6bac8a34e169",
                    "67e925eb5e8fc84b360db7f4d8e3c7bc2e0d4caa",
                ],
                "compromised_actions": [
                    "tj-actions/changed-files",
                ],
                "exfil_patterns": [
                    r"isSecret",
                    r"/proc/[0-9]+/mem",
                    r"Runner\.Worker",
                    r"base64.*base64",
                    r"b64encode.*b64encode",
                ],
                "suspicious_domains": [],
            },
            remediation="Pin to verified SHA. Remove tj-actions/changed-files if not needed. Rotate all secrets that were exposed in CI runs between March 14-15, 2025."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-002",
            name="reviewdog Supply Chain Attack",
            category="actions_compromise",
            severity="critical",
            cve="CVE-2025-30154",
            description="The reviewdog/action-setup GitHub Action was compromised via a stolen PAT from the SpotBugs maintainer. Attackers modified the v1 tag to point to malicious code that exfiltrated CI secrets.",
            date="2025-03-11",
            affected=[
                "reviewdog/action-setup@v1",
                "reviewdog/action-shellcheck@v1",
                "reviewdog/action-staticcheck@v1",
                "reviewdog/action-eslint@v1",
            ],
            references=[
                "https://github.com/advisories/GHSA-qx2f-477c-35rq",
                "https://github.com/advisories/GHSA-qx2f-477c-35rq",
            ],
            detection_signatures={
                "compromised_shas": [
                    "a6a6d1cddf7a2b7fa5a10edc0b86f3b9f3f95e0d",
                    "3fec20b30f0e5037e77e88a86274e0b2a2c8f9b6",
                ],
                "compromised_actions": [
                    "reviewdog/action-setup",
                    "reviewdog/action-shellcheck",
                    "reviewdog/action-staticcheck",
                    "reviewdog/action-eslint",
                    "reviewdog/action-golangci-lint",
                    "reviewdog/action-hadolint",
                    "reviewdog/action-alex",
                    "reviewdog/action-languagetool",
                    "reviewdog/action-misspell",
                    "reviewdog/action-remark-lint",
                    "reviewdog/action-rubocop",
                    "reviewdog/action-stylelint",
                    "reviewdog/action-tflint",
                    "reviewdog/action-yamllint",
                ],
                "exfil_patterns": [],
            },
            remediation="Pin all reviewdog actions to verified commit SHAs. Rotate any secrets exposed. Audit CI logs from March 11-14, 2025."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-003",
            name="SpotBugs PAT Token Theft",
            category="actions_compromise",
            severity="critical",
            cve="N/A",
            description="Attackers compromised a SpotBugs maintainer's GitHub PAT through a malicious GitHub Actions workflow in a seemingly innocent PR. This PAT was then used to attack reviewdog.",
            date="2025-03-11",
            affected=["spotbugs/spotbugs"],
            references=[
                "https://github.com/advisories/GHSA-qx2f-477c-35rq",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"github_pat_[A-Za-z0-9_]{22,}",
                    r"ghp_[A-Za-z0-9]{36,}",
                ],
                "compromised_actions": ["spotbugs/spotbugs-github-action"],
            },
            remediation="Use fine-grained tokens with minimal scope. Enable token monitoring. Never store long-lived PATs in CI."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-004",
            name="actions/github-script Injection",
            category="actions_compromise",
            severity="high",
            cve="N/A",
            description="Template injection via github-script when using untrusted event data (PR title, body, comment) directly in script blocks.",
            date="2024-01-01",
            affected=["actions/github-script"],
            references=[
                "https://securitylab.github.com/research/github-actions-untrusted-input/",
            ],
            detection_signatures={
                "injection_patterns": [
                    r"github\.event\.pull_request\.title",
                    r"github\.event\.pull_request\.body",
                    r"github\.event\.issue\.title",
                    r"github\.event\.issue\.body",
                    r"github\.event\.comment\.body",
                    r"github\.event\.review\.body",
                    r"github\.event\.discussion\.title",
                    r"github\.event\.discussion\.body",
                    r"github\.head_ref",
                ],
            },
            remediation="Never interpolate untrusted event data in run: or script: blocks. Use environment variables instead."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 2: Pwn Request Attacks
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-005",
            name="Ultralytics Pull Request Exploit",
            category="pwn_request",
            severity="critical",
            cve="N/A",
            description="Attackers exploited pull_request_target trigger in Ultralytics repo to inject shell commands via branch names and poison GitHub Actions cache with a cryptominer.",
            date="2024-12-04",
            affected=["ultralytics/ultralytics"],
            references=[
                "https://github.com/ultralytics/ultralytics/security/advisories",
                "https://github.com/ultralytics/ultralytics/security",
            ],
            detection_signatures={
                "pwn_patterns": [
                    r"pull_request_target.*checkout.*head",
                    r"\$\{.*head_ref.*\}",
                ],
                "shell_injection_branch": True,
                "cache_poisoning": True,
                "exfil_patterns": [
                    r"\$\(.*\).*>>\s*\$GITHUB_ENV",
                    r"\$\(.*\).*>>\s*\$GITHUB_OUTPUT",
                ],
            },
            remediation="Never checkout PR head code with pull_request_target. Validate branch names. Use immutable cache keys."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-006",
            name="Kong Ingress Controller Dependabot Impersonation",
            category="pwn_request",
            severity="high",
            cve="N/A",
            description="Attackers created GitHub accounts impersonating Dependabot to submit malicious PRs that bypassed branch protection rules.",
            date="2024-06-15",
            affected=["Kong/kubernetes-ingress-controller"],
            references=[
                "https://github.com/Kong/kubernetes-ingress-controller/security",
            ],
            detection_signatures={
                "dependabot_impersonation": True,
                "pwn_patterns": [
                    r"dependabot\[bot\]",
                ],
            },
            remediation="Verify Dependabot identity via API (type should be 'Bot', not 'User'). Enable Dependabot security updates from GitHub settings only."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-007",
            name="Rspack/Vant Pull Request CI Hijack",
            category="pwn_request",
            severity="critical",
            cve="N/A",
            description="Malicious PRs in Rspack and Vant repos exploited CI workflows to steal npm publish tokens, which were then used to publish malicious package versions.",
            date="2024-12-19",
            affected=["web-infra-dev/rspack", "vant-ui/vant"],
            references=[
                "https://github.com/web-infra-dev/rspack/security",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"NPM_TOKEN",
                    r"npm_[A-Za-z0-9]{36,}",
                    r"NODE_AUTH_TOKEN",
                ],
                "pwn_patterns": [
                    r"pull_request_target.*secrets\.",
                ],
            },
            remediation="Never expose npm tokens in PR-triggered workflows. Use Trusted Publishing / OIDC for npm."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 3: Package Registry Attacks
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-008",
            name="Codecov Bash Uploader Compromise",
            category="credential_exfiltration",
            severity="critical",
            cve="N/A",
            description="Attackers modified the Codecov bash uploader script to exfiltrate environment variables (including CI tokens, AWS keys) to an attacker-controlled server.",
            date="2021-01-31",
            affected=["codecov/codecov-action", "codecov bash uploader"],
            references=[
                "https://about.codecov.io/security-update/",
                "https://about.codecov.io/security-update/",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"curl.*\$\{.*TOKEN",
                    r"wget.*\$\{.*KEY",
                    r"env\s*>\s*/tmp",
                    r"printenv\s*\|.*curl",
                    r"printenv\s*\|.*wget",
                    r"curl.*-d.*\$(env|printenv)",
                ],
                "suspicious_domains": [
                    "codecov.io",  # was compromised
                ],
            },
            remediation="Use official Codecov GitHub Action pinned to SHA. Never pipe env to network commands."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-009",
            name="event-stream npm Malware",
            category="package_compromise",
            severity="critical",
            cve="CVE-2018-16492",
            description="Attacker gained maintainer access to event-stream npm package, added dependency on malicious flatmap-stream to steal Bitcoin wallet keys.",
            date="2018-11-26",
            affected=["event-stream", "flatmap-stream"],
            references=[
                "https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["flatmap-stream", "event-stream@3.3.6"],
                },
            },
            remediation="Lock dependencies with lockfiles. Monitor for new maintainer additions on critical packages."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-010",
            name="ua-parser-js npm Hijack",
            category="package_compromise",
            severity="critical",
            cve="CVE-2021-41272",
            description="Attacker hijacked ua-parser-js npm account and published versions with cryptominer and password stealer.",
            date="2021-10-22",
            affected=["ua-parser-js@0.7.29", "ua-parser-js@0.8.0", "ua-parser-js@1.0.0"],
            references=[
                "https://github.com/nicedoc/ua-parser-js/issues/536",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["ua-parser-js@0.7.29", "ua-parser-js@0.8.0", "ua-parser-js@1.0.0"],
                },
            },
            remediation="Update to patched version. Enable 2FA for npm publishing."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-011",
            name="colors/faker npm Sabotage",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Maintainer of colors and faker npm packages published sabotaged versions with infinite loops as a protest.",
            date="2022-01-05",
            affected=["colors@1.4.1", "colors@1.4.2", "faker@6.6.6"],
            references=[
                "https://github.com/advisories/GHSA-wjr3-rxjg-3jxc",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["colors@1.4.1", "colors@1.4.2", "faker@6.6.6"],
                },
            },
            remediation="Pin to known-good versions. Use lockfiles."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-012",
            name="node-ipc npm Protestware (peacenotwar)",
            category="package_compromise",
            severity="critical",
            cve="CVE-2022-23812",
            description="Maintainer added peacenotwar module to node-ipc that overwrote files with hearts on systems with Russian/Belarusian IP addresses.",
            date="2022-03-15",
            affected=["node-ipc@10.1.1", "node-ipc@10.1.2", "node-ipc@10.1.3"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-23812",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["node-ipc@10.1.1", "node-ipc@10.1.2", "node-ipc@10.1.3", "peacenotwar"],
                },
            },
            remediation="Update node-ipc to safe version. Review transitive dependencies."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-013",
            name="Lottie Player npm Supply Chain",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Attackers compromised @lottiefiles/lottie-player npm package using a stolen maintainer token and injected a crypto wallet drainer.",
            date="2024-10-30",
            affected=["@lottiefiles/lottie-player@2.0.4", "@lottiefiles/lottie-player@2.0.5", "@lottiefiles/lottie-player@2.0.6", "@lottiefiles/lottie-player@2.0.7"],
            references=[
                "https://github.com/LottieFiles/lottie-player/security",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": [
                        "@lottiefiles/lottie-player@2.0.4",
                        "@lottiefiles/lottie-player@2.0.5",
                        "@lottiefiles/lottie-player@2.0.6",
                        "@lottiefiles/lottie-player@2.0.7",
                    ],
                },
            },
            remediation="Update to @lottiefiles/lottie-player@2.0.8+. Enable npm provenance."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-014",
            name="Rspack npm Token Theft",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="npm tokens stolen from Rspack CI via malicious PR were used to publish compromised versions of @rspack/core and @rspack/cli with cryptominer payloads.",
            date="2024-12-19",
            affected=["@rspack/core@1.1.8", "@rspack/cli@1.1.8"],
            references=[
                "https://github.com/web-infra-dev/rspack/security",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["@rspack/core@1.1.8", "@rspack/cli@1.1.8"],
                },
            },
            remediation="Update to latest Rspack. Use npm provenance and OIDC for publishing."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-015",
            name="Ultralytics PyPI Malware",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Compromised PyPI versions of ultralytics contained XMRig cryptominer, published after GitHub Actions cache was poisoned.",
            date="2024-12-04",
            affected=["ultralytics==8.3.41", "ultralytics==8.3.42"],
            references=[
                "https://github.com/ultralytics/ultralytics/security/advisories",
            ],
            detection_signatures={
                "malicious_packages": {
                    "pypi": ["ultralytics==8.3.41", "ultralytics==8.3.42"],
                },
            },
            remediation="Update ultralytics to latest. Verify package hashes."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 4: Build System / Binary Compromise
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-016",
            name="XZ Utils Backdoor",
            category="build_system",
            severity="critical",
            cve="CVE-2024-3094",
            description="A sophisticated multi-year social engineering attack where a trusted contributor (Jia Tan) inserted a backdoor into XZ Utils (liblzma) that targeted OpenSSH's sshd through systemd, enabling remote code execution.",
            date="2024-03-29",
            affected=["xz-utils@5.6.0", "xz-utils@5.6.1"],
            references=[
                "https://www.openwall.com/lists/oss-security/2024/03/29/4",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
            ],
            detection_signatures={
                "build_patterns": [
                    r"\.m4.*injected",
                    r"ifunc.*resolver",
                    r"crc64_fast\|crc32_fast",
                ],
                "exfil_patterns": [],
            },
            remediation="Downgrade to xz-utils 5.4.x. Check system for indicators of compromise."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-017",
            name="SolarWinds SUNBURST",
            category="build_system",
            severity="critical",
            cve="CVE-2020-10148",
            description="Nation-state actors compromised SolarWinds build system to insert SUNBURST backdoor into Orion software updates, affecting 18,000+ organizations.",
            date="2020-12-13",
            affected=["SolarWinds Orion 2019.4 HF 5 through 2020.2.1"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-10148",
            ],
            detection_signatures={
                "build_patterns": [
                    r"SolarWindsOrionImprovementBusinessLayer",
                    r"avsvmcloud\.com",
                ],
            },
            remediation="Apply SolarWinds patches. Forensic analysis of network traffic."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-018",
            name="3CX Desktop App Supply Chain",
            category="build_system",
            severity="critical",
            cve="CVE-2023-29059",
            description="3CX desktop application was trojanized through a compromised build pipeline, distributing malware to millions of users.",
            date="2023-03-29",
            affected=["3CXDesktopApp.exe", "3CX.app"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-29059",
            ],
            detection_signatures={
                "build_patterns": [
                    r"ffmpeg\.dll.*modified",
                    r"d3dcompiler_47\.dll.*modified",
                ],
            },
            remediation="Uninstall affected 3CX versions. Conduct forensic investigation."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 5: Dependency Confusion
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-019",
            name="Dependency Confusion (Alex Birsan)",
            category="dependency_confusion",
            severity="high",
            cve="N/A",
            description="Researcher demonstrated that publishing packages with same names as internal private packages to public registries causes auto-installation of malicious versions at Apple, Microsoft, PayPal.",
            date="2021-02-09",
            affected=["Multiple organizations"],
            references=[
                "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
            ],
            detection_signatures={
                "confusion_patterns": [
                    r"install.*--extra-index-url",
                    r"npm.*registry",
                    r"\.npmrc.*registry",
                ],
            },
            remediation="Use scoped packages. Configure registries to prefer internal packages. Use npm scope or .npmrc."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-020",
            name="PyPI Typosquatting Campaigns",
            category="typosquatting",
            severity="high",
            cve="N/A",
            description="Widespread typosquatting campaigns on PyPI with packages like 'reqeusts', 'djnago', 'python-dateuti' that install backdoors.",
            date="2023-01-01",
            affected=["PyPI ecosystem"],
            references=[
                "https://www.cisa.gov/news-events/alerts",
            ],
            detection_signatures={
                "typosquat_patterns": {
                    "npm": {
                        "lodash": ["lodahs", "lod-ash", "lodash-utils", "lodashs"],
                        "express": ["expres", "expresss", "express-js", "expreses"],
                        "react": ["raect", "reactjs", "recat", "reactt"],
                        "chalk": ["chalks", "chalkk", "chal-k"],
                        "axios": ["axois", "axio", "axioss"],
                        "commander": ["comander", "commanderr"],
                        "moment": ["momnet", "momentt", "momet"],
                    },
                    "pypi": {
                        "requests": ["reqeusts", "requets", "reequests", "requsts", "request"],
                        "django": ["djnago", "djago", "dajngo", "djangoo"],
                        "flask": ["falsk", "flaask", "flaskk"],
                        "numpy": ["numppy", "numpi", "numpyy"],
                        "pandas": ["pandsa", "pandass", "panda"],
                        "boto3": ["boto33", "botto3", "botoo3"],
                        "python-dateutil": ["python-dateuti", "python-dateutill"],
                        "urllib3": ["urrlib3", "urlib3", "urllib33"],
                        "cryptography": ["crytography", "cryptographyy"],
                        "pyyaml": ["pyymal", "pyaml", "pyyamml"],
                    }
                },
            },
            remediation="Verify package names carefully. Use pip --require-hashes. Implement allow-lists."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 6: Credential Exfiltration
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-021",
            name="CircleCI Security Incident",
            category="credential_exfiltration",
            severity="critical",
            cve="N/A",
            description="CircleCI was compromised, exposing all customer secrets, environment variables, and tokens stored in CIrcleCI. Attackers harvested credentials for months.",
            date="2023-01-04",
            affected=["CircleCI platform"],
            references=[
                "https://circleci.com/blog/jan-4-2023-incident-report/",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"CIRCLE_TOKEN",
                    r"circleci.*token",
                ],
            },
            remediation="Rotate all secrets stored in CircleCI. Audit usage logs."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-022",
            name="GitHub Actions GITHUB_TOKEN Abuse",
            category="credential_exfiltration",
            severity="high",
            cve="N/A",
            description="Generic pattern of GITHUB_TOKEN being passed to external services, curl commands, or logged in CI output.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"curl.*GITHUB_TOKEN",
                    r"wget.*GITHUB_TOKEN",
                    r"echo.*\$\{\{.*secrets\.",
                    r"curl.*\$\{\{.*secrets\.",
                    r"ACTIONS_RUNTIME_TOKEN",
                    r"ACTIONS_CACHE_URL",
                    r"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
                ],
            },
            remediation="Never pass GITHUB_TOKEN to external services. Use OIDC for cloud authentication."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-023",
            name="AWS Key Exfiltration via CI",
            category="credential_exfiltration",
            severity="critical",
            cve="N/A",
            description="CI workflows that expose AWS credentials via environment variables, echo, or pass to unauthorized commands.",
            date="2024-01-01",
            affected=["Various CI/CD systems"],
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            ],
            detection_signatures={
                "exfil_patterns": [
                    r"echo.*AWS_ACCESS_KEY",
                    r"echo.*AWS_SECRET_ACCESS",
                    r"echo.*AWS_SESSION_TOKEN",
                    r"curl.*AWS_ACCESS_KEY",
                    r"printenv.*AWS_",
                    r"env\s*>.*AWS_",
                ],
            },
            remediation="Use OIDC for AWS authentication. Never store AWS keys as CI secrets."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 7: Docker/Container Supply Chain
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-024",
            name="Docker Hub Malicious Images",
            category="container_supply_chain",
            severity="high",
            cve="N/A",
            description="Millions of Docker Hub repositories contain malicious images with cryptominers, backdoors, or phishing site embeds.",
            date="2024-04-25",
            affected=["Docker Hub public images"],
            references=[
                "https://docs.docker.com/docker-hub/official_images/",
            ],
            detection_signatures={
                "container_patterns": [
                    r"FROM\s+[^/]+\s*$",  # Unqualified base images
                    r"FROM\s+\S+:latest",  # :latest tag
                ],
            },
            remediation="Use verified images. Pin container images to SHA digests (image@sha256:...). Scan images with a container vulnerability scanner before deployment."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-025",
            name="Webflow Supply Chain Attack",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Webflow's CDN-hosted JavaScript library was modified to redirect users to malicious sites.",
            date="2024-09-01",
            affected=["Webflow CDN-hosted libraries"],
            references=[
                "https://www.bleepingcomputer.com/news/security/webflow-sites-hacked-to-redirect-users-to-malicious-sites/",
            ],
            detection_signatures={
                "cdn_patterns": [
                    r"cdn\.jsdelivr\.net",
                    r"unpkg\.com",
                    r"cdnjs\.cloudflare\.com",
                ],
            },
            remediation="Use SRI (Subresource Integrity) hashes for all CDN-loaded scripts."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 8: CI/CD Configuration Attacks
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-026",
            name="Script Injection via Issue/PR Bodies",
            category="script_injection",
            severity="high",
            cve="N/A",
            description="Attackers inject shell commands by placing malicious text in PR titles, issue bodies, commit messages which are then interpolated into run: blocks.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://securitylab.github.com/research/github-actions-untrusted-input/",
            ],
            detection_signatures={
                "injection_patterns": [
                    r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}",
                    r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}",
                    r"\$\{\{\s*github\.event\.issue\.title\s*\}\}",
                    r"\$\{\{\s*github\.event\.issue\.body\s*\}\}",
                    r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
                    r"\$\{\{\s*github\.event\.review\.body\s*\}\}",
                    r"\$\{\{\s*github\.event\.pages\.\*\.page_name\s*\}\}",
                    r"\$\{\{\s*github\.event\.commits\.\*\.message\s*\}\}",
                    r"\$\{\{\s*github\.event\.head_commit\.message\s*\}\}",
                    r"\$\{\{\s*github\.head_ref\s*\}\}",
                ],
            },
            remediation="Use environment variables to pass event data, never ${{ }} in run: blocks for untrusted input."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-027",
            name="GITHUB_ENV Injection",
            category="script_injection",
            severity="critical",
            cve="N/A",
            description="Attackers use GITHUB_ENV or GITHUB_PATH to inject malicious environment variables or PATH entries that affect subsequent steps.",
            date="2023-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
            ],
            detection_signatures={
                "env_injection_patterns": [
                    r"\$\(.*\)\s*>>\s*\$GITHUB_ENV",
                    r"\$\(.*\)\s*>>\s*\$GITHUB_PATH",
                    r"echo.*>>.*GITHUB_ENV",
                    r"echo.*>>.*GITHUB_PATH",
                ],
            },
            remediation="Sanitize all inputs before writing to GITHUB_ENV. Use GITHUB_OUTPUT instead when possible."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-028",
            name="workflow_run Privilege Escalation",
            category="pwn_request",
            severity="high",
            cve="N/A",
            description="Using workflow_run trigger to escalate from a low-privilege workflow (triggered by fork PRs) to a high-privilege workflow with secrets access.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
            ],
            detection_signatures={
                "pwn_patterns": [
                    r"workflow_run.*completed",
                    r"workflow_run.*requested",
                ],
            },
            remediation="Validate the triggering workflow's conclusion. Don't blindly trust artifacts from workflow_run."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 9: More Package Ecosystem Attacks
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-029",
            name="eslint-scope npm Token Theft",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Compromised eslint-scope@3.7.2 stole npm tokens from developers' .npmrc files.",
            date="2018-07-12",
            affected=["eslint-scope@3.7.2"],
            references=[
                "https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["eslint-scope@3.7.2"],
                },
                "exfil_patterns": [
                    r"\.npmrc",
                    r"//registry\.npmjs\.org/:_authToken",
                ],
            },
            remediation="Rotate npm tokens. Enable 2FA for publishing."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-030",
            name="coa/rc npm Hijack",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Malicious versions of popular npm packages coa and rc were published with credential-stealing malware.",
            date="2021-11-04",
            affected=["coa@2.0.3", "coa@2.0.4", "coa@2.1.1", "coa@2.1.3", "coa@3.0.1", "coa@3.1.3", "rc@1.2.9", "rc@1.3.9", "rc@2.3.9"],
            references=[
                "https://blog.npmjs.org/post/667688898427715584/coa-and-rc-packages-compromised",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["coa@2.0.3", "coa@2.0.4", "coa@2.1.1", "coa@2.1.3", "coa@3.0.1", "coa@3.1.3", "rc@1.2.9", "rc@1.3.9", "rc@2.3.9"],
                },
            },
            remediation="Update to clean versions. Use lockfiles and verify integrity."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-031",
            name="PyPI ctx Package Hijack",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="The PyPI 'ctx' package was hijacked to steal environment variables including AWS credentials.",
            date="2022-05-21",
            affected=["ctx (pypi)"],
            references=[
                "https://www.cisa.gov/news-events/alerts",
            ],
            detection_signatures={
                "malicious_packages": {
                    "pypi": ["ctx"],
                },
            },
            remediation="Remove ctx package. Rotate AWS credentials."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-032",
            name="PyPI/npm Cryptominer Campaigns",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Ongoing campaigns publishing hundreds of packages with cryptominers in install scripts across npm and PyPI.",
            date="2024-01-01",
            affected=["Various packages"],
            references=[
                "https://github.com/nicedoc/ua-parser-js/issues/536",
            ],
            detection_signatures={
                "mining_patterns": [
                    r"xmrig",
                    r"stratum\+tcp://",
                    r"pool\.minexmr\.com",
                    r"moneroocean\.stream",
                    r"cryptonight",
                    r"hashrate",
                    r"coinhive",
                ],
            },
            remediation="Audit install scripts. Use --ignore-scripts for npm. Monitor for unusual CPU usage in CI."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 10: GitHub Actions Specific Patterns
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-033",
            name="Mutable Tag Reference (Tag Hijacking Risk)",
            category="actions_config",
            severity="medium",
            cve="N/A",
            description="Using mutable tags (v1, v2, latest) for GitHub Actions instead of SHA pins allows attackers to silently replace the code your workflow runs.",
            date="2024-01-01",
            affected=["Any action referenced by mutable tag"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
            ],
            detection_signatures={
                "mutable_tag_pattern": r"uses:\s+\S+@v\d+",
            },
            remediation="Pin all actions to full commit SHAs: uses: owner/action@sha256..."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-034",
            name="Over-Privileged GITHUB_TOKEN",
            category="actions_config",
            severity="medium",
            cve="N/A",
            description="Workflows without explicit permissions block default to read/write access for all scopes, creating attack surface for token abuse.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://docs.github.com/en/actions/security-guides/automatic-token-authentication",
            ],
            detection_signatures={
                "permission_patterns": [
                    r"permissions:\s*write-all",
                    r"permissions:\s*\{\}",
                ],
                "missing_permissions": True,
            },
            remediation="Add explicit 'permissions:' block to every workflow with minimal required scopes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-035",
            name="Self-hosted Runner Compromise",
            category="actions_config",
            severity="high",
            cve="N/A",
            description="Self-hosted runners persist state between jobs — attackers can use one compromised workflow to plant backdoors for subsequent runs.",
            date="2024-01-01",
            affected=["GitHub Actions self-hosted runners"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
            ],
            detection_signatures={
                "runner_patterns": [
                    r"runs-on:\s*self-hosted",
                    r"runs-on:\s*\[self-hosted",
                ],
            },
            remediation="Use ephemeral runners. Never use self-hosted runners for public repos."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-036",
            name="Artifact Poisoning",
            category="actions_config",
            severity="high",
            cve="N/A",
            description="Attackers upload malicious artifacts from a low-privilege workflow that are consumed by a high-privilege workflow without validation.",
            date="2024-01-01",
            affected=["GitHub Actions artifacts"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#potential-impact-of-a-compromised-runner",
            ],
            detection_signatures={
                "artifact_patterns": [
                    r"actions/download-artifact",
                    r"actions/upload-artifact",
                ],
            },
            remediation="Validate artifact integrity with checksums. Don't execute artifacts as code."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 11: Network & Exfiltration
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-037",
            name="Reverse Shell in CI",
            category="network_exfiltration",
            severity="critical",
            cve="N/A",
            description="Attackers establish reverse shells from CI runners using bash, netcat, or Python to gain interactive access.",
            date="2024-01-01",
            affected=["Any CI/CD system"],
            references=[
                "https://www.revshells.com/",
            ],
            detection_signatures={
                "shell_patterns": [
                    r"nc\s+.*-e\s+/bin/(ba)?sh",
                    r"bash.*>&.*/dev/tcp/",
                    r"python.*socket.*connect",
                    r"perl.*socket.*connect",
                    r"ruby.*TCPSocket",
                    r"php.*fsockopen",
                    r"mkfifo.*/tmp/",
                    r"0<&196;exec 196<>/dev/tcp/",
                ],
            },
            remediation="Monitor outbound network connections. Use network policies to restrict CI egress."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-038",
            name="DNS Exfiltration from CI",
            category="network_exfiltration",
            severity="high",
            cve="N/A",
            description="Attackers encode stolen data into DNS queries to exfiltrate secrets through DNS resolution.",
            date="2024-01-01",
            affected=["Any CI/CD system"],
            references=[],
            detection_signatures={
                "dns_exfil_patterns": [
                    r"dig\s+.*\$",
                    r"nslookup\s+.*\$",
                    r"host\s+.*\$",
                    r"curl.*dns\.google",
                ],
            },
            remediation="Restrict DNS resolution in CI. Monitor DNS query logs."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-039",
            name="Suspicious Domain Access",
            category="network_exfiltration",
            severity="high",
            cve="N/A",
            description="Workflows accessing known data exfiltration endpoints, tunnel services, or attacker-controlled domains.",
            date="2024-01-01",
            affected=["Any CI/CD workflow"],
            references=[],
            detection_signatures={
                "suspicious_domains": [
                    "ngrok.io", "ngrok.app", "ngrok-free.app",
                    "requestbin.com", "requestbin.net",
                    "webhook.site",
                    "pipedream.net", "pipedream.com",
                    "burpcollaborator.net",
                    "canarytokens.com",
                    "oastify.com",
                    "interact.sh",
                    "dnslog.cn",
                    "ceye.io",
                    "beeceptor.com",
                    "hookbin.com",
                    "mockbin.org",
                    "requestcatcher.com",
                    "smee.io",
                    "localtunnel.me",
                    "serveo.net",
                    "portmap.io",
                    "pagekite.net",
                    "telebit.cloud",
                    "localhost.run",
                    "tunnelto.dev",
                    "bore.digital",
                    "0.gone.io",
                ],
            },
            remediation="Block access to known exfiltration endpoints. Use network egress policies."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 12: Cache Poisoning
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-040",
            name="GitHub Actions Cache Poisoning",
            category="cache_poisoning",
            severity="high",
            cve="N/A",
            description="Attackers poison GitHub Actions cache by injecting malicious content that gets restored in subsequent workflow runs. Used in Ultralytics and other attacks.",
            date="2024-12-04",
            affected=["GitHub Actions cache"],
            references=[
                "https://github.com/ultralytics/ultralytics/security/advisories",
                "https://adnanthekhan.com/2024/12/07/the-ultralytics-supply-chain-attack/",
            ],
            detection_signatures={
                "cache_patterns": [
                    r"actions/cache(?:@|\s)",
                    r"restore-keys:",
                ],
                "unsafe_cache": True,
            },
            remediation="Include lockfile hashes in cache keys. Verify cache integrity after restore. Don't use restore-keys with broad prefixes."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 13: More npm/PyPI malware
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-041",
            name="Protestware / Socio-Political Sabotage",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Maintainer-initiated sabotage of their own packages for political or economic protest (colors, faker, node-ipc, es5-ext).",
            date="2022-01-01",
            affected=["colors", "faker", "node-ipc", "es5-ext"],
            references=[
                "https://github.com/advisories/GHSA-wjr3-rxjg-3jxc",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["es5-ext@0.10.53", "es5-ext@0.10.54", "es5-ext@0.10.55", "es5-ext@0.10.56"],
                },
            },
            remediation="Pin to known-good versions. Use lockfiles with integrity hashes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-042",
            name="npm install script attacks",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Malicious packages use postinstall scripts to execute arbitrary code during npm install. This is the most common attack vector in npm.",
            date="2024-01-01",
            affected=["npm ecosystem"],
            references=[
                "https://docs.npmjs.com/cli/v10/using-npm/scripts#best-practices",
            ],
            detection_signatures={
                "install_script_patterns": [
                    r'"preinstall"',
                    r'"postinstall"',
                    r'"install".*"node\s',
                    r'"install".*"sh\s',
                ],
            },
            remediation="Use npm install --ignore-scripts for untrusted packages. Review install scripts."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-043",
            name="Typosquatting: crossenv (npm)",
            category="typosquatting",
            severity="high",
            cve="N/A",
            description="crossenv package on npm mimicked the popular cross-env package name to steal environment variables.",
            date="2017-08-01",
            affected=["crossenv (npm)"],
            references=[
                "https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["crossenv", "cross-env.js", "crossenv.js"],
                },
            },
            remediation="Double-check package names. Use npm audit."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 14: GitHub Actions Token Patterns
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-044",
            name="Exposed API Keys in Workflows",
            category="credential_exfiltration",
            severity="critical",
            cve="N/A",
            description="Hard-coded API keys, tokens, or passwords in workflow files instead of using GitHub Secrets.",
            date="2024-01-01",
            affected=["Any GitHub repository"],
            references=[
                "https://docs.github.com/en/actions/security-guides/encrypted-secrets",
            ],
            detection_signatures={
                "hardcoded_secret_patterns": [
                    r"AKIA[0-9A-Z]{16}",  # AWS Access Key
                    r"(?:^|[^a-zA-Z0-9])ghp_[A-Za-z0-9]{36}",  # GitHub PAT
                    r"(?:^|[^a-zA-Z0-9])github_pat_[A-Za-z0-9_]{22,}",  # GitHub fine-grained PAT
                    r"(?:^|[^a-zA-Z0-9])gho_[A-Za-z0-9]{36}",  # GitHub OAuth
                    r"(?:^|[^a-zA-Z0-9])ghs_[A-Za-z0-9]{36}",  # GitHub App installation
                    r"(?:^|[^a-zA-Z0-9])ghr_[A-Za-z0-9]{36}",  # GitHub refresh token
                    r"(?:^|[^a-zA-Z0-9])npm_[A-Za-z0-9]{36}",  # npm token
                    r"(?:^|[^a-zA-Z0-9])sk-[A-Za-z0-9]{32,}",  # OpenAI API key
                    r"(?:^|[^a-zA-Z0-9])SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",  # SendGrid
                    r"(?:^|[^a-zA-Z0-9])xox[bpsar]-[A-Za-z0-9-]+",  # Slack token
                    r"(?:^|[^a-zA-Z0-9])sk_live_[A-Za-z0-9]{24,}",  # Stripe
                    r"password\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                    r"api[_-]?key\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                    r"secret\s*[:=]\s*['\"][^'\"]{8,}['\"]",
                ],
            },
            remediation="Move all credentials to GitHub Secrets. Never hard-code secrets in workflow files."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-045",
            name="Actions Output Injection",
            category="script_injection",
            severity="high",
            cve="N/A",
            description="Attackers inject malicious values into step outputs that are consumed by downstream steps without sanitization.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
            ],
            detection_signatures={
                "output_injection_patterns": [
                    r"echo\s+['\"].*\$\{\{.*\}\}.*['\"].*>>\s*\$GITHUB_OUTPUT",
                    r"steps\.\w+\.outputs\.\w+.*run:",
                ],
            },
            remediation="Sanitize all step outputs. Quote variables in shell scripts."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 15: More Recent Attacks (2024-2025)
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-046",
            name="Polyfill.io Supply Chain Attack",
            category="cdn_compromise",
            severity="critical",
            cve="N/A",
            description="Chinese company acquired polyfill.io domain and CDN, then served malicious JavaScript to 100,000+ websites.",
            date="2024-06-25",
            affected=["cdn.polyfill.io"],
            references=[
                "https://sansec.io/research/polyfill-supply-chain-attack",
            ],
            detection_signatures={
                "suspicious_domains": [
                    "polyfill.io",
                    "cdn.polyfill.io",
                ],
                "cdn_patterns": [
                    r"polyfill\.io",
                ],
            },
            remediation="Remove all references to polyfill.io. Use modern browser APIs or a trusted, self-hosted polyfill alternative with SRI hashes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-047",
            name="PyTorch nightly torchtriton",
            category="dependency_confusion",
            severity="critical",
            cve="N/A",
            description="Malicious torchtriton package uploaded to PyPI that was a dependency confusion attack targeting PyTorch nightly builds, stealing SSH keys and other credentials.",
            date="2022-12-30",
            affected=["torchtriton (PyPI)"],
            references=[
                "https://pytorch.org/blog/compromised-nightly-dependency/",
            ],
            detection_signatures={
                "malicious_packages": {
                    "pypi": ["torchtriton"],
                },
                "confusion_patterns": [
                    r"--extra-index-url.*pypi\.org",
                ],
            },
            remediation="Use --index-url (not --extra-index-url) for private registries. Namespace packages."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-048",
            name="Ledger ConnectKit Supply Chain",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Ledger's Connect Kit npm package was compromised via a phishing attack on a former employee, injecting a crypto wallet drainer.",
            date="2023-12-14",
            affected=["@ledgerhq/connect-kit@1.1.5", "@ledgerhq/connect-kit@1.1.6", "@ledgerhq/connect-kit@1.1.7"],
            references=[
                "https://www.ledger.com/blog/a-letter-from-ledger-chairman-ceo-pascal-gauthier",
            ],
            detection_signatures={
                "malicious_packages": {
                    "npm": ["@ledgerhq/connect-kit@1.1.5", "@ledgerhq/connect-kit@1.1.6", "@ledgerhq/connect-kit@1.1.7"],
                },
            },
            remediation="Update to latest @ledgerhq/connect-kit. Enable 2FA on npm."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-049",
            name="GitHub Actions artifacts/token leaks",
            category="credential_exfiltration",
            severity="high",
            cve="N/A",
            description="Workflows uploading artifacts that inadvertently contain secrets, tokens, or sensitive configuration files.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[
                "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-artifacts",
            ],
            detection_signatures={
                "artifact_leak_patterns": [
                    r"upload-artifact.*\**",
                    r"upload-artifact.*path:\s*\.",
                    r"upload-artifact.*\.env",
                    r"upload-artifact.*\.npmrc",
                ],
            },
            remediation="Be explicit about artifact upload paths. Never upload workspace root or .env files."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-050",
            name="GitHub Actions OIDC Token Misconfiguration",
            category="actions_config",
            severity="high",
            cve="N/A",
            description="Misconfigured OIDC trust policies allowing any workflow or branch to obtain cloud credentials, not just the intended deployment workflows.",
            date="2024-01-01",
            affected=["GitHub Actions OIDC"],
            references=[
                "https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-cloud-providers",
            ],
            detection_signatures={
                "oidc_patterns": [
                    r"id-token:\s*write",
                    r"aws-actions/configure-aws-credentials",
                    r"azure/login",
                    r"google-github-actions/auth",
                ],
            },
            remediation="Configure OIDC trust with specific repo, branch, and environment constraints."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-051",
            name="Malicious GitHub Actions from Marketplace",
            category="actions_compromise",
            severity="high",
            cve="N/A",
            description="Fake or malicious actions published to GitHub Marketplace designed to steal secrets or inject malware.",
            date="2024-01-01",
            affected=["GitHub Actions Marketplace"],
            references=[
                "https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/malicious-github-actions",
            ],
            detection_signatures={
                "marketplace_risk_patterns": [
                    r"uses:\s+[^/]+/[^@]+$",  # No version pin at all
                ],
            },
            remediation="Verify action source before use. Check stars, maintainer history, and code."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-052",
            name="NPM Debug/Chalk Token Theft (Sep 2025 pattern)",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="Compromised maintainer tokens for popular npm packages (debug, chalk, ansi-regex) used to publish malicious versions.",
            date="2025-09-01",
            affected=["debug", "chalk", "ansi-regex"],
            references=[],
            detection_signatures={
                "compromised_actions": [],
                "exfil_patterns": [
                    r"npm_[A-Za-z0-9]{36}",
                ],
            },
            remediation="Verify package integrity. Check npm provenance. Use lockfiles with integrity hashes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-053",
            name="Hugging Face Supply Chain Risks",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Malicious ML models on Hugging Face Hub containing embedded code execution via pickle deserialization or custom model classes.",
            date="2024-01-01",
            affected=["Hugging Face Hub models"],
            references=[
                "https://huggingface.co/docs/hub/security",
            ],
            detection_signatures={
                "ml_patterns": [
                    r"pickle\.load",
                    r"torch\.load",
                    r"joblib\.load",
                    r"from_pretrained\(",
                ],
            },
            remediation="Use safetensors format. Verify model provenance. Scan models for embedded code."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-054",
            name="GitHub Actions Workflow Dispatch token abuse",
            category="actions_config",
            severity="medium",
            cve="N/A",
            description="workflow_dispatch events can be triggered by any user with write access, potentially abusing elevated permissions.",
            date="2024-01-01",
            affected=["GitHub Actions"],
            references=[],
            detection_signatures={
                "dispatch_patterns": [
                    r"workflow_dispatch",
                ],
            },
            remediation="Restrict workflow_dispatch to protected branches. Limit who can trigger."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-055",
            name="Codecov Uploader SHA256 Verification Bypass",
            category="build_system",
            severity="high",
            cve="N/A",
            description="The Codecov uploader binary was replaced with a malicious version that was not caught because the SHA256 verification step was optional.",
            date="2021-04-01",
            affected=["Codecov bash uploader"],
            references=[
                "https://about.codecov.io/security-update/",
            ],
            detection_signatures={
                "verification_bypass": [
                    r"curl.*codecov.*bash",
                    r"bash\s+<\(curl",
                    r"curl\s+-s.*\|\s*bash",
                ],
            },
            remediation="Always verify downloaded scripts with checksums. Use official GitHub Action instead of bash uploader."
        ))

        # ═══════════════════════════════════════════════════════
        # CATEGORY 16: Recent 2025 Attacks
        # ═══════════════════════════════════════════════════════

        self.attacks.append(AttackPattern(
            id="SCA-056",
            name="LiteLLM Credential Stealer in PyPI Wheel",
            category="package_compromise",
            severity="critical",
            cve="N/A",
            description="A malicious PyPI wheel for litellm contained a credential stealer hidden only in the wheel distribution (.whl) but not in the source distribution (.tar.gz). The stealer harvested environment variables (API keys, AWS credentials, database URLs) and exfiltrated them to an attacker-controlled endpoint. This technique exploits the fact that pip prefers wheels over source distributions.",
            date="2025-02-15",
            affected=["litellm (malicious wheel)"],
            references=[
                "https://github.com/advisories",
            ],
            detection_signatures={
                "malicious_packages": {
                    "pypi": ["litellm"],
                },
                "wheel_stealer_patterns": [
                    r"os\.environ",
                    r"requests\.post.*env",
                    r"urllib\.request.*env",
                    r"__import__\(['\"]requests['\"]\)",
                    r"base64\.b64encode.*environ",
                    r"subprocess\..*env",
                ],
                "exfil_patterns": [
                    r"\.env.*requests\.post",
                    r"environ.*urlopen",
                    r"os\.environ\.get.*OPENAI",
                    r"os\.environ\.get.*DATABASE_URL",
                    r"os\.environ\.get.*AWS_",
                    r"os\.environ\.get.*ANTHROPIC",
                    r"os\.environ\.get.*AZURE_",
                ],
                "suspicious_domains": [
                    "r]equest.ey.r.appspot.com",
                ],
            },
            remediation="Verify wheel contents match source. Use pip install --no-binary to force source builds. Compare .whl and .tar.gz contents. Pin hashes with pip --require-hashes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-057",
            name="MavenGate - Abandoned Namespace Hijacking",
            category="dependency_confusion",
            severity="high",
            cve="N/A",
            description="Attackers hijack abandoned domain names used in Maven groupIds to publish malicious packages that replace legitimate dependencies in Java/Kotlin/Android projects.",
            date="2024-01-22",
            affected=["Maven Central / Gradle ecosystem"],
            references=[
                "https://blog.oversecured.com/Introducing-MavenGate-a-supply-chain-attack-method-for-Java-and-Android-applications/",
            ],
            detection_signatures={
                "maven_patterns": [
                    r"implementation\s+['\"]",
                    r"<dependency>",
                    r"<groupId>",
                ],
            },
            remediation="Verify domain ownership for all Maven dependencies. Use dependency verification in Gradle."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-058",
            name="Wheel Diff Attack Pattern",
            category="package_compromise",
            severity="high",
            cve="N/A",
            description="Generic pattern where PyPI wheel distributions contain different (malicious) code than the corresponding source distributions. Pip prefers wheels, so most users get the malicious version.",
            date="2025-01-01",
            affected=["PyPI ecosystem"],
            references=[
                "https://github.com/advisories",
            ],
            detection_signatures={
                "wheel_diff_indicators": [
                    r"setup\.py.*__import__",
                    r"setup\.py.*exec\(",
                    r"setup\.py.*eval\(",
                    r"setup\.py.*compile\(",
                    r"__init__\.py.*exec\(",
                    r"__init__\.py.*eval\(",
                    r"conftest\.py.*requests\.post",
                ],
                "exfil_patterns": [
                    r"os\.environ.*json\.dumps",
                    r"dict\(os\.environ\)",
                    r"\{k:v for k,v in os\.environ",
                ],
            },
            remediation="Always compare wheel and source distributions. Use --no-binary for sensitive installs. Pin with hashes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-059",
            name="GitHub Actions Workflow Injection via CODEOWNERS",
            category="script_injection",
            severity="high",
            cve="N/A",
            description="Attackers manipulate CODEOWNERS files to gain auto-review approval on malicious PRs that modify workflow files.",
            date="2025-01-01",
            affected=["GitHub Actions"],
            references=[],
            detection_signatures={
                "codeowner_patterns": [
                    r"\.github/CODEOWNERS",
                    r"\.github/workflows/.*CODEOWNERS",
                ],
            },
            remediation="Restrict who can modify CODEOWNERS. Require multiple approvals for workflow changes."
        ))

        self.attacks.append(AttackPattern(
            id="SCA-060",
            name="AI/LLM API Key Exposure in CI",
            category="credential_exfiltration",
            severity="critical",
            cve="N/A",
            description="Growing pattern of OpenAI, Anthropic, Cohere, and other AI API keys being exposed in CI workflows, setup scripts, and environment files.",
            date="2025-01-01",
            affected=["AI/LLM platforms"],
            references=[],
            detection_signatures={
                "hardcoded_secret_patterns": [
                    r"sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}",  # OpenAI key
                    r"sk-ant-[a-zA-Z0-9_-]{90,}",  # Anthropic key
                    r"AIzaSy[A-Za-z0-9_-]{33}",  # Google AI key
                    r"(?:^|[^a-zA-Z0-9])r8_[A-Za-z0-9]{20,}",  # Replicate token
                    r"hf_[A-Za-z0-9]{34}",  # Hugging Face token
                ],
                "exfil_patterns": [
                    r"OPENAI_API_KEY",
                    r"ANTHROPIC_API_KEY",
                    r"COHERE_API_KEY",
                    r"HUGGING_FACE_HUB_TOKEN",
                    r"REPLICATE_API_TOKEN",
                ],
            },
            remediation="Use OIDC-based authentication where possible. Store AI keys only in GitHub Secrets. Rotate keys regularly."
        ))
