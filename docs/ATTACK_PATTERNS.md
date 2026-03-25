# Attack Pattern Reference

This document lists all attack patterns in the Supply Chain Guardian database.

## Categories

### Actions Compromise (`actions_compromise`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-001 | tj-actions/changed-files Compromise | Critical | Compromised GitHub Action that exfiltrated CI secrets via modified post-run script |
| SCA-002 | reviewdog Action Compromise | Critical | Multiple reviewdog actions compromised to inject credential-stealing code |
| SCA-003 | Codecov Bash Uploader Compromise | Critical | Modified bash script that extracted env vars and uploaded to attacker server |
| SCA-004 | Compromised Action SHA Reference | Critical | Action pinned to a known-compromised commit SHA |

### Pwn Requests (`pwn_request`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-005 | Pwn Request via pull_request_target | Critical | Workflow checks out PR author's code with elevated permissions |
| SCA-025 | workflow_run Privilege Escalation | High | Workflow triggered by workflow_run inherits elevated privileges |
| SCA-026 | Script Injection via Untrusted Input | High | GitHub expression directly interpolated in run: block enables command injection |
| SCA-027 | GITHUB_ENV/PATH Injection | Critical | Command substitution output written to GITHUB_ENV/PATH enables environment poisoning |

### Dependency Attacks (`dependency_attack`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-006 | event-stream Compromise | High | npm package compromised to steal Bitcoin wallets |
| SCA-007 | ua-parser-js Compromise | High | Popular npm package backdoored with cryptominer |
| SCA-008 | coa/rc Compromise | High | npm packages compromised to deliver malware |
| SCA-056 | LiteLLM Credential Stealer | Critical | Malicious function hidden in PyPI wheel steals credentials via DNS exfiltration |
| SCA-057 | MavenGate Attack Pattern | High | Abandoned Maven group IDs hijacked for dependency injection |

### Secret Exposure (`secret_exposure`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-010 | Hardcoded AWS Access Key | Critical | AWS IAM access key found in workflow or source file |
| SCA-011 | Hardcoded GitHub PAT | Critical | GitHub Personal Access Token exposed in plaintext |
| SCA-012 | Secret Exfiltration Pattern | Critical | Pattern matches known credential theft techniques (curl, wget to external domain) |
| SCA-060 | AI/LLM API Key Exposure | High | OpenAI, Anthropic, or other AI service API keys in source code |

### Network Attacks (`network_attack`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-015 | Reverse Shell Detection | Critical | Bash/Python/Perl/Ruby reverse shell pattern in workflow run block |
| SCA-016 | DNS Exfiltration | High | Data sent via DNS queries to external servers |
| SCA-017 | Tunneling Service | Medium | Use of ngrok, Cloudflare tunnel, or similar services in CI |
| SCA-018 | Suspicious Domain Contact | High | Network requests to known attacker-controlled infrastructure |

### Permission Issues (`permission_abuse`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-034 | Missing Permissions Block | Medium | Workflow has no explicit permissions, defaults to read-write all |
| SCA-035 | Excessive Permissions (write-all) | High | Workflow grants write access to all scopes |
| SCA-036 | OIDC Token Misconfiguration | High | ID token write permission with broad audience |

### Cache Poisoning (`cache_poisoning`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-030 | Broad Restore Keys | Medium | Cache restore-keys too broad, enabling cross-branch poisoning |
| SCA-031 | Cache in pull_request_target | High | Cache action used in pull_request_target workflow |
| SCA-032 | Missing Lockfile Hash | Medium | Cache key doesn't include lockfile hash, enabling package substitution |

### Typosquatting (`typosquatting`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-040 | Known Typosquat Package | High | Package matches a known typosquat entry in the attack database |
| SCA-041 | Levenshtein Distance Match | Medium | Package name is edit-distance 1 from a popular package |

### Provenance (`provenance`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-042 | Polyfill.io CDN Hijack | Critical | Reference to polyfill.io which was hijacked to serve malicious JS |
| SCA-043 | Missing Lockfile Integrity | Medium | npm lockfile entry lacks integrity hash |
| SCA-044 | Missing Python Hash Pin | Medium | requirements.txt entry lacks `--hash=` pin |

### Wheel Diff Attack (`wheel_diff_attack`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-058 | Wheel Diff Attack Pattern | Critical | Malicious code in built wheel but not in source distribution (LiteLLM-style) |

### CODEOWNERS Injection (`codeowners_injection`)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SCA-059 | CODEOWNERS Bypass | High | CODEOWNERS file modified to add attacker-controlled review approvals |

## Adding New Patterns

To add a new attack pattern, add an `AttackPattern` entry in `src/db/attack_db.py`:

```python
AttackPattern(
    id="SCA-XXX",
    name="Attack Name",
    category="category_name",
    severity="critical",  # critical, high, medium, low, info
    description="Detailed description of the attack.",
    indicators=["regex_pattern_1", "regex_pattern_2"],
    references=["https://blog.example.com/analysis"],
    cve="CVE-YYYY-XXXXX",  # if applicable
    affected_ecosystems=["npm", "pypi"],
    detection_query="search_pattern",
    remediation="Steps to fix.",
    first_seen="2025-01-01",
    last_updated="2025-03-25",
)
```
