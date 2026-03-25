# Supply Chain Guardian

Enterprise-grade GitHub Actions supply chain security scanner.  
Detects **60+ known attack patterns** plus **behavioral indicators of future compromises** that no signature database can catch.  
Scans, alerts, and blocks pipelines on true-positive threats.

```
uses: anshumaan-10/supply-chain-guardian@v1
```

---

## Why This Exists

Every major supply chain attack on GitHub Actions follows the same lifecycle:

```
Infiltrate → Persist → Exfiltrate → Weaponise
```

Most security tools only detect attacks **after** a signature is published — days or weeks later.  
Supply Chain Guardian detects the **behavioral invariants** of that lifecycle, catching novel attacks **before** any advisory is issued.

---

## What It Detects

### Signature-Based (Known Attacks)

| Category | What's Detected | Patterns |
|----------|----------------|----------|
| **Compromised Actions** | Known-bad commit SHAs, tag mutation victims | 10+ |
| **Pwn Requests** | `pull_request_target` + checkout, script injection | 8 |
| **Dependency Attacks** | Malicious packages across npm, PyPI, Maven, RubyGems | 20+ |
| **Secret Exfiltration** | Hardcoded AWS keys, GitHub PATs, API keys, curl-to-evil | 35+ |
| **Network Attacks** | Reverse shells, DNS exfil, tunneling, C2 endpoints | 30+ |
| **Cache Poisoning** | Broad restore-keys, cross-branch cache injection | 5 |
| **Typosquatting** | Known typosquats + Levenshtein distance detection | Dynamic |

### Behavioral (Future Attacks)

| Category | What's Detected | Why It Matters |
|----------|----------------|----------------|
| **Obfuscation** | base64\|sh, hex chains, eval(decode()), gzip\|sh | Every supply chain attack hides its payload |
| **Dynamic Loading** | curl\|sh, download-then-execute, fetch+eval | Remote code injection without review |
| **Credential Harvesting** | Mass env dump, key file enumeration, token access | First step of every exfiltration |
| **Persistence** | Cron injection, git hooks, shell profile modification | Self-hosted runner takeover |
| **Anomalous Flow** | Time bombs, background exec, error suppression | Evasion of logging and detection |
| **Trust Boundary Abuse** | Privileged containers, host mounts, namespace escape | Runner compromise |
| **Artifact Tampering** | Post-build injection, checksum suppression | Poisoned releases |
| **Shadow Dependencies** | Non-standard registries, install-script overrides | Dependency confusion |
| **Covert Channels** | Steganographic payloads, zero-width Unicode | Invisible payloads |

**Total: 60+ signature patterns + 80+ behavioral indicators.**

### Proactive Monitoring (Pre-Compromise)

| Tool | Purpose |
|------|---------|
| `scripts/action_integrity_monitor.py` | Monitors upstream action repos for tag mutation, new maintainers, unsigned commits, suspicious commit patterns |
| `scripts/workflow_lockfile.py` | Generates and verifies a cryptographic lockfile of all action SHAs — detects when a tag is force-pushed |

---

## Quick Start

### Basic (push + PR)

```yaml
name: Supply Chain Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - uses: anshumaan-10/supply-chain-guardian@v1
        with:
          scan-mode: standard
          fail-on-severity: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: supply-chain-guardian.sarif
```

### Paranoid (schedule + workflow_call + dispatch)

```yaml
name: Supply Chain Guardian (Paranoid)
on:
  push:
    branches: [main, release/*]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:
  workflow_call:
    inputs:
      scan-mode:
        type: string
        default: 'paranoid'

permissions:
  contents: read
  security-events: write
  pull-requests: write
  issues: write

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: anshumaan-10/supply-chain-guardian@v1
        with:
          scan-mode: paranoid
          fail-on-severity: medium
          scan-provenance: "true"
          scan-runtime: "true"
          slack-webhook-url: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Proactive Integrity Monitoring (schedule)

```yaml
name: Action Integrity Monitor
on:
  schedule:
    - cron: "0 */6 * * *"
  workflow_dispatch:
  repository_dispatch:
    types: [integrity-check]

jobs:
  verify:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install -q requests
      - name: Verify Action Lockfile
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python scripts/workflow_lockfile.py --verify --workspace ${{ github.workspace }}
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-mode` | `standard` | Scan intensity: `quick`, `standard`, `deep`, `paranoid` |
| `fail-on-severity` | `high` | Minimum severity to fail the pipeline |
| `scan-workflows` | `true` | Scan workflow files for safety issues |
| `scan-dependencies` | `true` | Scan package manifests for malicious packages |
| `scan-secrets` | `true` | Detect hardcoded secrets and credential exfiltration |
| `scan-network` | `true` | Detect reverse shells, tunneling, DNS exfil |
| `scan-permissions` | `true` | Audit workflow permissions for least privilege |
| `scan-provenance` | `true` | Verify dependency provenance and integrity |
| `scan-runtime` | `false` | Monitor runner environment at execution time |
| `slack-webhook-url` | — | Slack Incoming Webhook URL for alerts |
| `teams-webhook-url` | — | Microsoft Teams Webhook URL for alerts |
| `github-token` | — | GitHub token for PR comments and issue creation |
| `exclude-paths` | — | Comma-separated paths to exclude |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-status` | `PASSED`, `WARNING`, or `FAILED` |
| `total-findings` | Total finding count |
| `critical-findings` | Critical severity count |
| `high-findings` | High severity count |
| `medium-findings` | Medium severity count |
| `low-findings` | Low severity count |
| `report-path` | Path to JSON report |
| `sarif-path` | Path to SARIF report |

---

## How Blocking Works

Supply Chain Guardian uses **confidence-aware blocking** to minimise false positives:

| Scanner Type | Blocking Rule |
|---|---|
| **Signature scanners** (compromised actions, known SHAs, network exfil, secrets) | Block at configured `fail-on-severity` threshold |
| **Behavioral scanner** (obfuscation, dynamic loading, credential harvest) | Block only on **critical** behavioral findings (e.g., `base64\|sh`, `curl\|sh`) |
| **Informational/heuristic** (low, info) | Alert only — never block |

This means: a signature match for a known-compromised SHA always blocks. A behavioral finding like "no timeout-minutes" (low severity) only alerts.

---

## Architecture

```
src/
├── main.py                            # Orchestrator + blocking logic
├── db/attack_db.py                    # 60+ attack patterns
├── scanners/
│   ├── base_scanner.py                # Abstract base class
│   ├── behavioral_scanner.py          # 80+ behavioral / future indicators
│   ├── compromised_action_scanner.py  # Known-bad action signatures
│   ├── pwn_request_scanner.py         # PR privilege escalation
│   ├── workflow_scanner.py            # General workflow analysis
│   ├── cache_poisoning_scanner.py     # Cache attack patterns
│   ├── permission_scanner.py          # Least-privilege auditing
│   ├── secret_scanner.py              # Secret detection + exfiltration
│   ├── network_scanner.py             # Reverse shells, tunnels, DNS exfil
│   ├── dependency_scanner.py          # Package manifest scanning
│   ├── typosquat_scanner.py           # Package name confusion
│   ├── provenance_scanner.py          # Integrity verification
│   └── runtime_scanner.py             # Runtime anomaly detection
├── reporters/
│   ├── table_reporter.py              # Console output
│   ├── json_reporter.py               # JSON report file
│   ├── sarif_reporter.py              # SARIF 2.1.0 for GitHub Code Scanning
│   └── github_reporter.py             # PR comments, issues, annotations
├── alerting/
│   ├── slack_alerter.py               # Slack webhooks
│   └── teams_alerter.py               # Teams Adaptive Cards
├── utils/
│   ├── config.py                      # Configuration management
│   ├── files.py                       # File discovery and YAML parsing
│   └── logger.py                      # Colorized logging
scripts/
├── action_integrity_monitor.py        # Proactive upstream monitoring
└── workflow_lockfile.py               # Cryptographic action lockfile
```

---

## Running Locally

```bash
export GITHUB_WORKSPACE=/path/to/your/repo
export INPUT_SCAN_MODE=standard
export INPUT_FAIL_ON_SEVERITY=high
python3 src/main.py
```

## Running Tests

```bash
pip install pyyaml tabulate colorama
python -m pytest tests/ -v
```

## Examples

See [`examples/`](../examples/) for ready-to-use workflows:

| File | Purpose |
|------|---------|
| `basic-scan.yml` | Push + PR scan with SARIF upload |
| `paranoid-scan.yml` | Maximum security with Slack/Teams alerts |
| `dependency-scan.yml` | Lightweight dependency-only scan |
| `reusable-workflow.yml` | Reusable `workflow_call` pattern |
| `integrity-monitor.yml` | Scheduled proactive monitoring |

---

## License

MIT
