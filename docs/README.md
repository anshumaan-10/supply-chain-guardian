# Supply Chain Guardian — v4.0.2

> Enterprise-grade CI/CD supply chain security scanner.
> **110+ attack signatures · 17 scanner modules · Binary analysis · Smart egress allowlisting · Enterprise exemption engine · Runtime monitoring daemon**

```yaml
uses: anshumaan-10/supply-chain-guardian@v4
```

By **Anshumaan Singh** ([@anshumaan-10](https://github.com/anshumaan-10)) — License: [Business Source License 1.1](../LICENSE)

---

## Table of Contents

1. [What It Does](#what-it-does)
2. [Scanner Modules](#scanner-modules)
3. [Quick Start](#quick-start)
4. [Installation Guide](#installation-guide)
5. [Runtime Monitoring](#runtime-monitoring)
6. [Binary Analysis](#binary-analysis)
7. [Smart Egress Detection](#smart-egress-detection)
8. [Exception & Exemption System](#exception--exemption-system)
9. [Configuration Reference](#configuration-reference)
10. [Outputs & Reports](#outputs--reports)
11. [CLI Usage](#cli-usage)
12. [Architecture](#architecture)
13. [Comparison with Commercial Tools](#comparison-with-commercial-tools)

---

## What It Does

Every supply chain attack on GitHub Actions follows the same lifecycle:

```
Infiltrate → Persist → Exfiltrate → Weaponise
```

Most scanners only fire after a CVE is published — days or weeks later. SCG detects the **behavioral invariants** of that lifecycle: the patterns every attack must exhibit regardless of implementation. Novel zero-days are caught before any advisory.

Key innovations in v4:

- **Smart egress allowlisting** — 80+ legitimate domains pre-trusted; only real C2 traffic fires alerts
- **Enterprise exemption engine** — per-repo `.scg-config.yml`, org-wide central config, inline `# scg-ignore` comments, expiring suppressions with audit trail
- **Binary analysis** — detects dropped ELF/PE/Mach-O executables, cryptominers, implants by magic bytes, name, SHA256, and location
- **Full-lifecycle runtime monitoring** — daemon starts before your build, watches processes/network/filesystem the entire time the runner is up

---

## Scanner Modules

### Signature Scanners (True-Positive, CVE-Mapped)

| # | Scanner | Detects | Patterns |
|---|---------|---------|---------|
| 1 | **Compromised Actions** | Known-bad SHA commits, tj-actions/reviewdog mutations | 10+ |
| 2 | **Pwn Request** | `pull_request_target` + checkout, script injection, env poisoning | 8 |
| 3 | **Workflow Analysis** | Unsafe triggers, missing concurrency, template injection | 15+ |
| 4 | **Cache Poisoning** | Broad restore-keys, cross-branch cache injection | 5 |
| 5 | **Permission Audit** | `write-all`, least-privilege violations, job-scope escalation | 10+ |
| 6 | **Secret Exposure** | AWS/GCP/Azure keys, PATs, AI API keys, 35+ credential patterns | 35+ |
| 7 | **Network Exfiltration** | Reverse shells, DNS exfil, C2 endpoints, tunneling tools | 30+ |
| 8 | **Dependency Integrity** | Compromised npm/PyPI/Maven/RubyGems/Cargo packages | 20+ |
| 9 | **Typosquatting** | Known typosquats + Levenshtein-distance detection (dynamic) | Dynamic |
| 10 | **Provenance Verification** | SLSA attestation, Sigstore, unsigned releases | 10+ |
| 11 | **OIDC Token Audit** | Scope escalation, wildcard audiences, identity confusion | 8 |
| 12 | **Artifact Integrity** | Download without verification, TOCTOU, artifact poisoning | 7 |
| 13 | **Container Security** | Unpinned images, `--privileged`, Docker socket mount, build-arg secrets | 12 |
| 14 | **Reusable Workflow Trust** | Mutable refs, secret inheritance, external org trust | 10 |
| 15 | **Behavioral Analysis** | 80+ heuristics: obfuscation, dynamic loading, persistence, staging | 80+ |
| 16 | **Cross-Platform CI/CD** | Jenkins, GitLab, CircleCI, Azure DevOps attack patterns | 15+ |

### New in v4.0

| # | Scanner | Detects |
|---|---------|---------|
| 17 | **Binary Analysis** | ELF/PE/Mach-O executables, cryptominers, implants, C2 agents by magic bytes + SHA256 + name |

**Total: 110+ signature patterns + 80+ behavioral indicators = 190+ detection rules**

---

## Quick Start

### Minimal — Scan on Every Push & PR

```yaml
# .github/workflows/supply-chain-scan.yml
name: Supply Chain Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # for SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - uses: anshumaan-10/supply-chain-guardian@v4
        with:
          scan-mode: standard
          fail-on-severity: high
```

### Standard — Deep Scan with Runtime Monitor

```yaml
      - uses: anshumaan-10/supply-chain-guardian@v4
        with:
          scan-mode: deep
          fail-on-severity: high
          runtime-monitor: 'true'
          scan-binaries: 'true'
          html-output: 'true'
          slack-webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

### Enterprise — Split-Mode (Monitor Full Pipeline)

```yaml
jobs:
  build-and-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: SCG — Start Runtime Monitor
        uses: anshumaan-10/supply-chain-guardian@v4
        with:
          mode: monitor-start

      - run: npm ci
      - run: npm test
      - run: docker build -t myapp:latest .

      - name: SCG — Full Scan
        uses: anshumaan-10/supply-chain-guardian@v4
        with:
          mode: scan
          scan-mode: deep
          fail-on-severity: high
          scan-runtime: 'true'
          html-output: 'true'
          exceptions-config: .scg-config.yml
```

---

## Installation Guide

### GitHub Actions (Recommended)

Pin to a specific SHA for maximum integrity:

```yaml
# Always use a SHA-pinned reference in production
uses: anshumaan-10/supply-chain-guardian@<COMMIT_SHA>
# Get latest SHA: gh release view v4 --json tagName,targetCommitish
```

### Reusable Workflow Pattern (Central Control)

```yaml
on:
  workflow_call:
    inputs:
      scan-mode:
        type: string
        default: standard
      fail-on-severity:
        type: string
        default: high

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: anshumaan-10/supply-chain-guardian@v4
        with:
          scan-mode: ${{ inputs.scan-mode }}
          fail-on-severity: ${{ inputs.fail-on-severity }}
```

### Local CLI

```bash
git clone https://github.com/anshumaan-10/supply-chain-guardian.git
cd supply-chain-guardian
pip install pyyaml requests tabulate colorama jsonschema semver

python src/main.py --workspace /path/to/my-repo
python src/main.py --workspace /path/to/my-repo --scan-mode deep
python src/main.py --workspace /path/to/my-repo --scan-mode paranoid
```

---

## Runtime Monitoring

The runtime monitor is a background daemon that starts before your build and watches for threats the entire time the runner is alive. This catches attacks that happen during `npm install`, `docker build`, or `terraform apply` — not just in workflow YAML.

### What It Monitors

| Category | Examples |
|----------|---------|
| Process spawn | Cryptominers (xmrig, minerd), reverse shells, privilege escalation |
| Network connections | Unexpected outbound TCP, known C2 IP ranges, DNS tunneling |
| Filesystem events | Writes to `/tmp`, `/dev/shm`, cron directories, `.ssh/`, new executables |
| Memory access | `/proc/mem` reads, ptrace attempts |
| Credentials | `.env`, `.npmrc`, `.pypirc`, `.docker/config.json` writes |
| Persistence | systemd unit creation, `~/.bashrc` modifications, `authorized_keys` changes |

### Runtime Monitor Configuration

```yaml
  - uses: anshumaan-10/supply-chain-guardian@v4
    with:
      mode: monitor-start
      runtime-monitor-interval: '3'   # poll every 3s (default: 5)
```

---

## Binary Analysis

The binary scanner runs a one-time sweep of the workspace and temp directories to detect executables that should not be there.

### Detection Methods

| Method | Details |
|--------|---------|
| Magic bytes | ELF, PE (MZ), Mach-O, Universal binary |
| Suspicious names | xmrig, minerd, ncat, socat, chisel, frp, ngrok, sliver, mimikatz, lazagne |
| Known-bad SHA256 | Cross-referenced against 50+ malicious binary hashes |
| Unexpected location | Binaries in `.github/`, `config/`, `docs/`, `tests/` trigger HIGH |
| Temp directory sweep | `/tmp`, `/dev/shm`, `/var/tmp` scanned in deep/paranoid mode |

### Enabling Binary Analysis

Binary analysis runs automatically in `deep` and `paranoid` modes:

```yaml
  - uses: anshumaan-10/supply-chain-guardian@v4
    with:
      scan-mode: standard
      scan-binaries: 'true'     # enable explicitly in standard mode
```

---

## Smart Egress Detection

SCG detects data exfiltration without generating alert fatigue from legitimate network traffic.

80+ domains are pre-trusted (GitHub, npm, PyPI, Maven, Docker Hub, GCP, AWS, Azure, CDNs, OS package repos, CI platforms). Every outbound domain is checked against this list before any alert fires. Known-bad C2 domains are never allowlisted regardless.

Add your internal domains in `.scg-config.yml` under `egress_allowlist`.

### What Still Fires Alerts

- Connections to known C2 infrastructure
- DNS exfiltration patterns (base64-encoded subdomains)
- Reverse shell patterns
- Direct IP connections (no hostname)
- Connections to Tor exit nodes or known-bad IP ranges

---

## Exception & Exemption System

Three-layer exemption system with full audit trail.

### Layer 1: Inline Code Suppression

Add `# scg-ignore:RULE-ID` on the same line in your workflow file.

### Layer 2: Repository-Level Config

```yaml
# .scg-config.yml
version: "1"

exemptions:
  - rule_id: SCA-017
    reason: "ngrok used for Playwright e2e testing only"
    approved_by: "security-team"
    expires: "2027-01-01"

egress_allowlist:
  - "*.internal.corp.example.com"
  - "artifactory.corp.example.com"

disabled_scanners:
  - "provenance"

severity_overrides:
  SCA-042: medium
```

### Layer 3: Org-Wide Central Config

```yaml
- uses: anshumaan-10/supply-chain-guardian@v4
  with:
    exceptions-config: /path/to/central-scg-exceptions.yml
```

Exempted findings remain in the JSON report with `"status": "exempted"` for compliance audit.

---

## Configuration Reference

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `scan` | `scan` / `monitor-start` / `monitor-stop` |
| `scan-mode` | `standard` | `quick` / `standard` / `deep` / `paranoid` |
| `fail-on-severity` | `high` | `critical` / `high` / `medium` / `low` / `info` |
| `exceptions-config` | `` | Path to exceptions YAML file |
| `scan-binaries` | `false` | Enable binary analysis explicitly |
| `scan-workflows` | `true` | Scan workflow YAML files |
| `scan-dependencies` | `true` | Scan package manifests |
| `scan-secrets` | `true` | Scan for exposed credentials |
| `scan-network` | `true` | Scan for exfiltration patterns |
| `scan-permissions` | `true` | Audit least-privilege |
| `scan-provenance` | `true` | Verify SLSA attestations |
| `scan-runtime` | `false` | Include runtime daemon findings |
| `runtime-monitor` | `false` | Start/stop monitor inside scan step |
| `runtime-monitor-interval` | `5` | Daemon poll interval in seconds |
| `slack-webhook-url` | `` | Slack webhook for alerts |
| `teams-webhook-url` | `` | Teams webhook for alerts |
| `alert-on-severity` | `high` | Minimum severity to alert on |
| `sarif-output` | `true` | Generate SARIF report |
| `html-output` | `false` | Generate self-contained HTML report |
| `html-output-path` | `supply-chain-guardian-report.html` | HTML report filename |
| `json-output` | `supply-chain-guardian-report.json` | JSON report path |
| `table-output` | `true` | Print findings table to job logs |
| `block-pr` | `true` | Block PR merge on critical findings |
| `create-issue` | `true` | Open GitHub issue on critical findings |
| `auto-comment-pr` | `true` | Comment scan results on PRs |
| `github-token` | `${{ github.token }}` | Token for GitHub API |
| `verbose` | `false` | Debug output |

### Action Outputs

| Output | Description |
|--------|-------------|
| `scan-status` | `PASSED` / `WARNING` / `FAILED` |
| `total-findings` | Total findings including exempted |
| `critical-findings` | Critical severity count (active only) |
| `high-findings` | High severity count (active only) |
| `medium-findings` | Medium severity count |
| `low-findings` | Low severity count |
| `exempted-findings` | Count of suppressed/exempted findings |
| `report-path` | Path to JSON report |
| `sarif-path` | Path to SARIF report |

### Scan Modes

| Mode | Scanners Active | Duration | Best For |
|------|----------------|----------|----------|
| `quick` | Signatures only | < 10s | PR drafts, fast feedback |
| `standard` | Signatures + behavioral | 10–30s | Default for all branches |
| `deep` | Standard + deep heuristics + binary | 30–90s | Main branch, release PRs |
| `paranoid` | Everything + /tmp scan + max patterns | 90s+ | Release pipelines, audit |

---

## Outputs & Reports

### HTML Report

Enable with `html-output: 'true'` — self-contained file, no server required. Suitable for emailing or attaching to tickets.

### JSON Report

Machine-readable with all findings, metadata, exemption details, and timestamps. Compatible with JIRA, Splunk, Datadog, custom dashboards.

### SARIF Report

SARIF 2.1.0 compatible with GitHub Advanced Security. Findings appear in the Security tab with inline annotations on the exact line.

### Artifacts

All reports auto-uploaded as workflow artifacts (retained 90 days):
- `supply-chain-guardian-report.json`
- `supply-chain-guardian-report.html` (if `html-output: 'true'`)
- `supply-chain-guardian.sarif`
- `runtime-findings.json` (if runtime monitor used)
- `monitor.log` (if runtime monitor used)

---

## CLI Usage

```bash
# Basic scan
python src/main.py --workspace /path/to/repo

# With environment variables (mirrors action inputs)
INPUT_SCAN_MODE=paranoid \
INPUT_FAIL_ON_SEVERITY=medium \
INPUT_VERBOSE=true \
python src/main.py --workspace .

# Runtime monitor
python src/runtime_monitor.py start 5   # start daemon, poll every 5s
python src/runtime_monitor.py status    # check status
python src/runtime_monitor.py stop      # stop, print findings
```

---

## Architecture

```
supply-chain-guardian/
├── action.yml
├── src/
│   ├── main.py                        # Orchestrator, scanner registry, reporting
│   ├── runtime_monitor.py             # Background daemon
│   ├── db/
│   │   └── attack_db.py               # 110+ signature patterns (SCA-001 to SCA-110)
│   ├── scanners/
│   │   ├── base_scanner.py
│   │   ├── compromised_action_scanner.py
│   │   ├── pwn_request_scanner.py
│   │   ├── workflow_scanner.py
│   │   ├── cache_poisoning_scanner.py
│   │   ├── permission_scanner.py
│   │   ├── secret_scanner.py
│   │   ├── network_scanner.py
│   │   ├── dependency_scanner.py
│   │   ├── typosquat_scanner.py
│   │   ├── provenance_scanner.py
│   │   ├── runtime_scanner.py
│   │   ├── oidc_scanner.py
│   │   ├── artifact_scanner.py
│   │   ├── container_scanner.py
│   │   ├── reusable_workflow_scanner.py
│   │   ├── cross_platform_scanner.py
│   │   ├── behavioral_scanner.py      # 80+ behavioral patterns
│   │   └── binary_scanner.py          # v4: ELF/PE/Mach-O, cryptominers, implants
│   ├── reporters/
│   │   ├── table_reporter.py
│   │   ├── json_reporter.py
│   │   ├── sarif_reporter.py          # SARIF 2.1.0
│   │   ├── html_reporter.py           # v4: Self-contained HTML report
│   │   └── github_reporter.py
│   ├── alerting/
│   │   ├── slack_alerter.py
│   │   └── teams_alerter.py
│   └── utils/
│       ├── config.py
│       ├── exceptions.py              # v4: Exemption engine
│       ├── files.py
│       └── logger.py
├── examples/
│   ├── basic-scan.yml
│   ├── devsecops-pipeline.yml
│   ├── paranoid-scan.yml
│   ├── reusable-workflow.yml
│   └── scg-config.yml
└── tests/
```

---

## Comparison with Commercial Tools

| Feature | SCG | Snyk | Wiz | Orca |
|---------|-----|------|-----|------|
| Actions compromise detection | 110+ sigs | No | No | No |
| Pwn request detection | Yes | No | No | No |
| Behavioral heuristics (zero-day) | 80+ | No | Limited | Limited |
| Runtime monitoring (full job) | Yes | No | Agent only | Agent only |
| Binary analysis in workspace | Yes | No | Yes | Yes |
| Smart egress allowlisting | 80+ domains | Partial | Yes | Yes |
| Exemption with audit trail | Yes | Yes | Yes | Yes |
| Expiring suppressions | Yes | Yes | No | Yes |
| HTML + JSON + SARIF reports | Yes | Yes | Yes | Yes |
| PR blocking | Yes | Yes | Yes | Yes |
| Slack/Teams alerts | Yes | Paid | Paid | Paid |
| GitHub native (no agent) | Yes | Yes | No | No |
| Self-hosted / air-gapped | Yes | No | Paid | Paid |
| Price | **Free / BSL** | $$$ | $$$$ | $$$$$ |

---

## Contributing & License

**License:** [Business Source License 1.1](../LICENSE) — free for non-commercial and research use; converts to Apache 2.0 on 2028-01-01.

Bug reports & feature requests: [github.com/anshumaan-10/supply-chain-guardian/issues](https://github.com/anshumaan-10/supply-chain-guardian/issues)

---

**110+ attack patterns · 17 scanner modules · DevSecOps-ready**

Created by **Anshumaan Singh** · [github.com/anshumaan-10](https://github.com/anshumaan-10)
