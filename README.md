# Supply Chain Guardian — v4.0.2

> **Enterprise-grade CI/CD supply chain security scanner.**
> 110+ real-world attack signatures · 17 scanner modules · Binary analysis · Smart egress allowlisting · Enterprise exemption engine · Runtime monitoring daemon

```
uses: anshumaan-10/supply-chain-guardian@v4
```

By **Anshumaan Singh** ([@anshumaan-10](https://github.com/anshumaan-10))  
License: [Business Source License 1.1](LICENSE)

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

Most scanners only fire **after** a CVE is published — days or weeks later. SCG also detects the **behavioral invariants** of that lifecycle: the patterns that every attack *must* exhibit regardless of implementation. Novel zero-days are caught before any advisory.

**Key innovations in v4.0:**
- **Smart egress allowlisting** — 80+ legitimate domains pre-trusted; only real C2 traffic fires alerts
- **Enterprise exemption engine** — per-repo `.scg-config.yml`, org-wide central config, inline `# scg-ignore` comments, expiring suppressions with audit trail
- **Binary analysis** — detects dropped ELF/PE/Mach-O executables, cryptominers, implants, and malicious tools by magic bytes, name, SHA256, and location
- **Full-lifecycle runtime monitoring** — daemon starts before your build, watches processes/network/filesystem the entire time the runner is up, reports at end of job

---

## Scanner Modules

### Signature Scanners (True-Positive, CVE-Mapped)

| # | Module | Detects | Patterns |
|---|--------|---------|----------|
| 1 | **Compromised Actions** | Known-bad SHA commits, tj-actions/reviewdog mutations | 10+ |
| 2 | **Pwn Request** | `pull_request_target` + checkout, script injection, env poisoning | 8 |
| 3 | **Workflow Analysis** | Unsafe triggers, missing concurrency, template injection | 15+ |
| 4 | **Cache Poisoning** | Broad restore-keys, cross-branch cache injection | 5 |
| 5 | **Permission Audit** | write-all, least-privilege violations, job-scope escalation | 10+ |
| 6 | **Secret Exposure** | AWS/GCP/Azure keys, PATs, AI API keys, 35+ credential patterns | 35+ |
| 7 | **Network Exfiltration** | Reverse shells, DNS exfil, C2 endpoints, tunneling tools | 30+ |
| 8 | **Dependency Integrity** | Compromised npm/PyPI/Maven/RubyGems/Cargo packages | 20+ |
| 9 | **Typosquatting** | Known typosquats + Levenshtein-distance detection (dynamic) | Dynamic |
| 10 | **Provenance Verification** | SLSA attestation, Sigstore, unsigned releases | 10+ |
| 11 | **OIDC Token Audit** | Scope escalation, wildcard audiences, identity confusion | 8 |
| 12 | **Artifact Integrity** | Download without verification, TOCTOU, artifact poisoning | 7 |
| 13 | **Container Security** | Unpinned images, --privileged, Docker socket mount, build-arg secrets | 12 |
| 14 | **Reusable Workflow Trust** | Mutable refs, secret inheritance, external org trust | 10 |
| 15 | **Behavioral Analysis** | 80+ heuristics: obfuscation, dynamic loading, persistence, staging | 80+ |
| 16 | **Cross-Platform CI** | Jenkins, GitLab, CircleCI, Azure DevOps attack patterns | 15+ |

### New in v4.0

| # | Module | Detects |
|---|--------|---------|
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
          runtime-monitor: true      # monitor the full job lifecycle
          scan-binaries: true        # check for dropped executables
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
      # 1. Start monitor BEFORE any build activity
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: SCG — Start Runtime Monitor
        uses: anshumaan-10/supply-chain-guardian@v4
        with:
          mode: monitor-start

      # 2. Your normal build/test/deploy steps
      - run: npm ci
      - run: npm test
      - run: docker build -t myapp:latest .

      # 3. Full scan + collect runtime findings
      - name: SCG — Full Scan
        uses: anshumaan-10/supply-chain-guardian@v4
        with:
          mode: scan
          scan-mode: deep
          fail-on-severity: high
          scan-runtime: true           # include daemon findings
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

### Local CLI

```bash
git clone https://github.com/anshumaan-10/supply-chain-guardian.git
cd supply-chain-guardian
pip install pyyaml requests tabulate colorama jsonschema semver

# Standard scan
python src/main.py --workspace /path/to/my-repo

# Deep + binary scan
python src/main.py --workspace /path/to/my-repo --scan-mode deep

# Paranoid mode (all scanners + binary analysis)
python src/main.py --workspace /path/to/my-repo --scan-mode paranoid

# With custom exceptions config
INPUT_EXCEPTIONS_CONFIG=/path/to/scg-exceptions.yml \
python src/main.py --workspace /path/to/my-repo
```

### Reusable Workflow Pattern (Central Control)

Create one reusable workflow and call it from all your repos:

```yaml
# .github/workflows/supply-chain-scan.yml (in your DevSecOps central repo)
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
          exceptions-config: ${{ inputs.exceptions-config || '' }}
```

---

## Runtime Monitoring

The runtime monitor is a **background daemon** that starts before your build and watches for threats the entire time the runner is alive. This catches attacks that happen *during* `npm install`, `docker build`, or `terraform apply` — not just in workflow YAML.

### What It Monitors

| Category | Examples |
|----------|---------|
| **Process spawn** | Cryptominers (xmrig, minerd), reverse shells (bash -i, nc -e), privilege escalation (sudo -s) |
| **Network connections** | Unexpected outbound TCP, known C2 IP ranges, DNS tunneling (long labels, high-entropy queries) |
| **Filesystem events** | Writes to /tmp, /dev/shm, cron directories, .ssh/, new executables created |
| **Memory access** | /proc/mem reads (TeamPCP CVE-2026-33634 pattern), ptrace attempts |
| **Credentials** | .env, .npmrc, .pypirc, .docker/config.json writes; AWS credential files |
| **Persistence** | systemd unit creation, ~/.bashrc modifications, authorized_keys changes |

### Split-Mode Use Case

```
Timeline:
  t=0s   SCG monitor-start   → daemon forks, begins polling every 5s
  t=2s   npm ci              → monitor watches for postinstall scripts
  t=45s  docker build        → monitor watches for malicious layers
  t=90s  terraform apply     → monitor watches for provider exfiltration
  t=120s SCG scan            → scanner runs + collects all daemon findings
          └─ Job summary shows: 17 static findings, 3 runtime findings (2 exempted)
```

### Runtime Monitor Configuration

```yaml
- uses: anshumaan-10/supply-chain-guardian@v4
  with:
    mode: monitor-start
    runtime-monitor-interval: '3'   # poll every 3s (default: 5)
```

---

## Binary Analysis

The binary scanner runs a **one-time sweep** of the workspace and temp directories to detect executables that should not be there.

### Detection Methods

| Method | Description |
|--------|-------------|
| **Magic bytes** | ELF (`\x7fELF`), PE (`MZ`), Mach-O (`\xcf\xfa\xed\xfe`), Universal binary |
| **Suspicious names** | xmrig, minerd, ncat, socat, chisel, frp, ngrok, cloudflared, sliver, beacon, msfvenom, mimikatz, lazagne |
| **Known-bad SHA256** | Cross-referenced against attack database of 50+ malicious binary hashes |
| **Unexpected location** | Compiled binaries found in .github/, config/, docs/, tests/ trigger HIGH findings |
| **Temp directory sweep** | /tmp, /dev/shm, /var/tmp scanned for dropped executables (deep/paranoid mode) |

### Enabling Binary Analysis

Binary analysis runs automatically in `deep` and `paranoid` scan modes. In `standard`/`quick`, enable explicitly:

```yaml
- uses: anshumaan-10/supply-chain-guardian@v4
  with:
    scan-mode: standard
    scan-binaries: true     # enable binary scanner explicitly
```

---

## Smart Egress Detection

SCG detects **data exfiltration** without generating alert fatigue from legitimate network traffic.

### How It Works

1. **Pre-trusted allowlist** — 80+ legitimate domains ship pre-trusted (GitHub, npm, PyPI, Maven, Docker Hub, GCP, AWS, Azure, CDNs, OS package repos, CI platforms)
2. **Allowlist check first** — every outbound domain is checked against the allowlist before any alert fires
3. **C2 override** — known-bad C2 domains (TeamPCP, Shai-Hulud IOCs) are **never** allowlisted regardless of any config
4. **Org-level additions** — add your internal domains to `.scg-config.yml` egress_allowlist

### What Still Fires Alerts

- Connections to known C2 infrastructure
- DNS exfiltration patterns (base64-encoded subdomains, unusually long queries)
- Reverse shell patterns (bash -i >& /dev/tcp/...)
- Requests to IP addresses directly (no hostname)
- Domains registered < 30 days ago (high entropy + new domain)
- Connections to Tor exit nodes or known-bad IP ranges

### Pre-Trusted Domains (Partial List)

```
GitHub:     github.com, api.github.com, raw.githubusercontent.com, *.ghcr.io
npm:        registry.npmjs.org, *.npmjs.com
PyPI:       pypi.org, files.pythonhosted.org
Maven:      repo.maven.apache.org, central.sonatype.org
Docker:     hub.docker.com, registry-1.docker.io, *.docker.com
GCP:        *.googleapis.com, *.gcr.io, *.pkg.dev
AWS:        *.amazonaws.com, *.awsstatic.com
Azure:      *.azure.com, *.azurecr.io, *.msecnd.net
OS repos:   packages.debian.org, dl.google.com, archive.ubuntu.com
CDN:        *.cloudflare.com, *.fastly.net, *.akamaized.net
CI:         *.circleci.com, *.travis-ci.com, app.codecov.io
```

---

## Exception & Exemption System

SCG ships with a **three-layer exemption system** that mirrors enterprise security workflows — no different from how Snyk, Veracode, or Prisma handle suppressions. Every exemption is preserved in the audit trail for compliance.

### Layer 1: Inline Code Suppression

Suppress a finding on a specific line:

```yaml
# In your workflow file:
- run: curl https://internal-registry.corp.example.com/healthcheck  # scg-ignore:SCA-017
- run: ngrok http 8080  # scg-ignore-next-line:SCA-017
- run: some-command
```

Wildcard suppression (suppress entire category):

```yaml
- run: some-script.sh  # scg-ignore:SCA-*   # suppresses all findings on this line
```

### Layer 2: Repository-Level Config

Create `.scg-config.yml` in your repo root:

```yaml
# .scg-config.yml
version: "1"

exemptions:
  - rule_id: SCA-017          # Specific rule ID
    reason: "ngrok used for Playwright e2e testing only, restricted to PR preview branches"
    approved_by: "security-team"
    expires: "2026-01-01"      # Auto-expires — forces review
    scope: "ci-only"           # for documentation / filtering

  - rule_id: "SCA-0*"          # Wildcard — all info-level network rules
    reason: "Internal network scanning allowed per security policy SEC-042"
    approved_by: "ciso"

egress_allowlist:
  - "*.internal.corp.example.com"
  - "artifactory.corp.example.com"
  - "sonarqube.infra.example.com"

disabled_scanners:
  - "provenance"               # Team doesn't use SLSA yet

severity_overrides:
  SCA-042: medium              # Downgrade from high (risk-accepted, tracked in JIRA-1234)
```

### Layer 3: Org-Wide Central Config

Pass a central exceptions file from your DevSecOps repo:

```yaml
# In your reusable workflow or per-repo workflow:
- uses: anshumaan-10/supply-chain-guardian@v4
  with:
    exceptions-config: /path/to/central-scg-exceptions.yml
    # Or via secret:
    # exceptions-config: ${{ vars.SCG_CENTRAL_EXCEPTIONS_PATH }}
```

Or via environment variable:

```bash
export SCG_EXCEPTIONS=/path/to/central-scg-exceptions.yml
python src/main.py --workspace .
```

### Exemption Priority

```
Inline # scg-ignore  >  .scg-config.yml in repo  >  central config  >  defaults
```

### Audit Trail

Exempted findings are **never deleted** — they stay in the JSON report with `"status": "exempted"` and `"exemption_reason": "..."`. This provides a compliance-ready audit log of every suppression decision.

```json
{
  "id": "SCA-017",
  "severity": "medium",
  "status": "exempted",
  "exemption_reason": "ngrok used for Playwright e2e testing only",
  "approved_by": "security-team",
  "expires": "2026-01-01"
}
```

### Exemptions Do NOT Block the Pipeline

A finding with `status: exempted` is excluded from the pass/fail threshold. The job still succeeds, but the finding is visible in the report and SARIF for audit purposes.

---

## Configuration Reference

### Action Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `mode` | `scan` | `scan` · `monitor-start` · `monitor-stop` |
| `scan-mode` | `standard` | `quick` · `standard` · `deep` · `paranoid` |
| `fail-on-severity` | `high` | `critical` · `high` · `medium` · `low` · `info` |
| `exceptions-config` | `` | Path to central/org exceptions YAML file |
| `scan-binaries` | `false` | Enable binary analysis scanner (auto-on in deep/paranoid) |
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
| `alert-on-severity` | `high` | Minimum severity to send alerts |
| `sarif-output` | `true` | Generate SARIF report |
| `json-output` | `supply-chain-guardian-report.json` | JSON report path |
| `table-output` | `true` | Print table to job logs |
| `block-pr` | `true` | Block PR merge on critical findings |
| `create-issue` | `true` | Open GitHub issue on critical findings |
| `auto-comment-pr` | `true` | Comment scan results on PRs |
| `github-token` | `${{ github.token }}` | Token for API access |
| `verbose` | `false` | Debug output |

### Action Outputs

| Output | Description |
|--------|-------------|
| `scan-status` | `PASSED` · `WARNING` · `FAILED` |
| `total-findings` | Total findings (includes exempted) |
| `critical-findings` | Critical severity count (active only) |
| `high-findings` | High severity count (active only) |
| `medium-findings` | Medium severity count |
| `low-findings` | Low severity count |
| `exempted-findings` | Count of suppressed findings (audit) |
| `report-path` | Path to JSON report |
| `sarif-path` | Path to SARIF report |

### Scan Modes

| Mode | What Runs | Speed | Use Case |
|------|-----------|-------|---------|
| `quick` | Signatures only, no behavioral | < 10s | PR drafts, fast feedback |
| `standard` | Signatures + behavioral | 10–30s | Default for all branches |
| `deep` | Standard + deep heuristics + binary scan | 30–90s | Main branch, release PRs |
| `paranoid` | Everything + /tmp scan + max patterns | 90s+ | Release pipelines, audit |

### .scg-config.yml Reference

See [examples/scg-config.yml](examples/scg-config.yml) for a fully annotated example.

---

## Outputs & Reports

### Console Output

Every scan prints a banner, per-scanner results, and a summary table:

```
╔══════════════════════════════════════════════════════════════════╗
║  ███████╗ ██████╗  ██████╗                                       ║
║  ██╔════╝██╔════╝ ██╔════╝   Supply Chain Guardian v4.0.0        ║
║  ███████╗██║      ██║        By Anshumaan Singh                  ║
║  ╚════██║██║      ██║        github.com/anshumaan-10             ║
║  ███████║╚██████╗ ╚██████╗                                       ║
║  ╚══════╝ ╚═════╝  ╚═════╝                                       ║
╚══════════════════════════════════════════════════════════════════╝

  Scanners Run:        17
  Patterns Checked:    110
  Total Findings:      4
  Exempted:            1 (still in report, won't block)

  ┌─────────────┬──────────┬────────────────────────────────────────┐
  │ Severity    │ Count    │ Scanners                               │
  ├─────────────┼──────────┼────────────────────────────────────────┤
  │ CRITICAL    │ 0        │                                        │
  │ HIGH        │ 1        │ secret_exposure                        │
  │ MEDIUM      │ 2        │ network_exfiltration, permissions      │
  │ LOW         │ 1        │ dependency_integrity                   │
  └─────────────┴──────────┴────────────────────────────────────────┘

  Verdict: ⚠ WARNING — 1 HIGH finding requires attention
```

### JSON Report

Machine-readable output with all findings, metadata, exemption details, and timestamps. Compatible with JIRA, Splunk, Datadog, custom dashboards.

### SARIF Report

SARIF 2.1.0 output compatible with GitHub Advanced Security. Findings appear in the **Security** tab of your repo with inline annotations on the exact line.

### Artifacts

All reports auto-uploaded as workflow artifacts (`supply-chain-guardian-report`), retained for 90 days.

---

## CLI Usage

```bash
# Basic scan
python src/main.py --workspace /path/to/repo

# Available environment variables (mirrors action inputs)
INPUT_SCAN_MODE=paranoid
INPUT_FAIL_ON_SEVERITY=medium
INPUT_SCAN_WORKFLOWS=true
INPUT_SCAN_DEPENDENCIES=true
INPUT_SCAN_SECRETS=true
INPUT_SCAN_NETWORK=true
INPUT_SCAN_PERMISSIONS=true
INPUT_SCAN_PROVENANCE=true
INPUT_VERBOSE=true
INPUT_EXCEPTIONS_CONFIG=/path/to/scg-config.yml

# Runtime monitor
python src/runtime_monitor.py start 5   # start daemon, poll every 5s
python src/runtime_monitor.py status    # check daemon status
python src/runtime_monitor.py stop      # stop daemon, print findings

# With exceptions config
INPUT_EXCEPTIONS_CONFIG=.scg-config.yml \
INPUT_SCAN_MODE=deep \
python src/main.py --workspace .
```

---

## Architecture

```
supply-chain-guardian/
├── action.yml                   # Composite action (scan / monitor-start / monitor-stop)
├── src/
│   ├── main.py                  # Entry point: orchestrator, scanner registry, reporting
│   ├── runtime_monitor.py       # Background daemon: fork, poll, baseline, collect
│   ├── db/
│   │   ├── attack_db.py         # 110 signature patterns (SCA-001 → SCA-110)
│   │   └── threat_feed.py       # Live IOC feed fetcher (threat-feed branch)
│   ├── scanners/
│   │   ├── base_scanner.py      # Abstract base: add_finding(), search_file_for_patterns()
│   │   ├── actions_scanner.py   # Compromised actions, SHA validation
│   │   ├── behavioral_scanner.py# 80+ heuristic patterns
│   │   ├── binary_scanner.py    # ★ NEW: ELF/PE/Mach-O, cryptominers, implants
│   │   ├── cache_scanner.py     # Cache poisoning
│   │   ├── container_scanner.py # Docker supply chain
│   │   ├── cross_platform_scanner.py  # Jenkins, GitLab, CircleCI, ADO
│   │   ├── dependency_scanner.py      # Package integrity
│   │   ├── network_scanner.py   # Egress + egress allowlisting ★ ENHANCED
│   │   ├── oidc_scanner.py      # OIDC token abuse
│   │   ├── permissions_scanner.py     # Least-privilege audit
│   │   ├── provenance_scanner.py      # SLSA attestation
│   │   ├── pwn_request_scanner.py     # Pwn request patterns
│   │   ├── reusable_workflow_scanner.py # Workflow trust
│   │   ├── runtime_scanner.py   # Runtime credential dump
│   │   ├── secrets_scanner.py   # Credential exposure
│   │   ├── typosquatting_scanner.py   # Package typosquats
│   │   └── workflow_scanner.py  # Workflow misconfiguration
│   ├── alerting/
│   │   ├── slack_alerter.py     # Slack webhook integration
│   │   └── teams_alerter.py     # MS Teams webhook integration
│   ├── reporters/
│   │   ├── sarif_reporter.py    # SARIF 2.1.0 output
│   │   └── json_reporter.py     # JSON report
│   └── utils/
│       ├── config.py            # ScanConfig: from_environment(), from_cli_args()
│       ├── exceptions.py        # ★ NEW: Exemption engine, allowlist, inline suppression
│       ├── files.py             # File utilities
│       └── logger.py            # Colored console output
├── docs/
│   ├── ATTACK_PATTERNS.md       # Full pattern reference (SCA-001 → SCA-110)
│   ├── HARDENING.md             # Security hardening guide
│   ├── INSTALL.md               # Multi-platform installation
│   └── README.md                # Extended documentation
├── examples/
│   ├── basic-scan.yml           # Minimal workflow
│   ├── devsecops-pipeline.yml   # Full enterprise pipeline
│   ├── paranoid-scan.yml        # Maximum detection
│   ├── reusable-workflow.yml    # Centralized reusable pattern
│   └── scg-config.yml           # ★ NEW: Full exceptions config example
└── tests/                       # 45+ unit tests
```

### Detection Pipeline

```
  Workspace
      │
      ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Scanner Registry (17 modules run in parallel phases)        │
  │                                                             │
  │  Phase 1: Workflow YAML, Actions, Pwn Request, Cache       │
  │  Phase 2: Network, Secrets, Permissions, Provenance        │
  │  Phase 3: Dependencies, Typosquatting, OIDC, Artifacts     │
  │           Container, Reusable, Behavioral, Cross-Platform  │
  │  Phase 4 (deep+): Binary Analysis                          │
  └───────────────────────┬─────────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Exception Engine     │
              │  · Inline suppress    │
              │  · .scg-config.yml    │
              │  · Central config     │
              │  · Expiry check       │
              └───────────┬───────────┘
                          │
              ┌───────────▼───────────┐
              │  Active vs Exempted   │
              │  Findings Split       │
              └──────┬──────────┬─────┘
                     │          │
                     ▼          ▼
              Verdict/Fail  Audit Trail
              (active only) (in report)
```

---

## Comparison with Commercial Tools

| Feature | SCG (Free) | Snyk | Aqua | Prisma Cloud |
|---------|-----------|------|------|--------------|
| Actions compromise detection | ✅ 110+ sigs | ❌ | ❌ | ❌ |
| Pwn request detection | ✅ | ❌ | ❌ | ❌ |
| Behavioral heuristics (zero-day) | ✅ 80+ | ❌ | ⚠ limited | ⚠ limited |
| Runtime monitoring (full job) | ✅ | ❌ | ⚠ agent only | ⚠ agent only |
| Binary analysis in workspace | ✅ | ❌ | ✅ | ✅ |
| Smart egress allowlisting | ✅ 80+ domains | ⚠ | ✅ | ✅ |
| Exemption with audit trail | ✅ | ✅ | ✅ | ✅ |
| Inline # scg-ignore suppression | ✅ | ✅ | ❌ | ❌ |
| Expiring suppressions | ✅ | ✅ | ❌ | ✅ |
| SARIF output | ✅ | ✅ | ✅ | ✅ |
| PR blocking | ✅ | ✅ | ✅ | ✅ |
| Slack/Teams alerts | ✅ | ✅ (paid) | ✅ (paid) | ✅ (paid) |
| GitHub native (no agent) | ✅ | ✅ | ❌ | ❌ |
| Self-hosted / air-gapped | ✅ | ❌ | ✅ (paid) | ✅ (paid) |
| **Price** | **Free / BSL** | $$$  | $$$$ | $$$$$ |

---

## Contributing & License

**License:** [Business Source License 1.1](LICENSE) — free for non-production use; converts to Apache 2.0 on 2028-01-01.

**Bug reports & feature requests:** Open an issue at [github.com/anshumaan-10/supply-chain-guardian](https://github.com/anshumaan-10/supply-chain-guardian)

**Pattern contributions:** See [docs/ATTACK_PATTERNS.md](docs/ATTACK_PATTERNS.md) for the pattern format.

---

*Supply Chain Guardian is a security research project. No warranty is expressed or implied. Run it. Break it. Make it better.*

**110+ attack patterns · 17 scanner modules · Binary analysis · Runtime monitoring · DevSecOps-ready**

Created by **Anshumaan Singh** ([github.com/anshumaan-10](https://github.com/anshumaan-10))

## Overview

This repository contains project code and supporting assets. It is maintained actively with periodic updates.

## Getting Started

1. Clone this repository.
2. Install dependencies as documented in the project files.
3. Run/build using the project-specific commands.

## Repository Structure

Key source code, configuration, and documentation are organized by folders at the repository root.

## Contribution Guidelines

Please open an issue for major changes and submit focused pull requests with clear descriptions.
