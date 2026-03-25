# Supply Chain Guardian

**Enterprise-grade supply chain security scanner for GitHub Actions & CI/CD pipelines.**

Detects **90+ known attack patterns** across **16 scanner modules** — plus **80+ behavioral indicators** of future compromises that no signature database can catch. Scans, alerts, and blocks pipelines on true-positive threats.

Created by **Anshumaan Singh** ([github.com/anshumaan-10](https://github.com/anshumaan-10))

```yaml
uses: anshumaan-10/supply-chain-guardian@v2
```

---

## What It Does

Every supply chain attack on GitHub Actions follows the same lifecycle:

```
Infiltrate >> Persist >> Exfiltrate >> Weaponise
```

Most security tools only detect attacks **after** a signature is published — days or weeks later. Supply Chain Guardian detects the **behavioral invariants** of that lifecycle, catching novel attacks before any advisory is issued.

---

## Scanner Modules (16)

### Signature Scanners (True-Positive Detection)

| # | Scanner | What It Detects | Patterns |
|---|---------|----------------|----------|
| 1 | **Compromised Actions** | Known-bad commit SHAs, tag mutation victims (tj-actions, reviewdog) | 10+ |
| 2 | **Pwn Request** | `pull_request_target` + checkout, script injection, env injection | 8 |
| 3 | **Workflow Analysis** | Unsafe triggers, missing concurrency, overly broad paths | 15+ |
| 4 | **Cache Poisoning** | Broad restore-keys, cross-branch cache injection | 5 |
| 5 | **Permission Audit** | write-all, missing least-privilege, job-level violations | 10+ |
| 6 | **Secret Exposure** | Hardcoded keys (AWS, GitHub, AI/LLM), exfiltration patterns | 35+ |
| 7 | **Network Exfiltration** | Reverse shells, DNS exfil, tunneling, C2 endpoints | 30+ |
| 8 | **Dependency Integrity** | Malicious packages across npm, PyPI, Maven, RubyGems, Cargo | 20+ |
| 9 | **Typosquatting** | Known typosquats + Levenshtein distance detection | Dynamic |
| 10 | **Provenance Verification** | SLSA attestation, Sigstore, unsigned releases | 10+ |
| 11 | **Runtime Monitor** | Credential dumping, memory scraping, proc filesystem abuse | 15+ |

### New Scanner Categories (v2.0)

| # | Scanner | What It Detects |
|---|---------|----------------|
| 12 | **OIDC Token Audit** | Token scope escalation, exfiltration, wildcard audiences, identity confusion in PR contexts |
| 13 | **Artifact Integrity** | Unsigned uploads, download without verification, workflow_run artifact poisoning, TOCTOU |
| 14 | **Container Security** | Unpinned base images, --privileged, Docker socket mount, insecure registries, build-arg secrets |
| 15 | **Reusable Workflow Trust** | Mutable refs, secret inheritance, input injection, external org trust boundaries |
| 16 | **Behavioral Analysis** | 80+ patterns across 10 categories (obfuscation, dynamic loading, persistence, etc.) |

---

## Quick Start

### Basic Usage

```yaml
name: Supply Chain Security
on: [push, pull_request]
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: anshumaan-10/supply-chain-guardian@v2
        with:
          scan-mode: standard
          fail-on-severity: high
```

### Paranoid Mode (Maximum Detection)

```yaml
      - uses: anshumaan-10/supply-chain-guardian@v2
        with:
          scan-mode: paranoid
          fail-on-severity: medium
          scan-runtime: 'true'
          verbose: 'true'
```

---

## DevSecOps Pipeline Placement

### Where to Scan in Your Pipeline

```
+------------------+     +-----------+     +-------------------+     +--------+
| Pre-Build Scan   | --> |   Build   | --> | Post-Build Scan   | --> | Deploy |
| (source, deps,   |     | (compile, |     | (container, art-  |     |        |
|  workflows,      |     |  test)    |     |  ifact integrity) |     |        |
|  secrets, OIDC)  |     |           |     |                   |     |        |
+------------------+     +-----------+     +-------------------+     +--------+
        |                                          |
        v                                          v
  BLOCK if critical                        BLOCK if critical
  (poisoned deps,                          (tampered images,
   compromised actions)                     unsigned artifacts)
```

### Pre-Build Scan (BEFORE `docker build` / `npm ci` / `go build`)

Catches: compromised actions, poisoned dependencies, secret exposure, OIDC abuse, pwn requests.

```yaml
  pre-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anshumaan-10/supply-chain-guardian@v2
        id: scan
        with:
          scan-mode: deep
          fail-on-severity: high
```

### Post-Build Scan (AFTER build, BEFORE push/deploy)

Catches: tampered artifacts, unsigned images, Dockerfile issues, container escape patterns.

```yaml
  post-build:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anshumaan-10/supply-chain-guardian@v2
        with:
          scan-mode: paranoid
          fail-on-severity: high
```

### Docker Build Pipeline

**Critical rule: scan BEFORE push. If a finding is detected between build and push, the image is NEVER pushed to the registry.**

See [examples/docker-pipeline.yml](../examples/docker-pipeline.yml) for the complete workflow.

---

## Complete Configuration

| Input | Default | Description |
|-------|---------|-------------|
| `scan-mode` | `standard` | `quick`, `standard`, `deep`, `paranoid` |
| `fail-on-severity` | `high` | `critical`, `high`, `medium`, `low`, `info` |
| `scan-workflows` | `true` | Scan workflow files (enables 7 sub-scanners) |
| `scan-dependencies` | `true` | Package dependency scanning |
| `scan-secrets` | `true` | Secret exposure detection |
| `scan-network` | `true` | Network exfiltration patterns |
| `scan-permissions` | `true` | Permission audit |
| `scan-provenance` | `true` | Provenance verification |
| `scan-runtime` | `false` | Runtime monitoring (enable for paranoid mode) |
| `verbose` | `false` | Detailed debug output |
| `exclude-paths` | `` | Comma-separated paths to exclude |
| `slack-webhook-url` | `` | Slack alerting |
| `teams-webhook-url` | `` | Microsoft Teams alerting |
| `alert-on-severity` | `high` | Minimum severity for alerts |
| `sarif-output` | `true` | SARIF report for GitHub Advanced Security |
| `json-output` | `...report.json` | JSON report path |
| `github-token` | `github.token` | GitHub API token |
| `block-pr` | `true` | Block PR merge on critical findings |
| `create-issue` | `true` | Create issue on critical findings |
| `auto-comment-pr` | `true` | Comment on PRs with results |

## Outputs

| Output | Description |
|--------|-------------|
| `scan-status` | `PASSED`, `WARNING`, or `FAILED` |
| `total-findings` | Total number of findings |
| `critical-findings` | Number of critical findings |
| `high-findings` | Number of high findings |
| `medium-findings` | Number of medium findings |
| `low-findings` | Number of low findings |
| `report-path` | Path to JSON report |
| `sarif-path` | Path to SARIF report |

---

## Attack Database

**90 known attack patterns** (SCA-001 to SCA-090) organized by category:

| Category | Pattern Range | Count |
|----------|--------------|-------|
| Actions Compromise | SCA-001 to SCA-010 | 10 |
| Pwn Requests | SCA-011 to SCA-018 | 8 |
| Credential Exfiltration | SCA-019 to SCA-030 | 12 |
| Package Compromise | SCA-031 to SCA-040 | 10 |
| Build System | SCA-041 to SCA-045 | 5 |
| Dependency Confusion | SCA-046 to SCA-050 | 5 |
| Typosquatting | SCA-051 to SCA-055 | 5 |
| Container Supply Chain | SCA-056 to SCA-058 | 3 |
| Script Injection | SCA-059 | 1 |
| AI/LLM Key Exposure | SCA-060 | 1 |
| **OIDC Token Abuse** | SCA-061 to SCA-066 | **6** |
| **Artifact Integrity** | SCA-067 to SCA-072 | **6** |
| **Container Security** | SCA-073 to SCA-083 | **11** |
| **Reusable Workflows** | SCA-084 to SCA-090 | **7** |

Plus **80+ behavioral patterns** across obfuscation, dynamic code loading, credential harvesting, persistence, control flow anomalies, trust boundary violations, artifact tampering, shadow dependencies, and covert channels.

---

## Blocking Logic

Supply Chain Guardian uses a **true-positive blocking strategy**:

- **Signature matches** (compromised SHAs, known-bad patterns) → **BLOCK** at threshold
- **Behavioral matches** → **Alert only** unless critical (e.g., curl|sh, base64|sh are always TP)
- **Combined** → BLOCK if any finding meets the `fail-on-severity` threshold

This prevents false-positive pipeline failures while catching real attacks.

---

## Examples

| Example | Description |
|---------|-------------|
| [basic-scan.yml](../examples/basic-scan.yml) | Simple PR/push scan |
| [paranoid-scan.yml](../examples/paranoid-scan.yml) | Maximum detection mode |
| [dependency-scan.yml](../examples/dependency-scan.yml) | Dependency-focused scan |
| [devsecops-pipeline.yml](../examples/devsecops-pipeline.yml) | **Full 5-stage DevSecOps pipeline** |
| [docker-pipeline.yml](../examples/docker-pipeline.yml) | **Docker build scan pipeline** |
| [reusable-workflow.yml](../examples/reusable-workflow.yml) | Reusable workflow pattern |

---

## FAQ

### Q: Where should I place the scan in my pipeline?

**Before the build** to catch compromised dependencies and actions. **After the build** to catch tampered artifacts and containers. See the [DevSecOps pipeline example](../examples/devsecops-pipeline.yml).

### Q: How do I scan Docker images?

Supply Chain Guardian scans Dockerfiles for unpinned base images, pipe-to-shell patterns, and build-arg secrets. For image-level vulnerability scanning, combine with Trivy or Grype. See [docker-pipeline.yml](../examples/docker-pipeline.yml).

### Q: Why does it block my pipeline?

A finding at or above your `fail-on-severity` threshold was detected. Check the scan output for the specific finding and its remediation guidance. To get alerts without blocking, set `fail-on-severity: critical`.

### Q: How do I pin actions to SHA?

Replace `uses: actions/checkout@v4` with `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`. The SHA ensures the action code cannot be changed without your knowledge.

---

## Architecture

```
src/
  main.py                          # Orchestrator (DevSecOps pipeline phases)
  scanners/
    base_scanner.py                # Abstract base class
    compromised_action_scanner.py  # SHA / tag detection
    pwn_request_scanner.py         # pull_request_target analysis
    workflow_scanner.py            # General workflow scanning
    cache_poisoning_scanner.py     # Cache attack patterns
    permission_scanner.py          # Least-privilege audit
    secret_scanner.py              # Secret detection
    network_scanner.py             # Network exfiltration
    dependency_scanner.py          # Package scanning
    typosquat_scanner.py           # Levenshtein detection
    provenance_scanner.py          # Integrity verification
    runtime_scanner.py             # Runtime monitoring
    oidc_scanner.py                # OIDC token audit (NEW)
    artifact_scanner.py            # Artifact integrity (NEW)
    container_scanner.py           # Container security (NEW)
    reusable_workflow_scanner.py   # Reusable workflow trust (NEW)
    behavioral_scanner.py          # 80+ behavioral patterns
  reporters/
    table_reporter.py              # Colored terminal tables
    json_reporter.py               # Structured JSON
    sarif_reporter.py              # GitHub Code Scanning
    github_reporter.py             # PR comments, issues, annotations
  alerting/
    slack_alerter.py               # Slack webhook
    teams_alerter.py               # Teams webhook
  db/
    attack_db.py                   # 90 attack patterns
  utils/
    config.py                      # 22 configuration inputs
    logger.py                      # Color-coded arrow logging
    files.py                       # File and YAML utilities
```

---

## License

Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.

This software is distributed under the [Business Source License 1.1](../LICENSE).
Use only via the published GitHub Action: `anshumaan-10/supply-chain-guardian@v2`.

---

**Built by Anshumaan Singh** | [github.com/anshumaan-10](https://github.com/anshumaan-10)
