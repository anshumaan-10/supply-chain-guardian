# Supply Chain Guardian — Multi-Platform Installation Guide

> **v3.0.0** | By Anshumaan Singh ([@anshumaan-10](https://github.com/anshumaan-10))

## Supported Platforms

| Platform | Config File | Scanner | Status |
|----------|-------------|---------|--------|
| GitHub Actions | `.github/workflows/*.yml` | Full (17 scanners) | ✅ Production |
| Jenkins | `Jenkinsfile` | Cross-Platform Scanner | ✅ Production |
| GitLab CI | `.gitlab-ci.yml` | Cross-Platform Scanner | ✅ Production |
| CircleCI | `.circleci/config.yml` | Cross-Platform Scanner | ✅ Production |
| Azure DevOps | `azure-pipelines.yml` | Cross-Platform Scanner | ✅ Production |
| Local CLI | Any directory | All scanners | ✅ Production |

---

## 1. GitHub Actions (Recommended)

### Basic Usage

```yaml
name: Supply Chain Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Supply Chain Guardian Scan
        uses: anshumaan-10/supply-chain-guardian@v3
        with:
          scan-mode: deep
          fail-on: high
          output-format: sarif
```

### Full Configuration

```yaml
      - name: Supply Chain Guardian Scan
        uses: anshumaan-10/supply-chain-guardian@v3
        with:
          scan-mode: paranoid        # quick | deep | paranoid
          fail-on: medium            # critical | high | medium | low | info
          output-format: sarif       # table | json | sarif | github
          scan-workflows: true
          scan-dependencies: true
          scan-secrets: true
          scan-network: true
          scan-permissions: true
          scan-runtime: true
          scan-provenance: true
          live-threat-feed: true     # Fetch latest IOCs from threat-feed branch
          slack-webhook: ${{ secrets.SLACK_WEBHOOK }}
          teams-webhook: ${{ secrets.TEAMS_WEBHOOK }}
```

### With SARIF Upload (GitHub Code Scanning)

```yaml
      - name: Supply Chain Guardian Scan
        uses: anshumaan-10/supply-chain-guardian@v3
        with:
          scan-mode: deep
          output-format: sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scg-results.sarif
```

---

## 2. Jenkins

### Pipeline Integration

```groovy
// Jenkinsfile
pipeline {
    agent any

    stages {
        stage('Supply Chain Security') {
            steps {
                sh '''
                    pip install pyyaml requests tabulate colorama jsonschema semver
                    git clone https://github.com/anshumaan-10/supply-chain-guardian.git /tmp/scg
                    cd /tmp/scg/src
                    python main.py \
                        --workspace "${WORKSPACE}" \
                        --scan-mode deep \
                        --fail-on high \
                        --output-format json
                '''
            }
        }
    }
}
```

### As a Shared Library Step

```groovy
def supplyChainScan(Map args = [:]) {
    def mode = args.get('mode', 'deep')
    def failOn = args.get('failOn', 'high')

    sh """
        pip install -q pyyaml requests tabulate colorama jsonschema semver
        git clone --depth 1 https://github.com/anshumaan-10/supply-chain-guardian.git /tmp/scg
        cd /tmp/scg/src && python main.py \
            --workspace "${WORKSPACE}" \
            --scan-mode ${mode} \
            --fail-on ${failOn} \
            --output-format json
    """
}
```

Supply Chain Guardian automatically detects and scans `Jenkinsfile` for:
- Secret exposure via `echo`, `println`, `sh` blocks
- Shared library references with mutable versions
- Insecure pipeline practices
- Pipe-to-shell patterns

---

## 3. GitLab CI

### `.gitlab-ci.yml` Integration

```yaml
supply-chain-scan:
  image: python:3.11-slim
  stage: test
  before_script:
    - pip install pyyaml requests tabulate colorama jsonschema semver
    - git clone --depth 1 https://github.com/anshumaan-10/supply-chain-guardian.git /tmp/scg
  script:
    - cd /tmp/scg/src && python main.py
        --workspace "${CI_PROJECT_DIR}"
        --scan-mode deep
        --fail-on high
        --output-format json
  artifacts:
    paths:
      - scg-results.json
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

Supply Chain Guardian scans `.gitlab-ci.yml` for:
- CI_JOB_TOKEN / PRIVATE_TOKEN exposure
- Remote template includes (external dependencies)
- Docker images using `:latest` tags
- Hardcoded secrets in variables blocks

---

## 4. CircleCI

### `.circleci/config.yml` Integration

```yaml
version: 2.1

jobs:
  supply-chain-scan:
    docker:
      - image: python:3.11-slim
    steps:
      - checkout
      - run:
          name: Install Supply Chain Guardian
          command: |
            pip install pyyaml requests tabulate colorama jsonschema semver
            git clone --depth 1 https://github.com/anshumaan-10/supply-chain-guardian.git /tmp/scg
      - run:
          name: Run Supply Chain Scan
          command: |
            cd /tmp/scg/src && python main.py \
              --workspace ~/project \
              --scan-mode deep \
              --fail-on high \
              --output-format json
      - store_artifacts:
          path: /tmp/scg/src/scg-results.json
          destination: security-scan

workflows:
  security:
    jobs:
      - supply-chain-scan
```

Supply Chain Guardian scans `.circleci/config.yml` for:
- CIRCLE_TOKEN exposure
- Orbs with volatile/mutable versions
- Cache poisoning risks
- SSH key management issues

---

## 5. Azure DevOps

### `azure-pipelines.yml` Integration

```yaml
trigger:
  branches:
    include:
      - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: |
      pip install pyyaml requests tabulate colorama jsonschema semver
      git clone --depth 1 https://github.com/anshumaan-10/supply-chain-guardian.git /tmp/scg
      cd /tmp/scg/src && python main.py \
        --workspace "$(Build.SourcesDirectory)" \
        --scan-mode deep \
        --fail-on high \
        --output-format json
    displayName: 'Supply Chain Guardian Scan'

  - publish: $(Build.SourcesDirectory)/scg-results.json
    artifact: SecurityScanResults
    condition: always()
```

Supply Chain Guardian scans `azure-pipelines.yml` for:
- System.AccessToken exposure
- Secret variable echo/logging
- External template references
- Pipe-to-shell patterns

---

## 6. Local CLI

### Quick Install

```bash
git clone https://github.com/anshumaan-10/supply-chain-guardian.git
cd supply-chain-guardian
pip install pyyaml requests tabulate colorama jsonschema semver
```

### Run Scan

```bash
cd src
python main.py --workspace /path/to/your/repo --scan-mode deep --fail-on high
```

### Scan Modes

| Mode | Description | Speed |
|------|-------------|-------|
| `quick` | Essential checks only | ~1s |
| `deep` | Full analysis + script scanning | ~5s |
| `paranoid` | Everything + behavioral analysis | ~15s |

### Output Formats

```bash
# Terminal table (default)
python main.py --workspace /path/to/repo

# JSON report
python main.py --workspace /path/to/repo --output-format json

# SARIF (for code scanning tools)
python main.py --workspace /path/to/repo --output-format sarif

# GitHub annotations
python main.py --workspace /path/to/repo --output-format github
```

---

## Detection Coverage (v3.0.0)

| Category | Patterns | Examples |
|----------|----------|---------|
| Actions Compromise | 20+ | tj-actions, Trivy/TeamPCP (75 SHAs), Checkmarx KICS, reviewdog |
| Credential Exfiltration | 15+ | Runner.Worker memory dump, env harvesting, IMDS access |
| Package Compromise | 25+ | Shai-Hulud (1193+ versions), CanisterWorm, LiteLLM, Scavenger |
| Network Exfiltration | 30+ | TeamPCP C2, ICP fallback, Cloudflare tunnel, reverse shells |
| Dependency Confusion | 10+ | Typosquatting, namespace hijacking |
| PWN Request | 8+ | pull_request_target exploitation |
| Cross-Platform CI/CD | 20+ | Jenkins, GitLab CI, CircleCI, Azure DevOps patterns |
| OIDC/Artifact/Cache | 15+ | Token misconfiguration, cache poisoning, artifact tampering |

### Total: 110 bundled attack patterns + live threat feed

---

## Live Threat Feed

Supply Chain Guardian automatically fetches the latest threat intelligence at scan time:

```
Bundled patterns: 110
+ Live feed (GHSA): ~20-30 additional
= Total protection: 130-140+ patterns
```

The live feed updates every 6 hours via GitHub Actions cron job and includes:
- Latest GitHub Security Advisories
- OSV.dev vulnerability feed
- npm/PyPI malicious package reports
- Real-time IOC updates

---

## Requirements

- Python 3.9+
- Dependencies: `pyyaml`, `requests`, `tabulate`, `colorama`, `jsonschema`, `semver`

---

## License

Business Source License 1.1 (BSL 1.1) — See [LICENSE](../LICENSE) for details.

Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
