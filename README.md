# Supply Chain Guardian

**Enterprise-grade supply chain security scanner for GitHub Actions & CI/CD pipelines.**

90+ attack patterns | 16 scanner modules | 80+ behavioral indicators | DevSecOps-ready

Created by **Anshumaan Singh** ([github.com/anshumaan-10](https://github.com/anshumaan-10))

---

## Quick Start

```yaml
- uses: anshumaan-10/supply-chain-guardian@v2
  with:
    scan-mode: standard
    fail-on-severity: high
```

## What It Scans

| Scanner | Coverage |
|---------|----------|
| Compromised Actions | Known-bad SHAs, mutable tags |
| Pwn Requests | pull_request_target dangers |
| OIDC Token Audit | Token scope, exfiltration, identity confusion |
| Artifact Integrity | Unsigned uploads, TOCTOU, verification gaps |
| Container Security | Unpinned images, --privileged, socket mount |
| Reusable Workflows | Trust boundaries, secret inheritance |
| Dependencies | Package compromise, typosquatting |
| Secrets | Credential exposure and exfiltration |
| Network | Reverse shells, DNS exfil, C2 |
| Behavioral | 80+ patterns detecting future attacks |

## Documentation

- [Full Documentation](docs/README.md) — complete configuration, examples, architecture
- [Hardening Guide](docs/HARDENING.md) — securing your GitHub Actions workflows
- [Attack Patterns](docs/ATTACK_PATTERNS.md) — all 90 known patterns

## Pipeline Placement

```
Pre-Build Scan >> Build >> Post-Build Scan >> Deploy
```

See [examples/devsecops-pipeline.yml](examples/devsecops-pipeline.yml) for a complete 5-stage DevSecOps pipeline.

## License

Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved. [BSL 1.1](LICENSE)
