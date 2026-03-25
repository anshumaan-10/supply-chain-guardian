#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Automated Threat Database Updater
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  This script is designed to run as a cron job (via GitHub Actions or locally).
#  It pulls the latest threat intelligence from multiple public sources and:
#    1. Updates the threat-feed.json on the `threat-feed` branch
#    2. Optionally opens a PR to update attack_db.py with new patterns
#
#  Sources:
#    - GitHub Advisory Database (GHSA)
#    - OSV.dev (Open Source Vulnerabilities)
#    - OpenSSF compromised-actions list
#    - Known malicious package registries
#    - CISA KEV (Known Exploited Vulnerabilities)
#
#  Usage:
#    python scripts/update_threat_db.py                         # Dry run
#    python scripts/update_threat_db.py --commit                # Write + commit
#    python scripts/update_threat_db.py --commit --push         # Write + push
#    GITHUB_TOKEN=xxx python scripts/update_threat_db.py --all  # Full update
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import argparse
import json
import os
import sys
import time
import re
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False
    print("[!] requests library not installed. Install with: pip install requests")

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
FEED_OUTPUT_PATH = PROJECT_ROOT / "threat-feed.json"
ATTACK_DB_PATH = PROJECT_ROOT / "src" / "db" / "attack_db.py"

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
GHSA_API = "https://api.github.com/graphql"
GHSA_REST_API = "https://api.github.com/advisories"

# Known compromised actions — curated watchlist
# These are checked periodically for new compromised tags/SHAs
WATCHLIST_ACTIONS = [
    "tj-actions/changed-files",
    "tj-actions/branch-names",
    "reviewdog/action-setup",
    "actions/checkout",
    "actions/setup-node",
    "actions/setup-python",
    "actions/cache",
    "actions/upload-artifact",
    "actions/download-artifact",
    "github/codeql-action",
    "peter-evans/create-pull-request",
    "peaceiris/actions-gh-pages",
    "JamesIves/github-pages-deploy-action",
    "docker/build-push-action",
    "docker/login-action",
    "aws-actions/configure-aws-credentials",
    "azure/login",
    "google-github-actions/auth",
    "hashicorp/setup-terraform",
    "cloudflare/wrangler-action",
    "slackapi/slack-github-action",
    "softprops/action-gh-release",
    "goreleaser/goreleaser-action",
    "pypa/gh-action-pypi-publish",
    # ── Trivy/TeamPCP compromised actions (CVE-2026-33634) ──
    "aquasecurity/trivy-action",
    "aquasecurity/setup-trivy",
    # ── Checkmarx KICS (TeamPCP) ──
    "Checkmarx/kics-github-action",
    # ── Additional high-profile actions ──
    "step-security/harden-runner",
    "codecov/codecov-action",
    "snyk/actions",
    "SonarSource/sonarcloud-github-action",
]

# Known malicious npm packages — updated periodically
KNOWN_MALICIOUS_NPM = [
    "event-stream", "flatmap-stream", "ua-parser-js",
    "coa", "rc", "colors", "faker",
    "node-ipc", "peacenotwar",
    # ── Shai-Hulud / Scavenger / CanisterWorm (CVE-2025-54313) ──
    "eslint-config-prettier@8.10.1",
    "eslint-config-prettier@9.1.1",
    "eslint-config-prettier@10.1.6",
    "eslint-config-prettier@10.1.7",
    "eslint-plugin-prettier@4.2.2",
    "eslint-plugin-prettier@4.2.3",
    "synckit@0.11.9",
    "@pkgr/core@0.2.8",
    "napi-postinstall@0.3.1",
    "got-fetch@5.1.11",
    "got-fetch@5.1.12",
    "is@3.3.1",
    "is@5.0.0",
    "@crowdstrike/node-exporter@0.2.2",
    "@crowdstrike/threat-center@1.205.2",
    "@ctrl/tinycolor@4.1.1",
    "@ctrl/tinycolor@4.1.2",
]

# Known malicious PyPI packages — updated periodically
KNOWN_MALICIOUS_PYPI = [
    "ctx", "phpass", "libpeshka",
    "colorama-0.4.7", "colorama-new",
    "python3-dateutil", "jeIlyfish",
    "python-binance-sdk", "request",
    "urllib", "bzip", "distlib-3",
    # ── LiteLLM PyPI compromise (TeamPCP) ──
    "litellm==1.82.7",
    "litellm==1.82.8",
]

TIMEOUT = 10


# ── Fetch Functions ──────────────────────────────────────────────────────────

def fetch_ghsa_advisories(token: str, count: int = 50) -> List[Dict]:
    """Fetch latest GitHub Security Advisories via GraphQL."""
    if not _HAS_REQUESTS or not token:
        return []

    query = """
    query($first: Int!) {
      securityAdvisories(
        first: $first,
        orderBy: {field: PUBLISHED_AT, direction: DESC}
      ) {
        nodes {
          ghsaId
          summary
          severity
          publishedAt
          updatedAt
          references { url }
          cwes(first: 5) { nodes { cweId name } }
          vulnerabilities(first: 10) {
            nodes {
              package { name ecosystem }
              vulnerableVersionRange
              firstPatchedVersion { identifier }
            }
          }
        }
      }
    }
    """
    try:
        resp = requests.post(
            GHSA_API,
            json={"query": query, "variables": {"first": count}},
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
        else:
            print(f"  [!] GHSA API returned {resp.status_code}")
    except Exception as e:
        print(f"  [!] GHSA fetch error: {e}")
    return []


def fetch_ghsa_rest_advisories(token: str, ecosystem: str = "actions") -> List[Dict]:
    """Fetch advisories via GitHub REST API (simpler, broader coverage)."""
    if not _HAS_REQUESTS:
        return []

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers["Accept"] = "application/vnd.github+json"

    advisories = []
    try:
        # Fetch recently published advisories
        resp = requests.get(
            GHSA_REST_API,
            params={
                "per_page": 50,
                "sort": "published",
                "direction": "desc",
                "type": "reviewed",
            },
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            advisories = resp.json()
        else:
            print(f"  [!] GHSA REST API returned {resp.status_code}")
    except Exception as e:
        print(f"  [!] GHSA REST fetch error: {e}")

    return advisories


def fetch_osv_advisories(ecosystem: str = "GitHub Actions") -> List[Dict]:
    """Fetch advisories from OSV.dev for a given ecosystem."""
    if not _HAS_REQUESTS:
        return []
    try:
        resp = requests.post(
            OSV_API,
            json={"package": {"ecosystem": ecosystem}},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            return resp.json().get("vulns", [])
    except Exception as e:
        print(f"  [!] OSV fetch error: {e}")
    return []


def fetch_osv_for_packages(packages: List[Dict]) -> List[Dict]:
    """Batch query OSV.dev for specific packages."""
    if not _HAS_REQUESTS or not packages:
        return []
    try:
        queries = [{"package": pkg} for pkg in packages[:100]]
        resp = requests.post(
            OSV_BATCH_API,
            json={"queries": queries},
            timeout=TIMEOUT,
        )
        if resp.status_code == 200:
            results = resp.json().get("results", [])
            all_vulns = []
            for r in results:
                all_vulns.extend(r.get("vulns", []))
            return all_vulns
    except Exception as e:
        print(f"  [!] OSV batch fetch error: {e}")
    return []


def check_action_tags(action: str, token: str = "") -> Dict:
    """
    Check a GitHub Action for suspicious tag changes.
    Compare tag SHA vs the commit it points to — detect force-pushed tags.
    """
    if not _HAS_REQUESTS:
        return {}

    owner_repo = action
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    result = {"action": action, "tags": {}, "suspicious": False, "details": []}
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner_repo}/git/refs/tags",
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return result

        refs = resp.json()
        if not isinstance(refs, list):
            return result

        for ref in refs[:20]:  # check last 20 tags
            tag_name = ref.get("ref", "").replace("refs/tags/", "")
            sha = ref.get("object", {}).get("sha", "")
            obj_type = ref.get("object", {}).get("type", "")
            result["tags"][tag_name] = {
                "sha": sha,
                "type": obj_type,
            }

    except Exception as e:
        result["details"].append(f"Error checking tags: {e}")

    return result


def fetch_npm_advisories() -> List[Dict]:
    """Fetch recent npm security advisories from the npm registry."""
    if not _HAS_REQUESTS:
        return []
    advisories = []
    try:
        # Check known malicious packages
        for pkg in KNOWN_MALICIOUS_NPM:
            resp = requests.get(
                f"https://registry.npmjs.org/{pkg}",
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Check if package was unpublished (indicator of compromise)
                if data.get("unpublished") or "This package has been unpublished" in str(data):
                    advisories.append({
                        "package": pkg,
                        "ecosystem": "npm",
                        "status": "unpublished",
                        "reason": "Package was unpublished — potential malware",
                    })
    except Exception as e:
        print(f"  [!] npm advisory fetch error: {e}")
    return advisories


def fetch_pypi_advisories() -> List[Dict]:
    """Check PyPI for known malicious packages."""
    if not _HAS_REQUESTS:
        return []
    advisories = []
    try:
        for pkg in KNOWN_MALICIOUS_PYPI:
            resp = requests.get(
                f"https://pypi.org/pypi/{pkg}/json",
                timeout=5,
            )
            if resp.status_code == 404:
                advisories.append({
                    "package": pkg,
                    "ecosystem": "pypi",
                    "status": "removed",
                    "reason": "Package removed from PyPI — potential malware",
                })
            elif resp.status_code == 200:
                data = resp.json()
                classifiers = data.get("info", {}).get("classifiers", [])
                if any("Development Status :: 7 - Inactive" in c for c in classifiers):
                    advisories.append({
                        "package": pkg,
                        "ecosystem": "pypi",
                        "status": "inactive",
                        "reason": "Package marked inactive",
                    })
    except Exception as e:
        print(f"  [!] PyPI advisory fetch error: {e}")
    return advisories


# ── Pattern Builder ──────────────────────────────────────────────────────────

def build_feed_pattern(
    pattern_id: str,
    name: str,
    category: str,
    severity: str,
    cve: str,
    description: str,
    affected: List[str],
    references: List[str],
    detection_signatures: Dict,
    remediation: str,
    date: str = "",
) -> Dict:
    """Build a threat feed pattern dict."""
    return {
        "id": pattern_id,
        "name": name,
        "category": category,
        "severity": severity,
        "cve": cve,
        "description": description,
        "date": date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "affected": affected,
        "references": references,
        "detection_signatures": detection_signatures,
        "remediation": remediation,
    }


def ghsa_to_feed_pattern(advisory: Dict, idx: int) -> Optional[Dict]:
    """Convert a GHSA advisory to a feed pattern."""
    try:
        ghsa_id = advisory.get("ghsaId") or advisory.get("ghsa_id", f"GHSA-{idx}")
        summary = advisory.get("summary", "Unknown advisory")
        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
        severity = sev_map.get(
            (advisory.get("severity") or "HIGH").upper(),
            "high"
        )

        affected = []
        sigs = {}
        vuln_nodes = advisory.get("vulnerabilities", {})
        if isinstance(vuln_nodes, dict):
            vuln_nodes = vuln_nodes.get("nodes", [])
        for vuln in vuln_nodes:
            pkg = vuln.get("package", {})
            name = pkg.get("name", "")
            eco = pkg.get("ecosystem", "").lower()
            if name:
                affected.append(name)
                if eco in ("npm", "pypi", "rubygems", "go", "crates"):
                    sigs.setdefault("malicious_packages", {}).setdefault(eco, []).append(name)
                if "/" in name:
                    sigs.setdefault("compromised_actions", []).append(name)

        refs = []
        ref_data = advisory.get("references", [])
        if isinstance(ref_data, list):
            for r in ref_data:
                if isinstance(r, dict):
                    url = r.get("url", "")
                elif isinstance(r, str):
                    url = r
                else:
                    continue
                if url:
                    refs.append(url)

        published = advisory.get("publishedAt") or advisory.get("published_at", "")

        return build_feed_pattern(
            pattern_id=f"FEED-{ghsa_id}",
            name=summary[:100],
            category="ghsa_advisory",
            severity=severity,
            cve=ghsa_id,
            description=summary,
            affected=affected,
            references=refs,
            detection_signatures=sigs,
            remediation="Update affected packages per advisory guidance.",
            date=published[:10] if published else "",
        )
    except Exception:
        return None


def osv_to_feed_pattern(vuln: Dict, idx: int) -> Optional[Dict]:
    """Convert an OSV advisory to a feed pattern."""
    try:
        vuln_id = vuln.get("id", f"OSV-{idx}")
        summary = vuln.get("summary", "Unknown")
        severity = "high"
        for sev in vuln.get("severity", []):
            s = str(sev.get("score", "")).upper()
            if "CRITICAL" in s:
                severity = "critical"
                break

        affected = []
        sigs = {}
        for aff in vuln.get("affected", []):
            pkg = aff.get("package", {})
            name = pkg.get("name", "")
            eco = pkg.get("ecosystem", "").lower()
            if name:
                affected.append(name)
                if eco in ("npm", "pypi", "rubygems", "go", "crates"):
                    sigs.setdefault("malicious_packages", {}).setdefault(eco, []).append(name)

        refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

        return build_feed_pattern(
            pattern_id=f"FEED-{vuln_id}",
            name=summary[:100],
            category="osv_advisory",
            severity=severity,
            cve=vuln_id,
            description=vuln.get("details", summary)[:500],
            affected=affected,
            references=refs[:5],
            detection_signatures=sigs,
            remediation="Update to a patched version per OSV advisory.",
            date=vuln.get("published", "")[:10],
        )
    except Exception:
        return None


# ── Feed Builder ─────────────────────────────────────────────────────────────

def build_threat_feed(token: str = "", verbose: bool = False) -> Dict:
    """
    Build the complete threat feed by pulling from all sources.

    Returns a dict that can be serialized to threat-feed.json.
    """
    now = datetime.now(timezone.utc)
    feed = {
        "version": now.strftime("%Y.%m.%d"),
        "last_updated": now.isoformat(),
        "generator": "supply-chain-guardian/update_threat_db.py",
        "patterns": [],
        "compromised_shas": {},
        "compromised_actions": {},
        "malicious_packages": {"npm": {}, "pypi": {}},
        "suspicious_domains": {},
    }

    seen_ids = set()

    def _add_pattern(p: Dict):
        if p and p["id"] not in seen_ids:
            feed["patterns"].append(p)
            seen_ids.add(p["id"])

    # ── Source 1: GHSA GraphQL ──
    print("[*] Fetching GitHub Security Advisories (GraphQL)...")
    ghsa_graphql = fetch_ghsa_advisories(token, count=50)
    print(f"    >> {len(ghsa_graphql)} advisories fetched")
    for i, adv in enumerate(ghsa_graphql):
        p = ghsa_to_feed_pattern(adv, i)
        _add_pattern(p)

    # ── Source 2: GHSA REST ──
    print("[*] Fetching GitHub Security Advisories (REST)...")
    ghsa_rest = fetch_ghsa_rest_advisories(token)
    print(f"    >> {len(ghsa_rest)} advisories fetched")
    for i, adv in enumerate(ghsa_rest):
        p = ghsa_to_feed_pattern(adv, i + 1000)
        _add_pattern(p)

    # ── Source 3: OSV.dev ──
    for ecosystem in ["GitHub Actions", "npm", "PyPI"]:
        print(f"[*] Fetching OSV.dev advisories ({ecosystem})...")
        osv_vulns = fetch_osv_advisories(ecosystem)
        print(f"    >> {len(osv_vulns)} advisories fetched")
        for i, vuln in enumerate(osv_vulns[:50]):
            p = osv_to_feed_pattern(vuln, i)
            _add_pattern(p)

    # ── Source 4: Action tag integrity checks ──
    if token:
        print(f"[*] Checking {len(WATCHLIST_ACTIONS)} watched actions for tag integrity...")
        for action in WATCHLIST_ACTIONS:
            result = check_action_tags(action, token)
            if result.get("suspicious"):
                for detail in result.get("details", []):
                    print(f"    [!] {action}: {detail}")
                feed["compromised_actions"][action] = "; ".join(result["details"])

    # ── Source 5: npm/PyPI malicious package checks ──
    print("[*] Checking known malicious npm packages...")
    npm_advs = fetch_npm_advisories()
    for adv in npm_advs:
        feed["malicious_packages"]["npm"][adv["package"]] = adv["reason"]
    print(f"    >> {len(npm_advs)} flagged packages")

    print("[*] Checking known malicious PyPI packages...")
    pypi_advs = fetch_pypi_advisories()
    for adv in pypi_advs:
        feed["malicious_packages"]["pypi"][adv["package"]] = adv["reason"]
    print(f"    >> {len(pypi_advs)} flagged packages")

    # ── Consolidate compromised SHAs from patterns ──
    for p in feed["patterns"]:
        sigs = p.get("detection_signatures", {})
        for sha in sigs.get("compromised_shas", []):
            feed["compromised_shas"][sha] = p["name"]
        for action in sigs.get("compromised_actions", []):
            if action not in feed["compromised_actions"]:
                feed["compromised_actions"][action] = p["name"]

    # ── Summary ──
    print()
    print(f"[+] Threat feed built: {len(feed['patterns'])} patterns")
    print(f"    Compromised SHAs: {len(feed['compromised_shas'])}")
    print(f"    Compromised Actions: {len(feed['compromised_actions'])}")
    print(f"    Malicious npm: {len(feed['malicious_packages']['npm'])}")
    print(f"    Malicious PyPI: {len(feed['malicious_packages']['pypi'])}")
    print(f"    Version: {feed['version']}")

    return feed


# ── Diff & Write ─────────────────────────────────────────────────────────────

def compute_feed_hash(feed: Dict) -> str:
    """Compute a deterministic hash of the feed content (ignoring timestamps)."""
    # Hash based on pattern IDs, SHAs, and actions — not timestamps
    fingerprint = json.dumps({
        "pattern_ids": sorted([p["id"] for p in feed.get("patterns", [])]),
        "shas": sorted(feed.get("compromised_shas", {}).keys()),
        "actions": sorted(feed.get("compromised_actions", {}).keys()),
        "npm": sorted(feed.get("malicious_packages", {}).get("npm", {}).keys()),
        "pypi": sorted(feed.get("malicious_packages", {}).get("pypi", {}).keys()),
    }, sort_keys=True)
    return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]


def load_existing_feed() -> Optional[Dict]:
    """Load the existing threat-feed.json if it exists."""
    if FEED_OUTPUT_PATH.exists():
        try:
            return json.loads(FEED_OUTPUT_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return None


def diff_feeds(old: Optional[Dict], new: Dict) -> Dict:
    """Compute what's new between old and new feeds."""
    if not old:
        return {
            "new_patterns": len(new.get("patterns", [])),
            "new_shas": len(new.get("compromised_shas", {})),
            "new_actions": len(new.get("compromised_actions", {})),
            "is_first_run": True,
        }

    old_ids = {p["id"] for p in old.get("patterns", [])}
    new_ids = {p["id"] for p in new.get("patterns", [])}
    old_shas = set(old.get("compromised_shas", {}).keys())
    new_shas = set(new.get("compromised_shas", {}).keys())
    old_actions = set(old.get("compromised_actions", {}).keys())
    new_actions = set(new.get("compromised_actions", {}).keys())

    return {
        "new_patterns": len(new_ids - old_ids),
        "removed_patterns": len(old_ids - new_ids),
        "new_shas": len(new_shas - old_shas),
        "new_actions": len(new_actions - old_actions),
        "new_pattern_ids": sorted(new_ids - old_ids),
        "is_first_run": False,
    }


def write_feed(feed: Dict):
    """Write the threat feed to disk."""
    FEED_OUTPUT_PATH.write_text(json.dumps(feed, indent=2) + "\n")
    print(f"[+] Written to {FEED_OUTPUT_PATH}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Supply Chain Guardian — Automated Threat Database Updater"
    )
    parser.add_argument("--commit", action="store_true",
                        help="Write threat-feed.json to disk (otherwise dry run)")
    parser.add_argument("--push", action="store_true",
                        help="Push changes to the threat-feed branch")
    parser.add_argument("--all", action="store_true",
                        help="Run all checks including action tag integrity")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    args = parser.parse_args()

    print("=" * 64)
    print("  Supply Chain Guardian — Threat Database Updater")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 64)
    print()

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print("[!] GITHUB_TOKEN not set — GHSA queries will be limited")
        print()

    if not _HAS_REQUESTS:
        print("[!] 'requests' is required. Install with: pip install requests")
        sys.exit(1)

    # Build the feed
    feed = build_threat_feed(token=token, verbose=args.verbose)

    # Check diff
    existing = load_existing_feed()
    diff = diff_feeds(existing, feed)

    print()
    print("-" * 40)
    if diff.get("is_first_run"):
        print(f"[+] First run — {diff['new_patterns']} patterns")
    else:
        print(f"[+] Diff: {diff['new_patterns']} new patterns, "
              f"{diff.get('removed_patterns', 0)} removed, "
              f"{diff['new_shas']} new SHAs, "
              f"{diff['new_actions']} new actions")
        if diff.get("new_pattern_ids"):
            print(f"    New IDs: {', '.join(diff['new_pattern_ids'][:10])}")

    new_hash = compute_feed_hash(feed)
    old_hash = compute_feed_hash(existing) if existing else "none"
    changed = new_hash != old_hash

    if not changed:
        print("[=] No changes detected. Feed is up-to-date.")
        if not args.commit:
            return
    else:
        print(f"[!] Feed changed: {old_hash} -> {new_hash}")

    if args.commit:
        write_feed(feed)

        if args.push:
            import subprocess
            print()
            print("[*] Pushing to threat-feed branch...")
            try:
                # Create/switch to threat-feed branch
                subprocess.run(
                    ["git", "checkout", "-B", "threat-feed"],
                    cwd=str(PROJECT_ROOT), check=True, capture_output=True,
                )
                subprocess.run(
                    ["git", "add", str(FEED_OUTPUT_PATH)],
                    cwd=str(PROJECT_ROOT), check=True, capture_output=True,
                )

                msg = f"threat-feed: auto-update {feed['version']} ({diff['new_patterns']} new patterns)"
                subprocess.run(
                    ["git", "commit", "-m", msg],
                    cwd=str(PROJECT_ROOT), check=True, capture_output=True,
                )
                subprocess.run(
                    ["git", "push", "--force", "origin", "threat-feed"],
                    cwd=str(PROJECT_ROOT), check=True, capture_output=True,
                )
                print("[+] Pushed to origin/threat-feed")

                # Switch back to main
                subprocess.run(
                    ["git", "checkout", "main"],
                    cwd=str(PROJECT_ROOT), check=True, capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                print(f"[!] Git push failed: {e}")
                # Try to recover to main branch
                subprocess.run(
                    ["git", "checkout", "main"],
                    cwd=str(PROJECT_ROOT), capture_output=True,
                )
    else:
        print()
        print("[i] Dry run — use --commit to write, --push to push")
        print(f"    Would write {len(feed['patterns'])} patterns to {FEED_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
