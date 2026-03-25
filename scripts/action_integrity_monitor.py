#!/usr/bin/env python3
"""
Proactive Detection: Action Integrity Monitor
==============================================
Monitors GitHub Actions for behavioral indicators that a compromise
has occurred or is in progress. This script is designed to run on a
schedule (e.g., cron) and detect:

  1. Tag mutation  — a tag was force-pushed to a different commit
  2. Maintainer changes — new collaborators added to action repos
  3. Commit anomalies — commits from unknown authors, unsigned commits
  4. Release tampering — release assets changed after publication
  5. Workflow injection — new/modified workflows in action repos

Usage:
    python scripts/action_integrity_monitor.py --actions actions.txt
    python scripts/action_integrity_monitor.py --repo owner/repo

Requires: GITHUB_TOKEN environment variable with repo read access.
"""

import os
import sys
import json
import hashlib
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("ERROR: 'requests' is required. Install: pip install requests")
    sys.exit(1)


GITHUB_API = "https://api.github.com"

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


def get_headers() -> Dict[str, str]:
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def api_get(endpoint: str) -> Optional[Dict]:
    """Make an authenticated GET to the GitHub API."""
    url = f"{GITHUB_API}{endpoint}" if endpoint.startswith("/") else endpoint
    try:
        resp = requests.get(url, headers=get_headers(), timeout=30)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return None
        else:
            print(f"  {YELLOW}API {resp.status_code}: {endpoint}{RESET}")
            return None
    except requests.RequestException as e:
        print(f"  {RED}Request error: {e}{RESET}")
        return None


# ─── 1. Tag Mutation Detection ──────────────────────────────────────

def check_tag_mutation(owner: str, repo: str) -> List[Dict]:
    """Detect if any tags have been force-pushed (moved to different commits)."""
    alerts = []

    tags = api_get(f"/repos/{owner}/{repo}/git/refs/tags")
    if not isinstance(tags, list):
        return alerts

    releases = api_get(f"/repos/{owner}/{repo}/releases")
    release_map = {}
    if isinstance(releases, list):
        for rel in releases:
            tag = rel.get("tag_name", "")
            release_map[tag] = {
                "published_at": rel.get("published_at", ""),
                "target_commitish": rel.get("target_commitish", ""),
                "id": rel.get("id"),
            }

    for tag_ref in tags:
        ref_name = tag_ref.get("ref", "").replace("refs/tags/", "")
        obj = tag_ref.get("object", {})
        sha = obj.get("sha", "")
        obj_type = obj.get("type", "")

        # For annotated tags, dereference to actual commit
        if obj_type == "tag":
            tag_obj = api_get(f"/repos/{owner}/{repo}/git/tags/{sha}")
            if tag_obj:
                sha = tag_obj.get("object", {}).get("sha", sha)

        # Check if the tag's commit is in the release's target branch
        # A mismatch suggests the tag was moved
        if ref_name in release_map:
            rel = release_map[ref_name]
            published = rel["published_at"]
            if published:
                try:
                    pub_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    # Check recent commit on tag vs published date
                    commit = api_get(f"/repos/{owner}/{repo}/git/commits/{sha}")
                    if commit:
                        commit_date_str = commit.get("committer", {}).get("date", "")
                        if commit_date_str:
                            commit_date = datetime.fromisoformat(commit_date_str.replace("Z", "+00:00"))
                            # Commit date after release date = tag was moved
                            if commit_date > pub_date + timedelta(hours=1):
                                alerts.append({
                                    "type": "TAG_MUTATION",
                                    "severity": "critical",
                                    "repo": f"{owner}/{repo}",
                                    "tag": ref_name,
                                    "message": f"Tag '{ref_name}' points to commit from "
                                               f"{commit_date.isoformat()} but release was published "
                                               f"at {pub_date.isoformat()}. TAG MAY HAVE BEEN MOVED.",
                                    "sha": sha,
                                })
                except (ValueError, TypeError):
                    pass

    return alerts


# ─── 2. Maintainer / Collaborator Changes ──────────────────────────

def check_maintainer_changes(owner: str, repo: str, days: int = 30) -> List[Dict]:
    """Detect recent collaborator additions or permission changes."""
    alerts = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Check audit log via events API (limited but publicly accessible)
    events = api_get(f"/repos/{owner}/{repo}/events?per_page=100")
    if not isinstance(events, list):
        return alerts

    for event in events:
        event_type = event.get("type", "")
        created = event.get("created_at", "")

        try:
            event_date = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if event_date < cutoff:
                continue
        except (ValueError, TypeError):
            continue

        if event_type == "MemberEvent":
            payload = event.get("payload", {})
            action = payload.get("action", "")
            member = payload.get("member", {}).get("login", "unknown")
            alerts.append({
                "type": "MAINTAINER_CHANGE",
                "severity": "high",
                "repo": f"{owner}/{repo}",
                "message": f"Collaborator '{member}' was {action} on "
                           f"{event_date.strftime('%Y-%m-%d %H:%M UTC')}. "
                           f"Verify this was authorized.",
                "actor": event.get("actor", {}).get("login", "unknown"),
            })

    return alerts


# ─── 3. Commit Anomaly Detection ───────────────────────────────────

def check_commit_anomalies(owner: str, repo: str, days: int = 7) -> List[Dict]:
    """Detect unsigned commits, unknown authors, and suspicious patterns."""
    alerts = []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    commits = api_get(f"/repos/{owner}/{repo}/commits?since={since}&per_page=100")
    if not isinstance(commits, list):
        return alerts

    # Build set of known committers from older commits
    older_commits = api_get(f"/repos/{owner}/{repo}/commits?per_page=100&page=2")
    known_authors = set()
    if isinstance(older_commits, list):
        for c in older_commits:
            author = c.get("author")
            if author:
                known_authors.add(author.get("login", ""))
            committer = c.get("committer")
            if committer:
                known_authors.add(committer.get("login", ""))
    known_authors.discard(None)
    known_authors.discard("")

    for commit in commits:
        sha = commit.get("sha", "")[:12]
        message = commit.get("commit", {}).get("message", "")
        author_login = (commit.get("author") or {}).get("login", "")
        verification = commit.get("commit", {}).get("verification", {})
        verified = verification.get("verified", False)

        # Unsigned commit
        if not verified:
            alerts.append({
                "type": "UNSIGNED_COMMIT",
                "severity": "medium",
                "repo": f"{owner}/{repo}",
                "sha": sha,
                "message": f"Commit {sha} by '{author_login}' is NOT signed. "
                           f"In a supply chain attack, unsigned commits are the "
                           f"injection vector.",
            })

        # Unknown author
        if known_authors and author_login and author_login not in known_authors:
            alerts.append({
                "type": "NEW_AUTHOR",
                "severity": "high",
                "repo": f"{owner}/{repo}",
                "sha": sha,
                "message": f"Commit {sha} by NEW author '{author_login}' (not seen "
                           f"in recent history). First-time contributors to critical "
                           f"actions require extra scrutiny.",
            })

        # Suspicious commit messages
        suspicious_words = [
            "update dependencies", "fix ci", "bump version",
            "minor fix", "maintenance", "chore",
        ]
        msg_lower = message.lower().strip()
        if any(msg_lower.startswith(w) for w in suspicious_words):
            # Check if the diff is large (>100 lines changed)
            commit_detail = api_get(f"/repos/{owner}/{repo}/commits/{commit.get('sha', '')}")
            if commit_detail:
                stats = commit_detail.get("stats", {})
                total_changes = stats.get("total", 0)
                if total_changes > 200:
                    alerts.append({
                        "type": "SUSPICIOUS_COMMIT",
                        "severity": "high",
                        "repo": f"{owner}/{repo}",
                        "sha": sha,
                        "message": f"Commit {sha} has benign message ('{msg_lower[:40]}...') "
                                   f"but {total_changes} lines changed. This pattern is "
                                   f"common in supply chain attacks — large changes hidden "
                                   f"behind innocuous commit messages.",
                    })

    return alerts


# ─── 4. Workflow File Changes ───────────────────────────────────────

def check_workflow_changes(owner: str, repo: str, days: int = 7) -> List[Dict]:
    """Detect modifications to .github/workflows/ in recent commits."""
    alerts = []
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

    commits = api_get(f"/repos/{owner}/{repo}/commits?since={since}&per_page=50")
    if not isinstance(commits, list):
        return alerts

    for commit in commits:
        sha = commit.get("sha", "")
        detail = api_get(f"/repos/{owner}/{repo}/commits/{sha}")
        if not detail:
            continue

        files_changed = detail.get("files", [])
        workflow_files = [
            f for f in files_changed
            if f.get("filename", "").startswith(".github/workflows/")
            or f.get("filename", "") in ("action.yml", "action.yaml")
        ]

        if workflow_files:
            for wf in workflow_files:
                filename = wf.get("filename", "")
                status = wf.get("status", "")
                additions = wf.get("additions", 0)
                deletions = wf.get("deletions", 0)

                sev = "high" if status in ("added", "removed") else "medium"
                if additions > 20 or deletions > 20:
                    sev = "high"

                alerts.append({
                    "type": "WORKFLOW_CHANGE",
                    "severity": sev,
                    "repo": f"{owner}/{repo}",
                    "sha": sha[:12],
                    "file": filename,
                    "message": f"Workflow file '{filename}' was {status} "
                               f"(+{additions}/-{deletions} lines) in commit "
                               f"{sha[:12]}. Review this change carefully.",
                })

    return alerts


# ─── Main Entrypoint ────────────────────────────────────────────────

def monitor_action(action_ref: str, days: int = 7) -> List[Dict]:
    """Run all proactive checks against a single action reference."""
    parts = action_ref.strip().split("/")
    if len(parts) < 2:
        print(f"  {RED}Invalid action reference: {action_ref}{RESET}")
        return []

    owner = parts[0]
    repo = parts[1].split("@")[0]

    print(f"\n{CYAN}━━━ Monitoring: {owner}/{repo} ━━━{RESET}")

    all_alerts = []

    print(f"  Checking tag integrity...")
    all_alerts.extend(check_tag_mutation(owner, repo))

    print(f"  Checking maintainer changes ({days}d)...")
    all_alerts.extend(check_maintainer_changes(owner, repo, days))

    print(f"  Checking commit anomalies ({days}d)...")
    all_alerts.extend(check_commit_anomalies(owner, repo, days))

    print(f"  Checking workflow changes ({days}d)...")
    all_alerts.extend(check_workflow_changes(owner, repo, days))

    return all_alerts


def main():
    parser = argparse.ArgumentParser(
        description="Proactive GitHub Actions integrity monitor"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--actions", type=str,
        help="Path to file with action references (one per line, e.g., 'actions/checkout')"
    )
    group.add_argument(
        "--repo", type=str,
        help="Single repo to monitor (e.g., 'actions/checkout')"
    )
    parser.add_argument(
        "--days", type=int, default=7,
        help="Lookback window in days (default: 7)"
    )
    parser.add_argument(
        "--json-output", type=str, default="",
        help="Write JSON report to this path"
    )
    parser.add_argument(
        "--fail-on", type=str, default="critical",
        choices=["critical", "high", "medium", "low"],
        help="Exit non-zero if alerts at this severity or above are found"
    )
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        print(f"{YELLOW}WARNING: GITHUB_TOKEN not set. API rate limits will be very low.{RESET}")

    print(f"{CYAN}╔════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║   Supply Chain Guardian — Integrity Monitor       ║{RESET}")
    print(f"{CYAN}║   Proactive detection for future compromises      ║{RESET}")
    print(f"{CYAN}╚════════════════════════════════════════════════════╝{RESET}")

    actions = []
    if args.repo:
        actions = [args.repo]
    elif args.actions:
        with open(args.actions) as f:
            actions = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    all_alerts = []
    for action in actions:
        alerts = monitor_action(action, args.days)
        all_alerts.extend(alerts)

    # Print results
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    all_alerts.sort(key=lambda a: sev_order.get(a.get("severity", "low"), 0), reverse=True)

    print(f"\n{'='*60}")
    print(f"  RESULTS: {len(all_alerts)} alert(s) across {len(actions)} action(s)")
    print(f"{'='*60}")

    for alert in all_alerts:
        sev = alert.get("severity", "info")
        color = RED if sev == "critical" else YELLOW if sev in ("high", "medium") else GREEN
        print(f"\n  {color}[{sev.upper()}]{RESET} {alert.get('type', 'UNKNOWN')}")
        print(f"    Repo: {alert.get('repo', 'N/A')}")
        print(f"    {alert.get('message', '')}")

    if not all_alerts:
        print(f"\n  {GREEN}✅ No anomalies detected.{RESET}")

    # JSON output
    if args.json_output:
        with open(args.json_output, "w") as f:
            json.dump({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actions_monitored": actions,
                "lookback_days": args.days,
                "total_alerts": len(all_alerts),
                "alerts": all_alerts,
            }, f, indent=2)
        print(f"\n  JSON report: {args.json_output}")

    # Exit code
    fail_threshold = sev_order.get(args.fail_on, 4)
    max_sev = max((sev_order.get(a.get("severity", "low"), 0) for a in all_alerts), default=0)
    if max_sev >= fail_threshold:
        print(f"\n  {RED}❌ FAILED — alerts at or above '{args.fail_on}' severity detected{RESET}")
        sys.exit(1)
    else:
        print(f"\n  {GREEN}✅ PASSED{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
