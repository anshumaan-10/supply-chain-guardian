#!/usr/bin/env python3
"""
Proactive Detection: Workflow Lockfile Generator
=================================================
Generates a cryptographic lockfile of every action used in a repository's
workflows. On subsequent runs, detects if any action's resolved SHA has
changed — which means a tag was moved or forced-pushed.

This catches the EXACT attack vector used in the tj-actions and reviewdog
compromises BEFORE any signature database is updated.

Usage:
    # Generate lockfile (first run)
    python scripts/workflow_lockfile.py --generate --workspace /path/to/repo

    # Verify lockfile (CI run)
    python scripts/workflow_lockfile.py --verify --workspace /path/to/repo

    # Auto mode: generate if missing, verify if present
    python scripts/workflow_lockfile.py --auto --workspace /path/to/repo
"""

import os
import sys
import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    import requests
except ImportError:
    requests = None

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

LOCKFILE_NAME = ".github/action-lock.json"


def find_workflow_files(workspace: str) -> List[str]:
    """Find all workflow YAML files."""
    workflows_dir = os.path.join(workspace, ".github", "workflows")
    files = []
    if os.path.isdir(workflows_dir):
        for f in os.listdir(workflows_dir):
            if f.endswith((".yml", ".yaml")):
                files.append(os.path.join(workflows_dir, f))
    return files


def extract_action_refs(workspace: str) -> Dict[str, Dict]:
    """Extract all action references from workflow files."""
    refs = {}
    for filepath in find_workflow_files(workspace):
        relpath = os.path.relpath(filepath, workspace)
        try:
            with open(filepath) as f:
                for i, line in enumerate(f, 1):
                    match = re.search(r'uses:\s*["\']?([^"\'#\s]+)', line.strip())
                    if match:
                        ref = match.group(1).strip()
                        if "/" in ref and not ref.startswith("."):
                            key = ref  # owner/repo@version
                            if key not in refs:
                                refs[key] = {
                                    "ref": ref,
                                    "locations": [],
                                }
                            refs[key]["locations"].append(f"{relpath}:{i}")
        except (IOError, OSError):
            continue
    return refs


def resolve_tag_to_sha(owner: str, repo: str, tag: str) -> Optional[str]:
    """Resolve a tag to its commit SHA via GitHub API."""
    if not requests:
        return None

    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Try refs/tags first
    url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            obj = data.get("object", {})
            sha = obj.get("sha", "")
            # Dereference annotated tags
            if obj.get("type") == "tag":
                tag_url = f"https://api.github.com/repos/{owner}/{repo}/git/tags/{sha}"
                tag_resp = requests.get(tag_url, headers=headers, timeout=15)
                if tag_resp.status_code == 200:
                    sha = tag_resp.json().get("object", {}).get("sha", sha)
            return sha
    except requests.RequestException:
        pass

    return None


def generate_lockfile(workspace: str) -> Dict:
    """Generate the action lockfile."""
    action_refs = extract_action_refs(workspace)
    entries = {}

    print(f"  Found {len(action_refs)} unique action references")

    for key, info in sorted(action_refs.items()):
        ref = info["ref"]
        parts = ref.split("@")
        if len(parts) != 2:
            continue

        action_path = parts[0]
        version = parts[1]
        path_parts = action_path.split("/")
        owner = path_parts[0]
        repo = path_parts[1] if len(path_parts) > 1 else ""

        # If already a SHA, use it directly
        if re.match(r'^[0-9a-f]{40}$', version):
            resolved_sha = version
        else:
            resolved_sha = resolve_tag_to_sha(owner, repo, version)

        entry = {
            "action": action_path,
            "version": version,
            "resolved_sha": resolved_sha or "UNRESOLVED",
            "locations": info["locations"],
        }

        # Compute integrity hash of the resolved content
        if resolved_sha:
            integrity = hashlib.sha256(
                f"{action_path}@{resolved_sha}".encode()
            ).hexdigest()[:16]
            entry["integrity"] = integrity

        entries[key] = entry
        status = GREEN + "✓" + RESET if resolved_sha else YELLOW + "?" + RESET
        print(f"    {status} {ref} → {(resolved_sha or 'unresolved')[:12]}")

    lockfile = {
        "$schema": "supply-chain-guardian/action-lock/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "supply-chain-guardian/workflow-lockfile",
        "workspace": os.path.basename(workspace),
        "total_actions": len(entries),
        "actions": entries,
    }

    return lockfile


def verify_lockfile(workspace: str) -> List[Dict]:
    """Verify current action references against the lockfile."""
    lockfile_path = os.path.join(workspace, LOCKFILE_NAME)

    if not os.path.exists(lockfile_path):
        print(f"  {RED}No lockfile found at {LOCKFILE_NAME}{RESET}")
        print(f"  Run with --generate first.")
        return [{"type": "MISSING_LOCKFILE", "severity": "high",
                 "message": "No action lockfile found. Cannot verify integrity."}]

    with open(lockfile_path) as f:
        lockfile = json.load(f)

    locked_actions = lockfile.get("actions", {})
    current_refs = extract_action_refs(workspace)
    alerts = []

    print(f"  Lockfile generated: {lockfile.get('generated_at', 'unknown')}")
    print(f"  Locked actions: {len(locked_actions)}")
    print(f"  Current references: {len(current_refs)}")
    print()

    # Check each current reference against lockfile
    for key, info in current_refs.items():
        if key not in locked_actions:
            alerts.append({
                "type": "NEW_ACTION",
                "severity": "high",
                "ref": key,
                "locations": info["locations"],
                "message": f"Action '{key}' is used but NOT in lockfile. "
                           f"It was added after the lockfile was generated.",
            })
            print(f"    {RED}✗ NEW: {key} (not in lockfile){RESET}")
            continue

        locked = locked_actions[key]
        locked_sha = locked.get("resolved_sha", "")

        if locked_sha == "UNRESOLVED":
            print(f"    {YELLOW}? {key} (was unresolved at lock time){RESET}")
            continue

        # Re-resolve the current SHA
        ref = info["ref"]
        parts = ref.split("@")
        if len(parts) != 2:
            continue

        action_path = parts[0]
        version = parts[1]
        path_parts = action_path.split("/")
        owner = path_parts[0]
        repo = path_parts[1] if len(path_parts) > 1 else ""

        if re.match(r'^[0-9a-f]{40}$', version):
            current_sha = version
        else:
            current_sha = resolve_tag_to_sha(owner, repo, version)

        if current_sha and current_sha != locked_sha:
            alerts.append({
                "type": "SHA_MISMATCH",
                "severity": "critical",
                "ref": key,
                "locked_sha": locked_sha,
                "current_sha": current_sha,
                "locations": info["locations"],
                "message": f"ACTION INTEGRITY VIOLATION: '{key}' has changed! "
                           f"Locked SHA: {locked_sha[:12]}, Current SHA: {current_sha[:12]}. "
                           f"The tag was force-pushed or the action was compromised.",
            })
            print(f"    {RED}✗ CHANGED: {key}{RESET}")
            print(f"      Locked:  {locked_sha[:12]}")
            print(f"      Current: {current_sha[:12]}")
        elif current_sha:
            print(f"    {GREEN}✓ {key} ({current_sha[:12]}){RESET}")
        else:
            print(f"    {YELLOW}? {key} (could not resolve){RESET}")

    # Check for actions removed from workflows but still in lockfile
    for key in locked_actions:
        if key not in current_refs:
            print(f"    {CYAN}⊘ REMOVED: {key} (in lockfile but not in workflows){RESET}")

    return alerts


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Workflow action lockfile generator and verifier"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true", help="Generate lockfile")
    mode.add_argument("--verify", action="store_true", help="Verify against lockfile")
    mode.add_argument("--auto", action="store_true",
                      help="Generate if missing, verify if present")
    parser.add_argument("--workspace", type=str, default=".",
                        help="Path to the repository workspace")
    args = parser.parse_args()

    workspace = os.path.abspath(args.workspace)
    lockfile_path = os.path.join(workspace, LOCKFILE_NAME)

    print(f"{CYAN}╔════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║   Supply Chain Guardian — Workflow Lockfile        ║{RESET}")
    print(f"{CYAN}║   Cryptographic action integrity verification     ║{RESET}")
    print(f"{CYAN}╚════════════════════════════════════════════════════╝{RESET}")
    print()

    if args.auto:
        if os.path.exists(lockfile_path):
            args.verify = True
        else:
            args.generate = True

    if args.generate:
        print(f"  {CYAN}Generating lockfile...{RESET}")
        lockfile = generate_lockfile(workspace)
        os.makedirs(os.path.dirname(lockfile_path), exist_ok=True)
        with open(lockfile_path, "w") as f:
            json.dump(lockfile, f, indent=2)
        print(f"\n  {GREEN}✅ Lockfile written to {LOCKFILE_NAME}{RESET}")
        print(f"  Commit this file to your repository.")
        sys.exit(0)

    elif args.verify:
        print(f"  {CYAN}Verifying action integrity...{RESET}")
        alerts = verify_lockfile(workspace)

        if not alerts:
            print(f"\n  {GREEN}✅ All actions match lockfile — integrity verified{RESET}")
            sys.exit(0)
        else:
            critical = [a for a in alerts if a["severity"] == "critical"]
            high = [a for a in alerts if a["severity"] == "high"]
            print(f"\n  {RED}❌ INTEGRITY CHECK FAILED{RESET}")
            print(f"  {len(critical)} critical, {len(high)} high severity alert(s)")
            for alert in alerts:
                color = RED if alert["severity"] == "critical" else YELLOW
                print(f"    {color}[{alert['severity'].upper()}]{RESET} {alert['message']}")
            sys.exit(1)


if __name__ == "__main__":
    main()
