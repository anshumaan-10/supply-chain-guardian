#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Live Threat Feed
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  Runtime threat intelligence fetcher.
#  Pulls the latest attack patterns from a remote JSON feed at scan time
#  so the scanner stays current without requiring action version bumps.
#
#  Feed sources:
#    1. Primary: GitHub-hosted threat-feed.json (this repo's `threat-feed` branch)
#    2. Fallback: OSV.dev API for latest GitHub Actions advisories
#    3. Fallback: GitHub Advisory Database API
#
#  Architecture:
#    - Fetch is best-effort with a 5s timeout
#    - If all feeds fail, scanner proceeds with bundled attack_db.py
#    - New patterns are merged into the AttackDatabase at runtime
#    - No version bump needed — the feed is independent of the action release
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import json
import os
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from db.attack_db import AttackPattern, AttackDatabase


# ── Feed Configuration ───────────────────────────────────────────────────────

# Primary feed: JSON hosted on the `threat-feed` branch of the main repo
_OWNER = "anshumaan-10"
_REPO = "supply-chain-guardian"
_FEED_BRANCH = "threat-feed"
_FEED_FILE = "threat-feed.json"

# Use GitHub API (works for both public and private repos with GITHUB_TOKEN)
PRIMARY_FEED_API_URL = (
    f"https://api.github.com/repos/{_OWNER}/{_REPO}/contents/{_FEED_FILE}"
    f"?ref={_FEED_BRANCH}"
)
# Fallback: raw URL (works only for public repos)
PRIMARY_FEED_RAW_URL = (
    f"https://raw.githubusercontent.com/{_OWNER}/{_REPO}/{_FEED_BRANCH}/{_FEED_FILE}"
)

# OSV.dev API — query for GitHub Actions ecosystem advisories
OSV_API_URL = "https://api.osv.dev/v1/query"

# GitHub Advisory Database — GraphQL
GHSA_API_URL = "https://api.github.com/graphql"

# Local cache to avoid repeated fetches within the same CI run
_CACHE_DIR = Path("/tmp/scg-threat-cache")
_CACHE_TTL_SECONDS = 3600  # 1 hour

FEED_TIMEOUT_SECONDS = 5


# ── Cache Helpers ────────────────────────────────────────────────────────────

def _cache_path() -> Path:
    """Return the path for the local threat-feed cache file."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _CACHE_DIR / "threat-feed-cache.json"


def _read_cache() -> Optional[Dict]:
    """Read cached feed if it exists and is fresh."""
    cp = _cache_path()
    if not cp.exists():
        return None
    try:
        data = json.loads(cp.read_text())
        cached_at = data.get("_cached_at", 0)
        if time.time() - cached_at > _CACHE_TTL_SECONDS:
            return None
        return data
    except (json.JSONDecodeError, OSError):
        return None


def _write_cache(data: Dict) -> None:
    """Write feed data to local cache."""
    try:
        data["_cached_at"] = time.time()
        _cache_path().write_text(json.dumps(data, indent=2))
    except OSError:
        pass


# ── Feed Fetchers ────────────────────────────────────────────────────────────

def _fetch_primary_feed() -> Optional[Dict]:
    """
    Fetch the primary threat-feed.json from the threat-feed branch.

    Expected JSON schema:
    {
        "version": "2025.06.2",
        "last_updated": "2025-06-15T12:00:00Z",
        "patterns": [
            {
                "id": "SCA-091",
                "name": "...",
                "category": "...",
                "severity": "critical|high|medium|low",
                "cve": "CVE-XXXX-XXXXX",
                "description": "...",
                "date": "YYYY-MM-DD",
                "affected": ["action/name@vX"],
                "references": ["https://..."],
                "detection_signatures": { ... },
                "remediation": "..."
            }
        ],
        "compromised_shas": {
            "<sha>": "Description of compromise"
        },
        "compromised_actions": {
            "<owner/action>": "Description"
        },
        "malicious_packages": {
            "npm": { "<pkg>": "reason" },
            "pypi": { "<pkg>": "reason" }
        },
        "suspicious_domains": {
            "<domain>": "reason"
        }
    }
    """
    if not _HAS_REQUESTS:
        return None

    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    # Attempt 1: GitHub API (works for private repos)
    try:
        api_headers = {**headers, "Accept": "application/vnd.github.v3.raw"}
        resp = requests.get(
            PRIMARY_FEED_API_URL, headers=api_headers,
            timeout=FEED_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            if "patterns" in data or "compromised_shas" in data:
                return data
    except Exception:
        pass

    # Attempt 2: Raw URL (public repos or repos with fine-grained PAT)
    try:
        resp = requests.get(
            PRIMARY_FEED_RAW_URL, headers=headers,
            timeout=FEED_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            if "patterns" in data or "compromised_shas" in data:
                return data
    except Exception:
        pass

    return None


def _fetch_osv_actions_advisories() -> Optional[List[Dict]]:
    """
    Query OSV.dev for recent GitHub Actions ecosystem advisories.
    Returns a list of simplified advisory dicts.
    """
    if not _HAS_REQUESTS:
        return None
    try:
        # Query for GIT ecosystem (covers GitHub Actions)
        payload = {
            "package": {"ecosystem": "GIT"},
        }
        resp = requests.post(OSV_API_URL, json=payload, timeout=FEED_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("vulns", [])
    except Exception:
        pass
    return None


def _fetch_ghsa_advisories() -> Optional[List[Dict]]:
    """
    Fetch latest GitHub Security Advisories for Actions ecosystem.
    Requires GITHUB_TOKEN in environment.
    """
    if not _HAS_REQUESTS:
        return None
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("INPUT_GITHUB_TOKEN")
    if not token:
        return None
    try:
        query = """
        {
          securityAdvisories(
            first: 20,
            orderBy: {field: PUBLISHED_AT, direction: DESC},
            classifications: MALWARE
          ) {
            nodes {
              ghsaId
              summary
              severity
              publishedAt
              references { url }
              vulnerabilities(first: 5) {
                nodes {
                  package { name ecosystem }
                  vulnerableVersionRange
                }
              }
            }
          }
        }
        """
        resp = requests.post(
            GHSA_API_URL,
            json={"query": query},
            headers={"Authorization": f"Bearer {token}"},
            timeout=FEED_TIMEOUT_SECONDS,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    except Exception:
        pass
    return None


# ── Pattern Conversion ───────────────────────────────────────────────────────

def _feed_pattern_to_attack(raw: Dict) -> Optional[AttackPattern]:
    """Convert a raw feed pattern dict into an AttackPattern object."""
    try:
        required = ["id", "name", "category", "severity"]
        if not all(k in raw for k in required):
            return None
        return AttackPattern(
            id=raw["id"],
            name=raw["name"],
            category=raw["category"],
            severity=raw["severity"],
            cve=raw.get("cve", "N/A"),
            description=raw.get("description", "Detected via live threat feed"),
            date=raw.get("date", time.strftime("%Y-%m-%d")),
            affected=raw.get("affected", []),
            references=raw.get("references", []),
            detection_signatures=raw.get("detection_signatures", {}),
            remediation=raw.get("remediation", "Review and remediate per advisory guidance"),
        )
    except Exception:
        return None


def _osv_to_attack(vuln: Dict, idx: int) -> Optional[AttackPattern]:
    """Convert an OSV advisory into an AttackPattern."""
    try:
        vuln_id = vuln.get("id", f"OSV-{idx}")
        summary = vuln.get("summary", "Unknown advisory")
        severity = "high"  # OSV doesn't always map to our severity levels
        for sev_obj in vuln.get("severity", []):
            score = sev_obj.get("score", "")
            if "CRITICAL" in str(score).upper():
                severity = "critical"
            elif "HIGH" in str(score).upper():
                severity = "high"

        affected_pkgs = []
        compromised_actions = []
        for aff in vuln.get("affected", []):
            pkg = aff.get("package", {})
            name = pkg.get("name", "")
            if name:
                affected_pkgs.append(name)
                if "/" in name:
                    compromised_actions.append(name)

        return AttackPattern(
            id=f"LIVE-{vuln_id}",
            name=summary[:80],
            category="live_advisory",
            severity=severity,
            cve=vuln_id,
            description=vuln.get("details", summary),
            date=vuln.get("published", time.strftime("%Y-%m-%d"))[:10],
            affected=affected_pkgs,
            references=[ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")],
            detection_signatures={
                "compromised_actions": compromised_actions,
            },
            remediation="Update to a patched version per the advisory.",
        )
    except Exception:
        return None


def _ghsa_to_attack(advisory: Dict, idx: int) -> Optional[AttackPattern]:
    """Convert a GHSA advisory into an AttackPattern."""
    try:
        ghsa_id = advisory.get("ghsaId", f"GHSA-{idx}")
        summary = advisory.get("summary", "Unknown advisory")
        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}
        severity = sev_map.get(advisory.get("severity", "HIGH"), "high")

        affected_pkgs = []
        for vuln_node in advisory.get("vulnerabilities", {}).get("nodes", []):
            pkg = vuln_node.get("package", {})
            name = pkg.get("name", "")
            if name:
                affected_pkgs.append(name)

        refs = [r.get("url", "") for r in advisory.get("references", []) if r.get("url")]

        return AttackPattern(
            id=f"LIVE-{ghsa_id}",
            name=summary[:80],
            category="live_advisory",
            severity=severity,
            cve=ghsa_id,
            description=summary,
            date=advisory.get("publishedAt", time.strftime("%Y-%m-%d"))[:10],
            affected=affected_pkgs,
            references=refs,
            detection_signatures={},
            remediation="Review advisory and apply recommended mitigations.",
        )
    except Exception:
        return None


# ── Public API ───────────────────────────────────────────────────────────────

def fetch_live_patterns(verbose: bool = False) -> Tuple[List[AttackPattern], Dict]:
    """
    Fetch the latest threat patterns from all available feeds.

    Returns:
        Tuple of (new_patterns, metadata)
        - new_patterns: List of AttackPattern objects to merge
        - metadata: Dict with feed version, source info, counts
    """
    metadata = {
        "feed_source": "none",
        "feed_version": "N/A",
        "patterns_fetched": 0,
        "extra_shas": {},
        "extra_actions": {},
        "extra_packages": {},
        "extra_domains": {},
        "fetch_time_ms": 0,
    }
    patterns = []
    start = time.time()

    # ── 1. Check local cache first ──
    cached = _read_cache()
    if cached:
        metadata["feed_source"] = "cache"
        metadata["feed_version"] = cached.get("version", "cached")
        for raw in cached.get("patterns", []):
            p = _feed_pattern_to_attack(raw)
            if p:
                patterns.append(p)
        metadata["extra_shas"] = cached.get("compromised_shas", {})
        metadata["extra_actions"] = cached.get("compromised_actions", {})
        metadata["extra_packages"] = cached.get("malicious_packages", {})
        metadata["extra_domains"] = cached.get("suspicious_domains", {})
        metadata["patterns_fetched"] = len(patterns)
        metadata["fetch_time_ms"] = int((time.time() - start) * 1000)
        return patterns, metadata

    # ── 2. Try primary feed (threat-feed branch) ──
    primary = _fetch_primary_feed()
    if primary:
        metadata["feed_source"] = "primary"
        metadata["feed_version"] = primary.get("version", "unknown")
        for raw in primary.get("patterns", []):
            p = _feed_pattern_to_attack(raw)
            if p:
                patterns.append(p)
        metadata["extra_shas"] = primary.get("compromised_shas", {})
        metadata["extra_actions"] = primary.get("compromised_actions", {})
        metadata["extra_packages"] = primary.get("malicious_packages", {})
        metadata["extra_domains"] = primary.get("suspicious_domains", {})
        _write_cache(primary)
        metadata["patterns_fetched"] = len(patterns)
        metadata["fetch_time_ms"] = int((time.time() - start) * 1000)
        return patterns, metadata

    # ── 3. Try OSV.dev ──
    osv_vulns = _fetch_osv_actions_advisories()
    if osv_vulns:
        metadata["feed_source"] = "osv"
        for i, vuln in enumerate(osv_vulns[:30]):  # cap at 30
            p = _osv_to_attack(vuln, i)
            if p:
                patterns.append(p)
        metadata["patterns_fetched"] = len(patterns)

    # ── 4. Try GHSA ──
    ghsa_advisories = _fetch_ghsa_advisories()
    if ghsa_advisories:
        if metadata["feed_source"] == "none":
            metadata["feed_source"] = "ghsa"
        else:
            metadata["feed_source"] += "+ghsa"
        for i, adv in enumerate(ghsa_advisories[:20]):
            p = _ghsa_to_attack(adv, i)
            if p:
                patterns.append(p)
        metadata["patterns_fetched"] = len(patterns)

    metadata["fetch_time_ms"] = int((time.time() - start) * 1000)
    return patterns, metadata


def merge_live_patterns(attack_db: AttackDatabase, patterns: List[AttackPattern],
                        metadata: Dict) -> int:
    """
    Merge live threat feed patterns into an existing AttackDatabase instance.

    Deduplicates by pattern ID — if a pattern with the same ID already exists
    in the bundled database, the live feed pattern is skipped (bundled = authoritative).

    Also merges extra compromised SHAs, actions, packages, and domains into
    the existing attack patterns (appended to the first relevant attack).

    Returns: number of NEW patterns added.
    """
    existing_ids = {a.id for a in attack_db.attacks}
    added = 0

    for pattern in patterns:
        if pattern.id not in existing_ids:
            attack_db.attacks.append(pattern)
            existing_ids.add(pattern.id)
            added += 1

    # Merge extra SHAs/actions/packages into a synthetic catch-all pattern
    extras = {
        "compromised_shas": metadata.get("extra_shas", {}),
        "compromised_actions": metadata.get("extra_actions", {}),
        "malicious_packages": metadata.get("extra_packages", {}),
        "suspicious_domains": metadata.get("extra_domains", {}),
    }

    has_extras = any(v for v in extras.values())
    if has_extras:
        extra_id = "LIVE-FEED-EXTRAS"
        if extra_id not in existing_ids:
            # Build merged detection_signatures
            sigs = {}
            if extras["compromised_shas"]:
                sigs["compromised_shas"] = list(extras["compromised_shas"].keys())
            if extras["compromised_actions"]:
                sigs["compromised_actions"] = list(extras["compromised_actions"].keys())
            if extras["malicious_packages"]:
                sigs["malicious_packages"] = {}
                for eco, pkgs in extras["malicious_packages"].items():
                    if isinstance(pkgs, dict):
                        sigs["malicious_packages"][eco] = list(pkgs.keys())
                    elif isinstance(pkgs, list):
                        sigs["malicious_packages"][eco] = pkgs
            if extras["suspicious_domains"]:
                sigs["suspicious_domains"] = list(extras["suspicious_domains"].keys())

            attack_db.attacks.append(AttackPattern(
                id=extra_id,
                name="Live Threat Feed — Additional Indicators",
                category="live_advisory",
                severity="critical",
                cve="N/A",
                description="Additional compromise indicators fetched from the live threat feed.",
                date=time.strftime("%Y-%m-%d"),
                affected=[],
                references=[],
                detection_signatures=sigs,
                remediation="Review indicators and cross-reference with the latest advisories.",
            ))
            added += 1

    return added
