#!/usr/bin/env python3
"""
GitHub Reporter
===============
Integrates with GitHub API for PR comments, issue creation,
and workflow annotations.
"""

import json
import os
from typing import Dict, Any, List

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

from utils.config import ScanConfig


class GitHubReporter:
    """Report findings via GitHub API — PR comments, issues, annotations."""

    def __init__(self, config: ScanConfig, token: str):
        self.config = config
        self.token = token
        self.api_url = "https://api.github.com"
        self.repo = os.environ.get("GITHUB_REPOSITORY", "")
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def annotate_findings(self, findings: List[Dict[str, Any]]):
        """Create GitHub Actions annotations for findings."""
        for finding in findings:
            severity = finding.get("severity", "info")
            title = finding.get("title", "")
            file_path = finding.get("file", "")
            line = finding.get("line", 0)
            desc = finding.get("description", "")

            # Use GitHub Actions annotation commands
            if severity in ("critical", "high"):
                annotation = "error"
            elif severity == "medium":
                annotation = "warning"
            else:
                annotation = "notice"

            if file_path and line:
                print(f"::{annotation} file={file_path},line={line},title=Supply Chain Guardian - {title}::{desc[:500]}")
            elif file_path:
                print(f"::{annotation} file={file_path},title=Supply Chain Guardian - {title}::{desc[:500]}")
            else:
                print(f"::{annotation} title=Supply Chain Guardian - {title}::{desc[:500]}")

    def comment_pr(self, report_data: Dict[str, Any]):
        """Post a comment on the PR with scan results."""
        event_path = os.environ.get("GITHUB_EVENT_PATH", "")
        if not event_path or not os.path.exists(event_path):
            return

        try:
            with open(event_path, "r") as f:
                event_data = json.load(f)
        except (json.JSONDecodeError, IOError):
            return

        pr_number = event_data.get("pull_request", {}).get("number")
        if not pr_number:
            return

        comment_body = self._build_pr_comment(report_data)
        url = f"{self.api_url}/repos/{self.repo}/issues/{pr_number}/comments"

        # Check for existing comment to update
        existing_id = self._find_existing_comment(pr_number)
        if existing_id:
            url = f"{self.api_url}/repos/{self.repo}/issues/comments/{existing_id}"
            self._api_request("PATCH", url, {"body": comment_body})
        else:
            self._api_request("POST", url, {"body": comment_body})

    def create_issue(self, report_data: Dict[str, Any]):
        """Create a GitHub issue for critical findings."""
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "critical"]

        if not critical:
            return

        title = (
            f"🚨 Supply Chain Guardian: {len(critical)} critical finding(s) detected"
        )

        body = self._build_issue_body(report_data)
        url = f"{self.api_url}/repos/{self.repo}/issues"

        self._api_request("POST", url, {
            "title": title,
            "body": body,
            "labels": ["security", "supply-chain", "critical"],
        })

    def _build_pr_comment(self, report_data: Dict[str, Any]) -> str:
        """Build a Markdown PR comment."""
        summary = report_data.get("summary", {})
        status = report_data.get("overall_status", "UNKNOWN")
        findings = report_data.get("findings", [])

        # Status badge
        status_icon = {"PASSED": "✅", "WARNING": "⚠️", "FAILED": "❌"}.get(status, "❓")

        lines = [
            f"## {status_icon} Supply Chain Guardian — {status}\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🚨 Critical | {summary.get('critical', 0)} |",
            f"| ⚠️ High | {summary.get('high', 0)} |",
            f"| 🔶 Medium | {summary.get('medium', 0)} |",
            f"| ℹ️ Low | {summary.get('low', 0)} |",
            f"| **Total** | **{summary.get('total_findings', 0)}** |",
            "",
            f"*Scan mode: {report_data.get('scan_mode', 'standard')} | "
            f"Attacks checked: {report_data.get('attacks_checked', 0)} | "
            f"Duration: {report_data.get('scan_duration_seconds', 0)}s*",
            "",
        ]

        # Add critical/high findings detail
        critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
        if critical_high:
            lines.append("### Critical & High Findings\n")
            lines.append("| # | Severity | Finding | Location |")
            lines.append("|---|----------|---------|----------|")

            for i, finding in enumerate(critical_high[:15], 1):
                sev = finding.get("severity", "info")
                icon = {"critical": "🚨", "high": "⚠️"}.get(sev, "")
                title = finding.get("title", "Unknown")[:65]
                file_info = finding.get("file", "")
                line_num = finding.get("line", 0)
                loc = f"`{file_info}:{line_num}`" if file_info else ""
                lines.append(f"| {i} | {icon} {sev} | {title} | {loc} |")

            if len(critical_high) > 15:
                lines.append(f"\n*...and {len(critical_high) - 15} more findings*")

            # Remediation section
            lines.append("\n### Recommended Actions\n")
            seen_remediation = set()
            for finding in critical_high[:5]:
                rem = finding.get("remediation", "")
                if rem and rem not in seen_remediation:
                    seen_remediation.add(rem)
                    lines.append(f"- {rem}")

        lines.append(f"\n---\n*🛡️ [Supply Chain Guardian](https://github.com/anshumaan-10/supply-chain-guardian) v{report_data.get('version', '1.0.0')}*")
        lines.append("<!-- supply-chain-guardian-comment -->")

        return "\n".join(lines)

    def _build_issue_body(self, report_data: Dict[str, Any]) -> str:
        """Build a GitHub issue body."""
        summary = report_data.get("summary", {})
        findings = report_data.get("findings", [])
        critical = [f for f in findings if f.get("severity") == "critical"]

        lines = [
            "## 🚨 Supply Chain Security Alert\n",
            f"Supply Chain Guardian detected **{len(critical)} critical findings** in this repository.\n",
            f"**Repository:** {report_data.get('repository', 'unknown')}",
            f"**Commit:** `{report_data.get('commit_sha', 'unknown')[:8]}`",
            f"**Ref:** {report_data.get('ref', 'unknown')}",
            "",
            "### Critical Findings\n",
        ]

        for i, finding in enumerate(critical[:10], 1):
            title = finding.get("title", "Unknown")
            desc = finding.get("description", "")[:300]
            rem = finding.get("remediation", "No remediation provided.")
            file_info = finding.get("file", "")
            line_num = finding.get("line", 0)

            lines.append(f"#### {i}. {title}")
            if file_info:
                lines.append(f"📁 `{file_info}:{line_num}`\n")
            lines.append(f"{desc}\n")
            lines.append(f"**Remediation:** {rem}\n")

        lines.append("---")
        lines.append("*This issue was automatically created by Supply Chain Guardian.*")

        return "\n".join(lines)

    def _find_existing_comment(self, pr_number: int):
        """Find an existing Supply Chain Guardian comment on the PR."""
        url = f"{self.api_url}/repos/{self.repo}/issues/{pr_number}/comments"
        try:
            comments = self._api_request("GET", url)
            if isinstance(comments, list):
                for comment in comments:
                    body = comment.get("body", "")
                    if "<!-- supply-chain-guardian-comment -->" in body:
                        return comment.get("id")
        except Exception:
            pass
        return None

    def _api_request(self, method: str, url: str, data: Dict = None):
        """Make a GitHub API request."""
        try:
            if HAS_REQUESTS:
                if method == "GET":
                    resp = requests.get(url, headers=self.headers, timeout=30)
                elif method == "POST":
                    resp = requests.post(url, json=data, headers=self.headers, timeout=30)
                elif method == "PATCH":
                    resp = requests.patch(url, json=data, headers=self.headers, timeout=30)
                else:
                    return None

                if resp.status_code in (200, 201):
                    return resp.json()
                return None
            elif HAS_URLLIB:
                req_data = json.dumps(data).encode("utf-8") if data else None
                req = Request(url, data=req_data, headers=self.headers, method=method)
                if req_data:
                    req.add_header("Content-Type", "application/json")
                resp = urlopen(req, timeout=30)
                if resp.status in (200, 201):
                    return json.loads(resp.read().decode("utf-8"))
                return None
        except Exception as e:
            print(f"  GitHub API error: {e}")
            return None
