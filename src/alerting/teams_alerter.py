#!/usr/bin/env python3
"""
Microsoft Teams Alerter
========================
Sends formatted alerts to Microsoft Teams via Incoming Webhooks.
Uses Adaptive Card format for rich message formatting.
"""

import json
import os
from typing import Dict, Any

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


class TeamsAlerter:
    """Send supply chain security alerts to Microsoft Teams."""

    SEVERITY_ICONS = {
        "critical": "🚨",
        "high": "⚠️",
        "medium": "🔶",
        "low": "ℹ️",
        "info": "💬",
    }

    STATUS_COLORS = {
        "PASSED": "Good",
        "WARNING": "Warning",
        "FAILED": "Attention",
    }

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_alert(self, report_data: Dict[str, Any]) -> bool:
        """Send alert to Microsoft Teams."""
        if not self.webhook_url:
            return False

        payload = self._build_payload(report_data)

        try:
            if HAS_REQUESTS:
                resp = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=30,
                )
                return resp.status_code in (200, 202)
            elif HAS_URLLIB:
                data = json.dumps(payload).encode("utf-8")
                req = Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                resp = urlopen(req, timeout=30)
                return resp.status in (200, 202)
            else:
                print("  Warning: Neither requests nor urllib available for Teams alerts")
                return False
        except Exception as e:
            print(f"  Error sending Teams alert: {e}")
            return False

    def _build_payload(self, report_data: Dict[str, Any]) -> Dict:
        """Build Microsoft Teams Adaptive Card payload."""
        summary = report_data.get("summary", {})
        status = report_data.get("overall_status", "UNKNOWN")
        repo = report_data.get("repository", "unknown")
        sha = report_data.get("commit_sha", "unknown")[:8]
        event = report_data.get("event", "unknown")
        findings = report_data.get("findings", [])
        color = self.STATUS_COLORS.get(status, "Default")

        # Status indicator
        status_icon = {"PASSED": "✅", "WARNING": "⚠️", "FAILED": "❌"}.get(status, "❓")

        # Build facts
        facts = [
            {"title": "Repository", "value": repo},
            {"title": "Commit", "value": sha},
            {"title": "Event", "value": event},
            {"title": "Scan Mode", "value": report_data.get("scan_mode", "standard")},
            {"title": "Duration", "value": f"{report_data.get('scan_duration_seconds', 0)}s"},
        ]

        # Summary section
        summary_text = (
            f"🚨 Critical: **{summary.get('critical', 0)}** | "
            f"⚠️ High: **{summary.get('high', 0)}** | "
            f"🔶 Medium: **{summary.get('medium', 0)}** | "
            f"ℹ️ Low: **{summary.get('low', 0)}**\n\n"
            f"**Total Findings:** {summary.get('total_findings', 0)} | "
            f"**Attacks Checked:** {report_data.get('attacks_checked', 0)}"
        )

        # Build findings list
        findings_text = ""
        critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
        for finding in critical_high[:8]:
            sev = finding.get("severity", "info")
            icon = self.SEVERITY_ICONS.get(sev, "❓")
            title = finding.get("title", "Unknown")
            file_info = finding.get("file", "")
            line = finding.get("line", 0)
            loc = f" ({file_info}:{line})" if file_info else ""
            findings_text += f"- {icon} **[{sev.upper()}]** {title}{loc}\n"

        if len(critical_high) > 8:
            findings_text += f"\n_...and {len(critical_high) - 8} more findings_"

        # Build Adaptive Card
        body = [
            {
                "type": "TextBlock",
                "size": "Large",
                "weight": "Bolder",
                "text": f"{status_icon} Supply Chain Guardian — {status}",
                "wrap": True,
            },
            {
                "type": "FactSet",
                "facts": [{"title": f.get("title", ""), "value": f.get("value", "")} for f in facts],
            },
            {
                "type": "TextBlock",
                "text": summary_text,
                "wrap": True,
            },
        ]

        if findings_text:
            body.append({
                "type": "TextBlock",
                "text": "**Top Findings:**",
                "weight": "Bolder",
                "wrap": True,
            })
            body.append({
                "type": "TextBlock",
                "text": findings_text,
                "wrap": True,
            })

        # Add action button
        run_id = report_data.get("run_id", os.environ.get("GITHUB_RUN_ID", ""))
        server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        actions = []
        if run_id and repo:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Full Report",
                "url": f"{server_url}/{repo}/actions/runs/{run_id}",
            })

        card = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                    "actions": actions,
                    "msteams": {
                        "width": "Full",
                    },
                },
            }],
        }

        return card
