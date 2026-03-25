#!/usr/bin/env python3
"""
Slack Alerter
=============
Sends formatted alerts to Slack via Incoming Webhooks.
Supports severity-based filtering and rich message formatting.
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


class SlackAlerter:
    """Send supply chain security alerts to Slack."""

    SEVERITY_EMOJI = {
        "critical": ":rotating_light:",
        "high": ":warning:",
        "medium": ":large_orange_diamond:",
        "low": ":information_source:",
        "info": ":speech_balloon:",
    }

    SEVERITY_COLOR = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#0066FF",
        "info": "#999999",
    }

    STATUS_EMOJI = {
        "PASSED": ":white_check_mark:",
        "WARNING": ":warning:",
        "FAILED": ":x:",
    }

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_alert(self, report_data: Dict[str, Any]) -> bool:
        """Send alert to Slack with scan results."""
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
                return resp.status_code == 200
            elif HAS_URLLIB:
                data = json.dumps(payload).encode("utf-8")
                req = Request(
                    self.webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                resp = urlopen(req, timeout=30)
                return resp.status == 200
            else:
                print("  Warning: Neither requests nor urllib available for Slack alerts")
                return False
        except Exception as e:
            print(f"  Error sending Slack alert: {e}")
            return False

    def _build_payload(self, report_data: Dict[str, Any]) -> Dict:
        """Build Slack message payload with blocks."""
        summary = report_data.get("summary", {})
        status = report_data.get("overall_status", "UNKNOWN")
        status_emoji = self.STATUS_EMOJI.get(status, ":question:")
        repo = report_data.get("repository", "unknown")
        sha = report_data.get("commit_sha", "unknown")[:8]
        event = report_data.get("event", "unknown")
        findings = report_data.get("findings", [])

        # Header
        header_text = f"{status_emoji} Supply Chain Guardian — {status}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n{repo}"},
                    {"type": "mrkdwn", "text": f"*Commit:*\n`{sha}`"},
                    {"type": "mrkdwn", "text": f"*Event:*\n{event}"},
                    {"type": "mrkdwn", "text": f"*Scan Mode:*\n{report_data.get('scan_mode', 'standard')}"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":rotating_light: *Critical:* {summary.get('critical', 0)}  |  "
                        f":warning: *High:* {summary.get('high', 0)}  |  "
                        f":large_orange_diamond: *Medium:* {summary.get('medium', 0)}  |  "
                        f":information_source: *Low:* {summary.get('low', 0)}\n"
                        f"*Total Findings:* {summary.get('total_findings', 0)}  |  "
                        f"*Attacks Checked:* {report_data.get('attacks_checked', 0)}"
                    )
                }
            },
        ]

        # Add top findings (max 5)
        critical_high = [f for f in findings if f.get("severity") in ("critical", "high")]
        if critical_high:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top Findings:*"}
            })

            for finding in critical_high[:5]:
                sev = finding.get("severity", "info")
                emoji = self.SEVERITY_EMOJI.get(sev, ":grey_question:")
                title = finding.get("title", "Unknown")
                file_info = finding.get("file", "")
                line = finding.get("line", 0)
                loc = f" (`{file_info}:{line}`)" if file_info else ""

                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *[{sev.upper()}]* {title}{loc}"
                    }
                })

            if len(critical_high) > 5:
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"_...and {len(critical_high) - 5} more critical/high findings_"
                    }]
                })

        # Add link to run
        run_id = report_data.get("run_id", os.environ.get("GITHUB_RUN_ID", ""))
        server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        if run_id and repo:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":link: <{server_url}/{repo}/actions/runs/{run_id}|View Full Report>"
                }
            })

        # Footer
        blocks.append({
            "type": "context",
            "elements": [{
                "type": "mrkdwn",
                "text": f"Supply Chain Guardian v{report_data.get('version', '1.0.0')} | "
                        f"DB v{report_data.get('attack_database_version', 'unknown')} | "
                        f"Scan duration: {report_data.get('scan_duration_seconds', 0)}s"
            }]
        })

        return {
            "text": f"Supply Chain Guardian: {status} - {summary.get('total_findings', 0)} findings in {repo}",
            "blocks": blocks,
        }
