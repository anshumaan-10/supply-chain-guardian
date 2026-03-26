#!/usr/bin/env python3
"""
HTML Report Generator
=====================
Converts a Supply Chain Guardian JSON report into a rich, self-contained
HTML page. Designed to be uploaded as a GitHub Actions artifact and viewed
directly in the browser.

Usage:
    python html_reporter.py report.json report.html

Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
"""

import json
import sys
import os
from datetime import datetime
from typing import Dict, Any, List


SEVERITY_COLOR = {
    "critical": ("#FF0000", "#FFF0F0", "🚨"),
    "high":     ("#FF6B35", "#FFF4EF", "⚠️"),
    "medium":   ("#F4A261", "#FFFBF0", "🔶"),
    "low":      ("#2196F3", "#F0F7FF", "ℹ️"),
    "info":     ("#9E9E9E", "#F9F9F9", "💬"),
}

STATUS_COLOR = {
    "FAILED":  ("#FF0000", "❌"),
    "WARNING": ("#FF8800", "⚠️"),
    "PASSED":  ("#00AA00", "✅"),
    "AUDIT":   ("#6600CC", "🔍"),
}


def _esc(text: str) -> str:
    """HTML escape."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _badge(severity: str) -> str:
    color, bg, icon = SEVERITY_COLOR.get(severity.lower(), ("#888", "#EEE", "·"))
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {color};'
        f'border-radius:4px;padding:2px 8px;font-size:12px;font-weight:700;white-space:nowrap">'
        f'{icon} {severity.upper()}</span>'
    )


def _status_badge(status: str) -> str:
    color, icon = STATUS_COLOR.get(status, ("#888", "·"))
    return (
        f'<span style="background:{color};color:#fff;border-radius:6px;'
        f'padding:4px 14px;font-size:16px;font-weight:700">'
        f'{icon} {status}</span>'
    )


def _finding_rows(findings: List[Dict]) -> str:
    if not findings:
        return '<tr><td colspan="5" style="text-align:center;color:#888;padding:20px">No findings</td></tr>'
    rows = []
    for i, f in enumerate(findings):
        sev = f.get("severity", "info").lower()
        _, bg, _ = SEVERITY_COLOR.get(sev, ("#888", "#FFF", "·"))
        exempted = f.get("status") == "exempted"
        row_style = f'background:{bg};' + ('opacity:0.6;' if exempted else '')
        exemption_note = ""
        if exempted:
            exemption_note = (
                f'<br><small style="color:#666">⊘ Exempted: {_esc(f.get("exemption_reason", ""))}'
                f' (approved by {_esc(f.get("approved_by", "?"))})</small>'
            )
        rows.append(f"""
        <tr style="{row_style}border-bottom:1px solid #ddd">
          <td style="padding:10px 8px;font-weight:600">{_badge(sev)}</td>
          <td style="padding:10px 8px;font-family:monospace;font-size:13px;font-weight:700">
            {_esc(f.get('id', f.get('rule_id', 'N/A')))}</td>
          <td style="padding:10px 8px">
            <strong>{_esc(f.get('name', f.get('title', 'Unknown')))}</strong>
            <br><small style="color:#555">{_esc(f.get('scanner', ''))}</small>
            {exemption_note}
          </td>
          <td style="padding:10px 8px;font-size:12px">{_esc(str(f.get('file', f.get('location', ''))))}</td>
          <td style="padding:10px 8px;font-size:12px;color:#444">{_esc(f.get('remediation', f.get('message', '')))[:200]}</td>
        </tr>""")
    return "\n".join(rows)


def generate_html(report_data: Dict[str, Any]) -> str:
    meta = report_data.get("metadata", {})
    summary = report_data.get("summary", {})
    findings = report_data.get("findings", [])

    status = summary.get("verdict", meta.get("status", "AUDIT")).upper()
    scan_mode = meta.get("scan_mode", "audit")
    repo = meta.get("repository", meta.get("workspace", "unknown"))
    sha = meta.get("commit_sha", meta.get("sha", ""))[:8] if meta.get("commit_sha", meta.get("sha", "")) else ""
    scanned_at = meta.get("scanned_at", datetime.utcnow().isoformat())
    duration = meta.get("duration_seconds", summary.get("duration_seconds", "?"))

    total    = summary.get("total_findings", len(findings))
    critical = summary.get("critical", 0)
    high     = summary.get("high", 0)
    medium   = summary.get("medium", 0)
    low      = summary.get("low", 0)
    info_cnt = summary.get("info", 0)
    exempted = summary.get("exempted", sum(1 for f in findings if f.get("status") == "exempted"))
    scanners = summary.get("scanners_run", meta.get("scanners_run", "?"))
    patterns = summary.get("patterns_checked", meta.get("patterns_checked", "?"))

    # Split findings by severity for grouped tables
    by_sev = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    exempted_list = []
    for f in findings:
        if f.get("status") == "exempted":
            exempted_list.append(f)
        else:
            sev = f.get("severity", "info").lower()
            by_sev.setdefault(sev, []).append(f)

    # Scanner breakdown
    scanner_counts: Dict[str, int] = {}
    for f in findings:
        sc = f.get("scanner", "unknown")
        scanner_counts[sc] = scanner_counts.get(sc, 0) + 1
    scanner_rows = "\n".join(
        f'<tr><td style="padding:6px 10px">{_esc(sc)}</td>'
        f'<td style="padding:6px 10px;text-align:center;font-weight:700">{cnt}</td></tr>'
        for sc, cnt in sorted(scanner_counts.items(), key=lambda x: -x[1])
    ) or '<tr><td colspan="2" style="text-align:center;color:#888">No findings</td></tr>'

    def section(sev: str) -> str:
        items = by_sev.get(sev, [])
        if not items:
            return ""
        color, bg, icon = SEVERITY_COLOR.get(sev, ("#888", "#EEE", "·"))
        return f"""
        <h3 style="color:{color};margin:24px 0 8px;border-bottom:2px solid {color};padding-bottom:4px">
          {icon} {sev.upper()} ({len(items)})
        </h3>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          <thead>
            <tr style="background:#f5f5f5">
              <th style="padding:8px;text-align:left;width:90px">Severity</th>
              <th style="padding:8px;text-align:left;width:90px">Rule ID</th>
              <th style="padding:8px;text-align:left">Finding</th>
              <th style="padding:8px;text-align:left;width:180px">Location</th>
              <th style="padding:8px;text-align:left">Remediation</th>
            </tr>
          </thead>
          <tbody>{_finding_rows(items)}</tbody>
        </table>"""

    status_color, _ = STATUS_COLOR.get(status, ("#888", "·"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SCG Audit Report — {_esc(repo)} {sha}</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           margin: 0; padding: 0; background: #f0f2f5; color: #1a1a1a; }}
    .banner {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
               color: #fff; padding: 28px 40px; border-bottom: 3px solid {status_color}; }}
    .banner h1 {{ margin: 0 0 4px; font-size: 26px; letter-spacing: -0.5px; }}
    .banner .sub {{ color: #8b949e; font-size: 14px; margin: 4px 0 0; }}
    .container {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
    .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,.08);
             padding: 20px 24px; margin-bottom: 20px; }}
    .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px,1fr));
                  gap: 14px; margin-bottom: 20px; }}
    .stat {{ background: #fff; border-radius: 8px; padding: 16px; text-align: center;
             box-shadow: 0 1px 4px rgba(0,0,0,.07); border-top: 3px solid #ddd; }}
    .stat .num {{ font-size: 32px; font-weight: 800; line-height: 1; }}
    .stat .lbl {{ font-size: 12px; color: #666; margin-top: 4px; text-transform: uppercase; }}
    .stat.crit {{ border-color: #FF0000; }} .stat.crit .num {{ color: #FF0000; }}
    .stat.high {{ border-color: #FF6B35; }} .stat.high .num {{ color: #FF6B35; }}
    .stat.med  {{ border-color: #F4A261; }} .stat.med  .num {{ color: #F4A261; }}
    .stat.low  {{ border-color: #2196F3; }} .stat.low  .num {{ color: #2196F3; }}
    .stat.info {{ border-color: #9E9E9E; }} .stat.info .num {{ color: #9E9E9E; }}
    .stat.exm  {{ border-color: #9C27B0; }} .stat.exm  .num {{ color: #9C27B0; }}
    .meta-table td {{ padding: 6px 12px; font-size: 13px; }}
    .meta-table td:first-child {{ color: #666; font-weight: 600; width: 160px; }}
    .audit-notice {{ background: #f3e8ff; border-left: 4px solid #9C27B0;
                     padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;
                     font-size: 14px; color: #4a0082; }}
    details summary {{ cursor:pointer; user-select:none; }}
    details summary:hover {{ color: #0066cc; }}
    @media print {{
      .banner {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    }}
  </style>
</head>
<body>

<div class="banner">
  <h1>🛡️ Supply Chain Guardian — Audit Report</h1>
  <div class="sub">
    {_esc(repo)}{(' @ ' + sha) if sha else ''} &nbsp;·&nbsp;
    Mode: <strong>{_esc(scan_mode)}</strong> &nbsp;·&nbsp;
    Scanned: {_esc(scanned_at)} &nbsp;·&nbsp;
    Duration: {_esc(str(duration))}s
  </div>
  <div style="margin-top:12px">{_status_badge(status)}</div>
</div>

<div class="container">

  <div class="audit-notice">
    🔍 <strong>AUDIT MODE</strong> — All findings are recorded for review. The pipeline is
    <strong>not blocked</strong> by any finding in this run. Exempted findings are preserved
    in the report for compliance traceability.
  </div>

  <!-- Summary stats -->
  <div class="stat-grid">
    <div class="stat" style="border-color:#555">
      <div class="num">{total}</div><div class="lbl">Total</div></div>
    <div class="stat crit"><div class="num">{critical}</div><div class="lbl">Critical</div></div>
    <div class="stat high"><div class="num">{high}</div><div class="lbl">High</div></div>
    <div class="stat med"><div class="num">{medium}</div><div class="lbl">Medium</div></div>
    <div class="stat low"><div class="num">{low}</div><div class="lbl">Low</div></div>
    <div class="stat info"><div class="num">{info_cnt}</div><div class="lbl">Info</div></div>
    <div class="stat exm"><div class="num">{exempted}</div><div class="lbl">Exempted</div></div>
    <div class="stat" style="border-color:#00AA00">
      <div class="num" style="font-size:18px;color:#00AA00">{_esc(str(scanners))}</div>
      <div class="lbl">Scanners</div></div>
    <div class="stat" style="border-color:#00AA00">
      <div class="num" style="font-size:18px;color:#00AA00">{_esc(str(patterns))}</div>
      <div class="lbl">Patterns</div></div>
  </div>

  <!-- Scan metadata -->
  <div class="card">
    <h2 style="margin:0 0 12px">Scan Metadata</h2>
    <table class="meta-table">
      <tr><td>Repository</td><td>{_esc(repo)}</td></tr>
      <tr><td>Commit SHA</td><td><code>{_esc(meta.get('commit_sha', meta.get('sha', 'N/A')))}</code></td></tr>
      <tr><td>Branch / Ref</td><td><code>{_esc(meta.get('ref', meta.get('branch', 'N/A')))}</code></td></tr>
      <tr><td>Scan Mode</td><td>{_esc(scan_mode)}</td></tr>
      <tr><td>Tool Version</td><td>{_esc(meta.get('tool_version', meta.get('version', '4.0.0')))}</td></tr>
      <tr><td>Trigger</td><td>{_esc(meta.get('event', meta.get('trigger', 'workflow_dispatch')))}</td></tr>
      <tr><td>Runner OS</td><td>{_esc(meta.get('runner_os', 'ubuntu-latest'))}</td></tr>
    </table>
  </div>

  <!-- Scanner breakdown -->
  <div class="card">
    <details open>
      <summary><h2 style="display:inline;margin:0">Findings by Scanner</h2></summary>
      <table style="width:100%;border-collapse:collapse;margin-top:12px;font-size:13px">
        <thead><tr style="background:#f5f5f5">
          <th style="padding:8px;text-align:left">Scanner Module</th>
          <th style="padding:8px;text-align:center">Findings</th>
        </tr></thead>
        <tbody>{scanner_rows}</tbody>
      </table>
    </details>
  </div>

  <!-- Findings by severity -->
  <div class="card">
    <h2 style="margin:0 0 4px">Findings Detail</h2>
    <p style="color:#666;font-size:13px;margin:0 0 16px">
      Sorted by severity. Exempted findings shown separately below.
    </p>
    {section('critical')}
    {section('high')}
    {section('medium')}
    {section('low')}
    {section('info')}
  </div>

  <!-- Exempted findings -->
  {"" if not exempted_list else f'''
  <div class="card">
    <details>
      <summary><h2 style="display:inline;margin:0;color:#9C27B0">
        ⊘ Exempted Findings ({len(exempted_list)})
      </h2></summary>
      <p style="color:#666;font-size:13px;margin:8px 0 16px">
        These findings were suppressed by .scg-config.yml or inline # scg-ignore comments.
        They are preserved here for the compliance audit trail.
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="background:#f5f5f5">
          <th style="padding:8px;text-align:left">Severity</th>
          <th style="padding:8px;text-align:left">Rule ID</th>
          <th style="padding:8px;text-align:left">Finding</th>
          <th style="padding:8px;text-align:left">Location</th>
          <th style="padding:8px;text-align:left">Exemption Reason</th>
        </tr></thead>
        <tbody>{_finding_rows(exempted_list)}</tbody>
      </table>
    </details>
  </div>
  '''}

  <div style="text-align:center;color:#888;font-size:12px;padding:20px 0">
    Generated by Supply Chain Guardian v4.0.0 &nbsp;·&nbsp;
    <a href="https://github.com/anshumaan-10/supply-chain-guardian">github.com/anshumaan-10/supply-chain-guardian</a>
    &nbsp;·&nbsp; {_esc(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}
  </div>

</div>
</body>
</html>"""


def main() -> int:
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <report.json> <output.html>")
        return 1

    json_path = sys.argv[1]
    html_path = sys.argv[2]

    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found")
        return 1

    with open(json_path) as f:
        report_data = json.load(f)

    html = generate_html(report_data)

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    findings_count = len(report_data.get("findings", []))
    print(f"[SCG] HTML report written: {html_path} ({findings_count} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
