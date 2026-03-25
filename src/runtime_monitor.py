#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Supply Chain Guardian — Runtime Monitoring Daemon
#  Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
#
#  Persistent background monitor that watches for threats throughout
#  the entire CI/CD job lifecycle — from first step to last.
#
#  Usage:
#    python runtime_monitor.py start   — launch daemon in background
#    python runtime_monitor.py stop    — stop daemon, collect findings
#    python runtime_monitor.py status  — check if daemon is running
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import os
import re
import sys
import json
import time
import signal
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# ── Daemon Configuration ─────────────────────────────────────────────────────

MONITOR_DIR = Path(os.environ.get("SCG_MONITOR_DIR", "/tmp/scg-runtime-monitor"))
PID_FILE = MONITOR_DIR / "monitor.pid"
FINDINGS_FILE = MONITOR_DIR / "runtime-findings.json"
LOG_FILE = MONITOR_DIR / "monitor.log"
SNAPSHOT_DIR = MONITOR_DIR / "snapshots"

DEFAULT_POLL_INTERVAL = int(os.environ.get("SCG_POLL_INTERVAL", "5"))  # seconds
MAX_FINDINGS = 500  # cap to prevent runaway disk usage


# ── Threat Signatures ────────────────────────────────────────────────────────
# These are checked continuously, not just once

SUSPICIOUS_PROCESSES = [
    ("xmrig", "Cryptominer (XMRig)", "critical"),
    ("minergate", "Cryptominer (Minergate)", "critical"),
    ("minerd", "Cryptominer (minerd)", "critical"),
    ("cpuminer", "Cryptominer (cpuminer)", "critical"),
    ("nc -e", "Netcat reverse shell", "critical"),
    ("ncat -e", "Ncat reverse shell", "critical"),
    ("socat ", "Socat tunnel", "high"),
    ("ngrok", "ngrok tunnel service", "critical"),
    ("cloudflared", "Cloudflare tunnel", "critical"),
    ("sysmon.py", "TeamPCP persistence daemon", "critical"),
    ("Runner.Worker", "Runner Worker targeting (TeamPCP)", "critical"),
]

SUSPICIOUS_PORTS = {
    "4444": "Metasploit default",
    "5555": "Common C2",
    "8888": "Alternative HTTP/C2",
    "9999": "Common C2",
    "1337": "Leet port / backdoor",
    "31337": "Back Orifice / classic backdoor",
    "4443": "Alternative HTTPS C2",
    "6666": "IRC C2 / backdoor",
    "6667": "IRC C2",
}

PERSISTENCE_PATHS = [
    ("~/.config/systemd/user/sysmon.py", "TeamPCP systemd persistence"),
    ("~/.config/systemd/user/sysmon.service", "TeamPCP systemd service"),
    ("/tmp/sysmon.py", "TeamPCP sysmon.py in /tmp"),
    ("/tmp/tpcp", "TeamPCP temp directory"),
    ("/tmp/.scg-bypass", "SCG bypass attempt"),
    ("/tmp/.hidden-*", "Hidden files in /tmp"),
    ("~/.bashrc.d/", "Bash persistence directory"),
    ("/dev/shm/.hidden", "Hidden file in shared memory"),
]

CREDENTIAL_FILES = [
    ("~/.npmrc", "npm credentials"),
    ("~/.pypirc", "PyPI credentials"),
    ("~/.docker/config.json", "Docker credentials"),
    ("~/.aws/credentials", "AWS credentials"),
    ("~/.kube/config", "Kubernetes config"),
    ("~/.ssh/id_rsa", "SSH private key"),
    ("~/.ssh/id_ed25519", "SSH private key (ed25519)"),
    ("/tmp/.env", "Dumped env file"),
    ("/tmp/secrets", "Secrets dump"),
]

PROC_MEM_PATTERNS = [
    (r"/proc/\d+/mem\b", "Process memory read (TeamPCP technique)"),
    (r"/proc/\d+/environ\b", "Process environ read"),
    (r"/proc/\d+/maps\b", "Process memory mapping read"),
    (r"/proc/\d+/cmdline\b", "Process cmdline inspection"),
]


# ── Logging ──────────────────────────────────────────────────────────────────

def _log(msg: str):
    """Append to the daemon log file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    line = f"[{ts}] {msg}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass


# ── Finding Storage ──────────────────────────────────────────────────────────

def _load_findings() -> list:
    """Load existing findings from disk."""
    if FINDINGS_FILE.exists():
        try:
            return json.loads(FINDINGS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


def _save_findings(findings: list):
    """Write findings to disk (atomic via rename)."""
    tmp = FINDINGS_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(findings, indent=2))
        tmp.rename(FINDINGS_FILE)
    except OSError as e:
        _log(f"ERROR saving findings: {e}")


def _add_finding(findings: list, seen: set, category: str, attack_id: str,
                 title: str, severity: str, description: str,
                 evidence: str = "", remediation: str = ""):
    """Add a finding, deduplicating by hash."""
    if len(findings) >= MAX_FINDINGS:
        return

    # Deduplicate by content hash
    key = hashlib.sha256(f"{attack_id}:{title}:{evidence[:100]}".encode()).hexdigest()[:16]
    if key in seen:
        return
    seen.add(key)

    findings.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "attack_id": attack_id,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence[:500],
        "remediation": remediation,
        "scanner": "runtime_monitor_daemon",
    })


# ── Process Baseline ─────────────────────────────────────────────────────────

def _snapshot_processes() -> dict:
    """Take a snapshot of running processes. Returns {pid: cmdline}."""
    procs = {}
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,ppid,user,args"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:  # skip header
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    procs[parts[0]] = parts[3]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return procs


def _snapshot_network() -> list:
    """Snapshot current network connections."""
    connections = []
    for cmd in [["ss", "-tnp"], ["netstat", "-tnp"]]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                connections = result.stdout.splitlines()
                break
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return connections


def _snapshot_file_hashes(paths: list) -> dict:
    """Hash a list of important files for tamper detection."""
    hashes = {}
    for path_str, _ in paths:
        expanded = os.path.expanduser(path_str)
        if os.path.isfile(expanded):
            try:
                h = hashlib.sha256(Path(expanded).read_bytes()).hexdigest()
                hashes[expanded] = h
            except OSError:
                pass
    return hashes


# ── Monitoring Checks (run every poll interval) ─────────────────────────────

def _check_processes(findings: list, seen: set, baseline_pids: set):
    """Check for suspicious or new processes."""
    try:
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return

        for line in result.stdout.splitlines():
            line_lower = line.lower()

            # Check against known suspicious process signatures
            for pattern, description, severity in SUSPICIOUS_PROCESSES:
                if pattern.lower() in line_lower:
                    _add_finding(
                        findings, seen,
                        category="suspicious_process",
                        attack_id="SCA-RT-PROC",
                        title=f"Suspicious process: {description}",
                        severity=severity,
                        description=f"Background monitor detected suspicious process matching "
                                    f"'{pattern.strip()}': {description}. This was caught by "
                                    f"continuous runtime monitoring during pipeline execution.",
                        evidence=line[:300],
                        remediation="Kill the process immediately. Rotate ALL secrets. "
                                    "Review recent workflow changes.",
                    )

            # Check for /proc memory access (TeamPCP technique)
            for pattern, description in PROC_MEM_PATTERNS:
                if re.search(pattern, line):
                    _add_finding(
                        findings, seen,
                        category="proc_memory_access",
                        attack_id="SCA-095",
                        title=f"Runtime: {description}",
                        severity="critical",
                        description=f"Process accessing {description}. This is the exact technique "
                                    f"used by TeamPCP (CVE-2026-33634) to steal Runner.Worker secrets "
                                    f"from process memory. Detected by continuous monitoring.",
                        evidence=line[:300],
                        remediation="Kill process immediately. Rotate ALL secrets. "
                                    "Use StepSecurity Harden-Runner to block /proc reads.",
                    )

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass


def _check_network(findings: list, seen: set):
    """Monitor for suspicious network connections."""
    connections = _snapshot_network()
    for line in connections:
        parts = line.split()
        for part in parts:
            if ":" in part:
                port = part.rsplit(":", 1)[-1]
                if port in SUSPICIOUS_PORTS:
                    reason = SUSPICIOUS_PORTS[port]
                    _add_finding(
                        findings, seen,
                        category="suspicious_network",
                        attack_id="SCA-RT-NET",
                        title=f"Suspicious connection: port {port} ({reason})",
                        severity="high",
                        description=f"Outbound connection to port {port} ({reason}). "
                                    f"Detected by continuous network monitoring.",
                        evidence=line[:300],
                        remediation="Investigate connection. Block outbound traffic to non-standard ports. "
                                    "Consider network policy enforcement.",
                    )


def _check_filesystem(findings: list, seen: set, baseline_hashes: dict):
    """Monitor filesystem for persistence and credential dumps."""
    # Check persistence paths
    for path_str, description in PERSISTENCE_PATHS:
        expanded = os.path.expanduser(path_str)
        # Handle glob-like patterns
        if "*" in expanded:
            import glob
            matches = glob.glob(expanded)
            for match in matches:
                _add_finding(
                    findings, seen,
                    category="persistence",
                    attack_id="SCA-096",
                    title=f"Persistence mechanism: {os.path.basename(match)}",
                    severity="critical",
                    description=f"Detected persistence file: {match} ({description}). "
                                f"Found by continuous filesystem monitoring.",
                    evidence=f"Path: {match}",
                    remediation=f"Remove {match} immediately. Check for systemd user services. "
                                f"Rotate ALL credentials.",
                )
        elif os.path.exists(expanded):
            _add_finding(
                findings, seen,
                category="persistence",
                attack_id="SCA-096",
                title=f"Persistence mechanism: {description}",
                severity="critical",
                description=f"Detected persistence at {path_str}: {description}. "
                            f"Found by continuous filesystem monitoring.",
                evidence=f"Path: {expanded}",
                remediation=f"Remove {expanded} immediately. Rotate ALL credentials.",
            )

    # Check for new credential files that appeared since baseline
    for path_str, description in CREDENTIAL_FILES:
        expanded = os.path.expanduser(path_str)
        if os.path.isfile(expanded):
            if expanded not in baseline_hashes:
                # New file appeared during the pipeline run!
                _add_finding(
                    findings, seen,
                    category="credential_file",
                    attack_id="SCA-RT-CRED",
                    title=f"New credential file: {path_str}",
                    severity="high",
                    description=f"Credential file appeared during pipeline execution: "
                                f"{description} at {path_str}. This file was not present when "
                                f"the monitor started.",
                    evidence=f"Path: {expanded}",
                    remediation=f"Remove {path_str} after use. Ensure it's not cached or "
                                f"uploaded as an artifact.",
                )
            else:
                # File existed at baseline — check if it was modified
                try:
                    current_hash = hashlib.sha256(Path(expanded).read_bytes()).hexdigest()
                    if current_hash != baseline_hashes.get(expanded):
                        _add_finding(
                            findings, seen,
                            category="credential_tamper",
                            attack_id="SCA-RT-CRED",
                            title=f"Credential file modified: {path_str}",
                            severity="critical",
                            description=f"Credential file was modified during pipeline execution: "
                                        f"{description} at {path_str}. Original hash differs from current.",
                            evidence=f"Path: {expanded}",
                            remediation=f"Investigate who/what modified {path_str}. Rotate credentials.",
                        )
                except OSError:
                    pass

    # Check for unexpected executables in /tmp
    try:
        for f in os.listdir("/tmp"):
            fpath = f"/tmp/{f}"
            if os.path.isfile(fpath) and os.access(fpath, os.X_OK):
                # Skip known-safe executables
                if f.startswith(("scg-", "npm-", "pip-", "go-build")):
                    continue
                _add_finding(
                    findings, seen,
                    category="suspicious_file",
                    attack_id="SCA-RT-FILE",
                    title=f"Executable in /tmp: {f}",
                    severity="medium",
                    description=f"An executable file was found in /tmp: {fpath}. "
                                f"Malware and credential stealers often drop executables in /tmp.",
                    evidence=f"Path: {fpath}",
                    remediation=f"Investigate {fpath}. Remove if suspicious.",
                )
    except OSError:
        pass


def _check_environment(findings: list, seen: set):
    """Check for secrets leaked into non-secret env vars."""
    secret_patterns = [
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key leaked"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT leaked"),
        (r"npm_[A-Za-z0-9]{36}", "npm token leaked"),
        (r"sk-[A-Za-z0-9]{20,}", "API key (OpenAI/Stripe) leaked"),
        (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab PAT leaked"),
        (r"xox[bsapr]-[A-Za-z0-9\-]{10,}", "Slack token leaked"),
    ]

    for var_name, var_value in os.environ.items():
        # Skip vars meant to hold secrets
        if any(x in var_name.upper() for x in [
            "SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL",
            "INPUT_", "ACTIONS_", "RUNNER_",
        ]):
            continue

        for pattern, desc in secret_patterns:
            try:
                if re.search(pattern, str(var_value)):
                    masked = var_value[:4] + "****" + var_value[-4:]
                    _add_finding(
                        findings, seen,
                        category="env_leak",
                        attack_id="SCA-RT-ENV",
                        title=f"{desc} in ${var_name}",
                        severity="critical",
                        description=f"Environment variable '{var_name}' contains what appears "
                                    f"to be a secret ({desc}) but is not marked as a secret. "
                                    f"Non-secret env vars are visible to all steps and logs.",
                        evidence=f"{var_name}={masked}",
                        remediation=f"Move '{var_name}' to GitHub Secrets. Rotate immediately.",
                    )
            except re.error:
                continue


# ── Daemon Lifecycle ─────────────────────────────────────────────────────────

def _write_pid():
    """Write daemon PID to file."""
    PID_FILE.write_text(str(os.getpid()))


def _read_pid() -> int:
    """Read daemon PID from file. Returns 0 if not running."""
    try:
        pid = int(PID_FILE.read_text().strip())
        # Verify process exists
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, OSError, ProcessLookupError):
        return 0


def _cleanup():
    """Clean up daemon files on exit."""
    try:
        PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def monitor_loop(poll_interval: int = DEFAULT_POLL_INTERVAL):
    """
    Main monitoring loop — runs until SIGTERM or SIGINT.
    Periodically checks for threats and writes findings to disk.
    """
    MONITOR_DIR.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    _write_pid()

    findings = _load_findings()
    seen = set()
    # Populate seen set from existing findings to avoid re-reporting
    for f in findings:
        key = hashlib.sha256(
            f"{f.get('attack_id')}:{f.get('title')}:{f.get('evidence', '')[:100]}".encode()
        ).hexdigest()[:16]
        seen.add(key)

    # Take baseline snapshots
    _log("Taking baseline snapshots...")
    baseline_procs = _snapshot_processes()
    baseline_pids = set(baseline_procs.keys())
    baseline_file_hashes = _snapshot_file_hashes(CREDENTIAL_FILES)
    _log(f"Baseline: {len(baseline_pids)} processes, {len(baseline_file_hashes)} tracked files")

    # Save baseline for post-mortem analysis
    baseline_snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "process_count": len(baseline_pids),
        "tracked_files": list(baseline_file_hashes.keys()),
    }
    try:
        (SNAPSHOT_DIR / "baseline.json").write_text(json.dumps(baseline_snapshot, indent=2))
    except OSError:
        pass

    # Register signal handlers for graceful shutdown
    running = True

    def _handle_signal(signum, frame):
        nonlocal running
        _log(f"Received signal {signum}, shutting down...")
        running = False

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _log(f"Monitor started (PID={os.getpid()}, interval={poll_interval}s)")
    cycle = 0

    while running:
        cycle += 1
        cycle_start = time.time()

        try:
            _check_processes(findings, seen, baseline_pids)
            _check_network(findings, seen)
            _check_filesystem(findings, seen, baseline_file_hashes)

            # Check environment less frequently (every 5 cycles)
            if cycle % 5 == 1:
                _check_environment(findings, seen)

            # Save findings to disk after each cycle
            _save_findings(findings)

            cycle_elapsed = time.time() - cycle_start
            if cycle % 12 == 0:  # Log stats every ~60s at 5s interval
                _log(f"Cycle {cycle}: {len(findings)} findings, {len(seen)} unique, "
                     f"check took {cycle_elapsed:.2f}s")

        except Exception as e:
            _log(f"ERROR in cycle {cycle}: {e}")

        # Sleep in small increments so we respond to signals promptly
        sleep_remaining = max(0, poll_interval - (time.time() - cycle_start))
        while sleep_remaining > 0 and running:
            time.sleep(min(sleep_remaining, 0.5))
            sleep_remaining -= 0.5

    # Final snapshot on exit
    _log(f"Monitor stopping after {cycle} cycles. Total findings: {len(findings)}")
    _save_findings(findings)

    final_snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cycles": cycle,
        "total_findings": len(findings),
        "unique_signatures": len(seen),
        "process_count": len(_snapshot_processes()),
    }
    try:
        (SNAPSHOT_DIR / "final.json").write_text(json.dumps(final_snapshot, indent=2))
    except OSError:
        pass

    _cleanup()
    _log("Monitor exited cleanly.")


# ── CLI Commands ─────────────────────────────────────────────────────────────

def cmd_start(poll_interval: int = DEFAULT_POLL_INTERVAL):
    """Start the monitoring daemon in the background."""
    existing_pid = _read_pid()
    if existing_pid:
        print(f"[SCG] Monitor already running (PID={existing_pid})")
        return 0

    MONITOR_DIR.mkdir(parents=True, exist_ok=True)

    # Fork to background
    pid = os.fork()
    if pid > 0:
        # Parent process
        time.sleep(0.5)  # Give child time to write PID
        child_pid = _read_pid()
        if child_pid:
            print(f"[SCG] Runtime monitor started (PID={child_pid}, interval={poll_interval}s)")
            print(f"[SCG] Findings will be written to: {FINDINGS_FILE}")
            print(f"[SCG] Logs at: {LOG_FILE}")
            return 0
        else:
            print("[SCG] ERROR: Monitor failed to start")
            return 1
    else:
        # Child (daemon) process
        # Detach from terminal
        os.setsid()
        # Close standard file descriptors
        sys.stdin.close()
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull

        try:
            monitor_loop(poll_interval)
        except Exception as e:
            _log(f"FATAL: {e}")
        finally:
            _cleanup()
        os._exit(0)


def cmd_stop() -> dict:
    """Stop the daemon and return collected findings."""
    pid = _read_pid()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            # Wait for graceful shutdown (up to 5s)
            for _ in range(10):
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
            print(f"[SCG] Monitor stopped (PID={pid})")
        except ProcessLookupError:
            print(f"[SCG] Monitor was not running (PID={pid})")
        except PermissionError:
            print(f"[SCG] Cannot stop monitor (PID={pid}): permission denied")
    else:
        print("[SCG] No running monitor found")

    # Collect findings
    findings = _load_findings()
    print(f"[SCG] Collected {len(findings)} runtime finding(s)")

    # Read log summary
    if LOG_FILE.exists():
        try:
            log_lines = LOG_FILE.read_text().splitlines()
            print(f"[SCG] Monitor log: {len(log_lines)} entries")
        except OSError:
            pass

    return {
        "findings": findings,
        "findings_count": len(findings),
        "findings_file": str(FINDINGS_FILE),
        "log_file": str(LOG_FILE),
    }


def cmd_status():
    """Check if the monitor is running."""
    pid = _read_pid()
    if pid:
        print(f"[SCG] Monitor is RUNNING (PID={pid})")
        findings = _load_findings()
        print(f"[SCG] Findings so far: {len(findings)}")
        if LOG_FILE.exists():
            try:
                lines = LOG_FILE.read_text().splitlines()
                if lines:
                    print(f"[SCG] Last log: {lines[-1]}")
            except OSError:
                pass
        return 0
    else:
        print("[SCG] Monitor is NOT running")
        return 1


def cmd_collect() -> list:
    """Read findings without stopping the daemon."""
    findings = _load_findings()
    return findings


# ── Entry Point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: runtime_monitor.py {start|stop|status|collect}")
        print()
        print("Commands:")
        print("  start   — Launch background monitor daemon")
        print("  stop    — Stop daemon, print collected findings")
        print("  status  — Check if daemon is running")
        print("  collect — Read findings without stopping")
        print()
        print("Environment:")
        print("  SCG_POLL_INTERVAL  — Check interval in seconds (default: 5)")
        print("  SCG_MONITOR_DIR    — Working directory (default: /tmp/scg-runtime-monitor)")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "start":
        interval = DEFAULT_POLL_INTERVAL
        if len(sys.argv) > 2:
            try:
                interval = int(sys.argv[2])
            except ValueError:
                pass
        sys.exit(cmd_start(interval))

    elif command == "stop":
        result = cmd_stop()
        # Print findings summary
        for f in result.get("findings", []):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Unknown")
            ts = f.get("timestamp", "")[:19]
            print(f"  [{sev}] {ts} — {title}")
        sys.exit(0)

    elif command == "status":
        sys.exit(cmd_status())

    elif command == "collect":
        findings = cmd_collect()
        print(json.dumps(findings, indent=2))
        sys.exit(0)

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
