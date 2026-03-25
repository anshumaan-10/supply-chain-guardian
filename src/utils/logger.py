#!/usr/bin/env python3
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Supply Chain Guardian — Logging Engine
# Copyright (c) 2025-2026 Anshumaan Singh. All rights reserved.
# Engineered for precision output in CI/CD pipelines and terminals.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import sys
import os
from datetime import datetime, timezone


class C:
    """ANSI escape sequences — no emoji, pure terminal control."""
    # Foreground
    R = "\033[91m"        # Red
    G = "\033[92m"        # Green
    Y = "\033[93m"        # Yellow
    B = "\033[94m"        # Blue
    M = "\033[95m"        # Magenta
    CY = "\033[96m"       # Cyan
    W = "\033[97m"        # White
    # Style
    BLD = "\033[1m"       # Bold
    DIM = "\033[2m"       # Dim
    UL = "\033[4m"        # Underline
    RST = "\033[0m"       # Reset
    # Background
    BG_R = "\033[41m"     # Background Red
    BG_G = "\033[42m"     # Background Green
    BG_Y = "\033[43m"     # Background Yellow
    BG_B = "\033[44m"     # Background Blue

    @classmethod
    def disable(cls):
        for attr in ('R','G','Y','B','M','CY','W','BLD','DIM','UL','RST',
                     'BG_R','BG_G','BG_Y','BG_B'):
            setattr(cls, attr, '')


# Backward compatibility alias
Colors = C

# Disable colors if not a TTY and not GitHub Actions
if not sys.stdout.isatty() and os.environ.get("GITHUB_ACTIONS") != "true":
    C.disable()


# ── Arrow & Marker Constants ────────────────────────────────────────────────
_ARROW_R  = f"{C.R}{C.BLD}>>{C.RST}"
_ARROW_G  = f"{C.G}{C.BLD}>>{C.RST}"
_ARROW_Y  = f"{C.Y}{C.BLD}>>{C.RST}"
_ARROW_B  = f"{C.B}{C.BLD}>>{C.RST}"
_ARROW_CY = f"{C.CY}{C.BLD}>>{C.RST}"
_MARKER_CRIT = f"{C.BG_R}{C.W}{C.BLD} CRITICAL {C.RST}"
_MARKER_HIGH = f"{C.R}{C.BLD} HIGH {C.RST}"
_MARKER_MED  = f"{C.Y}{C.BLD} MEDIUM {C.RST}"
_MARKER_LOW  = f"{C.B} LOW {C.RST}"
_MARKER_INFO = f"{C.DIM} INFO {C.RST}"
_MARKER_PASS = f"{C.BG_G}{C.W}{C.BLD} PASS {C.RST}"
_MARKER_FAIL = f"{C.BG_R}{C.W}{C.BLD} FAIL {C.RST}"
_MARKER_WARN = f"{C.BG_Y}{C.W}{C.BLD} WARN {C.RST}"

SEV_MARKERS = {
    "critical": _MARKER_CRIT,
    "high": _MARKER_HIGH,
    "medium": _MARKER_MED,
    "low": _MARKER_LOW,
    "info": _MARKER_INFO,
}

SEV_COLORS = {
    "critical": C.R + C.BLD,
    "high": C.R,
    "medium": C.Y,
    "low": C.B,
    "info": C.DIM,
}


class Logger:
    """
    Structured logger for Supply Chain Guardian.
    Clean arrows, color-coded severity, GitHub Actions annotations.
    No emoji. No AI branding. Pure engineering output.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._gha = os.environ.get("GITHUB_ACTIONS") == "true"

    # ── Core log levels ──────────────────────────────────────────────────

    def info(self, msg: str):
        print(f"  {_ARROW_CY} {msg}")

    def success(self, msg: str):
        print(f"  {_ARROW_G} {C.G}{msg}{C.RST}")

    def warning(self, msg: str):
        print(f"  {_ARROW_Y} {C.Y}{msg}{C.RST}")
        if self._gha:
            print(f"::warning::{msg}")

    def error(self, msg: str):
        print(f"  {_ARROW_R} {C.R}{msg}{C.RST}")
        if self._gha:
            print(f"::error::{msg}")

    def critical(self, msg: str):
        print(f"  {_MARKER_CRIT} {C.R}{C.BLD}{msg}{C.RST}")
        if self._gha:
            print(f"::error title=SUPPLY CHAIN ATTACK DETECTED::{msg}")

    def debug(self, msg: str):
        if self.verbose:
            print(f"  {C.DIM}   [{_ts()}] {msg}{C.RST}")

    # ── Structured output ────────────────────────────────────────────────

    def section(self, title: str):
        w = 62
        bar = "=" * w
        print(f"\n  {C.CY}{C.BLD}+{bar}+{C.RST}")
        print(f"  {C.CY}{C.BLD}|{C.RST} {C.W}{C.BLD}{title.center(w - 2)}{C.RST} {C.CY}{C.BLD}|{C.RST}")
        print(f"  {C.CY}{C.BLD}+{bar}+{C.RST}")

    def subsection(self, title: str):
        print(f"\n  {C.CY}--- {C.BLD}{title}{C.RST} {C.CY}{'~' * max(1, 55 - len(title))}{C.RST}")

    def phase(self, number: int, title: str, desc: str = ""):
        print(f"\n  {C.M}{C.BLD}[PHASE {number}]{C.RST} {C.W}{C.BLD}{title}{C.RST}")
        if desc:
            print(f"  {C.DIM}           {desc}{C.RST}")

    def scanner_start(self, name: str):
        print(f"\n  {C.CY}{C.BLD}>> SCANNING:{C.RST} {C.W}{C.BLD}{name}{C.RST}")
        print(f"  {C.DIM}{'.' * 64}{C.RST}")

    def scanner_done(self, name: str, count: int, elapsed: float = 0.0):
        if count == 0:
            print(f"  {_ARROW_G} {C.G}{name}: CLEAN{C.RST} {C.DIM}({elapsed:.1f}s){C.RST}")
        else:
            print(f"  {_ARROW_Y} {C.Y}{name}: {count} finding(s){C.RST} {C.DIM}({elapsed:.1f}s){C.RST}")

    def scanner_error(self, name: str, err: str):
        print(f"  {_ARROW_R} {C.R}{name}: ERROR -- {err}{C.RST}")

    def finding(self, severity: str, scanner: str, title: str, details: str = ""):
        marker = SEV_MARKERS.get(severity, _MARKER_INFO)
        color = SEV_COLORS.get(severity, C.DIM)
        print(f"    {marker} {color}[{scanner}]{C.RST} {title}")
        if details:
            print(f"    {C.DIM}         {details}{C.RST}")

    def kv(self, key: str, value: str, indent: int = 2):
        pad = " " * indent
        print(f"{pad}{C.DIM}{key}:{C.RST} {C.W}{value}{C.RST}")

    def separator(self, char: str = "-", width: int = 64):
        print(f"  {C.DIM}{char * width}{C.RST}")

    def blank(self):
        print()

    def annotate(self, severity: str, msg: str, file: str = "", line: int = 0):
        if not self._gha:
            return
        level_map = {"critical": "error", "high": "error", "medium": "warning",
                     "low": "warning", "info": "notice"}
        level = level_map.get(severity, "notice")
        loc = ""
        if file:
            loc = f" file={file}"
            if line:
                loc += f",line={line}"
        print(f"::{level}{loc}::{msg}")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")
